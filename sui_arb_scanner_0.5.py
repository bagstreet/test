#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sui_arb_scanner.py  —  GATE 0.5  (v3: МУЛЬТИ-ЧЕЙН, DexScreener, без ключа)
==========================================================================
Циклический арбитраж + перехват аномальных расхождений на нескольких сетях.

ИСТОЧНИК: DexScreener (бесплатно, без ключа). Та же проверка на любой сети —
меняется только chainId в эндпоинте:
  GET https://api.dexscreener.com/token-pairs/v1/{chain}/{tokenAddress}

ЧЕЙНЫ: sui, solana, base, aptos (см. CHAINS). Сиды — только высоконадёжные
адреса (native + USDC + пара хабов); остальной граф достраивается сам по парам.

ТРИ МОДУЛЯ (на КАЖДОЙ сети):
  1) CYCLE   — граф токенов, Bellman-Ford ищет кольца 2-5 ног, честная симуляция
               слиппеджа по реальной ликвидности + комиссии + газ.
  2) ANOMALY — кросс-DEX дисперсия (z-score, только ликвид) + всплеск объёма/
               priceChange m5 ("кит" = события типа IKA/TAKE).
  3) PAPER   — трекер исполнимости: вход с лагом, проверка, сколько живёт net>0
               (прямой замер разрыва paper<->live). actionable=1 — успел бы войти.

Логи (с колонкой chain) в STATE_DIR (=/home/user/.workspace):
  cycles_log.csv  anomaly_log.csv  dispersion_hist.csv  paper_exec_log.csv
  pending.json    seed_cache.json

ЗАПУСК:
  python3 sui_arb_scanner.py --once                 # 1 снимок по всем сетям
  python3 sui_arb_scanner.py --burst 5 --interval 90  # 5 снимков по 90с (для cron)
  python3 sui_arb_scanner.py                         # бесконечный цикл
==========================================================================
"""
import os, sys, csv, json, math, time, argparse, uuid
from datetime import datetime, timezone
from collections import defaultdict
import requests

DS_BASE = "https://api.dexscreener.com"
HTTP_TIMEOUT = 20
SCAN_INTERVAL = 60
STATE_DIR = os.getenv("ARB_STATE_DIR", "/home/user/.workspace")

# Сиды по сетям: symbol -> адрес (None = разрешить динамически через поиск).
# Только высоконадёжные канонические адреса; граф расширяется сам по quoteToken.
CHAINS = {
    "sui": {
        "SUI":  "0x2::sui::SUI",
        "USDC": "0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC",
        "DEEP": "0xdeeb7a4662eec9f2f3def03fb937a663dddaa2e215b8078a284d026b7946c270::deep::DEEP",
        "WAL":  "0x356a26eb9e012a68958082340d4c4116e7f55615cf27affcff209cf0ae544f59::wal::WAL",
        "haSUI":"0xbde4ba4c2e274a60ce15c1cfff9e5c42e41654ac8b6d906a57efa4bd3c29f47d::hasui::HASUI",
    },
    "solana": {
        "SOL":  "So11111111111111111111111111111111111111112",
        "USDC": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "USDT": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
        "JitoSOL": None,    # LST — резолвим по символу
    },
    "base": {
        "WETH": "0x4200000000000000000000000000000000000006",
        "USDC": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "cbETH": None,      # LST — резолвим
    },
    "aptos": {
        "APT":  "0x1::aptos_coin::AptosCoin",
        "USDC": None,       # резолвим (на Aptos несколько мостовых USDC)
    },
}
MAX_NODES_PER_CHAIN = 30

# Комиссии DEX по сетям (если нет — DEFAULT_FEE)
DEX_FEE = {
    # sui
    "cetus":0.0025,"turbos-finance":0.0025,"bluefin":0.0010,"flowx":0.0025,"kriya-dex":0.0030,
    "momentum":0.0020,"steamm":0.0010,"magma":0.0025,"aftermath":0.0020,"deepbook":0.0002,
    # solana
    "raydium":0.0025,"orca":0.0030,"meteora":0.0020,"phoenix":0.0002,"lifinity":0.0010,"fluxbeam":0.0025,
    # base / evm
    "uniswap":0.0030,"aerodrome":0.0005,"pancakeswap":0.0025,"sushiswap":0.0030,"baseswap":0.0025,
    # aptos
    "thala":0.0030,"liquidswap":0.0030,"pancakeswap-aptos":0.0025,"cellana":0.0005,
}
DEFAULT_FEE = 0.0025
# Газ на атомарный арб по сетям, USD (пессимистично)
GAS_USD_BY_CHAIN = {"sui":0.02,"solana":0.01,"base":0.03,"aptos":0.02}
MIN_LEG_TVL = 50_000
MAX_CYCLE_LEN = 5
MIN_NET_USD = 0.30

ANOM_WINDOW = 24
ANOM_Z = 3.0
ANOM_MIN_TVL = 250_000
WHALE_PRICECHANGE_M5 = 1.5
WHALE_VOL_M5_FRAC = 0.02

PAPER_MAX_AGE_MIN = 30
PAPER_MIN_PERSIST = 2
ENTRY_LAG_SNAPSHOTS = 1

def P(n): return os.path.join(STATE_DIR, n)

# ----------------------------- HTTP -----------------------------
def ds_get(path, retries=3):
    url = f"{DS_BASE}{path}"
    for i in range(retries):
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT, headers={"accept":"application/json"})
            if r.status_code == 429:
                time.sleep(2*(i+1)); continue
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if i == retries-1:
                print(f"  ! ds_get {path[:60]}: {e}"); return None
            time.sleep(1.0*(i+1))
    return None

def fnum(x, d=0.0):
    try: return float(x)
    except (TypeError, ValueError): return d

# ----------------------------- РЕЗОЛВЕР СИДОВ -----------------------------
def load_seed_cache():
    if os.path.exists(P("seed_cache.json")):
        try:
            with open(P("seed_cache.json")) as f: return json.load(f)
        except Exception: return {}
    return {}

def save_seed_cache(c):
    with open(P("seed_cache.json"),"w") as f: json.dump(c, f)

def resolve_seed(chain, symbol, cache):
    """Адрес токена по символу: ищем на DexScreener, берём пул с макс. ликвидностью."""
    key = f"{chain}:{symbol}"
    if key in cache:
        return cache[key]
    j = ds_get(f"/latest/dex/search?q={symbol}")
    best = None
    for p in (j or {}).get("pairs", []):
        if p.get("chainId") != chain:
            continue
        bt = p.get("baseToken", {}) or {}
        if (bt.get("symbol") or "").upper() != symbol.upper():
            continue
        liq = fnum((p.get("liquidity") or {}).get("usd"))
        if best is None or liq > best[1]:
            best = (bt.get("address"), liq)
    addr = best[0] if best else None
    cache[key] = addr
    return addr

def chain_seeds(chain, cache):
    out = {}
    for sym, addr in CHAINS[chain].items():
        a = addr or resolve_seed(chain, sym, cache)
        if a:
            out[sym] = a
        else:
            print(f"  ? {chain}:{sym} адрес не разрешён, пропуск")
    return out

# ----------------------------- СБОР ПУЛОВ -----------------------------
def fetch_pairs(chain, addr):
    j = ds_get(f"/token-pairs/v1/{chain}/{addr}")
    return j if isinstance(j, list) else []

def collect_pools(chain, seeds):
    seen, frontier = set(), dict(seeds)
    pools = []
    while frontier and len(seen) < MAX_NODES_PER_CHAIN:
        sym, addr = frontier.popitem()
        if addr in seen: continue
        seen.add(addr)
        for p in fetch_pairs(chain, addr):
            if p.get("chainId") != chain: continue
            bt, qt = p.get("baseToken",{}), p.get("quoteToken",{})
            base = (bt.get("symbol") or "?").upper(); quote = (qt.get("symbol") or "?").upper()
            liq = fnum((p.get("liquidity") or {}).get("usd"))
            if liq <= 0: continue
            vol = p.get("volume",{}) or {}; pc = p.get("priceChange",{}) or {}
            tx = (p.get("txns",{}) or {}).get("m5",{}) or {}
            pools.append({
                "dex":p.get("dexId","?"),"base":base,"quote":quote,
                "price_native":fnum(p.get("priceNative")),"price_usd":fnum(p.get("priceUsd")),
                "tvl":liq,"vol_m5":fnum(vol.get("m5")),"pc_m5":fnum(pc.get("m5")),
            })
            qaddr = qt.get("address")
            if qaddr and qaddr not in seen and len(seen)+len(frontier) < MAX_NODES_PER_CHAIN:
                frontier.setdefault(quote, qaddr)
    return pools

# ----------------------------- СЛИППЕДЖ / ЦИКЛЫ -----------------------------
def cpmm_out(a_usd, r_usd, fee):
    if r_usd <= 0: return 0.0
    a = a_usd*(1-fee)
    return (a*r_usd)/(r_usd+a)

def simulate_cycle(edges, notional, gas_usd):
    amt = notional
    for e in edges:
        amt = cpmm_out(amt, e["tvl"]/2.0, e["fee"]) * e["rate"]
    return amt - notional - gas_usd

def optimize_notional(edges, gas_usd):
    mt = min(e["tvl"] for e in edges)
    lo, hi = 1.0, max(2.0, mt*0.5)
    for _ in range(60):
        m1, m2 = lo+(hi-lo)/3, hi-(hi-lo)/3
        if simulate_cycle(edges,m1,gas_usd) < simulate_cycle(edges,m2,gas_usd): lo=m1
        else: hi=m2
    b=(lo+hi)/2
    return b, simulate_cycle(edges,b,gas_usd)

def clean_pools(pools):
    """Убирает пулы с бредовой ценой (мислейбл/битые данные): цена вне [0.33x,3x]
    медианы по этому токену среди его пулов. Реальный спред/депег сюда не попадёт."""
    from statistics import median
    by = defaultdict(list)
    for p in pools:
        if p["price_usd"] > 0: by[p["base"]].append(p["price_usd"])
    med = {s: median(v) for s, v in by.items() if v}
    out = []
    for p in pools:
        m = med.get(p["base"])
        if m and (p["price_usd"] <= 0 or p["price_usd"] < 0.33 * m or p["price_usd"] > 3 * m):
            continue
        out.append(p)
    return out

def build_edges(pools):
    edges = defaultdict(list)
    for p in pools:
        if p["price_native"] <= 0: continue
        a,b = p["base"],p["quote"]; fee = DEX_FEE.get(p["dex"], DEFAULT_FEE)
        edges[(a,b)].append({"dex":p["dex"],"fee":fee,"tvl":p["tvl"],"rate":p["price_native"]})
        edges[(b,a)].append({"dex":p["dex"],"fee":fee,"tvl":p["tvl"],"rate":1.0/p["price_native"]})
    return edges

def best_edge(edges,a,b):
    c = edges.get((a,b))
    return max(c, key=lambda e:e["rate"]*(1-e["fee"])) if c else None

def find_cycles(edges):
    nodes = list({n for e in edges for n in e})
    adj = defaultdict(list)
    for (a,b) in edges:
        e = best_edge(edges,a,b)
        if e and e["rate"]>0:
            adj[a].append((b, -math.log(max(e["rate"]*(1-e["fee"]),1e-12)), e))
    found = {}
    for src in nodes:
        dist={n:math.inf for n in nodes}; pred={n:None for n in nodes}; dist[src]=0.0; x=None
        for _ in range(min(len(nodes),MAX_CYCLE_LEN+1)):
            x=None
            for a in nodes:
                if dist[a]==math.inf: continue
                for (b,w,e) in adj[a]:
                    if dist[a]+w < dist[b]-1e-12:
                        dist[b]=dist[a]+w; pred[b]=(a,e); x=b
        if x is None: continue
        for _ in range(len(nodes)):
            if pred[x] is None: break
            x=pred[x][0]
        cn,ce,cur,g=[],[],x,0
        while True:
            if pred[cur] is None: break
            prev,e=pred[cur]; cn.append(cur); ce.append(e); cur=prev; g+=1
            if cur==x or g>MAX_CYCLE_LEN+1: break
        if cur==x and 2<=len(ce)<=MAX_CYCLE_LEN:
            key=tuple(sorted(set(cn)))
            if key not in found: found[key]=(list(reversed(cn+[x])), list(reversed(ce)))
    return list(found.values())

# ----------------------------- ДИСПЕРСИЯ / АНОМАЛИИ -----------------------------
def dispersion(pools):
    by=defaultdict(list)
    for p in pools:
        if p["tvl"]>=ANOM_MIN_TVL and p["price_usd"]>0: by[p["base"]].append(p)
    out={}
    for sym,ps in by.items():
        if len(ps)<2: continue
        lo=min(ps,key=lambda p:p["price_usd"]); hi=max(ps,key=lambda p:p["price_usd"])
        out[sym]={"disp_pct":(hi["price_usd"]-lo["price_usd"])/lo["price_usd"]*100,
                  "lo_dex":lo["dex"],"hi_dex":hi["dex"],"min_tvl":min(lo["tvl"],hi["tvl"]),
                  "max_pc_m5":max(abs(p["pc_m5"]) for p in ps),
                  "max_vol_frac":max((p["vol_m5"]/p["tvl"]) if p["tvl"] else 0 for p in ps)}
    return out

def load_hist():
    h=defaultdict(list)
    if os.path.exists(P("dispersion_hist.csv")):
        with open(P("dispersion_hist.csv")) as f:
            for row in csv.DictReader(f):
                h[f"{row.get('chain','')}:{row['token']}"].append(float(row["disp_pct"]))
    return h

def append_hist(ts, chain, disp):
    new = not os.path.exists(P("dispersion_hist.csv"))
    with open(P("dispersion_hist.csv"),"a",newline="") as f:
        w=csv.writer(f)
        if new: w.writerow(["ts","chain","token","disp_pct"])
        for sym,d in disp.items(): w.writerow([ts,chain,sym,round(d["disp_pct"],4)])

def detect_anomalies(ts, chain, disp, hist):
    hits=[]
    for sym,d in disp.items():
        h=hist.get(f"{chain}:{sym}",[])[-ANOM_WINDOW:]
        whale = (d["max_pc_m5"]>=WHALE_PRICECHANGE_M5) or (d["max_vol_frac"]>=WHALE_VOL_M5_FRAC)
        z=None
        if len(h)>=8:
            med=sorted(h)[len(h)//2]; mean=sum(h)/len(h)
            std=(sum((x-mean)**2 for x in h)/max(len(h)-1,1))**0.5
            if std>1e-9: z=(d["disp_pct"]-med)/std
        if (z is not None and z>=ANOM_Z and d["disp_pct"]>0.3) or (whale and d["disp_pct"]>0.3):
            hits.append({**d,"token":sym,"z":round(z,2) if z is not None else "","whale":whale})
    return sorted(hits,key=lambda x:x["disp_pct"],reverse=True)

# ----------------------------- PAPER-ИСПОЛНЕНИЕ -----------------------------
def net_after_costs(disp_pct, min_tvl, fee=DEFAULT_FEE, gas=0.02):
    notional=min(min_tvl*0.02,2000)
    slip=(notional/(min_tvl/2.0))*100 if min_tvl else 99
    return disp_pct - fee*2*100 - slip - (gas/max(notional,1)*100)

def load_pending():
    if os.path.exists(P("pending.json")):
        try:
            with open(P("pending.json")) as f: return json.load(f)
        except Exception: return []
    return []

def save_pending(l):
    with open(P("pending.json"),"w") as f: json.dump(l,f)

def update_paper(ts, chain, disp, anomalies, gas_usd):
    now=datetime.fromisoformat(ts); pending=load_pending()
    active={(p["chain"],p["token"]) for p in pending}
    for a in anomalies:
        if (chain,a["token"]) in active: continue
        pending.append({"id":uuid.uuid4().hex[:8],"chain":chain,"token":a["token"],"t0":ts,
                        "entry_spread":round(a["disp_pct"],4),"lo_dex":a["lo_dex"],"hi_dex":a["hi_dex"],
                        "min_tvl":a["min_tvl"],"whale":a["whale"],"samples":[]})
    fin,still=[],[]
    for p in pending:
        if p["chain"]!=chain:
            still.append(p); continue
        age=(now-datetime.fromisoformat(p["t0"])).total_seconds()/60.0
        cur=disp.get(p["token"]); cd=cur["disp_pct"] if cur else 0.0
        ct=cur["min_tvl"] if cur else p["min_tvl"]
        net=net_after_costs(cd,ct,gas=gas_usd)
        p["samples"].append([round(age,1),round(cd,4),round(net,4)])
        if age>=PAPER_MAX_AGE_MIN or cd<0.05:
            after=p["samples"][ENTRY_LAG_SNAPSHOTS:]; pos=[s for s in after if s[2]>0]
            fin.append([p["t0"],p["chain"],p["token"],p["entry_spread"],p["lo_dex"],p["hi_dex"],
                        int(p["min_tvl"]),int(bool(p["whale"])),len(p["samples"]),len(pos),
                        round(max((s[2] for s in after),default=0.0),4),int(len(pos)>=PAPER_MIN_PERSIST)])
        else:
            still.append(p)
    save_pending(still)
    if fin:
        new=not os.path.exists(P("paper_exec_log.csv"))
        with open(P("paper_exec_log.csv"),"a",newline="") as f:
            w=csv.writer(f)
            if new: w.writerow(["t0","chain","token","entry_spread_pct","lo_dex","hi_dex","min_tvl",
                                "whale","n_samples","n_pos_after_entry","best_net_pct","actionable"])
            for r in fin: w.writerow(r)
    return fin

def log_rows(path, header, rows):
    new=not os.path.exists(path)
    with open(path,"a",newline="") as f:
        w=csv.writer(f)
        if new: w.writerow(header)
        for r in rows: w.writerow(r)

# ----------------------------- ПРОХОД -----------------------------
def scan_chain(ts, chain, cache):
    seeds=chain_seeds(chain, cache)
    if not seeds: return 0,0,0
    pools=clean_pools(collect_pools(chain, seeds))
    gas=GAS_USD_BY_CHAIN.get(chain,0.02)
    n_tok=len({p["base"] for p in pools})
    print(f"  [{chain}] пулов {len(pools)} / токенов {n_tok}", end="")
    if not pools: print(" — пусто"); return 0,0,0
    # циклы
    edges=build_edges(pools); cyc=[]
    for nodes,ce in find_cycles(edges):
        ex=all(e["tvl"]>=MIN_LEG_TVL for e in ce); size,net=optimize_notional(ce,gas)
        gross=1.0
        for e in ce: gross*=e["rate"]*(1-e["fee"])
        win=int(net>MIN_NET_USD and ex)
        if net>-1.0:
            cyc.append([ts,chain,"→".join(nodes),len(ce),"/".join(e["dex"] for e in ce),
                        round((gross-1)*100,4),round(size,2),round(net,4),int(ex),win])
    cyc.sort(key=lambda r:r[7],reverse=True)
    log_rows(P("cycles_log.csv"),
             ["ts","chain","cycle","legs","dexes","gross_pct","opt_usd","net_usd","executable","win"],cyc)
    wins=sum(r[-1] for r in cyc)
    # аномалии
    disp=dispersion(pools); hist=load_hist(); anoms=detect_anomalies(ts,chain,disp,hist)
    append_hist(ts,chain,disp)
    log_rows(P("anomaly_log.csv"),
             ["ts","chain","token","disp_pct","z","cheap_dex","rich_dex","min_tvl","whale"],
             [[ts,chain,a["token"],round(a["disp_pct"],4),a["z"],a["lo_dex"],a["hi_dex"],
               int(a["min_tvl"]),int(a["whale"])] for a in anoms])
    # paper
    fin=update_paper(ts,chain,disp,anoms,gas); act=sum(r[-1] for r in fin)
    print(f" | циклов-win {wins} | аномалий {len(anoms)} | paper-actionable {act}")
    for a in anoms[:3]:
        print(f"     ! {chain}/{a['token']} disp={a['disp_pct']:.3f}% [{a['lo_dex']}→{a['hi_dex']}]"
              f"{' 🐋' if a['whale'] else ''}")
    return wins,len(anoms),act

def scan_once():
    os.makedirs(STATE_DIR, exist_ok=True)
    ts=datetime.now(timezone.utc).isoformat()
    cache=load_seed_cache()
    print(f"\n=== СКАН {ts} ===")
    tot=[0,0,0]
    for chain in CHAINS:
        try:
            w,a,act=scan_chain(ts,chain,cache)
            tot[0]+=w; tot[1]+=a; tot[2]+=act
        except Exception as e:
            print(f"  ! [{chain}] упал: {e}")
    save_seed_cache(cache)
    print(f"  ИТОГ: циклов-win {tot[0]} | аномалий {tot[1]} | actionable {tot[2]}")
    return tot

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--once",action="store_true")
    ap.add_argument("--burst",type=int,default=0,help="сколько снимков за один запуск")
    ap.add_argument("--interval",type=int,default=90,help="секунд между снимками в burst")
    a=ap.parse_args()
    print(f"sui_arb_scanner GATE0.5 v3 | мульти-чейн {list(CHAINS)} | state={STATE_DIR}")
    if a.burst>0:
        for i in range(a.burst):
            scan_once()
            if i<a.burst-1: time.sleep(a.interval)
        return
    if a.once:
        scan_once(); return
    while True:
        try: scan_once()
        except KeyboardInterrupt: print("\nстоп."); break
        except Exception as e: print(f"  ! проход упал: {e}")
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main()
