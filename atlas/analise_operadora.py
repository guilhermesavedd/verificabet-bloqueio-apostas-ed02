#!/usr/bin/env python3
# @vertical bloqueio
"""Análise POR OPERADORA — v3 RESOLVER-AWARE, com CACHE e coleta PARALELA.

use_probe_resolver retorna VÁRIAS respostas por probe (uma por resolvedor local).
O bloqueio é aplicado no resolvedor do ISP; resolvedores PÚBLICOS (Google/Cloudflare/
Quad9/OpenDNS) furam o bloqueio. Então medimos SÓ as respostas de resolvedor NÃO-público.

Cada resposta de resolvedor-ISP → {resolve / block / dead}:
  resolve = devolve IP público roteável (bloqueio NÃO aplicado nesse resolvedor)
  block   = NXDOMAIN sem SOA / SERVFAIL / REFUSED / vazio / sinkhole (bloqueio sintético)
  dead    = NXDOMAIN COM SOA do TLD (domínio morto — RFC 2308)
Veredito da célula domínio×operadora = maioria das respostas ISP dessa operadora.
Headline por operadora = % dos domínios VIVOS (DoH) em que o resolvedor do ISP BLOQUEIA,
IC Wilson. NÃO soma o piloto. NÃO gasta crédito.

v3: os resultados do Atlas ficam em `resultados.jsonl` (forma compacta por resposta:
resolvedor, rcode, IPs A, SOA) — coleta resumível e paralela; a análise roda do cache.
Saídas: placar_operadora.csv · placar_asn.csv (ASN a ASN, inclusive dentro de "outras")
· vereditos_dominio.csv (uma linha por domínio, veredito por operadora → lista de vazamento).

Uso: ./venv/bin/python analise_operadora.py --out ~/atlas-run/saida-500 [--workers 8]
"""
import argparse
import ipaddress
import json
import math
import os
import time
import warnings
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor

warnings.filterwarnings("ignore")
import requests
from ripe.atlas.sagan import DnsResult

API = "https://atlas.ripe.net/api/v2"
WORKERS_PADRAO = 8

OPERADORA = {18881: "Vivo", 26599: "Vivo", 27699: "Vivo",
             28573: "Claro", 26615: "TIM", 8167: "V.tal", 28130: "outro-bloq"}
OPS_FIXAS = ["Vivo", "Claro", "TIM", "V.tal", "outro-bloq", "outras"]
HOSTING = {16509, 14618, 20473, 13335, 8075, 15169, 396982, 14061, 16276, 24940,
           63949, 45102, 132203, 174, 3356, 6939, 54113, 53667, 199524, 14593,
           207990, 20940, 54994,
           # vistas na frota BR (nome pela RIPEstat, 29/09): hospedagem/nuvem/empresa — não são
           # rede de ACESSO; o desenho exclui datacenter e a regra vale para rede corporativa
           7195,     # EdgeUno (trânsito/hosting)
           31898,    # Oracle Cloud
           47583,    # Hostinger
           212238,   # CDNEXT / Datacamp
           270631,   # Totvs (corporativa)
           272432,   # Magazine Luiza (corporativa)
           274734,   # LNS - Linux and Network Solutions (hosting)
           396509,   # LetsCloud
           }
# Sonda discordante da própria rede = caminho de DNS que NÃO passa pelo resolvedor da operadora
# (resolvedor de contêiner/cluster, roteador apontado p/ DNS público). Critério: numa operadora
# fixa cuja sonda mediana bloqueia >= BYPASS_MEDIANA_MIN, sonda com >= BYPASS_N_MIN domínios vivos
# e bloqueio < BYPASS_PCT_MAX conta como "DNS público", não como a operadora. Listado em sondas.csv.
BYPASS_MEDIANA_MIN = 50.0
BYPASS_PCT_MAX = 5.0
BYPASS_N_MIN = 50
# Resolvedores PÚBLICOS (furam o bloqueio do ISP) — descartar. v4 + v6.
RES_PUBLICO = {
    "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2606:4700:4700::1112", "2606:4700:4700::1002",
    "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10",
    "2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10",
    "208.67.222.222", "208.67.220.220", "2620:119:35::35", "2620:119:53::53",
    "94.140.14.14", "94.140.15.15", "76.76.2.0", "76.76.10.0",
}


def get(url, tries=6):
    for i in range(tries):
        try:
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            return r.json()
        except Exception:
            time.sleep(3 * (i + 1))
    return None


def sinkhole(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_unspecified or a.is_reserved
    except Exception:
        return True


# ---------- coleta (Atlas → cache compacto) ----------

def compacta_resposta(resp):
    """Uma resposta de UM resolvedor → dict compacto suficiente para classificar."""
    ab = getattr(resp, "abuf", None)
    if not ab:
        return {"res": getattr(resp, "destination_address", None), "rc": None, "ips": [], "soa": False}
    ips = [getattr(a, "address", None) for a in (ab.answers or [])
           if getattr(a, "type", "") == "A" and getattr(a, "address", None)]
    soa = any(getattr(au, "type", "") == "SOA" for au in (getattr(ab, "authorities", None) or []))
    return {"res": getattr(resp, "destination_address", None),
            "rc": getattr(ab.header, "return_code", None), "ips": ips, "soa": soa}


def compacta_medicao(dados):
    """Lista crua do Atlas → [{prb, respostas:[compacta…]}]."""
    saida = []
    for raw in dados:
        try:
            P = DnsResult(raw)
        except Exception:
            continue
        # `from` = IP público da probe NA HORA da medição → ASN de então (probe pode mudar de rede;
        # a API de probes só dá a ASN atual). Ver asn_na_hora.py.
        saida.append({"prb": raw.get("prb_id"), "from": raw.get("from"),
                      "ts": raw.get("timestamp"),
                      "respostas": [compacta_resposta(r) for r in P.responses]})
    return saida


def baixa_um(item):
    dom, msm = item
    dados = get(f"{API}/measurements/{msm}/results/?format=json")
    if dados is None:
        return dom, msm, None
    return dom, msm, compacta_medicao(dados)


def coleta(est, cache_path, workers):
    """Baixa o que ainda não está no cache (resumível) e devolve {dom: probes}."""
    cache = {}
    if os.path.exists(cache_path):
        for l in open(cache_path):
            if l.strip():
                r = json.loads(l)
                cache[r["dominio"]] = r["probes"]
    faltam = [(o["dominio"], o["msm"]) for o in est if o["dominio"] not in cache]
    print(f"cache: {len(cache)} domínios · a baixar: {len(faltam)} · workers: {workers}", flush=True)
    if not faltam:
        return cache
    falhas = 0
    t0 = time.time()
    with open(cache_path, "a") as f, ThreadPoolExecutor(workers) as pool:
        for i, (dom, msm, probes) in enumerate(pool.map(baixa_um, faltam), 1):
            if probes is None:
                falhas += 1
                continue
            cache[dom] = probes
            f.write(json.dumps({"dominio": dom, "msm": msm, "probes": probes}) + "\n")
            if i % 1000 == 0:
                f.flush()
                print(f"  baixados {i}/{len(faltam)} · {time.time()-t0:.0f}s", flush=True)
    if falhas:
        print(f"  ! {falhas} medições não baixadas (rede/API) — rodar de novo completa", flush=True)
    return cache


# ---------- classificação ----------

def classifica(c):
    """Resposta compacta → 'resolve'|'block'|'dead'|None."""
    if c.get("rc") is None and not c.get("ips"):
        return None
    if [ip for ip in c.get("ips", []) if not sinkhole(ip)]:
        return "resolve"
    if c["rc"] == "NXDOMAIN" and c.get("soa"):
        return "dead"
    if c["rc"] in ("NXDOMAIN", "SERVFAIL", "REFUSED", "NOERROR"):
        return "block"
    return None


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    center = (p + z * z / (2 * n)) / d
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d
    low, high = max(0.0, center - half), min(1.0, center + half)
    if k == 0:
        high = min(high, 3.0 / n)
    if k == n:
        low = max(low, 1 - 3.0 / n)
    return (p, low, high)


def op_de(asn):
    if asn in OPERADORA:
        return OPERADORA[asn]
    if asn in HOSTING:
        return None
    return "outras"


def mapa_asn(prb_ids):
    asn = {}
    ids = sorted(p for p in prb_ids if p is not None)
    for i in range(0, len(ids), 100):
        j = get(f"{API}/probes/?id__in={','.join(map(str, ids[i:i+100]))}"
                f"&fields=id,asn_v4&format=json") or {}
        for x in j.get("results", []):
            asn[x["id"]] = x.get("asn_v4")
    return asn


def carrega_vivos(base, est):
    vivo = {o["dominio"] for o in est if o.get("reais")}
    recheck_path = f"{base}/liveness-recheck.jsonl"
    if not os.path.exists(recheck_path):
        return vivo
    ultimo = {}
    for l in open(recheck_path):
        if l.strip():
            r = json.loads(l)
            ultimo[r["dominio"]] = r.get("status")
    recuperados = {d for d, s in ultimo.items() if s == "alive"} - vivo
    print(f"recheck de liveness: {len(ultimo)} reconferidos · "
          f"{len(recuperados)} falso-mortos recuperados", flush=True)
    return vivo | recuperados


def vereditos_isp(probes):
    """[{prb, respostas}] → [(prb, [vereditos ISP])], contagens (isp, pub)."""
    saida, n_isp, n_pub = [], 0, 0
    for p in probes:
        vs = []
        for c in p["respostas"]:
            if c.get("res") in RES_PUBLICO:
                n_pub += 1
                continue
            v = classifica(c)
            if v:
                n_isp += 1
                vs.append(v)
        saida.append((p["prb"], vs))
    return saida, n_isp, n_pub


def maioria(vs):
    return Counter(vs).most_common(1)[0][0]


def linha_placar(rotulo, n_probes, cells, vivo_doh):
    """cells = [(dom, veredito)] → linha CSV do placar."""
    res = sum(1 for _, v in cells if v == "resolve")
    blk = sum(1 for _, v in cells if v == "block")
    ded = sum(1 for _, v in cells if v == "dead")
    vivos = [(d, v) for d, v in cells if d in vivo_doh and v in ("resolve", "block")]
    blk_v = sum(1 for _, v in vivos if v == "block")
    p, lo, hi = wilson(blk_v, len(vivos))
    return (f"{rotulo},{n_probes},{len(cells)},{res},{blk},{ded},"
            f"{len(vivos)},{blk_v},{round(100*p,1)},{round(100*lo,1)},{round(100*hi,1)}")


CABECALHO = ("n_probes,dom_medidos,resolve,block,dead,"
             "vivos_medidos,block_entre_vivos,pct_block_vivos,ic95_low,ic95_high")


def vereditos_por_sonda(cache):
    """cache → [(dom, prb, [vereditos ISP])] só para sondas com veredito; contagens (isp, pub)."""
    saida, tot_isp, tot_pub = [], 0, 0
    for dom, probes in cache.items():
        por_prb, n_isp, n_pub = vereditos_isp(probes)
        tot_isp += n_isp
        tot_pub += n_pub
        saida.extend((dom, p, vs) for p, vs in por_prb if vs)
    return saida, tot_isp, tot_pub


def resolvedores_por_sonda(cache):
    """prb → Counter(ip de resolvedor NÃO-público) — pra documentar o caminho de DNS da sonda."""
    res = defaultdict(Counter)
    for probes in cache.values():
        for p in probes:
            for c in p["respostas"]:
                if c.get("res") and c["res"] not in RES_PUBLICO:
                    res[p["prb"]][c["res"]] += 1
    return res


def estatistica_sondas(triplas, asn, vivo_doh):
    """prb → {op, asn, n (vivos c/ resolve|block), block, pct}."""
    n, blk = Counter(), Counter()
    for dom, p, vs in triplas:
        if dom not in vivo_doh:
            continue
        v = maioria(vs)
        if v in ("resolve", "block"):
            n[p] += 1
            blk[p] += (v == "block")
    return {p: {"op": op_de(asn.get(p)), "asn": asn.get(p), "n": n[p], "block": blk[p],
                "pct": 100.0 * blk[p] / n[p]} for p in n}


def sondas_bypass(stats):
    """Sondas discordantes da própria rede (ver BYPASS_*). Só operadoras fixas (não 'outras')."""
    flag = set()
    for op in OPS_FIXAS:
        if op == "outras":
            continue
        pcts = sorted(s["pct"] for s in stats.values() if s["op"] == op and s["n"] >= BYPASS_N_MIN)
        if not pcts:
            continue
        mediana = pcts[len(pcts) // 2]
        if mediana < BYPASS_MEDIANA_MIN:
            continue
        flag |= {p for p, s in stats.items()
                 if s["op"] == op and s["n"] >= BYPASS_N_MIN and s["pct"] < BYPASS_PCT_MAX}
    return flag


def monta_celulas(triplas, asn, excluir):
    """Células domínio×operadora e domínio×ASN (maioria), sem as sondas excluídas."""
    cel_op, cel_asn = defaultdict(list), defaultdict(list)
    for dom, p, vs in triplas:
        if p in excluir:
            continue
        op = op_de(asn.get(p))
        if op is None:
            continue
        cel_op[(dom, op)].extend(vs)
        cel_asn[(dom, asn.get(p))].extend(vs)
    return ({k: maioria(vs) for k, vs in cel_op.items()},
            {k: maioria(vs) for k, vs in cel_asn.items()})


def escreve_placar(path, ver, chave_rotulo, n_probes, vivo_doh, cabecalho):
    linhas = [cabecalho + "," + CABECALHO]
    for k in sorted({k2 for (_, k2) in ver}, key=lambda x: (str(op_de(x) if isinstance(x, int) else x), str(x))):
        cells = [(d, v) for (d, k2), v in ver.items() if k2 == k]
        linhas.append(linha_placar(chave_rotulo(k), n_probes.get(k, 0), cells, vivo_doh))
    with open(path, "w") as f:
        f.write("\n".join(linhas) + "\n")
    return linhas


def escreve_sondas(path, stats, resolvedores, flag):
    with open(path, "w") as f:
        f.write("prb,asn,operadora,vivos_medidos,block,pct_block,bypass,resolvedores\n")
        for p, s in sorted(stats.items(), key=lambda kv: (kv[1]["op"] or "", -kv[1]["n"])):
            top = " ".join(ip for ip, _ in resolvedores[p].most_common(3))
            f.write(f"{p},{s['asn']},{s['op']},{s['n']},{s['block']},{s['pct']:.1f},"
                    f"{int(p in flag)},{top}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.expanduser("~/atlas-run/saida-500"))
    ap.add_argument("--workers", type=int, default=WORKERS_PADRAO)
    args = ap.parse_args()
    base = args.out
    est = [json.loads(l) for l in open(f"{base}/estado.jsonl") if l.strip()]
    vivo_doh = carrega_vivos(base, est)
    print(f"{len(est)} domínios · {len(vivo_doh)} vivos por DoH", flush=True)

    cache = coleta(est, f"{base}/resultados.jsonl", args.workers)
    triplas, tot_isp, tot_pub = vereditos_por_sonda(cache)
    asn = mapa_asn({p for (_, p, _) in triplas})
    stats = estatistica_sondas(triplas, asn, vivo_doh)
    flag = sondas_bypass(stats)
    escreve_sondas(f"{base}/sondas.csv", stats, resolvedores_por_sonda(cache), flag)

    print(f"\nrespostas ISP usadas: {tot_isp} · respostas públicas descartadas: {tot_pub}")
    print(f"sondas com veredito: {len(stats)} · discordantes da própria rede (bypass, excluídas): "
          f"{sorted(flag)}\n")

    # placar BRUTO (sem exclusão) — transparência — e placar OFICIAL (sem bypass)
    n_op = lambda excl: Counter(s["op"] for p, s in stats.items() if s["op"] and p not in excl)
    n_asn = lambda excl: Counter(s["asn"] for p, s in stats.items() if s["op"] and p not in excl)
    ver_bruto, _ = monta_celulas(triplas, asn, set())
    escreve_placar(f"{base}/placar_operadora_bruto.csv", ver_bruto, lambda k: k, n_op(set()),
                   vivo_doh, "operadora")
    ver_op, ver_asn = monta_celulas(triplas, asn, flag)
    linhas = escreve_placar(f"{base}/placar_operadora.csv", ver_op, lambda k: k, n_op(flag),
                            vivo_doh, "operadora")
    escreve_placar(f"{base}/placar_asn.csv", ver_asn, lambda a: f"{a},{op_de(a)}", n_asn(flag),
                   vivo_doh, "asn,operadora")
    print("\n".join(linhas))

    # vereditos por domínio (lista de vazamento por operadora)
    with open(f"{base}/vereditos_dominio.csv", "w") as f:
        f.write("dominio,vivo_doh," + ",".join(OPS_FIXAS) + "\n")
        for o in est:
            d = o["dominio"]
            f.write(f"{d},{int(d in vivo_doh)}," +
                    ",".join(ver_op.get((d, op), "") for op in OPS_FIXAS) + "\n")

    print(f"\nOK. {base}/placar_operadora.csv · placar_operadora_bruto.csv · placar_asn.csv · "
          f"sondas.csv · vereditos_dominio.csv")
    print("pct_block_vivos = % dos domínios VIVOS que o resolvedor do ISP BLOQUEIA (headline, IC95 Wilson).")
    print("resolve/block/dead = triplo cru por domínio (maioria das respostas ISP). n_probes<5 = descritivo.")


if __name__ == "__main__":
    main()
