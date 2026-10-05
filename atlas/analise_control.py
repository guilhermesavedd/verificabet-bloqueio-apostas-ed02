#!/usr/bin/env python3
"""Matriz operadora × domínio-controle. Veredito (resolve/block/dead) por resolvedor ISP.
Valida se os resolvedores funcionam: google/wikipedia/etc devem RESOLVER; o inexistente
deve dar DEAD (NXDOMAIN+SOA). ISP que dá BLOCK no google = resolvedor quebrado → descartar."""
import ipaddress, json, os, time, warnings
from collections import defaultdict, Counter
warnings.filterwarnings("ignore")
import requests
from ripe.atlas.sagan import DnsResult

API = "https://atlas.ripe.net/api/v2"
BASE = os.path.expanduser("~/atlas-run/saida-control")
OPER = {18881: "Vivo", 26599: "Vivo", 27699: "Vivo", 28573: "Claro",
        26615: "TIM", 8167: "V.tal", 28130: "outro-bloq"}
HOSTING = {16509, 14618, 20473, 13335, 8075, 15169, 24940, 63949, 174, 3356, 6939, 20940}
RES_PUBLICO = {"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
               "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
               "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
               "208.67.222.222", "208.67.220.220"}


def get(url, tries=6):
    for i in range(tries):
        try:
            r = requests.get(url, timeout=30); r.raise_for_status(); return r.json()
        except Exception:
            time.sleep(3)
    return None


def sinkhole(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_unspecified or a.is_reserved
    except Exception:
        return True


def verdito(resp):
    res = getattr(resp, "destination_address", None)
    ab = getattr(resp, "abuf", None)
    if not ab:
        return None, res
    rc = getattr(ab.header, "return_code", None)
    ips = [getattr(a, "address", None) for a in (ab.answers or [])
           if getattr(a, "type", "") == "A" and getattr(a, "address", None)]
    if [ip for ip in ips if not sinkhole(ip)]:
        return "resolve", res
    soa = any(getattr(au, "type", "") == "SOA" for au in (getattr(ab, "authorities", None) or []))
    if rc == "NXDOMAIN" and soa:
        return "dead", res
    if rc in ("NXDOMAIN", "SERVFAIL", "REFUSED", "NOERROR"):
        return "block", res
    return None, res


def op_de(a):
    return OPER.get(a, None if a in HOSTING else "outras")


est = [json.loads(l) for l in open(f"{BASE}/estado.jsonl") if l.strip()]
prb = set()
cel = defaultdict(list)   # (dom, op) -> vereditos ISP
raw_por_dom = {}
for o in est:
    dom = o["dominio"]
    dados = get(f"{API}/measurements/{o['msm']}/results/?format=json") or []
    raw_por_dom[dom] = dados
    for r in dados:
        prb.add(r.get("prb_id"))
asn = {}
ids = list(prb)
for i in range(0, len(ids), 100):
    j = get(f"{API}/probes/?id__in={','.join(map(str,ids[i:i+100]))}&fields=id,asn_v4&format=json") or {}
    for x in j.get("results", []):
        asn[x["id"]] = x.get("asn_v4")

for dom, dados in raw_por_dom.items():
    for r in dados:
        op = op_de(asn.get(r.get("prb_id")))
        if op is None:
            continue
        try:
            P = DnsResult(r)
        except Exception:
            continue
        for resp in P.responses:
            v, res = verdito(resp)
            if res in RES_PUBLICO or not v:
                continue
            cel[(dom, op)].append(v)

doms = [o["dominio"] for o in est]
ops = ["Vivo", "Claro", "TIM", "V.tal", "outro-bloq", "outras"]
print(f"{'dominio':<38} " + " ".join(f"{o:>10}" for o in ops))
for dom in doms:
    row = []
    for op in ops:
        vs = cel.get((dom, op))
        if not vs:
            row.append("-")
        else:
            c = Counter(vs)
            top = c.most_common(1)[0][0]
            row.append(f"{top}({c[top]}/{len(vs)})")
    print(f"{dom:<38} " + " ".join(f"{x:>10}" for x in row))
print("\nLEITURA: google/wikipedia/cloudflare/github devem dar 'resolve' num ISP honesto.")
print("'nao-existe-*' deve dar 'dead' (NXDOMAIN+SOA). ISP que dá 'block' no google = QUEBRADO → descartar do claim.")
