#!/usr/bin/env python3
# @vertical bloqueio
"""
Mede a APLICAÇÃO do bloqueio de domínios de aposta nas redes de acesso BR via
RIPE Atlas (DNS no resolvedor local da probe) e agrega por ASN.

Blindado e resumível:
  - todo HTTP tem retry (tolera blip de rede — não crasha mais);
  - verdade-terreno via DoH/HTTPS (imune a bloqueio de UDP:53);
  - CREATE-ALL-THEN-COLLECT: cria todas as medições, depois coleta (mais rápido);
  - state file (estado.jsonl): reusa medição já criada, não re-cria nem re-gasta;
  - gate de claim por ASN = nº de PROBES DISTINTAS >= 5 (não por resultado).

NÃO roda sem ATLAS_API_KEY (env) + créditos. Deps: requests, ripe.atlas.sagan.
Uso: ATLAS_API_KEY=... python3 atlas_bloqueio.py dominios.txt --out ./saida --probes 500
"""
import os
import sys
import json
import time
import argparse
from collections import defaultdict

import requests
from ripe.atlas.sagan import DnsResult

API = "https://atlas.ripe.net/api/v2"
ATLAS_KEY = os.environ.get("ATLAS_API_KEY")
DOH_ENDPOINTS = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]
CREATE_PAUSE_S = 3   # ritmo p/ ~20k one-offs: ~75 simultâneas, sem rajada
N_MIN_PROBES = 5          # piso de PROBES DISTINTAS para claim por operadora
HTTP_TRIES = 6
HTTP_BACKOFF_S = 4
COLLECT_TIMEOUT_S = 180   # por medição, na fase de coleta
COLLECT_STEP_S = 15
NET_WAIT_S = 60           # portão de rede: sem internet, espera (não consome domínio)
DOH_SEM_RESPOSTA_MAX = 3  # rodadas de DoH sem NENHUMA resposta com rede OK → segue vazio

# Alocação FIXA de probes por operadora-alvo (Design #2 estratificado por operadora).
# ASNs mapeados no piloto 50 (placar_por_asn_v2.csv). Fixar por ASN garante que TODO
# domínio é medido pelas MESMAS operadoras → n=500 domínios por operadora (senão o
# sorteio aleatório de BR deixaria as operadoras finas — TIM/V.tal — sem cobertura).
# Colapso probe→veredito por célula domínio×operadora é feito na análise, não aqui.
PROBE_ALLOC = [
    (18881, 3),   # Vivo/Telefônica (frota ~7) — 0% bloq no piloto
    (28573, 3),   # Claro (frota ~5) — 0%
    (26615, 4),   # TIM (frota ~4) — ~22% bloq
    (8167,  2),   # V.tal/Oi (frota ~2) — ~45% bloq — n<5 → DESCRITIVO, fora do headline
    (28130, 2),   # outro bloqueador (frota ~2) — ~50%
]
PROBE_FILL_BR = 1         # 1 probe BR aleatória extra (breadth descritiva "N redes")
# Total ≈ 15 probes/domínio × 500 × 20 créditos = ~150k.


def exige_chave():
    if not ATLAS_KEY:
        sys.exit("ATLAS_API_KEY ausente no ambiente. Aborta.")


def carrega_dominios(path):
    with open(path) as f:
        doms = [l.strip().lower() for l in f if l.strip() and not l.startswith("#")]
    if not doms:
        sys.exit(f"nenhum domínio em {path}")
    # Preserva a ORDEM do arquivo (dedup mantém a 1ª ocorrência). Ordenar alfabeticamente
    # destruiria um embaralhamento com semente: qualquer prefixo de uma lista embaralhada é
    # amostra aleatória válida; um prefixo alfabético (0-9, a-c) é viés puro.
    return list(dict.fromkeys(doms))


def http_get(url):
    """GET com retry. Levanta a última exceção se esgotar."""
    ultimo = None
    for i in range(HTTP_TRIES):
        try:
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            return r
        except Exception as e:
            ultimo = e
            time.sleep(HTTP_BACKOFF_S * (i + 1))
    raise ultimo


def http_post(url, body):
    """POST com retry. 4xx não repete (erro do pedido)."""
    ultimo = None
    for i in range(HTTP_TRIES):
        try:
            r = requests.post(
                url,
                headers={"Authorization": f"Key {ATLAS_KEY}",
                         "Content-Type": "application/json"},
                data=json.dumps(body), timeout=30,
            )
            if r.status_code in (200, 201):
                return r
            if 400 <= r.status_code < 500:
                raise RuntimeError(f"{r.status_code} {r.text[:200]}")
            ultimo = RuntimeError(f"{r.status_code} {r.text[:120]}")
        except RuntimeError:
            raise
        except Exception as e:
            ultimo = e
        time.sleep(HTTP_BACKOFF_S * (i + 1))
    raise ultimo


def verdade_terreno(dominio):
    """IPs 'reais' via DoH (HTTPS) — robusto a bloqueio de UDP:53.
    Devolve set() = domínio sem A (inexistente/morto); None = NENHUM endpoint respondeu
    (rede), para não confundir queda de internet com domínio morto (bug de 23/09)."""
    viu_resposta = False
    for _ in range(2):
        for url in DOH_ENDPOINTS:
            try:
                r = requests.get(url, params={"name": dominio, "type": "A"},
                                 headers={"accept": "application/dns-json"}, timeout=8)
                if r.status_code != 200:
                    continue
                viu_resposta = True
                ips = {a["data"] for a in r.json().get("Answer", [])
                       if a.get("type") == 1}
                if ips:
                    return ips
            except Exception:
                continue
        time.sleep(2)
    return set() if viu_resposta else None


def rede_ok():
    """Internet + API alcançável? Qualquer resposta HTTP conta (só testa o caminho)."""
    try:
        requests.get(f"{API}/", timeout=8)
        return True
    except Exception:
        return False


def espera_rede():
    """Portão de rede: sem internet, ESPERA. Nada é consumido como falha nem como morto."""
    avisou = False
    while not rede_ok():
        if not avisou:
            print("  … sem rede — aguardando (nenhum domínio é consumido)", flush=True)
            avisou = True
        time.sleep(NET_WAIT_S)
    if avisou:
        print("  … rede voltou", flush=True)


def cria_com_portao(dom, probes):
    """Cria a medição de `dom` atrás do portão de rede.
    Devolve (msm, reais) ou None se a API recusou COM rede OK (erro do pedido, não repete)."""
    doh_vazias = 0
    while True:
        espera_rede()
        reais = verdade_terreno(dom)
        if reais is None:
            doh_vazias += 1
            if doh_vazias < DOH_SEM_RESPOSTA_MAX:
                print(f"  … DoH sem resposta p/ {dom} — rede? aguardando", flush=True)
                time.sleep(NET_WAIT_S)
                continue
            reais = set()   # rede OK e DoH mudo 3×: segue; recheck_liveness.py corrige depois
        try:
            return cria_medicao(dom, probes), reais
        except Exception as e:
            if not rede_ok():
                print(f"  … falha criar {dom} sem rede — vai repetir", flush=True)
                continue
            print(f"  ! {dom}: falha criar: {e}", flush=True)
            return None


def probes_spec():
    """Probes FIXAS por ASN de operadora-alvo + 1 fill BR. Mesmo conjunto em todo
    domínio → cobertura por operadora garantida (Design #2)."""
    sets = [{"type": "asn", "value": asn, "requested": n} for asn, n in PROBE_ALLOC]
    if PROBE_FILL_BR:
        sets.append({"type": "country", "value": "BR", "requested": PROBE_FILL_BR})
    return sets


def cria_medicao(dominio, n_probes):
    # n_probes IGNORADO: probes vêm de PROBE_ALLOC (fixas por operadora). Arg mantido
    # por compatibilidade de assinatura/resume.
    body = {
        "is_oneoff": True,
        "definitions": [{
            "type": "dns", "af": 4, "query_class": "IN", "query_type": "A",
            "query_argument": dominio, "use_probe_resolver": True,
            "resolve_on_probe": True, "description": f"bloqueio-bet {dominio}",
        }],
        "probes": probes_spec(),
    }
    return http_post(f"{API}/measurements/", body).json()["measurements"][0]


def carrega_estado(path):
    """Retoma: {dominio: {'msm': id, 'reais': [ips]}}."""
    est = {}
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            est[o["dominio"]] = {"msm": o["msm"], "reais": o["reais"]}
    return est


def anota_estado(path, dominio, msm, reais):
    with open(path, "a") as f:
        f.write(json.dumps({"dominio": dominio, "msm": msm, "reais": sorted(reais)}) + "\n")


def espera_resultados(msm_id):
    prev, estavel, t0 = -1, 0, time.time()
    dados = []
    while time.time() - t0 < COLLECT_TIMEOUT_S:
        try:
            dados = http_get(f"{API}/measurements/{msm_id}/results/?format=json").json()
        except Exception:
            time.sleep(10)
            continue
        if len(dados) and len(dados) == prev:
            estavel += 1
            if estavel >= 2:
                break
        else:
            estavel = 0
        prev = len(dados)
        time.sleep(COLLECT_STEP_S)
    return dados


def ips_e_rcode(raw):
    ips, rcode = set(), None
    try:
        parsed = DnsResult(raw)
    except Exception:
        return ips, rcode
    for resp in parsed.responses:
        abuf = getattr(resp, "abuf", None)
        if not abuf:
            continue
        rcode = getattr(abuf.header, "return_code", rcode)
        for ans in (abuf.answers or []):
            if getattr(ans, "type", "") == "A" and getattr(ans, "address", None):
                ips.add(ans.address)
    return ips, rcode


def classifica(raw, ips_reais):
    ips, rcode = ips_e_rcode(raw)
    if ips:
        return "aberto" if (ips & ips_reais) else "redirecionado"
    if rcode in ("NXDOMAIN", "REFUSED", "SERVFAIL", "NOERROR"):
        return "bloqueado"
    return "inconclusivo"


def mapa_asn(prb_ids):
    m = {}
    ids = list(prb_ids)
    for i in range(0, len(ids), 100):
        lote = ",".join(str(x) for x in ids[i:i + 100])
        j = http_get(f"{API}/probes/?id__in={lote}&fields=id,asn_v4&format=json").json()
        for p in j.get("results", []):
            m[p["id"]] = p.get("asn_v4")
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dominios")
    ap.add_argument("--probes", type=int, default=500)
    ap.add_argument("--out", default="./saida")
    args = ap.parse_args()

    exige_chave()
    os.makedirs(args.out, exist_ok=True)
    estado_path = os.path.join(args.out, "estado.jsonl")
    doms = carrega_dominios(args.dominios)
    estado = carrega_estado(estado_path)
    n_fixo = sum(n for _, n in PROBE_ALLOC) + PROBE_FILL_BR
    print(f"{len(doms)} domínios · {len(estado)} já no estado (reuso) · "
          f"probes FIXAS por operadora ≈{n_fixo}/domínio "
          f"(ASNs {[a for a, _ in PROBE_ALLOC]})", flush=True)

    # FASE A — garantir uma medição por domínio (reusa o que já existe)
    for dom in doms:
        if dom in estado:
            continue
        # DoH = sinal de liveness (vazio = morto/inexistente). Design LIVENESS-AGNÓSTICO:
        # NÃO pula morto — mede e classifica "inexistente" (RFC 2308) na análise. Pular
        # morto reintroduziria o viés de seleção do piloto (só vivos → superestima aberto).
        criado = cria_com_portao(dom, args.probes)
        if criado is None:
            continue
        msm, reais = criado
        estado[dom] = {"msm": msm, "reais": sorted(reais)}
        anota_estado(estado_path, dom, msm, reais)
        tag = "" if reais else " [morto p/ DoH → inexistente]"
        print(f"  criada {dom}: msm {msm}{tag}", flush=True)
        time.sleep(CREATE_PAUSE_S)

    # FASE B — coletar + classificar
    linhas, prb_ids = [], set()
    for dom, obj in estado.items():
        reais = set(obj["reais"])
        dados = espera_resultados(obj["msm"])
        for raw in dados:
            prb = raw.get("prb_id")
            prb_ids.add(prb)
            linhas.append((dom, prb, classifica(raw, reais)))
        print(f"  coletado {dom}: {len(dados)} probes", flush=True)

    asn = mapa_asn(prb_ids)
    linhas = [(d, p, asn.get(p), s) for (d, p, s) in linhas]

    with open(os.path.join(args.out, "resultados.csv"), "w") as f:
        f.write("dominio,prb_id,asn,status\n")
        for d, p, a, s in linhas:
            f.write(f"{d},{p},{a},{s}\n")

    # placar por ASN: conta PROBES DISTINTAS (gate) e resultados por status
    probes_por_asn = defaultdict(set)
    st = defaultdict(lambda: defaultdict(int))
    for d, p, a, s in linhas:
        if a is None or s == "inconclusivo":
            continue
        probes_por_asn[a].add(p)
        st[a]["n"] += 1
        st[a][s] += 1
    with open(os.path.join(args.out, "placar_por_asn.csv"), "w") as f:
        f.write("asn,probes_distintas,n_result,aberto,bloqueado,redirecionado,pct_bloqueado,claim_ok\n")
        for a, c in sorted(st.items(), key=lambda kv: -len(probes_por_asn[kv[0]])):
            nd = len(probes_por_asn[a])
            n = c["n"]
            bloq = c["bloqueado"] + c["redirecionado"]
            pct = round(100 * bloq / n, 1) if n else 0
            f.write(f"{a},{nd},{n},{c['aberto']},{c['bloqueado']},{c['redirecionado']},"
                    f"{pct},{'sim' if nd >= N_MIN_PROBES else 'nao'}\n")

    tot = sum(c["n"] for c in st.values())
    redes_claim = sum(1 for a in st if len(probes_por_asn[a]) >= N_MIN_PROBES)
    ab = sum(c["aberto"] for c in st.values())
    bl = sum(c["bloqueado"] + c["redirecionado"] for c in st.values())
    print(f"\nOK. {len(estado)} domínios · {tot} resultados úteis · {len(st)} ASNs · "
          f"{redes_claim} com >={N_MIN_PROBES} probes. "
          f"agregado aberto={ab} bloqueado={bl}. Saída em {args.out}/", flush=True)


if __name__ == "__main__":
    main()
