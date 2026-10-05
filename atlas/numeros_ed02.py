#!/usr/bin/env python3
# @vertical bloqueio
"""Números da §9 e do lede da ed02 — fonte única, recalculável a partir do kit.

Tudo o que a ed02 diz sobre a medição RIPE Atlas sai daqui, nunca digitado à mão:
  - placar por operadora (oficial e bruto) da amostra 500 e do censo das 20.567;
  - comparação lado a lado resolvedor da operadora × DNS público (o "furo" do DNS);
  - sobreposição dos vazamentos entre operadoras no censo ("o que vaza é o lote");
  - parte `.br` da lista oficial de 15/09 (o alcance do art. 23 da MP 1.394).

Entradas (pastas de saída de analise_operadora.py, já rodado):
  estado.jsonl, resultados.jsonl, liveness-recheck.jsonl (opcional), sondas.csv,
  placar_operadora.csv, placar_operadora_bruto.csv, vereditos_dominio.csv.
Saída: um JSON com os números e o md5 de cada arquivo de entrada (proveniência).

Uso:
  python3 numeros_ed02.py --amostra saida-500 --censo saida-cohort-full \
      --lista lai-dominios-registraveis.txt --out numeros-ed02-atlas.json
"""
import argparse
import csv
import gzip
import hashlib
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analise_operadora as A  # noqa: E402  (classifica, RES_PUBLICO, carrega_vivos, maioria)

OPERADORAS_GRANDES = ("Vivo", "TIM", "V.tal")
BLOQUEADORAS = ("Vivo", "TIM", "V.tal", "outro-bloq")
CASAS_PCT = 1


def md5_arquivo(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h.update(bloco)
    return h.hexdigest()


def arquivo_resultados(base):
    """resultados.jsonl, ou resultados.jsonl.gz no kit público."""
    for nome in ("resultados.jsonl", "resultados.jsonl.gz"):
        caminho = os.path.join(base, nome)
        if os.path.exists(caminho):
            return caminho
    raise FileNotFoundError(f"sem resultados.jsonl(.gz) em {base}")


def abre_texto(caminho):
    return gzip.open(caminho, "rt") if caminho.endswith(".gz") else open(caminho)


def pct(k, n):
    return round(100.0 * k / n, CASAS_PCT) if n else None


def le_placar(path):
    with open(path) as f:
        return {r["operadora"]: {
            "sondas": int(r["n_probes"]),
            "vivos_medidos": int(r["vivos_medidos"]),
            "bloqueia": int(r["block_entre_vivos"]),
            "pct": float(r["pct_block_vivos"]),
            "ic95": [float(r["ic95_low"]), float(r["ic95_high"])],
        } for r in csv.DictReader(f)}


def le_sondas(path):
    """prb → (operadora, bypass)."""
    with open(path) as f:
        return {int(r["prb"]): (r["operadora"], r["bypass"] == "1") for r in csv.DictReader(f)}


def comparacao_publico(base, vivos, sondas):
    """Lado a lado: quando o resolvedor da operadora bloqueia um domínio VIVO, o que o
    resolvedor público da MESMA sonda responde. Conta também as respostas públicas que
    não devolvem endereço, separando domínio vivo de morto."""
    lado_a_lado = Counter()     # veredito público quando o ISP bloqueia domínio vivo
    ops_lado_a_lado = Counter()
    publico = Counter()         # (veredito, 'vivo'|'morto') de toda resposta pública
    with abre_texto(arquivo_resultados(base)) as f:
        for linha in f:
            r = json.loads(linha)
            dom = r["dominio"]
            estado = "vivo" if dom in vivos else "morto"
            for p in r["probes"]:
                isp = [A.classifica(c) for c in p["respostas"] if c.get("res") not in A.RES_PUBLICO]
                isp = [v for v in isp if v]
                isp_v = A.maioria(isp) if isp else None
                for c in p["respostas"]:
                    if c.get("res") not in A.RES_PUBLICO:
                        continue
                    v = A.classifica(c) or "sem_resposta"
                    publico[(v, estado)] += 1
                    if estado == "vivo" and isp_v == "block" and v != "sem_resposta":
                        lado_a_lado[v] += 1
                        ops_lado_a_lado[sondas.get(p["prb"], ("?", False))[0]] += 1
    total = sum(lado_a_lado.values())
    nao_resolve = {e: sum(n for (v, e2), n in publico.items() if e2 == e and v != "resolve")
                   for e in ("vivo", "morto")}
    return {
        "comparacoes": total,
        "publico_resolve": lado_a_lado["resolve"],
        "pct_publico_resolve": pct(lado_a_lado["resolve"], total),
        "operadoras_das_sondas": dict(ops_lado_a_lado),
        "respostas_publicas": sum(publico.values()),
        "publicas_sem_endereco": nao_resolve,
    }


def vazamentos(base):
    """No censo: quais domínios vivos cada operadora deixa passar, e a sobreposição."""
    with open(os.path.join(base, "vereditos_dominio.csv")) as f:
        vivos = [r for r in csv.DictReader(f) if r["vivo_doh"] == "1"]
    passa = {op: {r["dominio"] for r in vivos if r[op] == "resolve"} for op in BLOQUEADORAS}
    medidos = {op: {r["dominio"] for r in vivos if r[op] in ("resolve", "block")} for op in BLOQUEADORAS}
    tres = set.intersection(*(medidos[op] for op in OPERADORAS_GRANDES))
    lv, lt, lx = (passa[op] & tres for op in OPERADORAS_GRANDES)
    bloqueados_nas_4 = sum(1 for r in vivos if r["dominio"] in tres
                           and all(r[op] == "block" for op in BLOQUEADORAS))
    escapa_1 = len(lv | lt | lx)
    return {
        "vivos": len(vivos),
        "medidos_nas_3_grandes": len(tres),
        "passa": {op: len(passa[op] & tres) for op in BLOQUEADORAS},
        "vivo_e_tim": len(lv & lt),
        "vivo_e_vtal": len(lv & lx),
        "tim_e_vtal": len(lt & lx),
        "nas_3": len(lv & lt & lx),
        "so_vivo": len(lv - lt - lx),
        "so_tim": len(lt - lv - lx),
        "so_vtal": len(lx - lv - lt),
        "bloqueados_nas_4_bloqueadoras": bloqueados_nas_4,
        "pct_bloqueados_nas_4": pct(bloqueados_nas_4, len(tres)),
        "escapa_em_ao_menos_1_grande": escapa_1,
        "pct_escapa_em_ao_menos_1_grande": pct(escapa_1, len(tres)),
        "_listas": {"vivo_tim": sorted(lv & lt), "vtal": sorted(lx)},
    }


def sufixo_br(lista_path, listas_vazamento):
    with open(lista_path) as f:
        doms = [l.strip().lower() for l in f if l.strip() and not l.startswith("#")]
    br = [d for d in doms if d.endswith(".br")]
    por_sufixo = Counter(".".join(d.split(".")[-2:]) for d in br)
    principais = {s: por_sufixo[s] for s in ("com.br", "net.br")}
    saida = {
        "dominios_registraveis": len(doms),
        "terminam_em_br": len(br),
        "pct_br": pct(len(br), len(doms)),
        "por_sufixo": principais,
        "outros_br": len(br) - sum(principais.values()),
        "bet_br": por_sufixo.get("bet.br", 0),
        "fora_do_br": len(doms) - len(br),
        "pct_fora_do_br": pct(len(doms) - len(br), len(doms)),
    }
    for nome, lst in listas_vazamento.items():
        b = sum(1 for d in lst if d.endswith(".br"))
        saida[f"br_no_vazamento_{nome}"] = {"n": len(lst), "br": b, "pct": pct(b, len(lst))}
    return saida


def bloco_medicao(base):
    est = [json.loads(l) for l in open(os.path.join(base, "estado.jsonl")) if l.strip()]
    vivos = A.carrega_vivos(base, est)
    sondas = le_sondas(os.path.join(base, "sondas.csv"))
    return est, vivos, sondas, {
        "dominios": len(est),
        "vivos_doh": len(vivos),
        "pct_vivos": pct(len(vivos), len(est)),
        "placar": le_placar(os.path.join(base, "placar_operadora.csv")),
        "placar_bruto": le_placar(os.path.join(base, "placar_operadora_bruto.csv")),
        "sondas_bypass": sorted(p for p, (_, b) in sondas.items() if b),
        "dns_publico": comparacao_publico(base, vivos, sondas),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--amostra", required=True, help="pasta da amostra 500")
    ap.add_argument("--censo", required=True, help="pasta do censo das 20.567")
    ap.add_argument("--lista", required=True, help="domínios registráveis da lista de 15/09")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    _, _, _, amostra = bloco_medicao(args.amostra)
    _, _, _, censo = bloco_medicao(args.censo)
    vaz = vazamentos(args.censo)
    listas = vaz.pop("_listas")
    censo["vazamento"] = vaz
    br = sufixo_br(args.lista, listas)

    entradas = []
    for d in (args.amostra, args.censo):
        entradas += [os.path.join(d, "estado.jsonl"), arquivo_resultados(d)]
        entradas += [os.path.join(d, n) for n in ("sondas.csv", "placar_operadora.csv",
                                                  "vereditos_dominio.csv")]
    entradas.append(args.lista)
    saida = {
        "amostra_500": amostra,
        "censo_20567": censo,
        "lista_15_09": br,
        "proveniencia": {os.path.join(os.path.basename(os.path.dirname(os.path.abspath(p))),
                                      os.path.basename(p)): md5_arquivo(p) for p in entradas},
    }
    with open(args.out, "w") as f:
        json.dump(saida, f, ensure_ascii=False, indent=2)
    print(f"OK {args.out}")


if __name__ == "__main__":
    main()
