#!/usr/bin/env python3
# @vertical bloqueio
"""
Re-confere a liveness (DoH) dos domínios cujo `reais` ficou VAZIO no estado.jsonl.

Por quê: `verdade_terreno` do runner devolve conjunto vazio tanto para "inexistente"
quanto para "erro de rede" (queda de internet durante o run de 23/09). Um domínio vivo
marcado como morto sai do denominador "vivos por DoH" da análise. Aqui a saída
distingue os três estados e NUNCA reescreve o estado.jsonl (dado não se apaga):
grava `liveness-recheck.jsonl` ao lado, append-only e resumível; a análise lê os dois.

Uso: python3 recheck_liveness.py --out ~/atlas-run/saida-cohort-full [--all]
"""
import os
import sys
import json
import time
import argparse
from concurrent.futures import ThreadPoolExecutor

import requests

DOH_ENDPOINTS = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]
ROUNDS = 2
TIMEOUT_S = 8
WORKERS = 8
STATUS_NXDOMAIN = 3


def consulta_doh(dominio):
    """Devolve (status, ips): alive | dead | unknown. `dead` só com resposta 200 sem A."""
    viu_resposta = False
    for _ in range(ROUNDS):
        for url in DOH_ENDPOINTS:
            try:
                r = requests.get(url, params={"name": dominio, "type": "A"},
                                 headers={"accept": "application/dns-json"},
                                 timeout=TIMEOUT_S)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            body = r.json()
            viu_resposta = True
            ips = sorted({a["data"] for a in body.get("Answer", []) if a.get("type") == 1})
            if ips:
                return "alive", ips
            if body.get("Status") == STATUS_NXDOMAIN:
                return "dead", []
        time.sleep(1)
    return ("dead", []) if viu_resposta else ("unknown", [])


def carrega_jsonl(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--all", action="store_true", help="reconfere todos, não só os vazios")
    args = ap.parse_args()

    estado = carrega_jsonl(os.path.join(args.out, "estado.jsonl"))
    if not estado:
        sys.exit("estado.jsonl vazio ou ausente")
    saida = os.path.join(args.out, "liveness-recheck.jsonl")
    # 'unknown' (erro de rede no próprio recheck) não conta como feito: volta na fila
    feitos = {r["dominio"] for r in carrega_jsonl(saida) if r.get("status") != "unknown"}
    alvo = [o["dominio"] for o in estado
            if (args.all or not o.get("reais")) and o["dominio"] not in feitos]
    print(f"{len(estado)} no estado · {len(alvo)} a reconferir · {len(feitos)} já feitos",
          flush=True)

    contagem = {"alive": 0, "dead": 0, "unknown": 0}
    with open(saida, "a") as f, ThreadPoolExecutor(WORKERS) as pool:
        for dom, (status, ips) in zip(alvo, pool.map(consulta_doh, alvo)):
            contagem[status] += 1
            f.write(json.dumps({"dominio": dom, "status": status, "ips": ips,
                                "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}) + "\n")
            f.flush()
    print(f"reconferidos: {contagem}", flush=True)
    if contagem["unknown"]:
        print("  ! há 'unknown' (erro de rede no recheck) — rodar de novo com rede boa "
              "(resumível: só os não feitos)", flush=True)


if __name__ == "__main__":
    main()
