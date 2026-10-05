#!/usr/bin/env python3
# @vertical bloqueio
"""Conferência da lista oficial (LAI 18800.136437/2026-78, 71.795 linhas).
Deduplica para domínio registrável (heurística eTLD+1) e caracteriza a inflação
(subdomínio, path, porta). Não gasta rede."""
import csv, os, re, sys
from collections import Counter

_AQUI = os.path.dirname(os.path.abspath(__file__))
# Uso: python3 lai-conferencia.py [SitesBloqueados.csv] [saida.txt]
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(_AQUI, "lai-2026-09-22", "SitesBloqueados.csv")
SAIDA = sys.argv[2] if len(sys.argv) > 2 else os.path.join(_AQUI, "lai-2026-09-22", "lai-dominios-registraveis.txt")
# ccTLDs de 2 níveis comuns (br domina); resto = eTLD single-label.
DUAS = {"br", "uk", "au", "za", "in", "co"}  # 'co' só quando .co.<x>? tratado abaixo
BR2 = {"com.br", "net.br", "org.br", "gov.br", "bet.br", "app.br", "blog.br",
       "eco.br", "art.br", "inf.br", "ind.br", "srv.br", "tur.br"}

def registravel(host):
    h = host.strip().lower().lstrip("﻿")
    h = re.sub(r"^https?://", "", h)
    h = h.split("/")[0].split("?")[0].split(":")[0]  # tira path/query/porta
    h = h.rstrip(".")
    parts = h.split(".")
    if len(parts) < 2:
        return h, h, False
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:]) if len(parts) >= 3 else last2
    # sufixo br de 2 níveis?
    if parts[-1] == "br" and ".".join(parts[-2:]) in BR2:
        reg = last3
    elif parts[-1] in ("uk", "au", "za") and len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac"):
        reg = last3
    else:
        reg = last2
    is_sub = (h != reg)
    return h, reg, is_sub

linhas = []
with open(SRC, encoding="utf-8-sig") as f:
    for row in f:
        s = row.strip()
        if s:
            linhas.append(s)

hosts, regs, com_path, com_porta, subdom = [], [], 0, 0, 0
tld = Counter()
for s in linhas:
    if "/" in s:
        com_path += 1
    if re.search(r":\d+", s):
        com_porta += 1
    h, reg, is_sub = registravel(s)
    hosts.append(h)
    regs.append(reg)
    if is_sub:
        subdom += 1
    tld[reg.split(".")[-1]] += 1

n = len(linhas)
hosts_dist = len(set(hosts))
regs_dist = len(set(regs))
print(f"linhas (URLs oficiais):        {n}")
print(f"hosts distintos:               {hosts_dist}")
print(f"DOMÍNIOS REGISTRÁVEIS distintos: {regs_dist}   <- nossa conferência (o número honesto)")
print(f"  inflação: {n} URLs / {regs_dist} domínios = {n/regs_dist:.2f}x")
print(f"linhas que são subdomínio:     {subdom}")
print(f"linhas com path:               {com_path}")
print(f"linhas com porta:              {com_porta}")
print("\nTLD (por domínio registrável) — top 15:")
for t, c in tld.most_common(15):
    print(f"  .{t:12} {c}")

# salva a lista de domínios registráveis distintos p/ o reconcile SQL
with open(SAIDA, "w") as f:
    for d in sorted(set(regs)):
        f.write(d + "\n")
print(f"\nsalvo: {SAIDA} ({regs_dist} domínios)")
