#!/usr/bin/env python3
"""
Reincidência de marca por trimestre — regra REPRODUZÍVEL da ed02.

Por que este arquivo existe: a ed01 publicou 24,3% de reincidência e o script que
produziu esse número NÃO foi salvo. Ninguém consegue refazer a conta, nem nós.
A ed02 troca aquele número por este, que roda com um comando e cujas escolhas
estão todas escritas aqui embaixo — inclusive as que a ed01 deixou implícitas.

    python3 reincidencia.py <csv_do_MF> [saida.csv]

Entrada: a planilha da LAI 18800.126199/2026-92, colunas `url,data_envio,trimestre`.

A REGRA, como está descrita em lai-bloqueio-2026-08/ACHADOS.md §1:
  1. do host, pega o RÓTULO registrável (o pedaço à esquerda do sufixo público)
  2. remove os dígitos desse rótulo  →  brlbet0, brlbet1, brlbet999 → brlbet
  3. raízes genéricas são DESCARTADAS: juntariam operações que não têm relação
  4. agrupa por trimestre; "nova" é a marca vista pela primeira vez, "reincidente"
     é a que já apareceu num trimestre anterior

⚠️ O QUE A ed01 NÃO DOCUMENTOU, e que aqui está fixado por escolha explícita —
é aqui que mora a diferença entre 24,3% e o número que este script devolve:

  (a) SUFIXO COMPOSTO. `apostas.com.br` tem rótulo `apostas`, não `com`. A ed01 não
      diz como tratava isso. Lista fechada abaixo, montada a partir dos sufixos que
      de fato ocorrem nesta planilha — não é a PSL inteira, e não precisa ser.
  (b) HOSPEDAGEM COMPARTILHADA. `d1234abc.cloudfront.net` não é marca, é um id de
      CDN. Tratados como sufixo, o que descarta a linha em vez de inventar marca.
  (c) SEPARADORES. `casa-777.vip` → tira dígitos → `casa-` → o hífen de sobra cai.
      Sem isso `casa-` e `casa` seriam marcas diferentes.
  (d) RÓTULO QUE SOME. `0007bet` → sem dígitos → `bet` → genérico → descartado.
      Idem para rótulo 100% numérico, que vira string vazia.

Cada uma dessas quatro é uma decisão que muda o número. Estão aqui para que a
ed03 mude por vontade, não por acidente.
"""
from __future__ import annotations

import csv
import sys
from collections import defaultdict

# Raízes que a ACHADOS.md §1 manda excluir: são palavras do setor, não marcas.
# Juntar todo mundo que tem "bet" no nome seria dizer que são a mesma operação.
GENERICAS = {"bet", "win", "game", "jogo", "luck", "pg"}

# (a) e (b). Sufixos de mais de um rótulo que ocorrem nesta planilha. A escolha é
# fechar a lista no que o dado tem, em vez de arrastar a Public Suffix List
# inteira: assim a conta não muda sozinha quando a PSL for atualizada lá fora.
SUFIXOS_COMPOSTOS = {
    # ccTLD de segundo nível
    "com.br", "net.br", "org.br", "app.br", "art.br", "blog.br", "eco.br",
    "com.cn", "com.co", "com.mx", "com.ar", "co.uk", "org.uk", "co.za",
    # revendas que se comportam como sufixo
    "uk.com", "br.com", "us.com", "it.com", "eu.com", "sa.com",
    # (b) hospedagem: o rótulo à esquerda é id de máquina, não marca
    "cloudfront.net", "azurefd.net", "pages.dev", "workers.dev",
    "web.app", "firebaseapp.com", "netlify.app", "vercel.app",
    "github.io", "herokuapp.com", "amazonaws.com", "r2.dev", "blogspot.com",
}

ORDEM_TRIMESTRE = [
    ("Jan25 a Mar25", "2025-T1"),
    ("Abr25 a Jun25", "2025-T2"),
    ("Jul25 a Set25", "2025-T3"),
    ("Out25 a Dez25", "2025-T4"),
    ("Jan26 a Mar26", "2026-T1"),
    ("Abr26 a Jun26", "2026-T2"),
    ("Jul26", "2026-T3p"),
]


def raiz_da_marca(entrada: str) -> str | None:
    """Host → raiz de marca, ou None quando não sobra marca nenhuma."""
    host = entrada.strip().lower()
    if not host:
        return None
    # a fonte rotula a coluna como URL; 5 linhas trazem caminho (um encurtador)
    host = host.split("/")[0].split("?")[0]
    if host.startswith("www."):
        host = host[4:]
    partes = [p for p in host.split(".") if p]
    if len(partes) < 2:
        return None

    # descasca o sufixo: primeiro tenta o composto, depois o simples
    if len(partes) >= 3 and ".".join(partes[-2:]) in SUFIXOS_COMPOSTOS:
        rotulo = partes[-3]
    else:
        rotulo = partes[-2]

    # (2) tira os dígitos, e (c) as sobras de separador nas pontas
    raiz = "".join(c for c in rotulo if not c.isdigit())
    raiz = raiz.strip("-_")
    # (d) rótulo que era só dígito, ou que virou palavra do setor
    if not raiz or raiz in GENERICAS:
        return None
    return raiz


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    caminho = sys.argv[1]
    saida = sys.argv[2] if len(sys.argv) > 2 else None

    # marcas distintas vistas em cada trimestre
    por_trimestre: dict[str, set[str]] = defaultdict(set)
    linhas = descartadas = 0

    with open(caminho, newline="", encoding="utf-8") as fh:
        for reg in csv.DictReader(fh):
            linhas += 1
            raiz = raiz_da_marca(reg.get("url", ""))
            if raiz is None:
                descartadas += 1
                continue
            por_trimestre[reg.get("trimestre", "").strip()].add(raiz)

    vistas: set[str] = set()
    tabela = []
    for chave, rotulo in ORDEM_TRIMESTRE:
        marcas = por_trimestre.get(chave, set())
        reincidentes = marcas & vistas
        novas = marcas - vistas
        vistas |= marcas
        pct = 100 * len(reincidentes) / len(marcas) if marcas else 0.0
        tabela.append((chave, rotulo, len(novas), len(reincidentes), pct))

    tot_novas = sum(t[2] for t in tabela)
    tot_reinc = sum(t[3] for t in tabela)
    tot_pares = tot_novas + tot_reinc

    print(f"linhas lidas ............ {linhas}")
    print(f"descartadas (genérica / sem marca) {descartadas}"
          f"  ({100*descartadas/linhas:.1f}%)")
    print(f"marcas distintas ........ {len(vistas)}\n")
    print(f"{'trimestre':<12}{'novas':>8}{'reincid.':>10}{'% reincid.':>12}")
    for _, rotulo, novas, reinc, pct in tabela:
        mostra = f"{pct:.1f}%" if (novas + reinc) else "—"
        print(f"{rotulo:<12}{novas:>8}{reinc:>10}{mostra:>12}")
    print(f"{'TOTAL':<12}{tot_novas:>8}{tot_reinc:>10}"
          f"{100*tot_reinc/tot_pares:>11.1f}%")

    if saida:
        with open(saida, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["trimestre", "rotulo", "marcas_novas",
                        "marcas_reincidentes", "pct_reincidencia"])
            for chave, rotulo, novas, reinc, pct in tabela:
                w.writerow([chave, rotulo, novas, reinc, f"{pct:.1f}"])
        print(f"\ngravado: {saida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
