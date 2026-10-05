# VerificaBet · Relatório de bloqueio de apostas, edição 02 — kit de reprodução

Dados e scripts por trás dos números da edição 02 do relatório de bloqueio de apostas
do VerificaBet: https://verificabet.com.br/pt-br/relatorios/bloqueio-apostas

Todo número do relatório sai de um arquivo daqui. Se um número do texto não bate com o
que estes scripts produzem, o erro é do texto — avise.

## O que tem aqui

| Pasta | Seção do relatório | O que é |
|---|---|---|
| `atlas/` | §9 e lede | Medição multi-rede com RIPE Atlas: amostra aleatória de 500 domínios (18/09/2026) e censo das 20.567 ordens novas (22–25/09/2026) |
| `lai/` | §1.1, §9.6 | Lista oficial de bloqueio (resposta da SPA/MF à LAI 18800.136437/2026-78) e a conferência por domínio registrável |
| `etapa1/` | §1 a §8 | Universo, cumprimento, classificação de conteúdo, reincidência, sucessores |
| `MANIFEST.sha256` | — | Hash de cada arquivo, para conferir que nada mudou depois da publicação |

### `atlas/`

- `atlas_bloqueio.py` — cria as medições (DNS A, `use_probe_resolver`, sondas fixas por operadora) e guarda a liveness por DoH. Lê a chave da RIPE de `ATLAS_API_KEY`; sem ela, não roda.
- `analise_operadora.py` — baixa os resultados (cache compacto em `resultados.jsonl`), classifica cada resposta em resolve / bloqueio sintético / inexistente (assinatura SOA, RFC 2308), descarta resolvedor público, agrupa por operadora e escreve `placar_operadora.csv`, `placar_operadora_bruto.csv`, `placar_asn.csv`, `sondas.csv`, `vereditos_dominio.csv`.
- `recheck_liveness.py` — reconfere por DoH os domínios que a primeira passada marcou sem endereço (separa "não existe" de "não consegui perguntar").
- `analise_control.py` e `controle/` — o controle (`google.com`, `wikipedia.org`, `github.com`, `cloudflare.com` e um domínio inexistente) nas mesmas redes.
- `numeros_ed02.py` → `numeros-ed02-atlas.json` — **todos os números da §9 e do lede**, recalculados a partir das pastas abaixo, com o md5 de cada entrada.
- `amostra-500/` — sorteio (`SORTEIO.md`: semente, checksum), lista, estado com os IDs das medições, resultados crus, placares, placar por sonda.
- `censo-20567/` — lista, estado com os IDs, liveness reconferida, resultados crus (`.gz`), placares, vereditos por domínio e as **listas nominais de vazamento** (`vazamento-vivo-tim.txt`, `vazamento-vtal.txt`).
- `frame-jul/` — as 51.150 ordens do frame de julho, de onde a amostra de 500 foi sorteada, com a data de cada ordem.

As medições da RIPE Atlas são públicas: qualquer ID em `estado.jsonl` pode ser baixado de novo em `https://atlas.ripe.net/api/v2/measurements/<id>/results/`.

**Correção feita antes da publicação.** A primeira análise da amostra de 500 (18/09) agrupou errado as "outras redes". O placar daquela rodada fica em `amostra-500/placar_operadora_v2_2026-09-18.csv`, para quem quiser ver a diferença. As regras que o relatório aplica depois de olhar o dado — sondas cujo DNS não passa pela operadora contam como DNS público; redes de nuvem, hospedagem e empresa ficam fora da conta de acesso — estão em `analise_operadora.py`, e o placar sem elas está em `placar_operadora_bruto.csv`.

### `lai/`

- `SitesBloqueados.csv` — a lista oficial, como a SPA/MF entregou (71.795 URLs distintas até 15/09/2026).
- `lai-conferencia.py` → `lai-dominios-registraveis.txt` — deduplicação por domínio registrável (71.155).
- `urls_bloqueadas_oficial_LAI_jan2025_jul2026.csv` — planilha de ordens de jan/2025 a jul/2026, resposta a pedido de acesso à informação **de terceiro** (protocolo 18800.126199/2026-92). O VerificaBet usa o dado público e não reivindica sua autoria.

### `etapa1/`

Scripts e saídas do recálculo das §1 a §8: `classifica.py` (classificador de conteúdo), `reincidencia.py` (regra da §6, um comando), `analise_dns_hoje.py`, `analise_rdap.py`, `rdap_direto.py`, `mede_bulk.sh`, e os arquivos de entrada e saída que eles leem e escrevem.

## Como reproduzir

```bash
python3 -m venv venv && . venv/bin/activate
pip install requests ripe.atlas.sagan dnspython

# números da §9 a partir do que está aqui (sem gastar nada na RIPE)
python3 atlas/numeros_ed02.py --amostra atlas/amostra-500 --censo atlas/censo-20567 \
    --lista lai/lai-dominios-registraveis.txt --out /tmp/numeros.json
diff <(python3 -m json.tool /tmp/numeros.json) <(python3 -m json.tool atlas/numeros-ed02-atlas.json)

# conferência da lista oficial
python3 lai/lai-conferencia.py lai/SitesBloqueados.csv /tmp/regs.txt
```

`numeros_ed02.py` lê os resultados crus direto do `.gz`. Refazer a
medição do zero exige uma conta na RIPE Atlas com créditos.

## O que não está aqui, e por quê

- **Dados da conexão que mediu o ponto único** (IP, localização): são pessoais.
- **Denúncias recebidas pelo VerificaBet** (§8): são dados de pessoas; o relatório publica só o agregado.
- **Credenciais**: nenhuma. O runner lê a chave do ambiente.

## Escopo do que isto mede

Camada de DNS, no resolvedor padrão da operadora, nas sondas medidas, na janela de cada
medição. "Resolveu para um IP" não é "o site está acessível". Nada aqui é juízo de
conformidade: se é ou não descumprimento, decide o regulador.

## Licença

Código sob MIT (`LICENSE`). Dados produzidos pelo VerificaBet sob CC BY 4.0
(`LICENSE-DADOS.md`), com crédito ao VerificaBet e o link do relatório. A lista oficial
e a planilha de terceiro são informação pública do governo, obtida por LAI, e não entram
na licença.

## English summary

Reproduction kit for edition 02 of VerificaBet's report on the enforcement of Brazil's
betting-site blocking orders. `atlas/` holds RIPE Atlas DNS measurements (a random
sample of 500 blocked domains and a census of 20,567 newly ordered domains, measured
through each probe's default resolver), the analysis scripts and every number used in
the report (`numeros-ed02-atlas.json`). `lai/` holds the official blocking list obtained
through a freedom-of-information request. All RIPE Atlas measurements are public; their
IDs are in each `estado.jsonl`.
