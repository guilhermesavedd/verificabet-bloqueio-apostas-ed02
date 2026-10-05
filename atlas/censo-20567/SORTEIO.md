# Sorteio — cohort de ordens novas (jul→set/2026) — medição RIPE Atlas

Pré-registração, escrita ANTES do run (22/09/2026). Pergunta: **as ordens recentes já estão
aplicadas no resolvedor padrão de cada operadora?** Comparável 1:1 com a §9.3 (mesmo desenho).

## Frame (cohort)
- Lista oficial da LAI 18800.136437/2026-78 (71.795 URLs distintas até 15/09/2026) **menos** o
  frame de julho (`block_order`, 51.121 domínios) = **20.567 domínios novos**
  (`~/atlas-run/lai-novos-2026-09-15.txt`). Sem filtro de liveness (liveness-agnóstico).

## Método
- **SRS sem reposição, n = 500** (2,4% do cohort). Semente: **`ed02-cohort-set2026-2026-09-22`**.
- Seleção = 500 menores `md5(domínio + semente)`. Reproduzível; lista em `dominios-cohort-500.txt`.
- Checksum (ordenado por domínio, vírgula, sem newline): ver linha `md5=` no log do run.
- Runner v2 resolver-aware (mesma alocação fixa por operadora da §9.3: Vivo/Claro/TIM/V.tal/outro
  + 1 fill BR ≈ 14–15 sondas/domínio). Custo teto 500 × 15 × 20 = 150k; real ≈ 140k.
- Análise: `analise_operadora.py --out ~/atlas-run/saida-cohort` — descarta resolvedor público,
  tripla RFC 2308 por maioria, IC Wilson por operadora. Denominador headline = vivos por DoH.
- Frota fina (V.tal 2, TIM 3 sondas) = descritivo, como na §9.3.

## LEI
- NUNCA somar com a amostra de 500 da §9.3 nem com o piloto: cohorts diferentes, perguntas diferentes.
- Claim escopado: "ordens de jul–set/2026, resolvedor padrão, camada DNS, na janela [data]".
- "irregular", nunca "golpe"; nunca "o bloqueio não funciona".
