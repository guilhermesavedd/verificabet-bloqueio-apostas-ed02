# Sorteio da amostra 500 — medição de bloqueio ed02 §9 (RIPE Atlas)

Pré-registração. Reproduzível por qualquer um com o frame + a semente.

## Frame (universo)
- Tabela `block_order` (Supabase `dzwoahpslzzvkdegnrjg`), extraída em **2026-09-18**.
- `fonte` = **Ministério da Fazenda** · `protocolo` = **18800.126199/2026-92** (LAI), single-source.
- **51.254 linhas · 51.150 domínios distintos** · `data_envio` 2025-01-14 → 2026-07-22.
- Exclusão: 1 domínio `%.bet.br` (TLD legal/autorizado). Frame amostral = **51.150**.
- Unidade amostral = **domínio (entrada da lista MF)**. Granularidade: hosts como o MF ordenou
  (inclui alguns subdomínios/CDN — ex. `d16…cloudfront.net`, `m.bet-lg.com`; NÃO filtrados
  pós-sorteio, pra não reintroduzir viés — são propriedade da lista MF, reportar como ressalva).

## Método
- **SRS sem reposição**, n = **500** (0,977% ≈ 1% do universo).
- Semente registrada: **`ed02-bloqueio-mf-500-2026-09-18`**
- Seleção = os 500 domínios com menor `md5(domain || 'ed02-bloqueio-mf-500-2026-09-18')`.
- **Checksum do conjunto** (domínios ordenados por `domain`, joined por vírgula, sem newline):
  **`md5 = 549806b8a60e757bcd2b43c86c883ee1`** (n=500). Verificado byte-a-byte contra o banco.

### SQL do sorteio (reproduzível)
```sql
select domain
from (select distinct domain from block_order where domain not like '%.bet.br') t
order by md5(domain || 'ed02-bloqueio-mf-500-2026-09-18')
limit 500;
```

## Composição do sorteio (sanidade do viés corrigido)
- **467/500 (93,4%) nunca raspados** pelo radar (cego) · 33 no radar · 30 reachable · 0 parked.
- Confirma que a amostra é o **corte cego do universo**, não a ponta viva do piloto.
- ⚠️ Esperar muitos **mortos** → classe "inexistente" (RFC 2308), não "bloqueado".

## Classificação (pré-registrada — RFC 2308, tripla)
- **aberto** = resolvedor devolve QUALQUER IP público roteável (bloqueio de DNS NÃO aplicado).
  (correção do falso-positivo de CDN/anycast já embutida: IP alternativo da mesma anycast = aberto).
- **bloqueado-sintético** = NXDOMAIN **sem** SOA / SERVFAIL / resposta vazia / sinkhole (0.0.0.0/privado).
- **inexistente** = NXDOMAIN **com** SOA do TLD (domínio morto) — FORA do numerador de bloqueio.
- Validar a heurística contra controles known-blocked / known-dead; reportar taxa de erro.

## Inferência e claim
- Margem **pior caso ±4,4pp @95%** (p=0,5, n=500; FPC desprezível). **POR OPERADORA**, nunca nacional pooled.
- IC real por **Wilson**; extremos ~0% bloqueado → **Regra dos 3** ("≥99,4% aberto", um lado).
- V.tal (n=2 probes) fica **descritivo**, fora do headline. Declarar sempre o n de probes.
- **Piloto de 50 NUNCA é somado** aos 500 (viés de seleção "vivo/fresco") — só sidebar rotulado "conveniência".
- Figura secundária "subconjunto vivo" como robustez (liveness NÃO é pré-filtro).

## Escopo do claim (inviolável)
- Camada **DNS apenas** (operadora pode bloquear por IP/SNI/DPI) — confirmar que a ordem MF é de DNS.
- **Resolvedor padrão da operadora via 53/UDP** — DoH/DoT/DNS público/VPN/Private Relay furam e NÃO são avaliados.
- "resolveu para IP público" **≠** "site acessível".
- "irregular", nunca "golpe". **NUNCA** "o bloqueio não funciona" nem "a operadora descumpre".

## Origem da metodologia
Painel multi-agente `wf_acad0382-f51` (3 desenhos + auditoria estatística + auditoria claim/legal
+ síntese). Design escolhido: **#2 estratificado por operadora**. Ver handoff `docs/2026-09-18-HANDOFF-ATLAS-MEDICAO.md`.
