#!/bin/bash
# Medição DNS em massa, mesmo método da ed01 (RFC 2308):
#   NXDOMAIN sem SOA na AUTHORITY = bloqueio sintético do provedor
#   NXDOMAIN com SOA               = domínio realmente inexistente (morto)
#   NOERROR                        = resolve (não bloqueado neste ponto)
# Consulta o resolvedor do SISTEMA (roteador → resolver do ISP). É isso que torna
# o bloqueio visível: de datacenter ele não existe.
S="$1"; LISTA="$2"; OUT="$3"
d_um() {
  d="$1"
  r=$(dig +noall +comments +authority "$d" A +time=3 +tries=1 2>/dev/null)
  st=$(printf '%s' "$r" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
  soa=$(printf '%s' "$r" | grep -c '[[:space:]]IN[[:space:]]SOA[[:space:]]')
  echo "$d|${st:-SEM_RESPOSTA}|$soa"
}
export -f d_um
# carimbo de proveniência ANTES
curl -s --max-time 10 https://ipinfo.io/json > "$S/ipinfo_antes.json"
date -u +%Y-%m-%dT%H:%M:%SZ > "$S/dns_inicio.txt"
xargs -P 12 -I{} bash -c 'd_um "$@"' _ {} < "$LISTA" > "$OUT"
date -u +%Y-%m-%dT%H:%M:%SZ > "$S/dns_fim.txt"
curl -s --max-time 10 https://ipinfo.io/json > "$S/ipinfo_depois.json"
echo "linhas medidas: $(wc -l < "$OUT")"
