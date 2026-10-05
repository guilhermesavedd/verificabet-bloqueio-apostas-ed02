import csv, io, json, collections, sys
S=sys.argv[1]; REPO=sys.argv[2]
def classifica(st, soa):
    if st=='NOERROR': return 'resolve'
    if st=='NXDOMAIN': return 'bloqueado' if soa==0 else 'morto'
    return 'indeterminado'
hoje={}
for l in io.open(f'{S}/dns_hoje.txt',encoding='utf-8',errors='ignore'):
    p=l.rstrip('\n').split('|')
    if len(p)==3: hoje[p[0].lower()]=classifica(p[1],int(p[2] or 0))
ana={r['dominio'].lower():r for r in csv.DictReader(io.open(f'{REPO}/.lovable/research/anablock-2026-08/anablock_universo_completo_88997.csv',encoding='utf-8'))}
lai={d for d,r in ana.items() if r['na_lista_oficial_LAI']=='sim'}
a=json.load(open(f'{S}/ipinfo_antes.json')); b=json.load(open(f'{S}/ipinfo_depois.json'))
print(f"proveniencia: antes {a.get('org')} ({a.get('ip')})  |  depois {b.get('org')} ({b.get('ip')})")
print(f"janela: {open(f'{S}/dns_inicio.txt').read().strip()} → {open(f'{S}/dns_fim.txt').read().strip()}   medidos {len(hoje):,}")
def funil(dom, titulo):
    c=collections.Counter(hoje.get(d,'nao_medido') for d in dom); n=len(dom)
    print(f'\n[{titulo}] n={n:,}')
    for k in ('bloqueado','resolve','morto','indeterminado','nao_medido'):
        if c[k]: print(f'   {k:14} {c[k]:>7,}  {c[k]/n*100:6.2f}%')
    return c
cB=funil(lai, 'UNIVERSO B em 04/09 — LAI ∩ AnaBlock(24/08)')
funil(set(ana), 'lista de 24/08 inteira, medida em 04/09')
novos=set(hoje)-set(ana); funil(novos, f'{len(novos):,} novos na lista desde 24/08')
mud=collections.Counter()
for d in lai:
    x=ana[d]['dns_status_vivo']; x='indeterminado' if x.startswith('outro') else x
    h=hoje.get(d)
    if h and h!=x: mud[(x,h)]+=1
print(f'\nmudaram de estado no universo B, 24/08 → 04/09: {sum(mud.values()):,} de {len(lai):,} ({sum(mud.values())/len(lai)*100:.2f}%)')
for (x,h),n in mud.most_common(8): print(f'   {x:14} → {h:14} {n:>6,}')
op=[d for d,r in ana.items() if r['na_lista_oficial_LAI']=='sim' and r['classificacao']=='APOSTA' and r['dns_status_vivo']=='resolve']
co=collections.Counter(hoje.get(d,'nao_medido') for d in op)
print(f'\nos 1.531 operando (24/08) hoje: '+'  '.join(f'{k} {v} ({v/len(op)*100:.1f}%)' for k,v in co.most_common()))
json.dump({'universoB_hoje':dict(cB),'mudancas':{f'{x}->{h}':n for (x,h),n in mud.items()},'operando_hoje':dict(co)}, open(f'{S}/analise_dns_hoje.json','w'), indent=1)
