import csv, io, sys, collections, statistics, json
S=sys.argv[1]
rows=list(csv.DictReader(io.open(f'{S}/rdap_trimestre.csv',encoding='utf-8')))
ORDEM=['Jan25 a Mar25','Abr25 a Jun25','Jul25 a Set25','Out25 a Dez25','Jan26 a Mar26','Abr26 a Jun26','Jul26']
ROT={'Jan25 a Mar25':'2025-T1','Abr25 a Jun25':'2025-T2','Jul25 a Set25':'2025-T3','Out25 a Dez25':'2025-T4','Jan26 a Mar26':'2026-T1','Abr26 a Jun26':'2026-T2','Jul26':'2026-T3p'}
def q(v,p):
    v=sorted(v); k=(len(v)-1)*p; f=int(k); c=min(f+1,len(v)-1); return v[f]+(v[c]-v[f])*(k-f)
print(f'amostra: {len(rows):,}   recuperáveis (ok): {sum(1 for r in rows if r["motivo"]=="ok"):,}')
mot=collections.Counter(r['motivo'].split(':')[0] for r in rows)
print('motivos:', ', '.join(f'{k} {v}' for k,v in mot.most_common()))
print('\nPOR TRIMESTRE DA ORDEM (dias entre registro do domínio e a ordem):')
print(f'{"trimestre":10} {"n":>4} {"ok":>4} {"404":>4} {"mediana":>8} {"p25":>6} {"p75":>6} {"≤90d":>7} {"≤30d":>7}')
todos=[]; por={}
for tri in ORDEM:
    rs=[r for r in rows if r['trimestre']==tri]
    ok=[int(r['dias']) for r in rs if r['motivo']=='ok' and r['dias']!='']
    ok=[d for d in ok if d>=0]  # registro depois da ordem = outro registro reusando o nome; fora
    n404=sum(1 for r in rs if r['motivo']=='http_404')
    if len(ok)>=5:
        med=statistics.median(ok); p25=q(ok,.25); p75=q(ok,.75)
        a90=sum(1 for d in ok if d<=90)/len(ok)*100; a30=sum(1 for d in ok if d<=30)/len(ok)*100
        print(f'{ROT[tri]:10} {len(rs):>4} {len(ok):>4} {n404:>4} {med:>8.0f} {p25:>6.0f} {p75:>6.0f} {a90:>6.1f}% {a30:>6.1f}%')
        por[ROT[tri]]=dict(n=len(rs),ok=len(ok),n404=n404,mediana=med,p25=p25,p75=p75,ate90=a90,ate30=a30)
    todos+=ok
print(f'\nTODOS (igual peso por trimestre): n={len(todos)}  mediana {statistics.median(todos):.0f}  p25 {q(todos,.25):.0f}  p75 {q(todos,.75):.0f}  ≤90d {sum(1 for d in todos if d<=90)/len(todos)*100:.1f}%')
# ponderado pelo volume real de cada trimestre (LAI): media das medianas pesada
vol={'2025-T1':3444,'2025-T2':2393,'2025-T3':5047,'2025-T4':3580,'2026-T1':8034,'2026-T2':22532,'2026-T3p':6265}
w=sum(vol[k]*v['mediana'] for k,v in por.items())/sum(vol[k] for k in por)
a90w=sum(vol[k]*v['ate90'] for k,v in por.items())/sum(vol[k] for k in por)
print(f'PONDERADO pelo volume de cada trimestre: mediana ~{w:.0f} dias · ≤90d ~{a90w:.1f}%')
print(f'ed01: mediana 209 · p25 76 · p75 375 · ≤90d 28,8% (n=524 de 900, amostra aleatória sem estratificar)')
neg=sum(1 for r in rows if r['motivo']=='ok' and r['dias']!='' and int(r['dias'])<0)
print(f'\nregistrados DEPOIS da ordem (excluídos: é outro registro reusando o nome): {neg}')
json.dump({'por_trimestre':por,'todos':{'n':len(todos),'mediana':statistics.median(todos),'ate90':sum(1 for d in todos if d<=90)/len(todos)*100},'ponderado':{'mediana':w,'ate90':a90w},'motivos':dict(mot),'registro_apos_ordem':neg}, open(f'{S}/analise_rdap.json','w'), indent=1)
