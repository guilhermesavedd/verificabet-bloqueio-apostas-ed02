"""
RDAP DIRETO no registro de cada TLD (bootstrap IANA), 8 em paralelo.
⚠️ A versão anterior usava o redirecionador rdap.org: 57% de timeout, ~13 s por
consulta — inviável. Registrar falha POR TLD é parte do resultado.
"""
import csv, io, json, random, sys, time, urllib.request, urllib.error, collections
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date

CSV, OUT, POR_TRI = sys.argv[1], sys.argv[2], int(sys.argv[3])
random.seed(20260904)

# bootstrap IANA: TLD -> URL base do servidor RDAP
boot = json.load(urllib.request.urlopen('https://data.iana.org/rdap/dns.json', timeout=30))
SERV = {}
for tlds, urls in boot['services']:
    for t in tlds:
        SERV[t.lower()] = urls[0].rstrip('/') + '/'
print(f'bootstrap IANA: {len(SERV)} TLDs com RDAP', flush=True)

rows = list(csv.DictReader(io.open(CSV, encoding='utf-8')))
por_tri = collections.defaultdict(list)
for r in rows: por_tri[r['trimestre']].append(r)
amostra = []
for tri, lst in sorted(por_tri.items()):
    amostra += random.sample(lst, min(POR_TRI, len(lst)))
print(f'amostra: {len(amostra)} em {len(por_tri)} trimestres', flush=True)

def consulta(r):
    host = r['url'].split('/')[0].lower()
    tld = host.rsplit('.', 1)[-1]
    base = SERV.get(tld)
    if not base:
        return host, r, None, f'tld_sem_rdap:{tld}'
    req = urllib.request.Request(f'{base}domain/{host}',
        headers={'Accept': 'application/rdap+json', 'User-Agent': 'VerificaBet-pesquisa/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            d = json.load(resp)
    except urllib.error.HTTPError as e:
        return host, r, None, f'http_{e.code}'
    except Exception as e:
        return host, r, None, e.__class__.__name__
    for ev in d.get('events', []):
        if ev.get('eventAction') == 'registration' and ev.get('eventDate'):
            return host, r, ev['eventDate'][:10], 'ok'
    return host, r, None, 'sem_data_registro'

t0 = time.time(); feitas = 0
with io.open(OUT, 'w', encoding='utf-8') as f, ThreadPoolExecutor(max_workers=8) as ex:
    w = csv.writer(f)
    w.writerow(['dominio', 'tld', 'trimestre', 'data_envio', 'data_registro', 'dias', 'motivo'])
    futs = [ex.submit(consulta, r) for r in amostra]
    for fut in as_completed(futs):
        host, r, reg, motivo = fut.result()
        dias = ''
        if reg:
            try:
                dias = (date.fromisoformat(r['data_envio']) - date.fromisoformat(reg)).days
            except Exception:
                motivo = 'data_invalida'
        w.writerow([host, host.rsplit('.',1)[-1], r['trimestre'], r['data_envio'], reg or '', dias, motivo])
        feitas += 1
        if feitas % 200 == 0:
            f.flush(); print(f'  {feitas}/{len(amostra)}  {time.time()-t0:.0f}s', flush=True)
print(f'fim: {feitas} em {time.time()-t0:.0f}s', flush=True)
