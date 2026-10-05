"""
Classificador de conteúdo de aposta — reproduzível, sem IA, sem custo.

🔴 O classificador da ed01 NÃO foi salvo. Este existe para que a ed02 seja
refazível por terceiro. Critério documentado em ACHADOS.md §4: sinal no CONTEÚDO
(provedor de jogo, jogo nomeado, ou aviso de jogo responsável) — nunca o nome do
domínio, nunca o status HTTP.

Dois modos:
  direto  — resolve normal. Para quem escapa do bloqueio.
  bypass  — resolve em 8.8.8.8 e força o IP com curl --resolve. Alcança o domínio
            BLOQUEADO por fora do resolvedor do provedor. É como a ed01 classificou
            os 47.987 bloqueados; sem isso, bloqueado seria indistinguível de morto.

⚠️ Cassino moderno é SPA: o conteúdo mora no bundle JS. Sem abrir o maior <script>
a classificação por HTML perde ~12% dos casos (ed01: +3.752 de 28.254).
"""
import csv, io, json, re, subprocess, sys, collections
from concurrent.futures import ThreadPoolExecutor, as_completed

UA = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36')

# Provedor de jogo / plataforma — sinal FORTE, específico do setor.
FORTES = [r'pragmatic\s*play', r'pg\s*soft', r'pgsoft', r'evolution\s*gaming',
          r'spribe', r'\bjili\b', r'playtech', r'ezugi', r'netent', r'habanero',
          r'\bcq9\b', r'\bbgaming\b', r'\bplaynt?go\b', r'red\s*tiger',
          r'fortune\s*tiger', r'fortune\s*ox', r'fortune\s*rabbit', r'fortune\s*mouse',
          r'\baviator\b', r'mines\s*game', r'jogo\s*do\s*bicho',
          r'jogo\s*respons[áa]vel', r'juego\s*responsable', r'responsible\s*gaming']
# Vocabulário do setor — sinal MÉDIO. Sozinho não classifica.
MEDIOS = [r'\bcassino\b', r'\bcasino\b', r'\bslots?\b', r'\bapostas?\b',
          r'\bbet\b', r'rodadas?\s*gr[áa]tis', r'free\s*spins', r'b[ôo]nus\s*de\s*dep[óo]sito',
          r'saque\s*(m[íi]nimo|r[áa]pido)', r'dep[óo]sito\s*m[íi]nimo', r'\bpix\b',
          r'roleta', r'blackjack', r'crash\s*game', r'ao\s*vivo']
RF = [re.compile(p, re.I) for p in FORTES]
RM = [re.compile(p, re.I) for p in MEDIOS]

def sh(cmd, timeout=25):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors='ignore')
        return p.stdout, p.returncode
    except Exception:
        return '', -1

def ip_de(host):
    """IP pelo resolvedor PÚBLICO — contorna o bloqueio do provedor."""
    out, _ = sh(['dig', '@8.8.8.8', '+short', host, 'A'], 10)
    for l in out.splitlines():
        l = l.strip()
        if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', l):
            return l
    return None

def busca(host, modo):
    base = ['curl', '-sS', '-L', '--max-redirs', '4', '--max-time', '18',
            '-A', UA, '-w', '\n@@%{http_code}|%{url_effective}|%{size_download}']
    if modo == 'bypass':
        ip = ip_de(host)
        if not ip:
            return None, '', '', 0, 'sem_ip_publico'
        base += ['--resolve', f'{host}:443:{ip}', '--resolve', f'{host}:80:{ip}']
    out, rc = sh(base + [f'https://{host}/'])
    if '@@' not in out:
        return None, '', '', 0, f'sem_resposta_rc{rc}'
    corpo, _, meta = out.rpartition('\n@@')
    code, url, size = (meta.split('|') + ['', '', ''])[:3]
    return corpo, code, url, int(size or 0), 'ok'

def maior_bundle(html, host, url_final):
    """Maior <script src> — é onde o SPA guarda o conteúdo."""
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    if not srcs:
        return ''
    from urllib.parse import urljoin
    cand = [urljoin(url_final or f'https://{host}/', s) for s in srcs]
    cand = [c for c in cand if c.startswith('http')]
    cand.sort(key=lambda c: (('.js' in c), len(c)), reverse=True)
    for c in cand[:2]:
        out, _ = sh(['curl', '-sS', '-L', '--max-time', '15', '-A', UA, c], 20)
        if len(out) > 2000:
            return out
    return ''

def pontua(txt):
    f = sum(1 for r in RF if r.search(txt))
    m = sum(1 for r in RM if r.search(txt))
    return f, m

def classifica(host, modo):
    html, code, url, size, motivo = busca(host, modo)
    if html is None:
        return dict(dominio=host, modo=modo, http='', url_final='', bytes=0,
                    fortes=0, medios=0, onde='', veredito='SEM_RESPOSTA', motivo=motivo)
    f, m = pontua(html)
    onde = 'html' if (f or m) else ''
    if f == 0:
        js = maior_bundle(html, host, url)
        if js:
            fj, mj = pontua(js)
            if fj or mj:
                f, m, onde = max(f, fj), max(m, mj), 'bundle'
    if f >= 1:
        ver = 'OPERANDO'
    elif m >= 3:
        ver = 'OPERANDO'          # vocabulário denso sem provedor nomeado
    elif size < 1500:
        ver = 'CASCA'
    elif m >= 1:
        ver = 'AMBIGUO'
    else:
        ver = 'SEM_SINAL'
    return dict(dominio=host, modo=modo, http=code, url_final=url, bytes=size,
                fortes=f, medios=m, onde=onde, veredito=ver, motivo='ok')

def main():
    lista, saida, modo, par = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    hosts = [l.strip().lower() for l in io.open(lista, encoding='utf-8') if l.strip()]
    campos = ['dominio','modo','http','url_final','bytes','fortes','medios','onde','veredito','motivo']
    n = 0
    with io.open(saida, 'w', encoding='utf-8', newline='') as fo, ThreadPoolExecutor(par) as ex:
        w = csv.DictWriter(fo, fieldnames=campos); w.writeheader()
        for fut in as_completed([ex.submit(classifica, h, modo) for h in hosts]):
            w.writerow(fut.result()); n += 1
            if n % 250 == 0:
                fo.flush(); print(f'  {n}/{len(hosts)}', flush=True)
    print(f'fim: {n}', flush=True)

main()
