"""Shared helpers for the hi-fi page generator. Run build.py to regenerate the HTML."""
import itertools, pathlib, html
HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE.parent
CSS = (HERE/'portal.css').read_text()
_uid = itertools.count(1)
def uid(p='id'): return f'{p}{next(_uid)}'

SPRITE = '''<svg xmlns="http://www.w3.org/2000/svg" style="display:none" aria-hidden="true">
<symbol id="i-found" viewBox="0 0 16 16"><path d="M8 1.5 14.5 8 8 14.5 1.5 8Z" fill="currentColor"/></symbol>
<symbol id="i-stop" viewBox="0 0 16 16"><path d="M8 1.5 14.5 8 8 14.5 1.5 8Z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M4.5 8h7" stroke="currentColor" stroke-width="2"/></symbol>
<symbol id="i-none" viewBox="0 0 16 16"><path d="M8 1.5 14.5 8 8 14.5 1.5 8Z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></symbol>
<symbol id="i-incomplete" viewBox="0 0 16 16"><path d="M8 1.5 14.5 8 8 14.5 1.5 8Z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M8 1.5 1.5 8 8 14.5Z" fill="currentColor"/></symbol>
<symbol id="i-warn" viewBox="0 0 16 16"><path d="M8 1.8 15 14H1Z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M8 6.2v4M8 11.7v.6" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></symbol>
<symbol id="i-arrow" viewBox="0 0 16 16"><path d="M2.5 8h10M8.5 3.5 13 8l-4.5 4.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></symbol>
<symbol id="i-pause" viewBox="0 0 16 16"><path d="M5.5 3v10M10.5 3v10" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></symbol>
<symbol id="i-dash" viewBox="0 0 16 16"><path d="M3 8h10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
<symbol id="i-check" viewBox="0 0 16 16"><path d="m3 8.5 3.2 3.2L13 4.8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
<symbol id="i-info" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M8 7.2v4M8 4.6v.1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></symbol>
<symbol id="i-err" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m5.6 5.6 4.8 4.8M10.4 5.6l-4.8 4.8" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></symbol>
<symbol id="i-ok" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m5 8.2 2.2 2.2L11 6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></symbol>
<symbol id="i-copy" viewBox="0 0 16 16"><rect x="5.5" y="5.5" width="8" height="8" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10.5 3.5v-.2a1 1 0 0 0-1-1H3.8a1 1 0 0 0-1 1v5.7a1 1 0 0 0 1 1h.2" fill="none" stroke="currentColor" stroke-width="1.5"/></symbol>
<symbol id="i-menu" viewBox="0 0 16 16"><path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></symbol>
<symbol id="i-chev" viewBox="0 0 16 16"><path d="m4 6 4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></symbol>
<symbol id="i-seal" viewBox="0 0 16 16"><path d="M8 1.5 13.5 3.6v4.2c0 3-2.2 5-5.5 6.7C4.7 12.8 2.5 10.8 2.5 7.8V3.6Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="m5.6 8 1.7 1.7 3.1-3.3" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></symbol>
<symbol id="i-vault" viewBox="0 0 40 40"><path d="M20 3 37 20 20 37 3 20Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M20 11 29 20 20 29 11 20Z" fill="currentColor" opacity=".25"/><path d="M20 11 29 20 20 29 11 20Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></symbol>
</svg>'''

def ic(name, cls=''): return f'<svg class="{cls}" aria-hidden="true" focusable="false"><use href="#i-{name}"/></svg>'

# chips ---------------------------------------------------------------
EV = {
 'found': ('ev-found','found','Consent record found'),
 'stop': ('ev-stop','stop','Stop on record'),
 'none': ('ev-none','none','No record'),
 'incomplete': ('ev-incomplete','incomplete','Record incomplete'),
 'na': ('ev-na','warn','Not available'),
}
def ev(kind, label=None):
    c, i, l = EV[kind]; return f'<span class="chip {c}">{ic(i)}{label or l}</span>'
def pol(kind, label=None):
    m = {'proceed':('pol-proceed','arrow','Your policy: proceed'),'hold':('pol-hold','pause','Your policy: hold'),'none':('pol-none','dash','No policy in force')}
    c,i,l = m[kind]; return f'<span class="chip {c}">{ic(i)}{label or l}</span>'
def st(kind, label):
    icon = {'success':'ok','danger':'err','warning':'warn','info':'info','neutral':'dash'}[kind]
    return f'<span class="chip st-{kind}">{ic(icon)}{label}</span>'
def na(): return '<span class="na">Not available</span>'

# blocks --------------------------------------------------------------
def btn(label, kind='primary', goto=None, extra='', sm=False, icon=None, attrs=''):
    g = f' data-goto="{goto}"' if goto else ''
    cls = f'btn btn-{kind}' + (' btn-sm' if sm else '')
    return f'<button type="button" class="{cls}"{g} {attrs}>{ic(icon) if icon else ""}{label}</button>'

def banner(kind, title, body, action='', live=None):
    icon = {'info':'info','success':'ok','warning':'warn','danger':'err'}[kind]
    role = {'danger':'alert'}.get(kind,'status') if live is None else live
    r = f' role="{role}"' if role else ''
    t = f'<b>{title}</b>' if title else ''
    return f'<div class="banner {kind}"{r}>{ic(icon)}<div class="bd">{t}{body}{action}</div></div>'

def cause(what, c, nxt, button='', kind='danger', title=None):
    w = f'<p>{what}</p>' if what else ''
    body = f'<div class="cause">{w}<p><b style="display:inline">Cause:</b> {c}</p><p><b style="display:inline">Next:</b> {nxt}</p></div>'
    return banner(kind, title, body, button)

def ph(title, lede='', action='', meta='', eyebrow=''):
    e = f'<div class="eyebrow">{eyebrow}</div>' if eyebrow else ''
    l = f'<p class="lede">{lede}</p>' if lede else ''
    m = f'<div class="meta">{meta}</div>' if meta else ''
    a = f'<div class="btn-row">{action}</div>' if action else ''
    return f'<div class="ph"><div>{e}<h1 tabindex="-1">{title}</h1>{l}{m}</div>{a}</div>'

def loading(label):
    return (f'<div aria-busy="true"><p class="loading-msg" role="status">Loading {label}.</p>'
            '<div class="skel"><i class="h"></i><i style="width:92%"></i><i style="width:76%"></i><i style="width:84%"></i></div></div>')

def skeleton_cards():
    return '<div class="grid g4" aria-busy="true">' + '<div class="card skel"><i style="width:55%"></i><i class="h" style="height:36px"></i><i style="width:70%"></i></div>'*4 + '</div>'

def empty(title, text, action='', icon='vault'):
    return f'<div class="empty"><svg class="big" aria-hidden="true"><use href="#i-{icon}"/></svg><h2>{title}</h2><p>{text}</p>{action}</div>'

def table(caption, heads, rows, actions=False, matrix=False, region=None):
    """heads: list of header labels; rows: list of list of cell html. If actions, the last header is an
    action column (visually hidden header)."""
    th = ''.join(f'<th scope="col">{h}</th>' if not (actions and i==len(heads)-1) else f'<th scope="col"><span class="sr">{h}</span></th>' for i,h in enumerate(heads))
    body = ''.join('<tr>'+''.join(f'<td>{c}</td>' for c in r)+'</tr>' for r in rows)
    cap = f'<caption class="sr">{caption}</caption>'
    t = f'<div class="tscroll as-table"><table>{cap}<thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>'
    cards = ''
    for r in rows:
        dl = ''.join(f'<dt>{heads[i]}</dt><dd>{c}</dd>' for i,c in enumerate(r) if not (actions and i==len(r)-1))
        act = r[-1] if actions else ''
        cards += f'<div class="rowcard"><dl>{dl}</dl>{act}</div>'
    return f'<div class="tw">{t}<div class="cards" role="group" aria-label="{caption}">{cards}</div></div>'

def dialog(title, body, actions, wide=False, kind='dialog', labelid=None, static=False):
    i = labelid or uid('dlg')
    return (f'<div class="overlay{" static" if static else ""}"><div class="dialog{" wide" if wide else ""}" role="{kind}" aria-modal="true" aria-labelledby="{i}">'
            f'<h2 id="{i}">{title}</h2>{body}<div class="actions">{actions}</div></div></div>')

def field(label, control_html, hint='', fid=None, error=''):
    return f'<div class="field"><label for="{fid}">{label}</label>{control_html}{hint}{error}</div>'

# shell ---------------------------------------------------------------
NAV = [
 ('Start', [('Overview','index.html'),('First test event','#')]),
 ('Evidence', [('Evidence lookup','evidence.html'),('Evidence packages','evidence.html#packages-default')]),
 ('Configuration', [('Brands','#'),('Capture sources','sources-credentials.html'),('Credentials','sources-credentials.html#cred-default'),('Wording','#'),('Policies','policies.html'),('Documentation checklists','#'),('Connected systems','deliveries.html'),('Retention','#')]),
 ('Organization', [('Members','#'),('Audit log','#'),('Billing','#'),('Settings','#'),('Rule references','#')]),
]
def nav(active):
    out=''
    for grp, items in NAV:
        out += f'<h2>{grp}</h2>'
        for label,href in items:
            cur = ' aria-current="page"' if label==active else ''
            out += f'<a href="{href}"{cur}>{label}</a>'
    return out

PAGES = [('Overview','index.html'),('Sources and credentials','sources-credentials.html'),('Evidence','evidence.html'),('Deliveries','deliveries.html'),('Policies','policies.html'),('Components','components.html')]

FONTS = '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Montserrat:wght@500;600;700&family=Cormorant+Garamond:wght@500;600&family=Geist:wght@400;500;600&display=swap">'

JS = '''(function(){var d=document,h=d.documentElement;h.classList.add('js');
var states=[].slice.call(d.querySelectorAll('.state')),sel=d.getElementById('stateSel');
function show(id){if(!id||(id!=='__all'&&!d.getElementById(id)))id=states[0]&&states[0].id;
 h.classList.toggle('all',id==='__all');
 states.forEach(function(s){s.classList.toggle('on',id==='__all'||s.id===id)});
 var cur=d.getElementById(id),rl=d.getElementById('roleLbl');if(cur&&rl&&cur.getAttribute('data-role'))rl.textContent=cur.getAttribute('data-role');
 if(sel)sel.value=id;try{history.replaceState(null,'','#'+id)}catch(e){}}
if(states.length){show(location.hash.slice(1));
 if(sel)sel.addEventListener('change',function(){show(sel.value)});
 d.addEventListener('click',function(e){var g=e.target.closest('[data-goto]');if(g){show(g.getAttribute('data-goto'));window.scrollTo(0,0)}});
 window.addEventListener('hashchange',function(){show(location.hash.slice(1))});}
var mb=d.getElementById('menuBtn'),sd=d.getElementById('side');
if(mb&&sd)mb.addEventListener('click',function(){var o=sd.classList.toggle('open');mb.setAttribute('aria-expanded',o)});
var seg=[].slice.call(d.querySelectorAll('[data-theme-set]'));
function theme(t){if(t==='system')h.removeAttribute('data-theme');else h.setAttribute('data-theme',t);
 seg.forEach(function(b){b.setAttribute('aria-pressed',b.getAttribute('data-theme-set')===t)});try{localStorage.setItem('cv-theme',t)}catch(e){}}
seg.forEach(function(b){b.addEventListener('click',function(){theme(b.getAttribute('data-theme-set'))})});
var t0='system';try{t0=localStorage.getItem('cv-theme')||'system'}catch(e){}theme(t0);
var q=location.search.match(/theme=(light|dark)/);if(q)theme(q[1]);
})();'''

def demo_bar(states, current_page):
    opts = ''.join(f'<option value="{sid}">{lab}</option>' for sid,lab,*_ in states)
    opts += '<option value="__all">All states, stacked</option>'
    links = ''.join('<a href="%s"%s>%s</a>' % (h, ' aria-current="page"' if l==current_page else '', l) for l,h in PAGES)
    sel = f'<label for="stateSel">State</label><select id="stateSel">{opts}</select>' if states else ''
    return (f'<div class="demo" role="region" aria-label="Design review controls">{sel}'
            '<span class="seg" role="group" aria-label="Theme"><button type="button" data-theme-set="system" aria-pressed="true">System</button><button type="button" data-theme-set="light" aria-pressed="false">Light</button><button type="button" data-theme-set="dark" aria-pressed="false">Dark</button></span>'
            f'<nav class="pagelinks" aria-label="Design review pages">{links}</nav></div>')

def page(fname, title, active, states, org='Acme Lending', role='Admin', head_extra=''):
    """states: list of (id, label, html). Writes OUT/fname."""
    secs = states if isinstance(states, str) else ''.join('<section class="state%s" id="%s" aria-label="%s" data-role="%s"><p class="state-tag">State: %s</p>%s</section>' % (' on' if i==0 else '', t[0], t[1], t[3] if len(t)>3 else role, t[1], t[2]) for i,t in enumerate(states))
    doc = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} | {org} | ConsentVault</title>
<meta name="robots" content="noindex">
{FONTS}
<link rel="stylesheet" href="tokens.css">
<style>
{CSS}
</style>
</head>
<body>
{SPRITE}
<a class="skip" href="#main">Skip to main content</a>
{demo_bar([] if isinstance(states, str) else states, active_page(fname))}
<header class="topbar">
  <button type="button" class="pill-btn menu-btn" id="menuBtn" aria-expanded="false" aria-controls="side">{ic("menu")}Menu</button>
  <a class="brand" href="index.html"><i aria-hidden="true"></i>CONSENTVAULT</a>
  <span class="spacer"></span>
  <button type="button" class="pill-btn org" aria-haspopup="menu"><span>{org}</span>{ic("chev")}</button>
  <button type="button" class="pill-btn who" aria-haspopup="menu"><span>D. Ruiz <small>(<span id="roleLbl">{role}</span>)</small></span>{ic("chev")}</button>
</header>
<div class="shell">
<nav class="side" id="side" aria-label="Portal">{nav(active)}</nav>
<main class="main" id="main"><div class="wrap">
{secs}
</div></main>
</div>
<script>{JS}</script>
</body>
</html>
'''
    assert '—' not in doc and '–' not in doc, 'dash in ' + fname
    (OUT/fname).write_text(doc)

def active_page(fname):
    return {k:v for v,k in PAGES}.get(fname, '')
