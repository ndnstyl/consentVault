#!/usr/bin/env python3
"""Computes WCAG 2.2 contrast for every token pair used by the hi-fi pages. Reads ../tokens.css. Writes ../contrast.md."""
import re, sys, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
css = (root/'tokens.css').read_text()
def block(sel_start):
    i = css.index(sel_start); j = css.index('{', i); depth=1; k=j+1
    while depth:
        depth += {'{':1,'}':-1}.get(css[k],0); k+=1
    return css[j+1:k-1]
def vars_of(b): return dict(re.findall(r'(--[a-z0-9-]+):\s*(#[0-9A-Fa-f]{6})\b', b))
light = vars_of(block(':root {'))
dark = dict(light); dark.update(vars_of(block(':root[data-theme="dark"]')))
# the media-query dark block must equal the explicit dark block
mq = vars_of(block(':root:not([data-theme="light"])'))
d2 = dict(light); d2.update(mq)
assert d2 == dark, 'media dark block and data-theme dark block differ: ' + str({k:(d2.get(k),dark.get(k)) for k in set(d2)|set(dark) if d2.get(k)!=dark.get(k)})
def lin(c): c/=255; return c/12.92 if c<=.03928 else ((c+.055)/1.055)**2.4
def lum(h): h=h.lstrip('#'); r,g,b=[int(h[i:i+2],16) for i in (0,2,4)]; return .2126*lin(r)+.7152*lin(g)+.0722*lin(b)
def ratio(a,b):
    la,lb=lum(a),lum(b); hi,lo=max(la,lb),min(la,lb); return (hi+.05)/(lo+.05)
S=['--color-surface','--color-bg','--color-surface-sunken','--color-surface-cream']
pairs=[]  # (label, fg, bg, need)
def add(label, fg, bgs, need=4.5):
    for bg in bgs: pairs.append((label, fg, bg, need))
add('Body text','--color-text',S)
add('Strong text','--color-text-strong',S)
add('Muted text','--color-text-muted',S)
add('Subtle text','--color-text-subtle',S)
add('Link text','--color-link',S)
add('Gold as text','--color-accent-ink',['--color-surface','--color-bg','--color-surface-cream','--color-accent-tint'])
add('Primary button label','--color-on-accent',['--color-accent','--color-accent-hover'])
add('Body text on gold tint (nav active)','--color-text-strong',['--color-accent-tint'])
for n in ['success','danger','warning','info']:
    add(f'{n.title()} text on its tint',f'--color-{n}',[f'--color-{n}-bg'])
    add(f'{n.title()} text on surface',f'--color-{n}',['--color-surface'])
for n in ['found','stop','none','incomplete']:
    add(f'Evidence {n} chip',f'--ev-{n}-fg',[f'--ev-{n}-bg'])
    add(f'Evidence {n} chip on surface (if bg lost)',f'--ev-{n}-fg',['--color-surface'])
add('Policy proceed chip','--pol-proceed-fg',['--color-surface','--color-bg','--color-surface-sunken'])
add('Policy hold chip','--pol-hold-fg',['--pol-hold-bg'])
add('Field edge (UI 3:1)','--color-border-strong',S[:3],3.0)
add('Focus ring vs page (UI 3:1)','--color-focus',['--color-surface','--color-bg','--color-surface-sunken','--color-accent-tint'],3.0)
add('Focus ring vs its gap (UI 3:1)','--color-focus',['--color-focus-gap'],3.0)
for n in ['found','stop','none','incomplete']:
    add(f'Chip border {n} vs surface (not required, informational)',f'--ev-{n}-border',['--color-surface'],1.0)
rows=[]; fails=0; low=None
for label,fg,bg,need in pairs:
    rl=ratio(light[fg],light[bg]); rd=ratio(dark[fg],dark[bg])
    pl='PASS' if rl>=need else 'FAIL'; pd='PASS' if rd>=need else 'FAIL'
    if need>1.0:
        fails+= (pl=='FAIL')+(pd=='FAIL')
        for r,t in ((rl,'light'),(rd,'dark')):
            if low is None or r/need<low[0]: low=(r/need,r,need,label,bg,t)
    rows.append(f'| {label} | `{fg}` on `{bg}` | {light[fg]} / {light[bg]} | {rl:.2f} | {pl} | {dark[fg]} / {dark[bg]} | {rd:.2f} | {pd} | {need} |')
out=['# Contrast table (computed by _build/contrast.py from tokens.css)','',
 'WCAG 2.2 AA: 4.5:1 text, 3:1 large text and UI components. Ratios use the WCAG relative-luminance formula. Rows with need 1.0 are informational (decorative borders) and not counted.','',
 f'Counted pairs: {sum(1 for p in pairs if p[3]>1.0)*2} (light + dark). FAIL count: {fails}.','',
 f'Lowest ratio relative to its requirement: {low[3]} on {low[4]} in {low[5]}: {low[1]:.2f}:1 (needs {low[2]}).','',
 '| Use | Tokens | Light colors | Light | Light verdict | Dark colors | Dark | Dark verdict | Need |','|---|---|---|---|---|---|---|---|---|']+rows
(root/'contrast.md').write_text('\n'.join(out)+'\n')
print('pairs',len(pairs),'fails',fails,'lowest',low)
sys.exit(1 if fails else 0)
