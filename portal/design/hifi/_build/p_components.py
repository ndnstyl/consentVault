from lib import *
from p_policies import attest_block
def sw(tokens):
    return '<div class="sw">'+''.join(f'<div><i style="background:var(--{t})"></i><span>--{t}</span></div>' for t in tokens)+'</div>'
def build():
    h=[]
    h.append(ph('Component sheet','Every component the five screens use, in the real tokens. Switch theme with the bar above.',eyebrow='ConsentVault Cloud portal'))
    h.append('<div class="cs">')
    h.append('<h2 class="sec">Color roles</h2><div class="stack"><p class="hint">Surfaces and text</p>'+sw(['color-bg','color-surface','color-surface-sunken','color-surface-cream','color-border','color-border-strong','color-text','color-text-muted','color-accent','color-accent-tint','color-focus'])
        +'<p class="hint">Operational status (organization, deliveries, banners)</p>'+sw(['color-success-bg','color-warning-bg','color-danger-bg','color-info-bg'])
        +'<p class="hint">Evidence status: descriptive hues, never red or green, so no chip reads as a verdict</p>'+sw(['ev-found-bg','ev-stop-bg','ev-none-bg','ev-incomplete-bg','pol-hold-bg'])+'</div>')
    h.append('<h2 class="sec">Type</h2><div class="card">'
        +'<div class="type-row"><code>text-stat 36</code><span style="font:600 var(--text-stat)/1.15 var(--font-display);font-variant-numeric:tabular-nums">4,812 of 10,000</span></div>'
        +'<div class="type-row"><code>text-xl 24 display</code><span style="font:600 var(--text-xl)/1.2 var(--font-display)">Evidence lookup</span></div>'
        +'<div class="type-row"><code>text-lg 20 display</code><span style="font:600 var(--text-lg)/1.2 var(--font-display)">Approve policy version 4</span></div>'
        +'<div class="type-row"><code>text-md 17</code><span style="font-size:var(--text-md)">Section heading and lede</span></div>'
        +'<div class="type-row"><code>text-base 15 Geist</code><span>Body text for tables, forms and explanations. Numbers line up: <span class="num">1,111 / 8,888</span>.</span></div>'
        +'<div class="type-row"><code>text-sm 13</code><span style="font-size:var(--text-sm)">Hints, table cells, chips</span></div>'
        +'<div class="type-row"><code>text-xs 12</code><span class="eyebrow" style="margin:0">Eyebrow label</span></div>'
        +'<div class="type-row"><code>serif accent</code><span style="font:600 var(--text-2xl)/1.15 var(--font-serif)">No packages built in this session</span></div></div>')
    h.append('<h2 class="sec">Buttons</h2><div class="card stack"><div class="row">'+btn('Issue a credential','primary')+btn('Cancel','secondary')+btn('Try again','quiet')+btn('Revoke now','danger')+btn('Disabled','primary',attrs='disabled aria-disabled="true"')+'</div><div class="row">'+btn('Small action','secondary',sm=True)+btn('Copy','secondary',sm=True,icon='copy')+'<button type="button" class="btn btn-primary focus-demo">Focus ring</button></div><p class="hint">Labels are verbs. 40px high on desktop, 44px on touch. One gold primary per view.</p></div>')
    e1,e2,e3,e4,e5=[uid('f') for _ in range(5)]
    h.append('<h2 class="sec">Inputs</h2><div class="card"><div class="grid g2"><div>'
        +field('Name',f'<input class="input" id="{e1}" type="text" value="Website form key">',hint='<div class="hint">Shown in your audit log.</div>',fid=e1)
        +field('Origin',f'<input class="input" id="{e2}" type="text" value="https://acmelending.example/form" aria-invalid="true" aria-describedby="{e2}e">',fid=e2,error=f'<div class="field-error" id="{e2}e">{ic("err")}Enter an origin with no path.</div>')
        +field('Disabled',f'<input class="input" id="{e3}" type="text" value="Not editable" disabled>',fid=e3)
        +f'<div class="field"><label for="{e4}">Kind</label><select class="select" id="{e4}"><option>Dialer</option><option>CRM</option></select></div>'
        +'</div><div>'
        +'<fieldset><legend>Signature</legend><label class="opt" for="x1"><input type="radio" name="sg" id="x1" checked><span><b>Ed25519 (recommended)</b>You load our public key into your system.</span></label><label class="opt" for="x2"><input type="radio" name="sg" id="x2"><span><b>HMAC shared secret</b>Shown once.</span></label></fieldset>'
        +'<fieldset><legend>Brands it may name</legend><label class="opt" for="x3"><input type="checkbox" id="x3" checked><span><b>Acme Lending</b></span></label><label class="opt" for="x4"><input type="checkbox" id="x4"><span><b>Acme Home Loans</b></span></label></fieldset>'
        +f'<div class="field"><label for="{e5}">Reason (recorded in the audit log)</label><textarea class="textarea" id="{e5}"></textarea></div></div></div></div>')
    rows=[['<strong>Dialer</strong>','Signed webhook',st('danger','2 undelivered'),'Nov 2, 2:58 PM ET','<span class="num">2</span>'],['<strong>CRM</strong>','Signed webhook',st('success','Delivering'),'Nov 3, 9:01 AM ET',na()]]
    h.append('<h2 class="sec">Table</h2>'+table('Example table',['System','Connector','State','Last acknowledged','Undelivered (dead)'],rows)+'<p class="hint" style="margin-top:var(--space-2)">Under 760px every row becomes a labelled card. Unknown values read Not available, never 0. Wide matrices scroll inside their own region.</p>')
    h.append('<h2 class="sec">Status chips</h2><div class="card stack"><p class="hint">Evidence status. Icon plus word, never color alone.</p><div class="row">'+ev('found')+ev('stop')+ev('none')+ev('incomplete','Record incomplete: missing 1 element')+ev('na','Not available: key did not answer')+'</div>'
        +'<p class="hint">Your policy: the outcome of the organization\'s own approved policy. Neutral ink, outline or solid.</p><div class="row">'+pol('proceed')+pol('hold')+pol('none')+'</div>'
        +'<p class="hint">Operational status</p><div class="row">'+st('success','Active')+st('warning','Past due')+st('danger','Suspended')+st('info','Sending')+st('success','Acknowledged')+st('warning','Retrying')+st('danger','Undelivered (dead)')+st('neutral','Revoked Oct 1')+'</div>'
        +'<p class="notice">Evidence status and the outcome of your organization\'s approved policy. Not a legal determination.</p></div>')
    h.append('<h2 class="sec">Banners</h2>'+banner('info','Nothing to do yet','<p>Information that needs no action.</p>')+banner('success','Package ready','<p>The download link works once, until 9:29 AM ET.</p>')+banner('warning','Past due','<p>Payment failed on Oct 28. Capture keeps recording.</p>',btn('Open billing','secondary'))+cause('','The list could not be read (503 service_unavailable).','Try again.',btn('Try again','secondary'),title='Connected systems did not load'))
    h.append('<h2 class="sec">Empty and loading</h2><div class="grid g2">'+empty('No credentials yet','Your systems need a credential to send consents. Start with a capture credential for your first source.',btn('Issue a credential','primary'))+'<div class="card">'+loading('connected systems')+'</div></div>')
    r=uid('f'); c=uid('c')
    h.append('<h2 class="sec">Dialogs</h2>'
        +dialog('Redrive 2 undelivered stops to Dialer?','<p>Do this after Dialer is fixed. Each stop is sent again, in order.</p>'+field('Reason (recorded in the audit log)',f'<input class="input" id="{r}" type="text">',fid=r),btn('Cancel','secondary')+btn('Redrive now','primary'),static=True)
        +dialog('Revoke Website form key?','<p>It stops working the moment you confirm.</p>','<button type="button" class="btn btn-secondary">Cancel</button><button type="button" class="btn btn-danger">Revoke now</button>',kind='alertdialog',static=True))
    h.append('<h2 class="sec">Attestation dialog</h2>'+dialog('Approve policy version 4','<p>Version 4 goes into force. Version 3 is retired. Both stay on record.</p>'+attest_block()+f'<div class="check"><input type="checkbox" id="{c}"><label for="{c}">I accept this attestation for Acme Lending.</label></div><p class="attest-note" style="margin-top:var(--space-3)">Approving as Dana Ruiz, dana@acmelending.example (from your sign-in). The attestation text is a draft and needs a ruling on final wording.</p>',btn('Back to draft','secondary')+btn('Approve version 4','primary',attrs='disabled aria-disabled="true"'),wide=True,static=True))
    h.append('</div>')
    return ''.join(h)
if __name__=='__main__':
    page('components.html','Component sheet','Components',build())
