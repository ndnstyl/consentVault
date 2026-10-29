from lib import *

ORIGIN='https://acmelending.example'
def src_table(partial=False):
    last1 = na() if partial else 'Oct 31, 10:42 AM ET'
    rows=[['<strong>Website form</strong>','Website (site key)','Acme Lending',f'<span class="mono">{ORIGIN}</span>',last1],
          ['<strong>Salesforce</strong>','Server (public key)','Acme Lending, Acme Home Loans','None (server source)',na()]]
    return table('Capture sources',['Source','Sends as','Brands','Allowed origins','Last event'],rows)

def cred_table(partial=False, suspended=False):
    src = (lambda s: na() if partial else s)
    rev = lambda: btn('Revoke','danger',goto='cred-revoke',sm=True)
    rows=[['<strong>Website form key</strong>','Site key','Capture',src('Website form'),'Oct 31',st('success','Active'),rev()],
          ['<strong>Salesforce server</strong>','Public key (ES256)','Capture',src('Salesforce'),'Oct 31',st('success','Active'),rev()],
          ['<strong>Old dialer check</strong>','Public key (RS256)','Gate check',src('None'),'Sep 2',st('neutral','Revoked Oct 1'),'']]
    return table('Credentials',['Name','Kind','Scope','Source','Created','Status','Actions'],rows,actions=True)

def sec(title, intro, action_html, content, sid=''):
    p = f'<p>{intro}</p>' if intro else ''
    return f'<div class="sec-head" id="{sid}"><h2 class="sec">{title}</h2>{action_html}{p}</div>{content}'

def head(): return ph('Sources and credentials','What sends consents to ConsentVault, and the keys it uses to do so.')

def default(partial=False, banner_html='', suspended=False):
    ca = btn('Issue a credential','primary',goto='issue-1') if not suspended else btn('Issue a credential','primary',attrs='disabled aria-disabled="true"')
    return (head()+banner_html
        + sec('Capture sources','Each website form, CRM or integration that sends consents may name only the brands you list for it.',btn('Add a capture source','primary',goto='add-source'),src_table(partial),'src')
        + sec('Credentials','To rotate: issue a new credential, switch your system to it, then revoke the old one.',ca,cred_table(partial,suspended),'cred'))

def radio(name, items, checked=0):
    out=''
    for i,(t,d) in enumerate(items):
        fid=uid('r')
        out+=f'<label class="opt" for="{fid}"><input type="radio" id="{fid}" name="{name}"{" checked" if i==checked else ""}><span><b>{t}</b>{d}</span></label>'
    return out

def check(label, checked=False, fid=None):
    fid=fid or uid('c')
    return f'<label class="opt" for="{fid}"><input type="checkbox" id="{fid}"{" checked" if checked else ""}><span><b>{label}</b></span></label>'

def add_source_dialog(error=False):
    n,o=uid('f'),uid('f'); summ=''; oattr=''; oerr=''
    if error:
        e=uid('e')
        summ=f'<div class="errsum" role="alert">'+cause('The source was not added.','https://acmelending.example/form is not an origin. An origin has no path (400 invalid_origin).','Enter https://acmelending.example.',btn('Fix origin','secondary',sm=True),title=None)+'</div>'
        oattr=f' aria-invalid="true" aria-describedby="{e}"'
        oerr=f'<div class="field-error" id="{e}">{ic("err")}Enter an origin with no path, for example https://acmelending.example.</div>'
        oval='https://acmelending.example/form'
    else: oval='https://acmelending.example'
    body = (summ + field('Name', f'<input class="input" id="{n}" type="text" value="Website form" autocomplete="off">', fid=n)
        + '<fieldset><legend>How it sends</legend>'+radio('how',[('Website form, in a browser','Uses a site key.'),('A server, CRM or integration','Uses a public key.')])+'</fieldset>'
        + '<fieldset><legend>Brands it may name</legend>'+check('Acme Lending',True)+check('Acme Home Loans')+'</fieldset>'
        + field('Allowed website origins', f'<textarea class="textarea" id="{o}" rows="3"{oattr}>{oval}</textarea>', hint='<div class="hint">One per line, for example https://acmelending.example. Requests from other sites are refused.</div>', fid=o, error=oerr))
    return dialog('Add a capture source', body, btn('Cancel','secondary',goto='default')+btn('Add source','primary'), wide=True)

def issue1():
    n,s=uid('f'),uid('f')
    body = ('<p class="wiz"><b>Step 1 of 3:</b> what it does</p>'
      + '<fieldset><legend>Scope</legend>'+radio('scope',[('Capture','Send consents and stops. Cannot read anything.'),('Gate check','Ask what the records show for a contact. Issued after your organization approves a policy.'),('Evidence read','Look up records and build evidence packages.')])+'</fieldset>'
      + '<fieldset><legend>Kind</legend>'+radio('kind',[('Site key for a website form',''),('Public key for a server','You keep the private key.'),('Signed webhook secret','For systems that cannot use keys.')])+'</fieldset>'
      + field('Capture source', f'<select class="select" id="{s}"><option>Website form</option><option>Salesforce</option></select>', fid=s)
      + field('Name', f'<input class="input" id="{n}" type="text" value="Website form key" autocomplete="off">', fid=n))
    return dialog('Issue a credential', body, btn('Cancel','secondary',goto='default')+btn('Next','primary',goto='issue-2',icon='arrow'), wide=True)

def issue2(error=False):
    k,a=uid('f'),uid('f'); summ=''; at=''; er=''
    if error:
        e=uid('e'); summ='<div class="errsum" role="alert">'+cause('The credential was not issued.','That text is a private key. Only a public key may be added (400 private_key_refused).','Paste the public half. Treat the private key you pasted as exposed and replace it.',btn('Back to key','secondary',sm=True,goto='issue-2'))+'</div>'
        at=f' aria-invalid="true" aria-describedby="{e}"'; er=f'<div class="field-error" id="{e}">{ic("err")}This is a private key. Paste the public half.</div>'
    body=(summ+'<p class="wiz"><b>Step 2 of 3:</b> add your public key (server credentials only)</p>'
      + field('Public key (PEM or JWKS)', f'<textarea class="textarea mono" id="{k}" rows="5"{at} placeholder="-----BEGIN PUBLIC KEY-----"></textarea>', hint='<div class="hint">Paste the public half only. Never paste a private key.</div>', fid=k, error=er)
      + field('Signing algorithm', f'<select class="select" id="{a}"><option>ES256</option><option>RS256</option><option>EdDSA</option></select>', hint='<div class="hint">Pinned for this credential. Tokens signed any other way are refused.</div>', fid=a))
    return dialog('Add your public key', body, btn('Back','secondary',goto='issue-1')+btn('Issue credential','primary',goto='secret'))

def secret():
    c=uid('c')
    body=('<p class="wiz"><b>Step 3 of 3:</b> copy it now</p>'
      + banner('warning','This is the only time it is shown','<p>ConsentVault stores it encrypted and cannot show it again.</p>')
      + '<div class="field"><span class="lbl" id="sl">Secret</span><div class="secret"><code aria-labelledby="sl">cvwh_3kqSAMPLE0only0example9Zp</code>'+btn('Copy secret','secondary',icon='copy')+'</div></div>'
      + f'<div class="check"><input type="checkbox" id="{c}"><label for="{c}">I stored this secret somewhere safe</label></div>'
      + '<p class="hint" style="margin-top:var(--space-3)">Done turns on after the box is ticked. Closing without ticking asks once to confirm.</p>')
    return dialog('Copy your signed webhook secret now', body, btn('Done','primary',attrs='disabled aria-disabled="true"'), kind='alertdialog')

def revoke():
    r=uid('f')
    body=('<p>It stops working the moment you confirm. Any form or system still using it will have its requests refused until it uses a new credential.</p>'
      + field('Reason (recorded in the audit log)', f'<input class="input" id="{r}" type="text" autocomplete="off">', fid=r))
    return dialog('Revoke Website form key?', body, btn('Cancel','secondary',goto='default')+btn('Revoke now','danger'), kind='alertdialog')

def states():
    D=default()
    S=[('default','Default',D),
     ('loading','Loading', head()+loading('capture sources and credentials')),
     ('empty','Empty', head()
        + sec('Capture sources','',btn('Add a capture source','primary',goto='add-source'),empty('No capture sources yet','A capture source is a website form, CRM or integration that sends consents. Each one gets its own credential.',btn('Add a capture source','primary',goto='add-source')))
        + sec('Credentials','',btn('Issue a credential','primary',attrs='disabled aria-disabled="true"'),empty('No credentials yet','Your systems need a credential to send consents. Start with a capture credential for your first source.',btn('Issue a credential','secondary',goto='issue-1')))),
     ('blocked','Blocked: no brand', head()+sec('Capture sources','',btn('Add a capture source','primary',attrs='disabled aria-disabled="true"'),empty('Add a brand first','Every capture source names at least one brand. Your organization has none yet.',btn('Add a brand','primary')))),
     ('partial','Partial', default(True, banner('warning','Some names did not load','<p>Last event times and capture source names did not load. They show as Not available. Sources and credentials are listed in full.</p>'))),
     ('error','Error', head()+cause('','The list could not be read (503 service_unavailable).','Try again.',btn('Try again','secondary'),title='Capture sources did not load')),
     ('add-source','Add a source: dialog', D+add_source_dialog()),
     ('add-source-error','Add a source: error', D+add_source_dialog(True)),
     ('source-success','Success: source added', default(banner_html=banner('success','Website form added','<p>Next: issue its credential.</p>',btn('Issue a credential for Website form','secondary',goto='issue-1')))),
     ('issue-1','Issue: step 1', D+issue1()),
     ('issue-2','Issue: step 2, key', D+issue2()),
     ('issue-2-error','Issue: step 2, error', D+issue2(True)),
     ('secret','Issue: secret shown once', D+secret()),
     ('cred-revoke','Revoke: dialog', D+revoke()),
     ('suspended','Suspended', default(banner_html=banner('danger','New credentials are paused while Acme Lending is suspended','<p>Existing capture credentials keep working. Resolve billing to issue new ones.</p>',btn('Open billing','secondary')),suspended=True)),
    ]
    return S
if __name__=='__main__':
    page('sources-credentials.html','Sources and credentials','Capture sources',states())
