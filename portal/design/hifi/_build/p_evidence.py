from lib import *
GATE='Evidence status and the outcome of your organization\'s approved policy. Not a legal determination.'
CONTACT='(555) 555-0100'

def tabs(active):
    a=lambda k:' aria-current="true"' if k==active else ''
    return f'<nav class="tabs" aria-label="Evidence"><a href="#lookup-default"{a("lookup")}>Evidence lookup</a><a href="#packages-default"{a("packages")}>Evidence packages</a></nav>'

def lookup_form(value='', busy=False, invalid=False):
    f=uid('f'); at=''; er=''
    if invalid:
        e=uid('e'); at=f' aria-invalid="true" aria-describedby="{e}"'; er=f'<div class="field-error" id="{e}">{ic("err")}Enter 10 digits, or a full email address.</div>'
    b = btn('Looking up','primary',attrs='disabled aria-disabled="true"') if busy else btn('Look up records','primary',goto='lookup-results')
    return (f'<form class="card" onsubmit="return false"><div class="inline-form"><div class="field"><label for="{f}">Phone number or email</label>'
            f'<input class="input" id="{f}" type="text" inputmode="tel" autocomplete="off" value="{value}"{at}><div class="hint">Sent in the request body, never in the page address. Cleared when you leave this page.</div>{er}</div>{b}</form>'
            .replace('</form>','</div></form>'))

def status_table():
    rows=[['SMS','marketing',ev('stop'),pol('hold')],['Voice','marketing',ev('stop'),pol('hold')],['Email','marketing',ev('none'),pol('proceed')]]
    return table('Evidence status now',['Channel','Purpose','Evidence status','Your policy (version 3)'],rows)+f'<p class="notice">{GATE}</p>'

def tl_item(kind,title,when,body,seal,extra=''):
    icon={'grant':'found','stop':'stop'}[kind]
    return f'<li>{ic(icon)}<div class="hd"><b>{title}</b><span class="when num">{when}</span></div><div class="body">{body}</div>{seal}{extra}</li>'
def sealed(t): return f'<span class="seal">{ic("seal")}Sealed {t}</span>'

def timeline(seal_pending=False, later_grant=False):
    g_seal = f'<span class="seal">{ic("warn")}Not sealed yet. Received 20 minutes ago.</span>' if seal_pending else sealed('Oct 31, 10:58 AM ET')
    items=tl_item('grant','Grant','Oct 31, 10:42:07 AM ET · seq 1','SMS, voice · marketing · Brand Acme Lending · Source Website form · Wording 2026-10',g_seal,'<div class="body">Checklist v2: 4 of 5 present, missing "Not a condition of purchase"</div>')
    items+=tl_item('stop','Stop (revoke)','Nov 2, 3:10 PM ET · seq 9','SMS, voice · all purposes · Source Texting platform (reply STOP)',sealed('Nov 2, 3:31 PM ET'))
    if later_grant:
        items+=tl_item('grant','Grant','Nov 3, 8:20 AM ET · seq 10','SMS · marketing · Source Website form · Stop on record kept (contact_control_unverified)',sealed('Nov 3, 8:41 AM ET'))
    return f'<ol class="tl" aria-label="Timeline in arrival order">{items}</ol>'

def gate_table():
    rows=[['Nov 2, 4:00 PM ET','SMS',ev('stop'),pol('hold'),'3'],['Nov 1, 9:00 AM ET','SMS',ev('found'),pol('proceed'),'3']]
    return table('Gate checks for this contact',['Checked','Channel','Evidence status','Policy action','Policy version'],rows)

def stops_table(ok=True):
    if not ok:
        return banner('warning','Stops sent to connected systems did not load','<p>Not available. Status, timeline and gate checks on this page are complete.</p>',btn('Try again','secondary',sm=True))
    rows=[['Dialer','Nov 2, 3:10 PM ET',st('danger','Undelivered (dead)'),'503 after 10 s'],['CRM','Nov 2, 3:10 PM ET',st('success','Acknowledged'),'200 in 212 ms']]
    return table('Stops sent to connected systems',['System','Sent','State','Result'],rows)

def results(seal_pending=False, later_grant=False, stops_ok=True, top=''):
    chain = ('<div class="card"><h2>Chain integrity</h2><p>'+st('success','Verified')+'</p><p class="hint" style="margin-top:var(--space-2)">Verified to anchor Nov 2, 4:00 AM ET</p>'
             '<div class="btn-row" style="margin-top:var(--space-4)">'+btn('Build evidence package','primary',goto='packages-default')+btn('Request erasure','danger',goto='erasure')+'</div></div>')
    main=('<h2 class="sec" style="margin-top:var(--space-6)">Evidence status now</h2>'+status_table()
       +'<div class="sec-head"><h2 class="sec">Timeline (arrival order)</h2></div><div class="card">'+timeline(seal_pending,later_grant)+'</div>'
       +'<div class="sec-head"><h2 class="sec">Gate checks for this contact</h2></div>'+gate_table()
       +'<div class="sec-head"><h2 class="sec">Stops sent to your connected systems</h2></div>'+stops_table(stops_ok))
    return (top+f'<div class="split"><div><h2 class="sec" style="margin-bottom:0">Records for {CONTACT} in Acme Lending</h2>{main}</div><aside aria-label="Actions">{chain}</aside></div>')

def head(): return ph('Evidence lookup','Everything Acme Lending\'s records hold for one contact point.')

def erasure():
    r=uid('f')
    body=(f'<p>What happens: this person\'s contact details become unreadable. Their fingerprint and stop records are kept so their opt-out keeps being honored. Your chain still verifies. This cannot be undone.</p>'
          '<p class="hint" style="margin-bottom:var(--space-4)">The operator confirms every erasure before it runs. A legal hold on this contact blocks it.</p>'
          + field('Reason (recorded in the audit log)', f'<input class="input" id="{r}" type="text" autocomplete="off">', fid=r))
    return dialog(f'Request erasure for {CONTACT}?', body, btn('Cancel','secondary',goto='lookup-results')+btn('Send erasure request','danger'), kind='alertdialog')

# packages --------------------------------------------------------
def pk_head(): return ph('Evidence packages','A package holds one person\'s records in Acme Lending, signed and checkable offline. Its cover page states that the records are evidence for an investigation or dispute, and that storing a record does not by itself establish valid consent.')
def pk_form(disabled=False):
    f=uid('f')
    b = btn('Build evidence package','primary',attrs='disabled aria-disabled="true"') if disabled else btn('Build evidence package','primary',goto='packages-building')
    return f'<div class="card"><div class="inline-form"><div class="field"><label for="{f}">Phone number or email</label><input class="input" id="{f}" type="text" inputmode="tel" autocomplete="off"><div class="hint">Never put in the page address.</div></div>{b}</div></div>'
def pk_table(status_html=None, expires='Nov 3, 9:29 AM ET', download=True):
    s = status_html or st('success','Ready')
    act = btn('Download','secondary',sm=True,goto='packages-ready') if download else ''
    rows=[['(555) ***-0100','Nov 3, 9:12 AM ET',s,expires if download else na() if False else expires,act]]
    return table('Evidence packages built in this session',['Contact','Started','Status','Link expires','Actions'],rows,actions=True)

def verify_card():
    return ('<div class="card" style="margin-top:var(--space-5)"><h2>How anyone can check this package</h2><ol style="padding-left:20px;display:grid;gap:6px;list-style:decimal"><li>Download the public verifier from the open-source ConsentVault repository.</li><li>Run it on the package, offline, with the timestamp authority\'s root certificate and the published anchors.</li><li>It names anything that fails. Change one byte and it fails by name.</li></ol>'
      '<dl class="kv" style="margin-top:var(--space-4)"><dt>Package sha256</dt><dd><span class="mono num">c81e9f0a...a744</span> '+btn('Copy','quiet',sm=True,icon='copy')+'</dd><dt>Signed by</dt><dd>Platform key, version 2</dd></dl></div>')

def states():
    S=[]
    S.append(('lookup-default','Lookup: default', tabs('lookup')+head()+lookup_form()))
    S.append(('lookup-loading','Lookup: loading', tabs('lookup')+head()+lookup_form(CONTACT,busy=True)+'<div style="margin-top:var(--space-5)">'+loading('records')+'</div>'))
    S.append(('lookup-none','Lookup: no records', tabs('lookup')+head()+lookup_form(CONTACT)+'<div style="margin-top:var(--space-5)">'+empty(f'No records for {CONTACT} in Acme Lending','Acme Lending has recorded no consent, stop or gate check for this contact point. Check the number, or try the email address the person used.')+f'<p class="notice">{GATE}</p></div>'))
    S.append(('lookup-results','Lookup: results', tabs('lookup')+head()+lookup_form(CONTACT)+'<div style="margin-top:var(--space-5)">'+results()+'</div>'))
    S.append(('lookup-partial','Lookup: partial', tabs('lookup')+head()+lookup_form(CONTACT)+'<div style="margin-top:var(--space-5)">'+results(stops_ok=False)+'</div>'))
    S.append(('lookup-seal','Lookup: seal pending', tabs('lookup')+head()+lookup_form(CONTACT)+'<div style="margin-top:var(--space-5)">'+results(seal_pending=True,top=banner('info','1 event is not sealed yet','<p>It was received 20 minutes ago. Outside timestamps are usually added within an hour. Packages built now mark it as unsealed.</p>'))+'</div>'))
    S.append(('lookup-stopkept','Lookup: later grant did not lift a stop', tabs('lookup')+head()+lookup_form(CONTACT)+'<div style="margin-top:var(--space-5)">'+results(later_grant=True,top=banner('warning','A later grant did not lift the stop on SMS','<p>On Nov 3 a web form grant arrived after the Nov 2 stop. The person\'s control of the phone number was not verified (contact_control_unverified), so the stop stays on record. It is listed for review.</p>'))+'</div>'))
    S.append(('lookup-error','Lookup: errors', tabs('lookup')+head()+cause('','Not available: your organization\'s encryption key did not answer (key_unavailable).','Try again in a minute. Nothing was changed. If it repeats, the operator has already been alerted by name.',btn('Try again','secondary'),title='Records could not be read')
        +cause('',f'(555) 555-01 is not a complete phone number (invalid_contact:phone).','Enter 10 digits, or a full email address.',btn('Fix entry','secondary'),kind='warning',title='Enter a phone number or email')
        +lookup_form('(555) 555-01',invalid=True)))
    S.append(('erasure','Lookup: erasure dialog', tabs('lookup')+head()+lookup_form(CONTACT)+'<div style="margin-top:var(--space-5)">'+results()+'</div>'+erasure()))
    S.append(('packages-default','Packages: default', tabs('packages')+pk_head()+pk_form()+'<div class="sec-head"><h2 class="sec">Built in this session</h2></div>'+pk_table()))
    S.append(('packages-empty','Packages: empty', tabs('packages')+pk_head()+empty('No packages built in this session','Enter a contact point, or start from Evidence lookup.')+'<div style="margin-top:var(--space-5)">'+pk_form()+'</div>'))
    S.append(('packages-building','Packages: building', tabs('packages')+pk_head()+banner('info','Building the package for (555) ***-0100','<p>Most finish in under 2 minutes. You can leave this page; it stays in the list.</p>')+loading('the package')))
    S.append(('packages-large','Packages: large history', tabs('packages')+pk_head()+banner('info','Still building: 18,000 of 42,000 records packed','<p>Large histories take longer. If the build stops, it resumes from where it stopped. A package is never cut short.</p><div class="meter" role="img" aria-label="18,000 of 42,000 records packed"><i style="width:43%"></i></div>')+pk_table(st('info','Building'),download=False)))
    S.append(('packages-ready','Packages: ready', tabs('packages')+pk_head()+banner('success','Package ready','<p>The download link works once, until 9:29 AM ET.</p>'+btn('Download package','primary',icon=None))+verify_card()))
    S.append(('packages-error','Packages: errors', tabs('packages')+pk_head()+cause('','The build stopped while reading sealed records (export failed: seal_store_unreachable). No partial package was made.','Start the build again. It resumes from where it stopped.',btn('Start again','secondary'),title='The package was not built')
        +cause('','Each link works once, for 15 minutes.','Get a new link. The package itself is unchanged.',btn('Get a new link','secondary'),kind='warning',title='This download link was used or expired')))
    S.append(('packages-suspended','Packages: suspended', tabs('packages')+pk_head()+banner('danger','Evidence packages are paused while Acme Lending is suspended','<p>Your records are kept and capture keeps recording. Resolve billing to build packages.</p>',btn('Open billing','secondary'))+pk_form(True)))
    return S
if __name__=='__main__':
    page('evidence.html','Evidence lookup','Evidence lookup',states())
