from lib import *
def head(): return ph('Connected systems','Every stop is pushed to each system below, retried for 24 hours, then marked undelivered and alerted.', btn('Connect a system','primary',goto='connect'))
def sys_link(n): return f'<a href="#detail" data-goto="detail"><strong>{n}</strong></a>'
def table_(partial=False):
    dead = (lambda n: na() if partial else f'<span class="num">{n}</span>')
    rows=[[sys_link('CRM'),'CRM','Signed webhook',st('success','Delivering'),'Nov 3, 9:01 AM ET',dead(0)],
          [sys_link('Dialer'),'Dialer','Signed webhook',st('danger','2 undelivered'),'Nov 2, 2:58 PM ET',dead(2)]]
    return table('Connected systems',['System','Kind','Connector','State','Last acknowledged','Undelivered (dead)'],rows)
def legend():
    return ('<div class="card" style="margin-top:var(--space-5)"><h2>What a delivery state means</h2><dl class="kv">'
      f'<dt>{st("info","Sending")}</dt><dd>The stop was sent and no answer has come back yet.</dd>'
      f'<dt>{st("success","Acknowledged")}</dt><dd>The system confirmed it received the stop.</dd>'
      f'<dt>{st("warning","Retrying")}</dt><dd>The system did not accept it. We try again for 24 hours.</dd>'
      f'<dt>{st("danger","Undelivered (dead)")}</dt><dd>24 hours passed with no acceptance. Redrive it after the system is fixed.</dd>'
      f'<dt>{st("neutral","Replaced by a newer change")}</dt><dd>A later change for the same contact took its place.</dd></dl></div>')
def default(partial=False, top=''):
    return head()+top+table_(partial)+legend()

def connect():
    n,k,e=uid('f'),uid('f'),uid('f')
    body=(field('Name',f'<input class="input" id="{n}" type="text" value="Dialer" autocomplete="off">',fid=n)
      +field('Kind',f'<select class="select" id="{k}"><option>CRM</option><option selected>Dialer</option><option>Texting</option><option>Email</option><option>AI agent</option><option>Other webhook</option></select>',fid=k)
      +field('Endpoint address (https only)',f'<input class="input mono" id="{e}" type="url" value="https://dialer.acmelending.example/consentvault" autocomplete="off">',fid=e)
      +'<fieldset><legend>Signature</legend>'+_r('sig',[('Ed25519 (recommended)','You load our public key into your system.'),('HMAC shared secret','Shown once after you connect.')])+'</fieldset>'
      +'<fieldset><legend>Contact sent as</legend>'+_r('cs',[('Plain contact point','The phone number or email.'),('Fingerprint only','A one-way fingerprint. Your system matches on it.')])+'</fieldset>'
      +'<div class="check"><input type="checkbox" id="rt" checked><label for="rt">Keep retrying for 24 hours (default)</label></div>')
    return dialog('Connect a system',body,btn('Cancel','secondary',goto='default')+btn('Connect and send a test push','primary'),wide=True)
def _r(name,items):
    o=''
    for i,(t,d) in enumerate(items):
        f=uid('r'); o+=f'<label class="opt" for="{f}"><input type="radio" id="{f}" name="{name}"{" checked" if i==0 else ""}><span><b>{t}</b>{d}</span></label>'
    return o

def detail(error=False, top=''):
    rows=[['Nov 2, 3:10 PM ET','<span class="mono">fp_7a1...</span>','SMS','503 after 10 s','<span class="num">14</span>'],['Nov 2, 3:12 PM ET','<span class="mono">fp_c02...</span>','Voice','Timed out (10 s)','<span class="num">14</span>']]
    err=''
    if error:
        err=cause('','Dialer answered 401 after 120 ms. It did not accept the signature.','Load the public key shown below into Dialer, then send another test push.',btn('Send another test push','secondary',sm=True)+' '+btn('Show public key','quiet',sm=True),title='Test push failed')
    return (top+ph('Dialer','',btn('Send a test push','secondary')+btn('Redrive undelivered','primary',goto='redrive'),meta=st('danger','2 undelivered')+' <a href="#default" data-goto="default">Back to Connected systems</a>')+err
      +'<div class="card"><dl class="kv"><dt>Endpoint</dt><dd class="mono">https://dialer.acmelending.example/consentvault</dd><dt>Signature</dt><dd>Ed25519, key version 1</dd><dt>Last test push</dt><dd>Nov 3, 8:55 AM ET: 200 in 340 ms</dd></dl></div>'
      +'<div class="sec-head"><h2 class="sec">Undelivered stops (dead)</h2></div>'+table('Undelivered stops',['Stop recorded','Contact (fingerprint)','Channel','Last answer','Attempts'],rows))

def redrive():
    r=uid('f')
    body=('<p>Do this after Dialer is fixed. Each stop is sent again, in order. Gate checks have answered "Stop on record" for these people the whole time.</p>'
      +field('Reason (recorded in the audit log)',f'<input class="input" id="{r}" type="text" autocomplete="off">',fid=r))
    return dialog('Redrive 2 undelivered stops to Dialer?',body,btn('Cancel','secondary',goto='detail')+btn('Redrive now','primary',goto='success'))

def states():
    return [
     ('default','Default',default()),
     ('loading','Loading',head()+loading('connected systems')),
     ('empty','Empty',head()+empty('No systems connected','Stops are recorded and gate checks honor them, but nothing is pushed to your CRM, dialer or texting platform until you connect them.',btn('Connect a system','primary',goto='connect'))),
     ('partial','Partial',default(True,banner('warning','Undelivered counts did not load','<p>They show as Not available, never as zero.</p>'))),
     ('error','Error',head()+cause('','The list could not be read (503 service_unavailable).','Try again. Pushes keep running while this page is down.',btn('Try again','secondary'),title='Connected systems did not load')),
     ('connect','Connect: dialog',default()+connect()),
     ('detail','System detail',detail()),
     ('detail-error','System detail: test push failed',detail(True)),
     ('redrive','Redrive: dialog',detail()+redrive()),
     ('success','Success: redrive started',detail(top=banner('success','Redrive started','<p>2 undelivered stops are being sent again to Dialer, in order. This page shows each one as it is acknowledged.</p>'))),
     ('viewer','Read only (compliance viewer)',ph('Connected systems','Every stop is pushed to each system below, retried for 24 hours, then marked undelivered and alerted.')+table_()+legend(),'Compliance viewer'),
    ]
if __name__=='__main__':
    page('deliveries.html','Connected systems and deliveries','Connected systems',states())
