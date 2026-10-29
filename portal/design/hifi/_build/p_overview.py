from lib import *

def stat(k, v, s='', action='', alert=False, small=False):
    cls = 'card stat' + (' alert' if alert else '')
    vv = f'<div class="v{" small" if small else ""}">{v}</div>'
    return f'<div class="{cls}"><div class="k">{k}</div>{vv}<div class="s">{s}</div>{action}</div>'

def meter(label, used, total, pct, extra=''):
    return (f'<div style="margin-bottom:var(--space-5)"><div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap"><b style="color:var(--color-text-strong);font-weight:600">{label}</b>'
            f'<span class="num">{used} of {total}</span></div><div class="meter" role="img" aria-label="{label}: {used} of {total}"><i style="width:{pct}%"></i></div>{extra}</div>')

def build(ev_na=False, unsealed=True):
    pass

def stats(usage_ok=True):
    ev_val = '4,812 <span class="of">of 10,000</span>' if usage_ok else '<span class="na">Not available</span>'
    ev_sub = 'Gate checks: 22,340 of 50,000' if usage_ok else 'Usage count did not load'
    return ('<div class="grid g4">'
        + stat('Policy in force','Version 3','Approved by Dana Ruiz, Oct 30', small=False)
        + stat('Events not yet sealed after 1 hour','<span class="num">0</span>','Checked 2 minutes ago')
        + stat('Undelivered stops (dead)','<span class="num">2</span>','Dialer: review and redrive', btn('Review in Connected systems','secondary',sm=True), alert=True)
        + stat('Events this period', ev_val, ev_sub)
        + '</div>')

def usage_card(usage_ok=True):
    if usage_ok:
        body = meter('Events this period','4,812','10,000',48) + meter('Gate checks this period','22,340','50,000',45)
    else:
        body = '<p class="na">Not available. Usage did not load.</p>'
    return f'<div class="card"><h2>Usage this period</h2>{body}</div>'

def org_card(status='Active'):
    chip = {'Active':st('success','Active'),'Past due':st('warning','Past due'),'Suspended':st('danger','Suspended')}[status]
    return ('<div class="card"><h2>Organization</h2><dl class="kv"><dt>Name</dt><dd>Acme Lending</dd><dt>Status</dt><dd>'+chip+'</dd><dt>Plan</dt><dd>Growth</dd><dt>Your role</dt><dd>Admin</dd></dl></div>')

def main_body(status='Active', usage_ok=True, banner_html=''):
    return (banner_html + ph('Overview','Where your organization stands: policy, sealing, deliveries and usage.', meta='Acme Lending · '+ {'Active':st('success','Active'),'Past due':st('warning','Past due'),'Suspended':st('danger','Suspended')}[status] +' · Growth plan')
        + stats(usage_ok)
        + '<div class="split" style="margin-top:var(--space-5)"><div>'+usage_card(usage_ok)+'</div><div>'+org_card(status)+'</div></div>')

SETUP = [('Add a brand',True),('Add a capture source',True),('Register your consent wording',False),('Issue a capture credential',False),('Send a test event',False)]
def setup_list(done_all=False):
    li=''
    nxt=False
    for i,(t,d) in enumerate(SETUP,1):
        d = d or done_all
        if d: cls,mark,ch = 'done', ic('check'), st('success','Done')
        else:
            is_next = not nxt; nxt=True
            cls = 'next' if is_next else ''; mark=str(i); ch = st('neutral','To do')
        n = f'<span class="n">{mark if not d else ic("check").replace("<svg","<svg width=16 height=16")}</span>'
        li += f'<li class="{cls}">{n}<span class="t">{t}</span>{ch}</li>'
    return f'<ol class="steps" aria-label="Setup steps">{li}</ol>'

def states():
    S=[]
    S.append(('default','Default', main_body()))
    S.append(('loading','Loading', ph('Overview','Where your organization stands: policy, sealing, deliveries and usage.')+skeleton_cards()))
    S.append(('empty','Empty: new organization',
        banner('info','Welcome to ConsentVault','<p>Finish these steps to record your first test event. About 15 minutes.</p>', '', live='status')
        + ph('Overview','')
        + '<div class="split"><div class="card"><h2>Setup</h2>'+setup_list()+'<div style="margin-top:var(--space-5)" class="btn-row">'+btn('Register your consent wording','primary',icon='arrow')+'</div></div><div class="grid">'
        + stat('Policy in force','None','Gate checks return evidence status only until you approve a policy.')
        + stat('Events this period','None yet','Your first event appears here.')
        + '</div></div>'))
    S.append(('partial','Partial',
        main_body(usage_ok=False, banner_html=banner('warning','Some figures did not load','<p>Usage is not available right now. Everything else on this page is current.</p>'))))
    S.append(('error','Error',
        ph('Overview','')+cause('',"Your organization's status could not be read (503 service_unavailable).",'Try again. Capture from your website and systems is not affected by this page.',btn('Try again','secondary',icon=None),title='The overview did not load')))
    S.append(('pastdue','Past due',
        main_body('Past due', banner_html=banner('warning','Payment failed on Oct 28','<p>Capture keeps recording and gate checks keep answering. Update your payment method to avoid suspension.</p>', btn('Open billing','secondary')))))
    S.append(('suspended','Suspended',
        main_body('Suspended', banner_html=banner('danger','Acme Lending is suspended','<p>Capture keeps recording, because evidence is never refused for non-payment. Evidence packages and new credentials are paused until billing is resolved.</p>', btn('Open billing','secondary')))))
    S.append(('done','Success: setup done',
        banner('success','Setup is complete','<p>Your first test event was recorded on Oct 31 at 10:42 AM ET.</p>')
        + ph('Overview','Where your organization stands: policy, sealing, deliveries and usage.')
        + '<div class="card" style="margin-bottom:var(--space-5)"><h2>Setup</h2>'+setup_list(True)+'</div>'
        + stats()))
    return S

if __name__=='__main__':
    page('index.html','Overview','Overview',states())
