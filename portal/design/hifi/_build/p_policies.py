from lib import *
ROWS=[('Consent record found',['proceed']*4,True),
      ('Stop on record',['hold']*4,False),
      ('No record',['hold','hold','hold','proceed'],False),
      ('Record incomplete (checklist v2)',['hold','hold','hold','proceed'],False),
      ('Records not available',['hold']*4,False)]
COLS=['SMS','Voice','Artificial voice','Email']
def matrix_read(cap='Policy rules'):
    th=''.join(f'<th scope="col">{c}</th>' for c in COLS)
    body=''
    for lab,vals,_ in ROWS:
        body+=f'<tr><th scope="row">{lab}</th>'+''.join(f'<td>{pol(v, "Proceed" if v=="proceed" else "Hold")}</td>' for v in vals)+'</tr>'
    return f'<div class="tw"><div class="tscroll matrix-scroll" role="region" aria-label="{cap}, scrolls sideways on narrow screens" tabindex="0"><table class="matrix"><caption class="sr">{cap}</caption><thead><tr><th scope="col">When the records show</th>{th}</tr></thead><tbody>{body}</tbody></table></div></div>'
def matrix_edit():
    th=''.join(f'<th scope="col">{c}</th>' for c in COLS)
    body=''
    for r,(lab,vals,locked) in enumerate(ROWS):
        body+=f'<tr><th scope="row">{lab}</th>'
        for c,v in enumerate(vals):
            if locked: body+=f'<td class="lock">{pol("proceed","Proceed")}<span class="sr"> fixed</span></td>'; continue
            n=f'm{r}{c}-{uid("g")}'; a,b=uid('o'),uid('o')
            body+=(f'<td><div class="pa" role="radiogroup" aria-label="{lab}, {COLS[c]}">'
                   f'<label><input type="radio" name="{n}" id="{a}"{" checked" if v=="proceed" else ""}><span>{ic("arrow")}Proceed</span></label>'
                   f'<label><input type="radio" name="{n}" id="{b}"{" checked" if v=="hold" else ""}><span>{ic("pause")}Hold</span></label></div></td>')
        body+='</tr>'
    return f'<div class="tw"><div class="tscroll matrix-scroll" role="region" aria-label="Policy rules editor, scrolls sideways on narrow screens" tabindex="0"><table class="matrix"><caption class="sr">Policy rules: what your systems do for each evidence status and channel</caption><thead><tr><th scope="col">When the records show</th>{th}</tr></thead><tbody>{body}</tbody></table></div></div>'

def vtable(partial=False, after=False):
    ap = (lambda s: na() if partial else s)
    rows=[['<a href="#readonly" data-goto="readonly"><strong>3</strong></a>',st('success','In force'),ap('Dana Ruiz'),'Oct 30, 2026',''],
          ['<a href="#editor" data-goto="editor"><strong>4</strong></a>',st('info','Draft'),'',' ',btn('Edit draft','secondary',sm=True,goto='editor')],
          ['<strong>2</strong>',st('neutral','Retired'),ap('Dana Ruiz'),'Oct 2, 2026','']]
    if after:
        rows=[[ '<strong>4</strong>',st('success','In force'),'Dana Ruiz','Nov 3, 2026',btn('View','quiet',sm=True)],['<strong>3</strong>',st('neutral','Retired'),'Dana Ruiz','Oct 30, 2026',btn('View','quiet',sm=True)],['<strong>2</strong>',st('neutral','Retired'),'Dana Ruiz','Oct 2, 2026',btn('View','quiet',sm=True)]]
        return table('Policy versions',['Version','Status','Approved by','Approved','Actions'],rows,actions=True)
    rows[0][4]=btn('View','quiet',sm=True,goto='readonly'); rows[2][4]=btn('View','quiet',sm=True)
    rows[1][2]='<span class="na">Not approved yet</span>'; rows[1][3]='<span class="na">Not approved yet</span>'
    return table('Policy versions',['Version','Status','Approved by','Approved','Actions'],rows,actions=True)

def head(): return ph('Policies','Gate checks return evidence status always, and your policy\'s action only when a policy is in force.',btn('Draft a new version','primary',goto='editor'))
GATE="Evidence status and the outcome of your organization's approved policy. Not a legal determination."

def editor_page(err=''):
    s=uid('f'); c=uid('f')
    return (err+ph('Draft policy version 4','Your policy tells your systems what to do with each evidence status. ConsentVault applies it exactly as written. It does not decide whether a message is allowed by law.')
      +'<div class="card" style="margin-bottom:var(--space-5)"><div class="inline-form">'
      +f'<div class="field"><label for="{s}">Start from</label><select class="select" id="{s}"><option>Version 3 (in force)</option><option>Template: hold unless a consent record is found</option><option>Blank</option></select></div>'
      +f'<div class="field"><label for="{c}">Documentation checklist used for "Record incomplete"</label><select class="select" id="{c}"><option>PEWC checklist, version 2</option><option>None</option></select></div></div></div>'
      +matrix_edit()+'<p class="notice">Consent record found is fixed at Proceed for every channel. All other rows are yours to set.</p>'
      +'<div class="btn-row" style="margin-top:var(--space-5)">'+btn('Save draft','secondary')+btn('Review and approve','primary',goto='approve',icon='arrow')+'</div>')

def attest_block(org='Acme Lending'):
    return (f'<div class="attest"><span class="ver">Attestation, version 1</span><p>I am an admin of {org}. {org} is responsible for whether this policy is legally sufficient for its marketing. ConsentVault recommends that {org}\'s counsel review it before approval. ConsentVault applies this policy as written and does not decide whether any communication is permitted by law.</p></div>')

def approve_page():
    c=uid('c')
    return (ph('Approve policy version 4','Read the rules once more, then record your attestation.')
      +matrix_read('Policy version 4 rules')
      +'<div class="split" style="margin-top:var(--space-5)"><div class="card"><h2>Attestation</h2>'+attest_block()
      +f'<div class="check"><input type="checkbox" id="{c}"><label for="{c}">I accept this attestation for Acme Lending.</label></div>'
      +'<dl class="kv" style="margin-top:var(--space-4)"><dt>Approving as</dt><dd>Dana Ruiz, dana@acmelending.example (from your sign-in)</dd><dt>On approval</dt><dd>Version 4 goes into force. Version 3 is retired. Both stay on record.</dd></dl>'
      +'<div class="btn-row" style="margin-top:var(--space-5)">'+btn('Approve version 4','primary',attrs='disabled aria-disabled="true"')+btn('Back to draft','secondary',goto='editor')+'</div>'
      +'<p class="hint" style="margin-top:var(--space-3)">Approve turns on after the box is ticked.</p></div><aside class="card" aria-label="What approval does"><h2>What approval does</h2><p class="hint">Gate checks return evidence status always. Once approved, they also return your policy\'s action for each status and channel.</p><p class="notice">'+GATE+'</p></aside></div>')

def states():
    return [
     ('default','Default',head()+vtable()),
     ('loading','Loading',head()+loading('policies')),
     ('empty','Empty',head()+empty('No policy in force','Without one, gate checks return evidence status only, with no action, and gate check credentials cannot be issued. Start from a template and change it to fit your rules.',btn('Draft a policy','primary',goto='editor'))),
     ('partial','Partial',head()+banner('warning','Approver names did not load','<p>Versions and statuses are current.</p>')+vtable(True)),
     ('error','Error',head()+cause('','The list could not be read (503 service_unavailable).','Try again. The policy in force keeps applying while this page is down.',btn('Try again','secondary'),title='Policies did not load')
        +cause('','Another admin approved version 5 while you were reviewing (409 policy_superseded).','Open version 5 and review it.',btn('Open version 5','secondary'),title='Version 4 was not approved')),
     ('editor','Draft editor',editor_page()),
     ('approve','Approve with attestation',approve_page()),
     ('success','Success: version in force',banner('success','Version 4 is in force','<p>Version 3 is retired. Both stay on record. Approved by Dana Ruiz, Nov 3, 2026.</p>')+head()+vtable(after=True)),
     ('readonly','Read only (compliance viewer)',ph('Policy version 3','In force since Oct 30, 2026. Approved by Dana Ruiz.',meta=st('success','In force'))+matrix_read('Policy version 3 rules')+f'<p class="notice">{GATE}</p>','Compliance viewer'),
    ]
if __name__=='__main__':
    page('policies.html','Policies','Policies',states())
