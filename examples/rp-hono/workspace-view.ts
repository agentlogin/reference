/** Browser UI for the same bounded notes API used by the Agent Login plugin. No credentials enter scripts. */
export function workspaceView(nonce: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Workspace</title><style nonce="${nonce}">
:root{color-scheme:light;--ink:#182523;--muted:#5b6c66;--line:#dce5df;--green:#176c4e}
*{box-sizing:border-box}body{margin:0;background:#f6f8f5;color:var(--ink);font:16px/1.6 system-ui,sans-serif}
header{border-bottom:1px solid var(--line);background:white}nav{max-width:1060px;margin:auto;padding:20px 28px;display:flex;justify-content:space-between;align-items:center}
strong{letter-spacing:-.025em}main{max-width:1060px;margin:64px auto;padding:0 28px}.eyebrow{font-size:12px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:var(--green)}
h1{font-size:clamp(32px,5vw,48px);letter-spacing:-.045em;line-height:1.15;margin:12px 0 18px}p{color:var(--muted)}.intro{max-width:640px;margin-bottom:36px}
.grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:24px}.panel{padding:28px;background:white;border:1px solid var(--line);border-radius:16px}h2{font-size:19px;margin:0 0 16px}
label{display:block;font-weight:600;margin-bottom:8px}textarea{display:block;resize:vertical;width:100%;min-height:160px;border:1px solid #b6c5bd;border-radius:8px;padding:12px;font:inherit;background:#fcfdfb;color:inherit}
button{font:600 14px system-ui;cursor:pointer;border:1px solid var(--line);background:white;color:var(--ink);border-radius:8px;padding:11px 16px}button.primary{background:var(--green);border-color:var(--green);color:white;margin-top:16px}button:disabled{opacity:.6;cursor:wait}
a{color:var(--green)}:focus-visible{outline:3px solid #68b392;outline-offset:3px}#status{min-height:24px;font-size:14px}#notes{list-style:none;padding:0;margin:0}#notes li{padding:16px 0;border-top:1px solid var(--line);overflow-wrap:anywhere;white-space:pre-wrap}#notes time{display:block;color:var(--muted);font-size:12px;margin-bottom:6px}small{color:var(--muted)}footer{margin-top:24px;font-size:13px;color:var(--muted)}@media(max-width:720px){main{margin:36px auto}.grid{grid-template-columns:1fr}.panel{padding:22px}}
</style></head><body><header><nav><strong>Agent Workspace</strong><button id="logout" type="button">Sign out</button></nav></header>
<main><div class="intro"><span class="eyebrow">Agent Login pilot</span><h1>A workspace for your agent.</h1><p id="identity">Loading your account...</p></div>
<div class="grid"><section class="panel"><h2>Save a note</h2><form id="form"><label for="text">Note</label><textarea id="text" name="text" maxlength="4096" required placeholder="What should your agent remember?"></textarea><small>Private to this agent account. Up to 4 KB per note.</small><br><button class="primary" id="save" type="submit">Save note</button><p id="status" role="status" aria-live="polite"></p></form></section>
<section class="panel" aria-labelledby="notes-title"><h2 id="notes-title">Recent notes</h2><p id="empty">Loading notes...</p><ul id="notes"></ul><button id="more" type="button" hidden>Load older notes</button></section></div>
<footer>Writes check current sign-in authority. When it expires, sign in again to continue. Notes are private to your agent account.</footer></main>
<script nonce="${nonce}">
const status=document.querySelector('#status'),text=document.querySelector('#text'),save=document.querySelector('#save');
let pending,nextCursor,saving=false,listGeneration=0,refreshing=false;
async function api(path,init){const response=await fetch(path,{...init,credentials:'same-origin',cache:'no-store'});const value=await response.json();if(!response.ok){if(response.status===401)throw Error('Please sign in again from the home page.');if(response.status===503)throw Error('Service unavailable.');const error=Error(value.error==='note_limit'?'This account has reached its note limit.':value.error==='idempotency_conflict'?'This request was already used. Reload before saving a new note.':'The request could not be completed.');error.definiteRejection=[400,409,413,415].includes(response.status);throw error;}return value;}
async function load(append=false){
  if(append&&(refreshing||!nextCursor))return;
  const generation=append?listGeneration:++listGeneration;
  const cursor=append?nextCursor:undefined;
  const current=()=>generation===listGeneration&&(!append||cursor===nextCursor);
  const more=document.querySelector('#more');
  if(!append){refreshing=true;more.disabled=true;}
  try{
    const result=await api('/notes'+(cursor?'?before='+encodeURIComponent(cursor):''));
    if(!current())return;
    if(!append)document.querySelector('#notes').replaceChildren();
    nextCursor=result.next_cursor;
    more.hidden=!nextCursor;
    document.querySelector('#empty').textContent=(result.notes.length||(append&&document.querySelector('#notes').childElementCount))?'':'Your saved notes will appear here.';
    for(const note of result.notes){
      const item=document.createElement('li'),time=document.createElement('time'),body=document.createElement('span');
      time.dateTime=new Date(note.createdAt*1000).toISOString();
      time.textContent=new Date(note.createdAt*1000).toLocaleString();
      body.textContent=note.text;
      item.append(time,body);
      document.querySelector('#notes').append(item);
    }
  }catch(error){
    // A refresh supersedes both the data and errors from older page requests.
    if(current()){
      if(append)status.textContent=error.message;
      else throw error;
    }
  }finally{
    if(!append&&generation===listGeneration){refreshing=false;more.disabled=false;}
  }
}
document.querySelector('#form').addEventListener('submit',async(event)=>{
  event.preventDefault();
  if(saving)return;
  if(!text.value.trim()){
    status.textContent='Write a note before saving.';
    return;
  }
  if(new TextEncoder().encode(text.value).length>4096){
    status.textContent='Keep your note within 4 KB.';
    return;
  }
  if(!pending)pending={id:crypto.randomUUID(),text:text.value};
  else if(pending.text!==text.value){
    status.textContent='Retry the original note before editing; its previous save may have succeeded.';
    return;
  }
  const submitted=pending;
  saving=true;
  save.disabled=true;
  try{
    try{
      await api('/notes',{
        method:'POST',
        headers:{'content-type':'application/json'},
        body:JSON.stringify(submitted)
      });
    }catch(error){
      if(error.definiteRejection)pending=undefined;
      status.textContent=error.message+(error.definiteRejection?'':' Retry the original note; its save may already have succeeded.');
      return;
    }
    pending=undefined;
    // A later draft is independent of the note whose acknowledgement just arrived.
    if(text.value===submitted.text)text.value='';
    status.textContent='Note saved.';
    try{
      await load();
    }catch{
      // The write is confirmed even if refreshing the list is unavailable.
      status.textContent='Note saved. Recent notes could not be refreshed.';
    }
  }finally{
    saving=false;
    save.disabled=false;
  }
});
document.querySelector('#more').addEventListener('click',async()=>{const button=document.querySelector('#more');button.disabled=true;try{await load(true);}finally{button.disabled=refreshing;}});
document.querySelector('#logout').addEventListener('click',async()=>{try{await api('/logout',{method:'POST'});location.assign('/');}catch(error){status.textContent=error.message;}});
api('/me').then(account=>{document.querySelector('#identity').textContent='Signed in as '+(account.handle||account.account);return load();}).catch(error=>{document.querySelector('#identity').textContent=error.message;const link=document.createElement('a');link.href='/';link.textContent='Return to sign-in';document.querySelector('.intro').append(link);save.disabled=true;document.querySelector('#empty').textContent='Sign in to view notes.';});
</script></body></html>`;
}
