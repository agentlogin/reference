// Wait page script (Section 5.3). Polls the Transaction Resource and follows the continue step when the
// Issuer releases a continue URL to this session. No inline script: the page's CSP permits only this file.
(function () {
  var el = document.getElementById('agent-login-transaction');
  if (!el) return;
  var tx = JSON.parse(el.textContent);
  var statusEl = document.getElementById('status');
  var idEl = document.getElementById('txid');
  if (idEl) idEl.textContent = tx.transaction_id;
  function render(t) {
    var text = {
      awaiting_agent: 'Waiting for your agent to sign in.',
      awaiting_owner: "Waiting for the agent's owner to approve.",
      awaiting_consent: 'Waiting for your agent to review what this application receives.',
      ready: 'Signed in. Returning you to the application.',
      completed: 'Done.',
      denied: 'Sign-in was not completed.',
      expired: 'This sign-in expired. Start again from the application.'
    }[t.status] || t.status;
    if (statusEl) statusEl.textContent = text;
    if (t.next && t.next.action === 'continue' && t.next.url) {
      window.location.replace(t.next.url);
      return true;
    }
    if (t.next && t.next.action === 'continue' && !t.next.url && statusEl) {
      statusEl.textContent += ' Your agent holds the result; it will open it for you.';
    }
    return t.status === 'completed';
  }
  if (render(tx)) return;
  var delay = 2000;
  function poll() {
    fetch(tx.url, { headers: { Accept: 'application/json' }, credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (t) {
        if (t.next && t.next.retry_after) delay = Math.max(1000, t.next.retry_after * 1000);
        if (!render(t) && t.status !== 'denied' && t.status !== 'expired') setTimeout(poll, delay);
      })
      .catch(function () { setTimeout(poll, delay * 2); });
  }
  setTimeout(poll, delay);
})();
