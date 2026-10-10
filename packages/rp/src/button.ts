// The "Sign in with your agent" control as plain HTML: no script, no external assets, works inside any template.
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

export interface SignInFormOptions {
  /** URL of the kit's `login` handler. */
  action: string;
  label?: string;
  placeholder?: string;
  /** Same-origin path to return to after sign-in. */
  returnTo?: string;
  /** Omit the handle field: for applications that accept exactly one Issuer. */
  withoutHandle?: boolean;
}

/** A form that posts the agent's handle to the login handler; the handle selects the Issuer by discovery. */
export function signInForm(o: SignInFormOptions): string {
  const label = esc(o.label ?? 'Sign in with your agent');
  const field = o.withoutHandle
    ? ''
    : `<label class="agent-login__label">Agent handle <input class="agent-login__input" type="email" name="handle" required autocomplete="username" autocapitalize="off" spellcheck="false" placeholder="${esc(o.placeholder ?? 'scout@example.com')}"></label>`;
  const ret = o.returnTo ? `<input type="hidden" name="return_to" value="${esc(o.returnTo)}">` : '';
  return `<form class="agent-login" method="get" action="${esc(o.action)}">${field}${ret}<button class="agent-login__button" type="submit">${label}</button></form>`;
}

/** Minimal styles for `signInForm`; optional. */
export const signInFormCss = `.agent-login{display:flex;gap:.5rem;flex-wrap:wrap;align-items:end;font:inherit}.agent-login__label{display:grid;gap:.25rem;font-size:.875rem}.agent-login__input{font:inherit;padding:.5rem .625rem;border:1px solid #c8c8c8;border-radius:.375rem;min-width:16rem}.agent-login__button{font:inherit;font-weight:600;padding:.5rem .875rem;border:0;border-radius:.375rem;background:#111;color:#fff;cursor:pointer}.agent-login__button:focus-visible,.agent-login__input:focus-visible{outline:2px solid #2563eb;outline-offset:2px}`;
