export class ApiError extends Error {
  constructor(status, code, message, reason = null, requestId = null) {
    super(message);
    Object.assign(this, { status, code, reason, requestId });
  }
}

async function send(method, path, { token, body } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers['content-type'] = 'application/json';

  let res;
  try {
    res = await fetch(`/v1${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
    });
  } catch {
    throw new ApiError(0, 'NETWORK', "can't reach the server. Check that it is running, then try again");
  }

  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!res.ok) {
    const e = data?.error;
    if (e) throw new ApiError(res.status, e.code, e.message, e.reason, e.requestId);
    throw new ApiError(res.status, `HTTP_${res.status}`, `the server answered ${res.status} without saying why`);
  }
  return data;
}

// Refresh tokens rotate, so two refreshes in flight would present the same cookie twice and the
// server would treat the second as a stolen token. Every caller shares the one request.
let refreshing = null;
export function refreshSession(orgId = null) {
  refreshing ??= send('POST', '/auth/refresh', { body: orgId ? { orgId } : {} }).finally(() => {
    refreshing = null;
  });
  return refreshing;
}

export const login = (email, password) => send('POST', '/auth/login', { body: { email, password } });
export const logout = () => send('POST', '/auth/logout', { body: {} });
export const peekInvite = (token) => send('GET', `/invites/${encodeURIComponent(token)}`);
export const acceptInvite = (token, body) => send('POST', `/invites/${encodeURIComponent(token)}/accept`, { body });

// Requests made as the signed-in user. A stale or expired access token is renewed once through
// the refresh cookie; if that fails the session is over and the app returns to sign-in.
export function createClient({ getSession, onSession, onExpired }) {
  async function renew(orgId) {
    try {
      return await refreshSession(orgId);
    } catch (err) {
      if (err.status === 403 || err.status === 404) return refreshSession(null);
      throw err;
    }
  }

  async function request(method, path, body) {
    const session = getSession();
    try {
      return await send(method, path, { token: session?.token, body });
    } catch (err) {
      if (err.status !== 401 || !session) throw err;
      let next;
      try {
        next = await renew(session.org.id);
      } catch (refreshErr) {
        onExpired(refreshErr);
        throw err;
      }
      onSession(next);
      if (next.org.id !== session.org.id) throw err;
      return send(method, path, { token: next.token, body });
    }
  }

  return {
    get: (path) => request('GET', path),
    post: (path, body = {}) => request('POST', path, body),
    patch: (path, body) => request('PATCH', path, body),
    del: (path) => request('DELETE', path),
  };
}
