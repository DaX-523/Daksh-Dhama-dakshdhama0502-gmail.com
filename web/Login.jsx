import React, { useState } from 'react';
import { login } from './api.js';
import { sentence } from './ui.jsx';

export default function Login({ notice, onSignedIn }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      onSignedIn(await login(email, password));
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  return (
    <main className="auth-page">
      <form className="auth-card" data-testid="login-form" onSubmit={submit} noValidate>
        <h1>RemoteOps</h1>
        <p className="muted">Sign in to your organization console.</p>
        {notice && <p className="notice-inline" role="status">{notice}</p>}

        <label>
          Email
          <input data-testid="login-email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label>
          Password
          <input data-testid="login-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>

        {error && (
          <p className="form-error" data-testid="login-error" data-error-code={error.code} role="alert" aria-live="assertive">
            {sentence(error.message)}
          </p>
        )}

        <button data-testid="login-submit" type="submit" className="primary" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}
