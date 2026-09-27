import React, { useEffect, useState } from 'react';
import { acceptInvite, logout, peekInvite } from './api.js';
import { sentence } from './ui.jsx';

// Deliberately says nothing about the org when the link is bad: the token is the only credential.
function refusal(err) {
  if (err.code === 'NOT_FOUND') return 'This invite link is not valid.';
  if (err.code === 'CONFLICT') return 'This invite has already been used.';
  return sentence(err.message);
}

export default function Invite({ token, onDone }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [submitError, setSubmitError] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    peekInvite(token).then(setInvite).catch(setError);
  }, [token]);

  async function submit(event) {
    event.preventDefault();
    setSubmitError(null);
    setBusy(true);
    try {
      await acceptInvite(token, { name, password });
      await logout().catch(() => {});
      onDone(`You joined ${invite.orgName}. Sign in with ${invite.email} to continue.`);
    } catch (err) {
      setSubmitError(err);
      setBusy(false);
    }
  }

  if (error) {
    return (
      <main className="auth-page">
        <div className="auth-card">
          <h1>Invitation</h1>
          <p className="form-error" data-testid="invite-error" role="alert">{refusal(error)}</p>
          <a href="/">Go to sign in</a>
        </div>
      </main>
    );
  }

  if (!invite) return <p className="starting">Checking your invitation…</p>;

  return (
    <main className="auth-page">
      <form className="auth-card" onSubmit={submit} noValidate>
        <h1>Join {invite.orgName}</h1>
        <p className="muted">
          You have been invited as <strong data-testid="invite-role">{invite.role}</strong>. The link expires{' '}
          {new Date(invite.expiresAt).toLocaleDateString()}.
        </p>
        <label>
          Email
          <input data-testid="invite-email" type="email" value={invite.email} readOnly />
        </label>
        <label>
          Your name
          <input data-testid="invite-name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" />
        </label>
        <label>
          Password
          <input data-testid="invite-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
        </label>
        <p className="hint">Already have a RemoteOps account with this email? Enter its password instead of a new one.</p>
        {submitError && (
          <p className="form-error" role="alert" data-error-code={submitError.code}>{sentence(submitError.message)}</p>
        )}
        <button data-testid="invite-submit" type="submit" className="primary" disabled={busy}>
          {busy ? 'Joining…' : 'Accept invitation'}
        </button>
      </form>
    </main>
  );
}
