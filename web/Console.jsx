import React, { useCallback, useState } from 'react';
import { refreshSession } from './api.js';
import { allowed, sentence } from './ui.jsx';
import Devices from './views/Devices.jsx';
import People from './views/People.jsx';
import Grants from './views/Grants.jsx';
import Sessions from './views/Sessions.jsx';
import Audit from './views/Audit.jsx';
import Admin from './views/Admin.jsx';

// Which permission governs each card (UI-INVENTORY.md). Whether the caller holds it is always
// the server's answer in session.permissions; nothing here knows what any role contains.
const CARDS = [
  { key: 'devices', label: 'Devices', permissions: ['device:list'], View: Devices },
  { key: 'people', label: 'People', permissions: ['user:read'], View: People },
  { key: 'grants', label: 'Grants', permissions: ['user:read'], View: Grants },
  { key: 'sessions', label: 'Sessions', permissions: ['session:view'], View: Sessions },
  { key: 'audit', label: 'Audit', permissions: ['audit:read'], View: Audit },
  { key: 'admin', label: 'Admin', permissions: ['org:update', 'org:delete'], View: Admin },
];

function Notice({ notice, onClose }) {
  if (!notice) return null;
  const error = notice.kind === 'error';
  return (
    <div
      className={`notice ${error ? 'notice-error' : 'notice-ok'}`}
      data-testid="notice"
      data-error-code={error ? notice.code : undefined}
      role={error ? 'alert' : 'status'}
    >
      <span>{notice.text}</span>
      {error && notice.code && <code>{notice.code}</code>}
      <button type="button" className="link" onClick={onClose} aria-label="Dismiss">Dismiss</button>
    </div>
  );
}

function Workspace({ session, client, report, notify, onOrgChanged, onOrgGone }) {
  const cards = CARDS.filter((c) => c.permissions.some((p) => allowed(session.permissions, p)));
  const [active, setActive] = useState(cards[0]?.key ?? null);
  const card = cards.find((c) => c.key === active) ?? cards[0];

  return (
    <div className="workspace">
      <nav className="cards" aria-label="Sections">
        {cards.map((c) => (
          <button
            key={c.key}
            type="button"
            data-testid={`nav-${c.key}`}
            data-permission={c.permissions.find((p) => allowed(session.permissions, p))}
            data-state="unlocked"
            aria-current={c.key === card?.key ? 'page' : undefined}
            onClick={() => setActive(c.key)}
          >
            {c.label}
          </button>
        ))}
      </nav>
      {card ? (
        <card.View
          key={card.key}
          session={session}
          client={client}
          report={report}
          notify={notify}
          onOrgChanged={onOrgChanged}
          onOrgGone={onOrgGone}
        />
      ) : (
        <p className="empty">Nothing in this organization is available to you.</p>
      )}
    </div>
  );
}

export default function Console({ session, client, onSession, onSignOut, onSessionLost }) {
  const [notice, setNotice] = useState(null);
  const report = useCallback((err) => setNotice({ kind: 'error', code: err.code, text: sentence(err.message) }), []);
  const notify = useCallback((text) => setNotice({ kind: 'ok', text }), []);
  const orgId = session.org.id;

  async function switchOrg(id) {
    if (id === orgId) return;
    try {
      onSession(await client.post('/auth/token', { orgId: id }));
      setNotice(null);
    } catch (err) {
      report(err);
    }
  }

  async function createOrg() {
    const name = window.prompt('Name for the new organization');
    if (name === null) return;
    try {
      const org = await client.post('/orgs', { name });
      onSession(await client.post('/auth/token', { orgId: org.id }));
      notify(`Created ${org.name}. You are its owner.`);
    } catch (err) {
      report(err);
    }
  }

  async function onOrgChanged() {
    try {
      onSession(await client.post('/auth/token', { orgId }));
    } catch (err) {
      report(err);
    }
  }

  async function onOrgGone(message) {
    try {
      onSession(await refreshSession(null));
      notify(message);
    } catch {
      onSessionLost(`${message} You are not an active member of any other organization.`);
    }
  }

  return (
    <div className="app-shell" data-testid="app-shell" data-org-id={orgId} data-org-theme={session.org.theme}>
      <aside className="sidebar">
        <div className="brand">RemoteOps</div>

        <section className="switcher" aria-label="Organizations">
          <h2>Organizations</h2>
          {session.orgs.map((o) => (
            <button
              key={o.id}
              type="button"
              className="org-option"
              data-testid="org-option"
              data-org-id={o.id}
              data-org-theme={o.theme}
              aria-current={o.id === orgId ? 'true' : undefined}
              onClick={() => switchOrg(o.id)}
            >
              <span className="swatch" aria-hidden="true" />
              <span className="org-name">{o.name}</span>
              <span className="org-role">{o.role}</span>
            </button>
          ))}
          <button type="button" className="create-org" data-testid="create-org" onClick={createOrg}>
            New organization
          </button>
        </section>

        <footer className="me">
          <div className="me-name">{session.user.name}</div>
          <div className="me-email">{session.user.email}</div>
          <button type="button" className="link" data-testid="sign-out" onClick={onSignOut}>Sign out</button>
        </footer>
      </aside>

      <main className="main">
        <header className="org-header">
          <div>
            <p className="eyebrow">Organization</p>
            <h1>{session.org.name}</h1>
          </div>
          <p className="role-badge">
            Your role: <span data-testid="active-role">{session.role}</span>
          </p>
        </header>
        <Notice notice={notice} onClose={() => setNotice(null)} />
        <Workspace
          key={orgId}
          session={session}
          client={client}
          report={report}
          notify={notify}
          onOrgChanged={onOrgChanged}
          onOrgGone={onOrgGone}
        />
      </main>
    </div>
  );
}
