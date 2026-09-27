import React, { useState } from 'react';
import { Gated, allowed, useLoad, Empty, LoadError, when } from '../ui.jsx';

function InviteForm({ roles, onInvite, onCancel }) {
  const assignable = roles.filter((r) => r.assignable);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState(assignable[assignable.length - 1]?.key ?? '');
  return (
    <form
      className="inline-form"
      onSubmit={(e) => {
        e.preventDefault();
        onInvite({ email, role });
      }}
    >
      <label>
        Email
        <input data-testid="invite-email-input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
      </label>
      <label>
        Role
        <select data-testid="invite-role-select" value={role} onChange={(e) => setRole(e.target.value)}>
          {assignable.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
        </select>
      </label>
      <button type="submit" className="primary" data-testid="invite-send">Create invite</button>
      <button type="button" className="link" onClick={onCancel}>Cancel</button>
    </form>
  );
}

export default function People({ session, client, report, notify }) {
  const orgId = session.org.id;
  const perms = session.permissions;
  const [state, reload] = useLoad(
    async () => {
      const [members, roles, invites] = await Promise.all([
        client.get(`/orgs/${orgId}/members`),
        client.get(`/orgs/${orgId}/roles`),
        allowed(perms, 'user:invite') ? client.get(`/orgs/${orgId}/invites`) : { invites: [] },
      ]);
      return { members: members.members, roles: roles.roles, invites: invites.invites };
    },
    [client, orgId],
    report
  );
  const [inviting, setInviting] = useState(false);
  const [link, setLink] = useState(null);

  const act = (fn) => async (...args) => {
    try {
      await fn(...args);
    } catch (err) {
      report(err);
      reload();
    }
  };

  const changeRole = act(async (member, role) => {
    await client.patch(`/orgs/${orgId}/members/${member.user_id}`, { role });
    notify(`${member.name} is now ${role}. Their sessions already running keep going until they end.`);
    reload();
  });

  const toggleSuspend = act(async (member) => {
    const suspended = member.status === 'suspended';
    const path = `/orgs/${orgId}/members/${member.user_id}/suspend`;
    if (suspended) await client.del(path);
    else await client.post(path);
    notify(suspended ? `${member.name} is active again.` : `${member.name} is suspended and their live sessions were ended.`);
    reload();
  });

  const remove = act(async (member) => {
    if (!window.confirm(`Remove ${member.name} from ${session.org.name}? Their account stays, their access here ends.`)) return;
    await client.del(`/orgs/${orgId}/members/${member.user_id}`);
    notify(`${member.name} was removed.`);
    reload();
  });

  const invite = act(async (body) => {
    const created = await client.post(`/orgs/${orgId}/invites`, body);
    setInviting(false);
    setLink({ email: created.invite.email, url: `${window.location.origin}/invite/${created.inviteToken}` });
    reload();
  });

  const cancelInvite = act(async (inv) => {
    await client.del(`/orgs/${orgId}/invites/${inv.id}`);
    notify(`The invite for ${inv.email} was cancelled.`);
    reload();
  });

  const data = state.data;
  const pending = data?.invites.filter((i) => i.status === 'pending') ?? [];

  return (
    <section className="card">
      <header className="card-head">
        <h2>People</h2>
        <Gated set={perms} permission="user:invite" testId="invite-user" onClick={() => setInviting((v) => !v)}>
          Invite someone
        </Gated>
      </header>
      {inviting && data && <InviteForm roles={data.roles} onInvite={invite} onCancel={() => setInviting(false)} />}
      {link && (
        <div className="invite-link" role="status">
          <p>
            Send this link to {link.email}. It is shown once and works for 7 days.
          </p>
          <code>{link.url}</code>
          <button type="button" onClick={() => navigator.clipboard?.writeText(link.url)}>Copy</button>
          <button type="button" className="link" onClick={() => setLink(null)}>Done</button>
        </div>
      )}

      {state.error && <LoadError error={state.error} onRetry={reload} />}
      {!data && !state.error && <p className="muted">Loading people…</p>}
      {data && (
        <table>
          <thead>
            <tr><th>Person</th><th>Role</th><th>Status</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {data.members.map((m) => (
              <tr key={m.user_id} data-testid="user-row" data-user-id={m.user_id}>
                <td>
                  <strong>{m.name}</strong>{m.user_id === session.user.id && <span className="muted"> (you)</span>}
                  <div className="muted">{m.email}</div>
                </td>
                <td>
                  {allowed(perms, 'user:role:update') ? (
                    <Gated
                      as="select"
                      set={perms}
                      permission="user:role:update"
                      testId="role-select"
                      aria-label={`Role for ${m.name}`}
                      value={m.role}
                      onChange={(e) => changeRole(m, e.target.value)}
                    >
                      {data.roles
                        .filter((r) => r.assignable || r.key === m.role)
                        .map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
                    </Gated>
                  ) : (
                    m.role
                  )}
                </td>
                <td><span className={`status ${m.status === 'active' ? 'on' : 'warn'}`}>{m.status}</span></td>
                <td>
                  <div className="actions">
                    <Gated set={perms} permission="user:remove" testId="suspend-user" onClick={() => toggleSuspend(m)}>
                      {m.status === 'suspended' ? 'Reinstate' : 'Suspend'}
                    </Gated>
                    <Gated set={perms} permission="user:remove" testId="remove-user" className="danger" onClick={() => remove(m)}>
                      Remove
                    </Gated>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {allowed(perms, 'user:invite') && data && (
        <>
          <h3>Pending invites</h3>
          {pending.length === 0 ? (
            <Empty testId="invites-empty">No pending invites.</Empty>
          ) : (
            <table>
              <thead>
                <tr><th>Email</th><th>Role</th><th>Expires</th><th /></tr>
              </thead>
              <tbody>
                {pending.map((i) => (
                  <tr key={i.id} data-testid="invite-row">
                    <td>{i.email}</td>
                    <td>{i.role}</td>
                    <td>{when(i.expires_at)}</td>
                    <td>
                      <Gated set={perms} permission="user:invite" testId="cancel-invite" className="link" onClick={() => cancelInvite(i)}>
                        Cancel
                      </Gated>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </section>
  );
}
