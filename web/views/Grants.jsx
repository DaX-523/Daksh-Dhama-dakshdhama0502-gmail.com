import React, { useState } from 'react';
import { Gated, allowed, useLoad, Empty, LoadError, when } from '../ui.jsx';

function GrantForm({ catalogue, members, devices, onCreate, onCancel }) {
  const [userId, setUserId] = useState(members[0]?.user_id ?? '');
  const [deviceId, setDeviceId] = useState('');
  const [effect, setEffect] = useState('allow');
  const [picked, setPicked] = useState([]);
  const [expires, setExpires] = useState('');

  const groups = catalogue.reduce((acc, key) => {
    const resource = key.split(':')[0];
    (acc[resource] ??= []).push(key);
    return acc;
  }, {});

  const toggle = (key) => setPicked((p) => (p.includes(key) ? p.filter((k) => k !== key) : [...p, key]));

  return (
    <form
      className="grant-form"
      onSubmit={(e) => {
        e.preventDefault();
        onCreate({
          userId,
          deviceId: deviceId || null,
          effect,
          permissions: picked,
          expiresAt: expires ? new Date(expires).toISOString() : null,
        });
      }}
    >
      <div className="row">
        <label>
          Person
          <select data-testid="grant-user" value={userId} onChange={(e) => setUserId(e.target.value)}>
            {members.map((m) => <option key={m.user_id} value={m.user_id}>{m.name} ({m.role})</option>)}
          </select>
        </label>
        <label>
          Where
          <select data-testid="grant-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
            <option value="">Whole organization</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
        </label>
        <label>
          Effect
          <select data-testid="grant-effect" value={effect} onChange={(e) => setEffect(e.target.value)}>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>
        </label>
        <label>
          Expires (optional)
          <input data-testid="grant-expires" type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />
        </label>
      </div>
      <fieldset>
        <legend>Permissions</legend>
        {Object.entries(groups).map(([resource, keys]) => (
          <div key={resource} className="perm-group">
            <span className="perm-resource">{resource}</span>
            {keys.map((key) => (
              <label key={key} className="check">
                <input type="checkbox" data-permission-key={key} checked={picked.includes(key)} onChange={() => toggle(key)} />
                {key.slice(resource.length + 1)}
              </label>
            ))}
          </div>
        ))}
      </fieldset>
      <button type="submit" className="primary" data-testid="grant-submit">Create grant</button>
      <button type="button" className="link" onClick={onCancel}>Cancel</button>
    </form>
  );
}

export default function Grants({ session, client, report, notify }) {
  const orgId = session.org.id;
  const perms = session.permissions;
  const canCreate = allowed(perms, 'grant:create');
  const [state, reload] = useLoad(
    async () => {
      const [grants, members, devices] = await Promise.all([
        client.get(`/orgs/${orgId}/grants`),
        canCreate ? client.get(`/orgs/${orgId}/members`) : { members: [] },
        canCreate && allowed(perms, 'device:list') ? client.get(`/orgs/${orgId}/devices`) : { devices: [] },
      ]);
      return { grants: grants.grants, members: members.members, devices: devices.devices };
    },
    [client, orgId],
    report
  );
  const [creating, setCreating] = useState(false);

  const act = (fn) => async (...args) => {
    try {
      await fn(...args);
    } catch (err) {
      report(err);
    }
  };

  const create = act(async (body) => {
    await client.post(`/orgs/${orgId}/grants`, body);
    setCreating(false);
    notify('Grant created. It applies from the next request.');
    reload();
  });

  const revoke = act(async (grant) => {
    if (!window.confirm(`Revoke this ${grant.effect} grant for ${grant.user_name}?`)) return;
    await client.del(`/orgs/${orgId}/grants/${grant.id}`);
    notify('Grant revoked. Sessions already running are not affected.');
    reload();
  });

  const data = state.data;
  const catalogue = Object.keys(perms).sort();

  return (
    <section className="card">
      <header className="card-head">
        <h2>Grants</h2>
        <Gated set={perms} permission="grant:create" testId="new-grant" onClick={() => setCreating((v) => !v)}>
          New grant
        </Gated>
      </header>
      <p className="muted">
        A grant adds to or takes away from someone's role. A deny always wins, wherever it applies.
      </p>
      {creating && data && (
        <GrantForm catalogue={catalogue} members={data.members} devices={data.devices} onCreate={create} onCancel={() => setCreating(false)} />
      )}

      {state.error && <LoadError error={state.error} onRetry={reload} />}
      {!data && !state.error && <p className="muted">Loading grants…</p>}
      {data && data.grants.length === 0 && <Empty testId="grants-empty">No grants in this organization.</Empty>}
      {data && data.grants.length > 0 && (
        <table>
          <thead>
            <tr><th>Person</th><th>Effect</th><th>Permissions</th><th>Where</th><th>Window</th><th /></tr>
          </thead>
          <tbody>
            {data.grants.map((g) => (
              <tr key={g.id} data-testid="grant-row" data-grant-id={g.id} data-effect={g.effect}>
                <td>{g.user_name}</td>
                <td><span className={`effect effect-${g.effect}`}>{g.effect}</span></td>
                <td>{g.permissions.map((p) => <code key={p} className="perm">{p}</code>)}</td>
                <td>{g.device_name ?? 'Whole organization'}</td>
                <td>
                  <span className={`status ${g.status === 'active' ? 'on' : 'warn'}`}>{g.status}</span>
                  {g.expires_at && <div className="muted">until {when(g.expires_at)}</div>}
                  {g.starts_at && <div className="muted">from {when(g.starts_at)}</div>}
                </td>
                <td>
                  <Gated set={perms} permission="grant:revoke" testId="revoke-grant" className="link danger" onClick={() => revoke(g)}>
                    Revoke
                  </Gated>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
