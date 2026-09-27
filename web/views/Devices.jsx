import React, { useState } from 'react';
import { Gated, allowed, lockReason, useLoad, Empty, LoadError, when } from '../ui.jsx';

const KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

function AddDevice({ onAdd, onCancel }) {
  const [name, setName] = useState('');
  const [kind, setKind] = useState(KINDS[0]);
  return (
    <form
      className="inline-form"
      onSubmit={(e) => {
        e.preventDefault();
        onAdd({ name, kind });
      }}
    >
      <label>
        Name
        <input data-testid="device-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="lab-mac-02" />
      </label>
      <label>
        Kind
        <select data-testid="device-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
          {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
        </select>
      </label>
      <button type="submit" className="primary" data-testid="device-submit">Add</button>
      <button type="button" className="link" onClick={onCancel}>Cancel</button>
    </form>
  );
}

function Locks({ actions, permissions }) {
  const locked = actions.filter((a) => !allowed(permissions, a.permission));
  if (locked.length === 0) return null;
  return (
    <details className="locks">
      <summary>{locked.length} unavailable</summary>
      <ul>
        {locked.map((a) => (
          <li key={a.testId}>
            <strong>{a.label}</strong>: {lockReason(permissions[a.permission])}
          </li>
        ))}
      </ul>
    </details>
  );
}

export default function Devices({ session, client, report, notify }) {
  const orgId = session.org.id;
  const [state, reload] = useLoad(() => client.get(`/orgs/${orgId}/devices`), [client, orgId], report);
  const [adding, setAdding] = useState(false);

  const act = (fn) => async (...args) => {
    try {
      await fn(...args);
    } catch (err) {
      report(err);
    }
  };

  const startSession = act(async (device, mode) => {
    const s = await client.post(`/orgs/${orgId}/sessions`, { deviceId: device.id, mode });
    notify(`Started a ${mode} session on ${device.name}. It ends at ${when(s.expires_at)} at the latest.`);
  });

  const rename = act(async (device) => {
    const name = window.prompt(`New name for ${device.name}`, device.name);
    if (!name || name === device.name) return;
    await client.patch(`/orgs/${orgId}/devices/${device.id}`, { name });
    notify(`Renamed ${device.name} to ${name}.`);
    reload();
  });

  const decommission = act(async (device) => {
    if (!window.confirm(`Decommission ${device.name}? Any live session on it ends now.`)) return;
    await client.del(`/orgs/${orgId}/devices/${device.id}`);
    notify(`${device.name} was decommissioned.`);
    reload();
  });

  const add = act(async (body) => {
    const { device } = await client.post(`/orgs/${orgId}/devices`, body);
    setAdding(false);
    notify(`Added ${device.name}.`);
    reload();
  });

  const actions = [
    { testId: 'start-view', permission: 'device:view', label: 'View', run: (d) => startSession(d, 'view') },
    { testId: 'start-control', permission: 'device:control', label: 'Control', run: (d) => startSession(d, 'control') },
    { testId: 'start-terminal', permission: 'device:terminal', label: 'Terminal', run: (d) => startSession(d, 'terminal') },
    {
      testId: 'transfer-files', permission: 'device:file_transfer', label: 'Files',
      run: (d) => notify(`You may transfer files on ${d.name}. Moving files is outside this console: sessions are records only.`),
    },
    { testId: 'rename-device', permission: 'device:update', label: 'Rename', run: rename },
    { testId: 'decommission-device', permission: 'device:provision', label: 'Decommission', run: decommission },
  ];

  const devices = state.data?.devices;

  return (
    <section className="card">
      <header className="card-head">
        <h2>Devices</h2>
        <Gated set={session.permissions} permission="device:provision" testId="add-device" onClick={() => setAdding((v) => !v)}>
          Add device
        </Gated>
      </header>
      {adding && <AddDevice onAdd={add} onCancel={() => setAdding(false)} />}

      {state.error && <LoadError error={state.error} onRetry={reload} />}
      {!devices && !state.error && <p className="muted">Loading devices…</p>}
      {devices && devices.length === 0 && (
        <Empty testId="devices-empty">No devices you can see in this organization yet.</Empty>
      )}
      {devices && devices.length > 0 && (
        <table>
          <thead>
            <tr><th>Device</th><th>Status</th><th>Actions</th><th>Not available</th></tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id} data-testid="device-row" data-device-id={d.id}>
                <td>
                  <strong>{d.name}</strong>
                  <div className="muted">{d.kind}</div>
                </td>
                <td><span className={`status ${d.online ? 'on' : 'off'}`}>{d.online ? 'Online' : 'Offline'}</span></td>
                <td>
                  <div className="actions">
                    {actions.map((a) => (
                      <Gated key={a.testId} set={d.permissions} permission={a.permission} testId={a.testId} onClick={() => a.run(d)}>
                        {a.label}
                      </Gated>
                    ))}
                  </div>
                </td>
                <td><Locks actions={actions} permissions={d.permissions} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
