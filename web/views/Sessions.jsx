import React, { useState } from 'react';
import { Gated, allowed, useLoad, Empty, LoadError, when } from '../ui.jsx';

const MODES = ['view', 'control', 'terminal'];

function NewSession({ devices, onStart, onCancel }) {
  const [deviceId, setDeviceId] = useState(devices[0]?.id ?? '');
  const [mode, setMode] = useState('view');
  if (devices.length === 0) return <p className="muted">There are no devices you can see.</p>;
  return (
    <form
      className="inline-form"
      onSubmit={(e) => {
        e.preventDefault();
        onStart({ deviceId, mode });
      }}
    >
      <label>
        Device
        <select data-testid="session-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
        </select>
      </label>
      <label>
        Mode
        <select data-testid="session-mode" value={mode} onChange={(e) => setMode(e.target.value)}>
          {MODES.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
      </label>
      <button type="submit" className="primary" data-testid="session-submit">Start</button>
      <button type="button" className="link" onClick={onCancel}>Cancel</button>
    </form>
  );
}

export default function Sessions({ session, client, report, notify }) {
  const orgId = session.org.id;
  const perms = session.permissions;
  const canStart = allowed(perms, 'session:start');
  const [state, reload] = useLoad(
    async () => {
      const [sessions, devices] = await Promise.all([
        client.get(`/orgs/${orgId}/sessions`),
        canStart && allowed(perms, 'device:list') ? client.get(`/orgs/${orgId}/devices`) : { devices: [] },
      ]);
      return { sessions: sessions.sessions, devices: devices.devices };
    },
    [client, orgId],
    report
  );
  const [starting, setStarting] = useState(false);

  const act = (fn) => async (...args) => {
    try {
      await fn(...args);
    } catch (err) {
      report(err);
    }
  };

  const start = act(async (body) => {
    const s = await client.post(`/orgs/${orgId}/sessions`, body);
    setStarting(false);
    notify(`Started a ${s.mode} session on ${s.device_name}.`);
    reload();
  });

  const stop = act(async (s) => {
    await client.del(`/sessions/${s.id}`);
    notify(s.user_id === session.user.id ? 'You ended your session.' : `You ended ${s.user_name}'s session.`);
    reload();
  });

  const data = state.data;

  return (
    <section className="card">
      <header className="card-head">
        <h2>Sessions</h2>
        <Gated set={perms} permission="session:start" testId="new-session" onClick={() => setStarting((v) => !v)}>
          Start a session
        </Gated>
      </header>
      <p className="muted">
        A session keeps the authority it started with. Changing someone's permissions stops their next session, not
        the one running; every session ends by its expiry time.
      </p>
      {starting && data && <NewSession devices={data.devices} onStart={start} onCancel={() => setStarting(false)} />}

      {state.error && <LoadError error={state.error} onRetry={reload} />}
      {!data && !state.error && <p className="muted">Loading sessions…</p>}
      {data && data.sessions.length === 0 && <Empty testId="sessions-empty">No sessions yet.</Empty>}
      {data && data.sessions.length > 0 && (
        <table>
          <thead>
            <tr><th>Device</th><th>Person</th><th>Mode</th><th>State</th><th>Started</th><th>Ends</th><th /></tr>
          </thead>
          <tbody>
            {data.sessions.map((s) => {
              const live = s.state !== 'ended';
              const own = s.user_id === session.user.id;
              const canStop = live && (own || allowed(perms, 'session:terminate'));
              return (
                <tr key={s.id} data-testid="session-row" data-session-id={s.id} data-state-value={s.state}>
                  <td>{s.device_name}</td>
                  <td>{s.user_name}{own && <span className="muted"> (you)</span>}</td>
                  <td>{s.mode}</td>
                  <td>
                    <span className={`status ${live ? 'on' : 'off'}`}>{s.state}</span>
                    {s.end_reason && <div className="muted">{s.end_reason.replace(/_/g, ' ')}</div>}
                  </td>
                  <td>{when(s.started_at)}</td>
                  <td>{when(s.ended_at ?? s.expires_at)}</td>
                  <td>
                    {canStop && (
                      <button
                        type="button"
                        className="link danger"
                        data-testid="stop-session"
                        data-permission={own ? undefined : 'session:terminate'}
                        data-state="unlocked"
                        onClick={() => stop(s)}
                      >
                        {own ? 'Stop' : 'Terminate'}
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}
