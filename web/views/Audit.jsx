import React, { useState } from 'react';
import { useLoad, Empty, LoadError, when } from '../ui.jsx';

const PAGE = 50;

export default function Audit({ session, client, report }) {
  const orgId = session.org.id;
  const [offset, setOffset] = useState(0);
  const [state, reload] = useLoad(
    () => client.get(`/orgs/${orgId}/audit?limit=${PAGE}&offset=${offset}`),
    [client, orgId, offset],
    report
  );
  const events = state.data?.events;

  return (
    <section className="card">
      <header className="card-head">
        <h2>Audit log</h2>
        <div className="pager">
          <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Newer</button>
          <button type="button" disabled={!events || events.length < PAGE} onClick={() => setOffset(offset + PAGE)}>Older</button>
        </div>
      </header>
      <p className="muted">Every change and every refused attempt in this organization. Entries cannot be edited or deleted.</p>

      {state.error && <LoadError error={state.error} onRetry={reload} />}
      {!events && !state.error && <p className="muted">Loading the audit log…</p>}
      {events && events.length === 0 && <Empty testId="audit-empty">Nothing recorded yet.</Empty>}
      {events && events.length > 0 && (
        <table>
          <thead>
            <tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Result</th></tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} data-testid="audit-row" data-result={e.result}>
                <td>{when(e.at)}</td>
                <td>{e.actor_name ?? e.actor_id ?? 'system'}</td>
                <td><code>{e.action}</code></td>
                <td className="muted">{e.target_type ? `${e.target_type} ${e.target_id ?? ''}` : ''}</td>
                <td>
                  <span className={`effect effect-${e.result}`}>{e.result}</span>
                  {e.reason_code && <div className="muted">{e.reason_code.replace(/_/g, ' ')}</div>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
