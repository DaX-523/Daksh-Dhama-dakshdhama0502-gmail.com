import React, { useState } from 'react';
import { Gated, allowed } from '../ui.jsx';

export default function Admin({ session, client, report, notify, onOrgChanged, onOrgGone }) {
  const org = session.org;
  const perms = session.permissions;
  const [name, setName] = useState(org.name);

  async function rename(event) {
    event.preventDefault();
    try {
      await client.patch(`/orgs/${org.id}`, { name });
      notify(`The organization is now called ${name.trim()}.`);
      onOrgChanged();
    } catch (err) {
      report(err);
    }
  }

  async function remove() {
    const typed = window.prompt(`This deletes ${org.name} for every member and ends all its sessions. Type the organization name to confirm.`);
    if (typed === null) return;
    if (typed.trim() !== org.name) {
      notify('The name did not match, so nothing was deleted.');
      return;
    }
    try {
      await client.del(`/orgs/${org.id}`);
      onOrgGone(`${org.name} was deleted.`);
    } catch (err) {
      report(err);
    }
  }

  return (
    <section className="card">
      <header className="card-head">
        <h2>Admin</h2>
      </header>

      {allowed(perms, 'org:update') && (
        <form className="inline-form" onSubmit={rename}>
          <label>
            Organization name
            <input data-testid="org-name" value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <Gated set={perms} permission="org:update" testId="rename-org" type="submit" className="primary">
            Rename
          </Gated>
        </form>
      )}

      {allowed(perms, 'org:delete') && (
        <div className="danger-zone">
          <h3>Delete this organization</h3>
          <p className="muted">Members lose access, devices go with it, and live sessions end. The audit log is kept.</p>
          <Gated set={perms} permission="org:delete" testId="delete-org" className="danger" onClick={remove}>
            Delete organization
          </Gated>
        </div>
      )}
    </section>
  );
}
