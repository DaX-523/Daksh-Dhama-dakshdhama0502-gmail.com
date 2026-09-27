import React, { useCallback, useEffect, useState } from 'react';

export const allowed = (set, permission) => set?.[permission]?.effect === 'allow';

// Present or absent, never disabled. The permission answer always comes from the server.
export function Gated({ set, permission, testId, as: Tag = 'button', children, ...rest }) {
  if (!allowed(set, permission)) return null;
  const extra = Tag === 'button' && rest.type === undefined ? { type: 'button' } : {};
  return (
    <Tag data-testid={testId} data-permission={permission} data-state="unlocked" {...extra} {...rest}>
      {children}
    </Tag>
  );
}

export const sentence = (text) => {
  const s = String(text ?? '').trim();
  if (!s) return '';
  const capital = s[0].toUpperCase() + s.slice(1);
  return /[.!?]$/.test(capital) ? capital : `${capital}.`;
};

const REASON_TEXT = {
  implicit: 'not part of your role, and nobody granted it',
  explicit_deny: 'someone denied it',
  suspended: 'your membership is suspended',
  scope_mismatch: 'the device is not in this organization',
  not_a_member: 'you are not a member here',
};

// How a lock explains itself: "nobody granted this" reads differently from "someone denied this".
export function lockReason(result) {
  if (!result) return REASON_TEXT.implicit;
  const base = REASON_TEXT[result.reason] ?? result.reason ?? 'not allowed';
  return result.reason === 'explicit_deny' && result.source ? `${base} (${result.source.replace(':', ' ')})` : base;
}

export function useLoad(load, deps, report) {
  const [state, setState] = useState({ loading: true, data: null, error: null });
  const reload = useCallback(async () => {
    setState((s) => ({ ...s, loading: true }));
    try {
      setState({ loading: false, data: await load(), error: null });
    } catch (err) {
      setState({ loading: false, data: null, error: err });
      report?.(err);
    }
  }, deps);
  useEffect(() => {
    reload();
  }, [reload]);
  return [state, reload];
}

export const when = (iso) => (iso ? new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '');

export function Empty({ testId, children }) {
  return (
    <p className="empty" data-testid={testId}>
      {children}
    </p>
  );
}

export function LoadError({ error, onRetry }) {
  return (
    <div className="load-error" role="alert">
      <p>{sentence(error.message)}</p>
      <button type="button" onClick={onRetry}>Try again</button>
    </div>
  );
}
