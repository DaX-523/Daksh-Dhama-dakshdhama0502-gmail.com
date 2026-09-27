import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createClient, refreshSession, logout } from './api.js';
import { sentence } from './ui.jsx';
import Login from './Login.jsx';
import Invite from './Invite.jsx';
import Console from './Console.jsx';

const invitePath = () => /^\/invite\/([^/]+)\/?$/.exec(window.location.pathname)?.[1] ?? null;

export default function App() {
  const [phase, setPhase] = useState('starting');
  const [session, setSessionState] = useState(null);
  const [notice, setNotice] = useState(null);
  const [inviteToken, setInviteToken] = useState(invitePath);
  const sessionRef = useRef(null);

  const setSession = useCallback((next) => {
    sessionRef.current = next;
    setSessionState(next);
    setPhase(next ? 'signed-in' : 'signed-out');
  }, []);

  const signOut = useCallback(
    (message = null) => {
      setSession(null);
      setNotice(message);
    },
    [setSession]
  );

  const client = useMemo(
    () =>
      createClient({
        getSession: () => sessionRef.current,
        onSession: setSession,
        onExpired: (err) => signOut(`Your session has ended (${err.message}). Please sign in again.`),
      }),
    [setSession, signOut]
  );

  // A reload keeps you signed in through the refresh cookie. The access token only lives in memory.
  useEffect(() => {
    if (invitePath()) return;
    refreshSession()
      .then(setSession)
      .catch((err) => {
        setSession(null);
        if (err.code === 'NETWORK' || err.status >= 500) setNotice(sentence(err.message));
      });
  }, []);

  if (inviteToken) {
    return (
      <Invite
        token={inviteToken}
        onDone={(message) => {
          window.history.replaceState(null, '', '/');
          setInviteToken(null);
          setNotice(message);
          setPhase('signed-out');
        }}
      />
    );
  }

  if (phase === 'starting') return <p className="starting">Loading RemoteOps…</p>;

  if (phase === 'signed-out') {
    return (
      <Login
        notice={notice}
        onSignedIn={(next) => {
          setNotice(null);
          setSession(next);
        }}
      />
    );
  }

  return (
    <Console
      session={session}
      client={client}
      onSession={setSession}
      onSignOut={async () => {
        try {
          await logout();
        } finally {
          signOut('You signed out.');
        }
      }}
      onSessionLost={signOut}
    />
  );
}
