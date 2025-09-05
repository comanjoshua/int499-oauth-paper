import React, { useEffect, useState } from 'react';

// Match the Node demo port
const BACKEND = 'http://localhost:3000';

export default function App() {
  const [me, setMe] = useState(null);
  const [err, setErr] = useState(null);

  async function fetchMe() {
    setErr(null);
    try {
      const res = await fetch(`${BACKEND}/me`, { credentials: 'include' });
      if (!res.ok) {
        setMe(null);
        return;
      }
      const data = await res.json();
      setMe(data.claims);
    } catch (e) {
      setErr(String(e));
    }
  }

  useEffect(() => {
    fetchMe();
  }, []);

  return (
    <div style={{ fontFamily: 'system-ui', padding: 24 }}>
      <h1>SPA + PKCE (React)</h1>
      <p>Status: {me ? 'signed in' : 'signed out'}</p>

      {!me ? (
        <a href={`${BACKEND}/login`}>
          <button>Login</button>
        </a>
      ) : (
        <button
          onClick={async () => {
            await fetch(`${BACKEND}/logout`, {
              method: 'POST',
              credentials: 'include'
            });
            setMe(null);
          }}
        >
          Logout
        </button>
      )}

      <div style={{ marginTop: 16 }}>
        <button onClick={fetchMe}>Refresh /me</button>
      </div>

      {me && (
        <pre style={{ marginTop: 16, background: '#f6f8fa', padding: 16 }}>
{JSON.stringify(me, null, 2)}
        </pre>
      )}

      {err && <p style={{ color: 'crimson' }}>{err}</p>}

      <p style={{ marginTop: 24 }}>
        The SPA calls the Node app for the code + PKCE flow.
      </p>
    </div>
  );
}
