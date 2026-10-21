import { useEffect, useState } from 'react';
import SubmitForm from './SubmitForm';
import ScanDetail from './ScanDetail';
import { listScans } from './api';

export default function App() {
  const [scanId, setScanId] = useState(null);
  const [recent, setRecent] = useState([]);
  const [token, setToken] = useState(localStorage.getItem('recon_token') || '');
  const [showSettings, setShowSettings] = useState(!token);

  useEffect(() => {
    if (!scanId) return;
    const t = setInterval(() => {
      listScans().then(setRecent).catch(() => {});
    }, 3000);
    return () => clearInterval(t);
  }, [scanId]);

  useEffect(() => {
    listScans().then(setRecent).catch(() => {});
  }, []);

  function saveToken() {
    localStorage.setItem('recon_token', token);
    setShowSettings(false);
  }

  function handleSubmitted(id) {
    setScanId(id);
    listScans().then(setRecent).catch(() => {});
  }

  return (
    <div className="container">
      <h1>recon-platform</h1>
      <div className="dim" style={{ marginBottom: 20, display: 'flex', justifyContent: 'space-between' }}>
        <span>Vulnerability scanner · legal gate enforced via scope.yaml</span>
        <button type="button" onClick={() => setShowSettings(!showSettings)} style={{ padding: '2px 6px', fontSize: 10 }}>⚙ Settings</button>
      </div>

      {showSettings && (
        <div className="panel" style={{ borderColor: 'var(--accent)' }}>
          <h2>API Authentication</h2>
          <p className="dim" style={{ marginTop: 0 }}>Paste the API token from your Termux terminal.</p>
          <input 
            type="password" 
            value={token} 
            onChange={e => setToken(e.target.value)} 
            placeholder="vPCHQR..." 
          />
          <button type="button" onClick={saveToken}>Save Token</button>
        </div>
      )}

      <SubmitForm onSubmitted={handleSubmitted} />
      {scanId && <ScanDetail scanId={scanId} />}
      
      <div className="panel">
        <h2>Recent Scans</h2>
        {recent.length === 0 && <div className="dim">No scans yet.</div>}
        {recent.slice(0, 10).map(s => (
          <div className="finding" key={s.id} style={{ cursor: 'pointer' }}
               onClick={() => setScanId(s.id)}>
            <strong>{s.id}</strong> · {s.target} ·{' '}
            <span className={`status ${s.status}`}>{s.status}</span>
            <span className="dim"> · {s.progress}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}
