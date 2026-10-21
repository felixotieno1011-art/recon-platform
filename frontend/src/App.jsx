import { useEffect, useState } from 'react';
import SubmitForm from './SubmitForm';
import ScanDetail from './ScanDetail';
import { listScans } from './api';

export default function App() {
  const [scanId, setScanId] = useState(null);
  const [recent, setRecent] = useState([]);

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

  function handleSubmitted(id) {
    setScanId(id);
    listScans().then(setRecent).catch(() => {});
  }

  return (
    <div className="container">
      <h1>recon-platform</h1>
      <div className="dim" style={{ marginBottom: 20 }}>
        Vulnerability scanner · legal gate enforced via scope.yaml
      </div>
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
