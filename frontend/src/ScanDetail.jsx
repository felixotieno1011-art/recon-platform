import { useEffect, useRef, useState } from 'react';
import { getScan, scanSocket } from './api';

export default function ScanDetail({ scanId }) {
  const [snap, setSnap] = useState(null);
  const [progress, setProgress] = useState(null);
  const [findings, setFindings] = useState([]);
  const [error, setError] = useState('');
  const wsRef = useRef(null);

  useEffect(() => {
    if (!scanId) return;
    setSnap(null); setProgress(null); setFindings([]); setError('');

    const ws = scanSocket(scanId);
    wsRef.current = ws;

    ws.onmessage = ev => {
      const msg = JSON.parse(ev.data);
      if (msg.type === 'snapshot' || msg.type === 'final') setSnap(msg.scan);
      if (msg.type === 'progress') setProgress(msg.payload);
      if (msg.type === 'final') {
        setFindings(msg.findings || []);
        ws.close();
      }
      if (msg.type === 'error') setError(msg.error);
    };
    ws.onerror = () => setError('WebSocket error');
    ws.onclose = () => {};

    getScan(scanId).then(d => {
      if (!snap) setSnap(d.scan);
      if (d.scan.status === 'done' || d.scan.status === 'failed') setFindings(d.findings);
    }).catch(e => setError(e.message));

    return () => { ws.close(); wsRef.current = null; };
  }, [scanId]);

  const pct = progress
    ? Math.round(progress.done * 100 / progress.total)
    : (snap?.progress || 0);

  return (
    <div className="panel">
      <h2>Scan {scanId}</h2>
      {error && <div className="error" style={{ marginBottom: 12 }}>{error}</div>}
      {snap && (
        <>
          <div className="dim" style={{ marginBottom: 8 }}>
            {snap.target} → {snap.resolved_ips} ·{' '}
            <span className={`status ${snap.status}`}>{snap.status}</span>
          </div>
          <progress value={pct} max={100} />
          <div className="dim" style={{ fontSize: 12, marginTop: 4 }}>
            {progress ? `${progress.done}/${progress.total} ports` : `${pct}%`}
          </div>
        </>
      )}
      <div style={{ marginTop: 16 }}>
        {findings.length === 0 && snap?.status === 'done' && (
          <div className="dim">No open ports found.</div>
        )}
        {findings.map((f, i) => {
          if (f.kind === 'port') {
            const b = f.data.banner;
            return (
              <div className="finding" key={i}>
                <strong>{f.data.port}/tcp</strong> open
                {b && <span className="dim"> · {b.slice(0, 60)}</span>}
              </div>
            );
          }
          if (f.kind === 'dns') {
            return (
              <div className="finding" key={i}>
                <strong>DNS</strong>{' '}
                {Object.entries(f.data).map(([k, v]) => `${k}=${v.length}`).join(' · ')}
              </div>
            );
          }
          return null;
        })}
      </div>
    </div>
  );
}
