import { useEffect, useState } from 'react';
import { getScan, scanSocket, reportUrl } from './api';

export default function ScanDetail({ scanId }) {
  const [snap, setSnap] = useState(null);
  const [progress, setProgress] = useState(null);
  const [findings, setFindings] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!scanId) return;
    setSnap(null); setProgress(null); setFindings([]); setError('');

    let ws = null;

    // 1. Fetch current state first
    getScan(scanId).then(d => {
      setSnap(d.scan);
      
      // 2. If already done, just set findings and close out.
      if (d.scan.status === 'done' || d.scan.status === 'failed') {
        setFindings(d.findings);
      } else {
        // 3. Only open WebSocket if still running
        ws = scanSocket(scanId);
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
      }
    }).catch(e => setError(e.message));

    return () => { if (ws) ws.close(); };
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
      
      {snap?.status === 'done' && (
        <div style={{ marginTop: 12, marginBottom: 8 }}>
          <a href={reportUrl(scanId)} download={`recon-report-${scanId}.json`}>
            <button type="button" style={{ fontSize: 11 }}>Download JSON Report</button>
          </a>
        </div>
      )}

      <div style={{ marginTop: 16 }}>
        {findings.length === 0 && snap?.status === 'done' && (
          <div className="dim">No open ports found.</div>
        )}
        {findings.map((f, i) => {
          if (f.kind === 'port') {
            const b = f.data.banner;
            const cves = f.data.cve_candidates || [];
            const fp = f.data.fingerprint;
            return (
              <div className="finding" key={i} style={{ paddingBottom: 8 }}>
                <div>
                  <strong>{f.data.ip}:{f.data.port}/tcp</strong> open
                  {fp && <span className="dim"> · {fp.product} {fp.version}</span>}
                  {!fp && b && <span className="dim"> · {b.slice(0, 40)}</span>}
                </div>
                {cves.map(c => (
                  <div key={c.id} style={{ marginLeft: 16, marginTop: 4, fontSize: 11 }}>
                    <span style={{
                      color: c.severity === 'CRITICAL' ? 'var(--err)' :
                             c.severity === 'HIGH' ? '#a85400' : 'var(--warn)',
                      fontWeight: 700, marginRight: 6
                    }}>[{c.severity}]</span>
                    <span style={{ marginRight: 6, fontSize: 10, opacity: 0.8 }}>
                      {c.confidence === 'high' ? '🟢' : c.confidence === 'medium' ? '🟡' : '🔴'} {c.confidence.toUpperCase()}
                    </span>
                    {c.id} — {c.desc}
                    {c.reason && <div className="dim" style={{ fontSize: 10, marginTop: 2 }}>{c.reason}</div>}
                  </div>
                ))}
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
