import { useState } from 'react';
import { submitScan } from './api';

export default function SubmitForm({ onSubmitted }) {
  const [target, setTarget] = useState('127.0.0.1');
  const [ports, setPorts] = useState('1-1000');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const res = await submitScan(target.trim(), ports.trim());
      onSubmitted(res.scan_id, res);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="panel" onSubmit={handleSubmit}>
      <h2>New Scan</h2>
      <div className="row">
        <div>
          <label>Target</label>
          <input value={target} onChange={e => setTarget(e.target.value)}
                 placeholder="127.0.0.1 or hostname" disabled={busy} />
        </div>
        <div>
          <label>Ports</label>
          <input value={ports} onChange={e => setPorts(e.target.value)}
                 placeholder="1-1024 or 22,80,443" disabled={busy} />
        </div>
      </div>
      <button type="submit" disabled={busy || !target.trim()}>
        {busy ? 'Submitting…' : 'Start Scan'}
      </button>
      {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}
    </form>
  );
}
