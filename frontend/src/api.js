const API = 'http://127.0.0.1:8000';
const WS_BASE = 'ws://127.0.0.1:8000';

function getToken() {
  return localStorage.getItem('recon_token') || '';
}

export async function submitScan(target, ports) {
  const token = getToken();
  if (!token) throw new Error('API Token missing. Please set it in Settings.');

  const r = await fetch(`${API}/api/scans`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ target, ports }),
  });
  const body = await r.json();
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
}

export async function getScan(scanId) {
  const r = await fetch(`${API}/api/scans/${scanId}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

export async function listScans() {
  const r = await fetch(`${API}/api/scans`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()).scans;
}

export function scanSocket(scanId) {
  return new WebSocket(`${WS_BASE}/ws/scans/${scanId}`);
}

export function reportUrl(scanId) {
  return `${API}/api/scans/${scanId}/report`;
}
