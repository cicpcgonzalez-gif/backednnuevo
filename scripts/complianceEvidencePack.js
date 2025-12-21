/*
  Compliance Evidence Pack
  Genera un paquete de evidencia para una rifa (incluye: rifa, ganador, auditoría).

  Uso:
    BASE_URL=https://backednnuevo.onrender.com node scripts/complianceEvidencePack.js --raffleId 10

  Variables:
    SUPERADMIN_EMAIL / SUPERADMIN_PASSWORD
*/

const fs = require('fs');
const path = require('path');

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const SUPERADMIN_EMAIL = process.env.SUPERADMIN_EMAIL || 'rifa@megarifasapp.com';
const SUPERADMIN_PASSWORD = process.env.SUPERADMIN_PASSWORD || 'rifasadmin123';

function nowIso() {
  return new Date().toISOString();
}

function argValue(name) {
  const idx = process.argv.findIndex((a) => a === name);
  if (idx === -1) return null;
  return process.argv[idx + 1] || null;
}

async function httpJson(pathname, { method = 'GET', body, token } = {}) {
  const url = `${BASE_URL}${pathname}`;
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });

  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }

  return { status: res.status, ok: res.ok, json };
}

async function main() {
  const raffleId = Number(argValue('--raffleId'));
  if (!Number.isFinite(raffleId)) {
    console.error('Uso: node scripts/complianceEvidencePack.js --raffleId <id>');
    process.exitCode = 2;
    return;
  }

  const pack = {
    baseUrl: BASE_URL,
    raffleId,
    generatedAt: nowIso(),
    checks: {}
  };

  // 0) Estado SANDBOX (público)
  const sandboxStatus = await httpJson('/sandbox/status');
  pack.checks.sandboxStatus = sandboxStatus;

  // Login superadmin
  const login = await httpJson('/auth/login', {
    method: 'POST',
    body: { email: SUPERADMIN_EMAIL, password: SUPERADMIN_PASSWORD }
  });
  if (!login.ok) throw new Error(`Superadmin login failed: ${login.status}`);
  const token = login.json?.accessToken || login.json?.token;

  // 1) Rifa
  const raffle = await httpJson(`/raffles/${raffleId}`);
  pack.checks.raffle = raffle;

  // 2) Ganador
  const winners = await httpJson('/winners');
  const winnerForRaffle = Array.isArray(winners.json)
    ? winners.json.filter((w) => Number(w?.raffleId) === raffleId)
    : [];
  pack.checks.winners = { status: winners.status, ok: winners.ok, count: winnerForRaffle.length, items: winnerForRaffle };

  // 3) Auditoría (acciones clave)
  const since = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(); // últimas 2h
  const auditRaffle = await httpJson(
    `/superadmin/audit/search?entity=Raffle&entityId=${encodeURIComponent(String(raffleId))}&since=${encodeURIComponent(since)}&limit=5000`,
    { token }
  );
  pack.checks.auditRaffle = auditRaffle;

  // 4) Auditoría de wallet/topup (por acción) - opcional
  const auditTopups = await httpJson(
    `/superadmin/audit/search?action=WALLET_TOPUP&since=${encodeURIComponent(since)}&limit=2000`,
    { token }
  );
  pack.checks.auditTopups = auditTopups;

  const outPath = path.join(__dirname, '..', 'artifacts', `compliance-pack-raffle-${raffleId}-${Date.now()}.json`);
  fs.writeFileSync(outPath, JSON.stringify(pack, null, 2), 'utf-8');

  console.log('OK - paquete de evidencia guardado en:', outPath);
  console.log('Raffle status:', raffle.json?.status || null);
  console.log('Winners found:', winnerForRaffle.length);
  console.log('Audit logs (Raffle):', auditRaffle.json?.count ?? null);
}

main().catch((err) => {
  console.error('Evidence pack FAILED:', err);
  process.exitCode = 1;
});
