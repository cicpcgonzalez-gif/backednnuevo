/*
  Compliance smoke test (Venezuela) - flujo end-to-end
  - Crea rifero (admin) + buyer (user)
  - Asigna plan al rifero
  - Recarga wallet buyer
  - Crea rifa con endDate cercano, la activa
  - Compra tickets
  - Espera endDate y ejecuta job de cierre
  - Verifica que se cerró y que existe Winner

  Uso:
    BASE_URL=https://backednnuevo.onrender.com node scripts/complianceSmokeTest.js

  Variables opcionales:
    SUPERADMIN_EMAIL / SUPERADMIN_PASSWORD
    WAIT_MS (default 15000)
*/

const fs = require('fs');
const path = require('path');

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const SUPERADMIN_EMAIL = process.env.SUPERADMIN_EMAIL || 'rifa@megarifasapp.com';
const SUPERADMIN_PASSWORD = process.env.SUPERADMIN_PASSWORD || 'rifasadmin123';
const WAIT_MS = Number(process.env.WAIT_MS || 15000);

function nowIso() {
  return new Date().toISOString();
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function httpJson(pathname, { method = 'GET', body, token } = {}) {
  const url = `${BASE_URL}${pathname}`;
  const headers = {
    'Content-Type': 'application/json'
  };
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

function uniqueEmail(prefix) {
  const s = Math.random().toString(16).slice(2);
  return `${prefix}.${Date.now()}.${s}@test.local`;
}

async function main() {
  const evidence = {
    baseUrl: BASE_URL,
    startedAt: nowIso(),
    steps: []
  };

  const step = (name, data) => evidence.steps.push({ name, at: nowIso(), ...data });

  // 1) Login superadmin
  const loginSuper = await httpJson('/auth/login', {
    method: 'POST',
    body: { email: SUPERADMIN_EMAIL, password: SUPERADMIN_PASSWORD }
  });
  step('login_superadmin', loginSuper);
  if (!loginSuper.ok) throw new Error(`Superadmin login failed: ${loginSuper.status}`);
  const superToken = loginSuper.json?.accessToken || loginSuper.json?.token;

  // 2) Crear rifero (admin)
  const riferoEmail = uniqueEmail('rifero');
  const riferoPassword = 'Test12345!';
  const createRifero = await httpJson('/superadmin/users', {
    method: 'POST',
    token: superToken,
    body: {
      email: riferoEmail,
      password: riferoPassword,
      role: 'admin',
      firstName: 'Rifero',
      lastName: 'Prueba',
      active: true
    }
  });
  step('create_rifero_admin', createRifero);
  if (!createRifero.ok) throw new Error(`Create rifero failed: ${createRifero.status}`);
  const riferoId = createRifero.json?.id;

  // 3) Asignar plan al rifero
  const plan = {
    tier: 'starter',
    raffleCreditsRemaining: 10,
    boostCreditsRemaining: 0
  };
  const setPlan = await httpJson(`/superadmin/users/${riferoId}/plan`, {
    method: 'PATCH',
    token: superToken,
    body: plan
  });
  step('set_rifero_plan', setPlan);
  if (!setPlan.ok) throw new Error(`Set plan failed: ${setPlan.status}`);

  // 4) Crear buyer (user)
  const buyerEmail = uniqueEmail('buyer');
  const buyerPassword = 'Test12345!';
  const createBuyer = await httpJson('/superadmin/users', {
    method: 'POST',
    token: superToken,
    body: {
      email: buyerEmail,
      password: buyerPassword,
      role: 'user',
      firstName: 'Buyer',
      lastName: 'Prueba',
      active: true
    }
  });
  step('create_buyer_user', createBuyer);
  if (!createBuyer.ok) throw new Error(`Create buyer failed: ${createBuyer.status}`);

  // 5) Login rifero y buyer
  const loginRifero = await httpJson('/auth/login', {
    method: 'POST',
    body: { email: riferoEmail, password: riferoPassword }
  });
  step('login_rifero', loginRifero);
  if (!loginRifero.ok) throw new Error(`Rifero login failed: ${loginRifero.status}`);
  const riferoToken = loginRifero.json?.accessToken || loginRifero.json?.token;

  const loginBuyer = await httpJson('/auth/login', {
    method: 'POST',
    body: { email: buyerEmail, password: buyerPassword }
  });
  step('login_buyer', loginBuyer);
  if (!loginBuyer.ok) throw new Error(`Buyer login failed: ${loginBuyer.status}`);
  const buyerToken = loginBuyer.json?.accessToken || loginBuyer.json?.token;

  // 6) Topup buyer
  const topup = await httpJson('/wallet/topup', {
    method: 'POST',
    token: buyerToken,
    body: { amount: 1000, provider: 'manual' }
  });
  step('wallet_topup_buyer', topup);
  if (!topup.ok) throw new Error(`Topup failed: ${topup.status}`);

  // 7) Crear rifa (draft) con endDate cercano
  const startDate = new Date(Date.now() - 5_000).toISOString();
  const endDate = new Date(Date.now() + 10_000).toISOString();
  const createRaffle = await httpJson('/raffles', {
    method: 'POST',
    token: riferoToken,
    body: {
      title: `Rifa Prueba ${new Date().toISOString()}`,
      description: 'Rifa de prueba para cumplimiento (tiempo de cierre)',
      ticketPrice: 10,
      totalTickets: 100,
      startDate,
      endDate,
      paymentMethods: ['wallet']
    }
  });
  step('create_raffle_draft', createRaffle);
  if (!createRaffle.ok) throw new Error(`Create raffle failed: ${createRaffle.status}`);
  const raffleId = createRaffle.json?.raffle?.id;

  // 8) Activar rifa
  const activate = await httpJson(`/admin/raffles/${raffleId}/activate`, {
    method: 'POST',
    token: riferoToken,
    body: {}
  });
  step('activate_raffle', activate);
  if (!activate.ok) throw new Error(`Activate raffle failed: ${activate.status}`);

  // 9) Comprar tickets
  const purchase = await httpJson(`/raffles/${raffleId}/purchase`, {
    method: 'POST',
    token: buyerToken,
    body: { quantity: 2 }
  });
  step('purchase_tickets', purchase);
  if (!purchase.ok) throw new Error(`Purchase failed: ${purchase.status}`);

  // 10) Esperar y ejecutar job de cierre
  step('wait_for_endDate', { waitMs: WAIT_MS, plannedEndDate: endDate });
  await sleep(WAIT_MS);

  const jobClose = await httpJson('/admin/jobs/close-expired-raffles', {
    method: 'POST',
    token: superToken,
    body: { limit: 200 }
  });
  step('job_close_expired_raffles', jobClose);

  // 11) Verificar estado de rifa
  const raffleAfter = await httpJson(`/raffles/${raffleId}`);
  step('raffle_after_close', raffleAfter);

  // 12) Verificar winner en /winners
  const winners = await httpJson('/winners');
  const winnerForRaffle = Array.isArray(winners.json)
    ? winners.json.find((w) => Number(w?.raffleId) === Number(raffleId))
    : null;
  step('winners_list', { status: winners.status, foundWinner: !!winnerForRaffle, winner: winnerForRaffle || null });

  // 13) Intentar compra luego del cierre (debe fallar)
  const purchaseAfter = await httpJson(`/raffles/${raffleId}/purchase`, {
    method: 'POST',
    token: buyerToken,
    body: { quantity: 1 }
  });
  step('purchase_after_close_expected_fail', purchaseAfter);

  evidence.finishedAt = nowIso();

  const outPath = path.join(__dirname, '..', 'artifacts', `compliance-smoke-${Date.now()}.json`);
  fs.writeFileSync(outPath, JSON.stringify(evidence, null, 2), 'utf-8');

  console.log('OK - evidencia guardada en:', outPath);
  console.log('RaffleId:', raffleId);
  console.log('WinnerFound:', !!winnerForRaffle);
}

main().catch((err) => {
  console.error('Compliance smoke test FAILED:', err);
  process.exitCode = 1;
});
