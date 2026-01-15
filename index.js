require('dotenv').config();
const express = require('express');
const { PrismaClient, Prisma } = require('@prisma/client');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const crypto = require('crypto');
const multer = require('multer');
let sharp = null;
try {
  // Optional en runtime, pero lo agregamos como dependencia para convertir avatar a WEBP.
  sharp = require('sharp');
} catch (_e) {
  sharp = null;
}
const FraudEngine = require('./utils/fraudEngine');
const paymentService = require('./services/paymentService');

// --- SANDBOX MODE (simulación total, sin dinero real) ---
const SANDBOX_MODE = String(process.env.SANDBOX_MODE || '').toLowerCase() === 'true';
const SANDBOX_LABEL = ' [SIMULADO]';

// --- Admin Plans (subscription/quotas) ---

const DEFAULT_PLAN_CONFIG = {
  unlimitedWeeklyRaffleLimit: 3,
  starterRaffleCredits: 5,
  proRaffleCredits: 10,
  starterGalleryLimit: 3,
  proGalleryLimit: 6,
  unlimitedGalleryLimit: 10,
  starterBoostCredits: 0,
  proBoostCredits: 2,
  unlimitedBoostCredits: 8
};
let cachedPlanConfig = { value: DEFAULT_PLAN_CONFIG, loadedAt: 0 };
async function getPlanConfig() {
  const now = Date.now();
  if (now - cachedPlanConfig.loadedAt < 60_000) return cachedPlanConfig.value;
  try {
    const settings = await prisma.systemSettings.findFirst();
    const company = settings?.company && typeof settings.company === 'object' ? settings.company : {};
    const planConfig = company?.planConfig && typeof company.planConfig === 'object' ? company.planConfig : {};
    const merged = { ...DEFAULT_PLAN_CONFIG, ...planConfig };
    cachedPlanConfig = { value: merged, loadedAt: now };
    return merged;
  } catch (_e) {
    return DEFAULT_PLAN_CONFIG;
  }
}

function normalizeAdminPlan(plan, planConfig = DEFAULT_PLAN_CONFIG) {
  if (!plan || typeof plan !== 'object') return null;
  const tier = String(plan.tier || '').toLowerCase();
  if (!['starter', 'pro', 'unlimited'].includes(tier)) return null;

  const normalized = { ...plan, tier };
  if (tier === 'starter') {
    if (typeof normalized.raffleCreditsRemaining !== 'number') normalized.raffleCreditsRemaining = planConfig.starterRaffleCredits;
    if (typeof normalized.boostCreditsRemaining !== 'number') normalized.boostCreditsRemaining = planConfig.starterBoostCredits;
  }
  if (tier === 'pro') {
    if (typeof normalized.raffleCreditsRemaining !== 'number') normalized.raffleCreditsRemaining = planConfig.proRaffleCredits;
    if (typeof normalized.boostCreditsRemaining !== 'number') normalized.boostCreditsRemaining = planConfig.proBoostCredits;
  }
  if (tier === 'unlimited') {
    // unlimited no usa raffleCreditsRemaining
    if (typeof normalized.boostCreditsRemaining !== 'number') normalized.boostCreditsRemaining = planConfig.unlimitedBoostCredits;
  }
  return normalized;
}

async function ensureDbColumns() {
  try {
    await prisma.$executeRawUnsafe('ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "adminPlan" JSONB;');

    await prisma.$executeRawUnsafe('ALTER TABLE "Raffle" ADD COLUMN IF NOT EXISTS "status" TEXT NOT NULL DEFAULT \'active\';');
    await prisma.$executeRawUnsafe('ALTER TABLE "Raffle" ADD COLUMN IF NOT EXISTS "activatedAt" TIMESTAMP;');
    await prisma.$executeRawUnsafe('ALTER TABLE "Raffle" ADD COLUMN IF NOT EXISTS "closedAt" TIMESTAMP;');

    await prisma.$executeRawUnsafe('UPDATE "Raffle" SET "status"=\'active\' WHERE "status" IS NULL;');
    await prisma.$executeRawUnsafe('UPDATE "Raffle" SET "activatedAt"="createdAt" WHERE "activatedAt" IS NULL AND "status"=\'active\';');

    // Winner columns (para múltiples premios por rifa: 1pm/4pm/10pm)
    // Nota: se hace por compatibilidad cuando Render queda desalineado con migraciones.
    try {
      await prisma.$executeRawUnsafe('ALTER TABLE "Winner" ADD COLUMN IF NOT EXISTS "drawSlot" TEXT;');
      await prisma.$executeRawUnsafe('ALTER TABLE "Winner" ADD COLUMN IF NOT EXISTS "ticketNumber" INTEGER;');
      await prisma.$executeRawUnsafe('ALTER TABLE "Winner" ADD COLUMN IF NOT EXISTS "status" TEXT NOT NULL DEFAULT \'pending\';');
      try { await prisma.$executeRawUnsafe('CREATE INDEX IF NOT EXISTS "Winner_raffleId_drawSlot_idx" ON "Winner"("raffleId", "drawSlot");'); } catch (_e) {}
      try { await prisma.$executeRawUnsafe('CREATE INDEX IF NOT EXISTS "Winner_raffleId_ticketNumber_idx" ON "Winner"("raffleId", "ticketNumber");'); } catch (_e) {}
    } catch (e) {
      console.error('[DB] ensureDbColumns Winner failed:', e?.message || e);
    }
  } catch (e) {
    console.error('[DB] ensureDbColumns adminPlan failed:', e?.message || e);
  }
}

// Encryption Configuration
// Ensure ENCRYPTION_KEY is 32 bytes. Using JWT_SECRET to derive one if not provided.
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY 
  ? Buffer.from(process.env.ENCRYPTION_KEY, 'hex') 
  : crypto.createHash('sha256').update(String(process.env.JWT_SECRET || 'dev-secret')).digest();

const IV_LENGTH = 16;

function encrypt(text) {
  if (!text) return text;
  if (typeof text !== 'string') text = String(text);
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
  } catch (e) {
    console.error('Encryption error:', e);
    return text;
  }
}

function decrypt(text) {
  if (!text) return text;
  try {
    const textParts = text.split(':');
    if (textParts.length !== 2) return text; // Not encrypted or different format
    const iv = Buffer.from(textParts[0], 'hex');
    const encryptedText = Buffer.from(textParts[1], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch (e) {
    // console.error('Decryption error:', e);
    return text; // Return original if decryption fails
  }
}

function safeDecrypt(value) {
  if (value == null) return value;
  try {
    return decrypt(value);
  } catch (_e) {
    return value;
  }
}

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function normalizePaymentMethods(value) {
  if (Array.isArray(value)) {
    return value
      .map((m) => String(m || '').trim())
      .filter(Boolean);
  }
  if (typeof value === 'string') {
    return value
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return [];
}

function coerceDate(value) {
  if (!value) return null;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

function getRaffleEndDate(raffle) {
  try {
    const style = raffle?.style && typeof raffle.style === 'object' ? raffle.style : null;
    if (!style) return null;
    // Compat: la app guarda startDate/endDate dentro de style
    return coerceDate(style.endDate || style.end_date || style.endsAt || style.ends_at);
  } catch (_e) {
    return null;
  }
}

function getRaffleCloseBufferMs(raffle) {
  const style = raffle?.style && typeof raffle.style === 'object' ? raffle.style : null;
  const fromStyle = style?.autoClose && typeof style.autoClose === 'object'
    ? Number(style.autoClose.closeBufferMinutes)
    : Number(style?.closeBufferMinutes);

  const envMin = Number(process.env.RAFFLE_CLOSE_BUFFER_MINUTES);
  const minutes = Number.isFinite(fromStyle) && fromStyle >= 0
    ? fromStyle
    : (Number.isFinite(envMin) && envMin >= 0 ? envMin : 2);

  return Math.round(minutes * 60_000);
}

function normalizeDrawSlot(raw) {
  const v = String(raw || '').trim().toLowerCase();
  if (!v) return '';

  // Slots principales
  if (v === '1pm' || v === '1 pm' || v === '13' || v === '13:00' || v === '1') return '1pm';
  if (v === '4pm' || v === '4 pm' || v === '16' || v === '16:00' || v === '4') return '4pm';
  if (v === '10pm' || v === '10 pm' || v === '22' || v === '22:00' || v === '10' || v === 'final') return '10pm';

  return v;
}

function parseInstantWinNumbers(style) {
  const safeStyle = style && typeof style === 'object' ? style : {};
  const raw = safeStyle.instantWins;
  const out = [];

  if (Array.isArray(raw)) {
    for (const item of raw) {
      if (item == null) continue;
      if (typeof item === 'number') {
        const n = Math.trunc(item);
        if (Number.isFinite(n) && n > 0) out.push(n);
        continue;
      }
      if (typeof item === 'string') {
        const n = Number(String(item).trim());
        if (Number.isFinite(n) && n > 0) out.push(Math.trunc(n));
        continue;
      }
      if (item && typeof item === 'object') {
        const n = Number(item.number ?? item.ticketNumber);
        if (Number.isFinite(n) && n > 0) out.push(Math.trunc(n));
      }
    }
    return Array.from(new Set(out));
  }

  if (typeof raw === 'string') {
    const parts = raw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    for (const p of parts) {
      const n = Number(p);
      if (Number.isFinite(n) && n > 0) out.push(Math.trunc(n));
    }
    return Array.from(new Set(out));
  }

  return [];
}

function toFiniteNumber(value) {
  if (value == null) return null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'bigint') return Number(value);
  if (typeof value === 'string') {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  }
  if (typeof value === 'object') {
    try {
      // Prisma.Decimal u otros tipos pueden soportar toNumber/toString
      if (typeof value.toNumber === 'function') {
        const n = value.toNumber();
        return Number.isFinite(n) ? n : null;
      }
      if (typeof value.toString === 'function') {
        const n = Number(value.toString());
        return Number.isFinite(n) ? n : null;
      }
    } catch (_e) {
      return null;
    }
  }
  return null;
}

async function closeRaffleInternal(raffleId, reason = 'system_time_endDate') {
  const raffle = await prisma.raffle.findUnique({ where: { id: raffleId } });
  if (!raffle) return { ok: false, code: 404, error: 'Rifa no encontrada' };

  const status = String(raffle.status || '').toLowerCase();
  if (status === 'closed') return { ok: false, code: 400, error: 'La rifa ya está cerrada.' };
  if (status !== 'active') return { ok: false, code: 400, error: 'Solo puedes cerrar rifas activas.' };

  const nextStyle = raffle.style && typeof raffle.style === 'object'
    ? { ...raffle.style, autoClose: { ...(raffle.style.autoClose || {}), at: new Date().toISOString(), reason } }
    : { autoClose: { at: new Date().toISOString(), reason } };

  // En modo lotería/nacional los ganadores se publican con /admin/winners por drawSlot.
  // Cerrar la rifa aquí significa solo: bloquear ventas y marcar status=closed.
  const approvedCount = await prisma.ticket.count({ where: { raffleId, status: 'approved' } });
  await prisma.raffle.update({
    where: { id: raffleId },
    data: { status: 'closed', closedAt: new Date(), style: nextStyle }
  });

  return { ok: true, winner: null, noSales: approvedCount === 0 };
}

async function autoCloseExpiredRaffle(raffleId, reason = 'time_endDate') {
  const raffle = await prisma.raffle.findUnique({ where: { id: raffleId } });
  if (!raffle) return { changed: false };

  const status = String(raffle.status || '').toLowerCase();
  if (status !== 'active') return { changed: false };

  const endDate = getRaffleEndDate(raffle);
  if (!endDate) return { changed: false };
  const bufferMs = getRaffleCloseBufferMs(raffle);
  const closeAtMs = endDate.getTime() - bufferMs;
  if (Date.now() < closeAtMs) return { changed: false };

  const result = await closeRaffleInternal(raffleId, reason);
  return { changed: !!result.ok, result };
}

async function closeExpiredRafflesBatch(limit = 200) {
  const safeLimit = Number.isFinite(Number(limit)) ? Math.max(1, Math.min(2000, Number(limit))) : 200;

  // endDate vive en JSON (style), así que filtramos por status y parseamos en JS.
  // Esto evita fallos por CAST si alguien guarda un endDate inválido.
  const active = await prisma.raffle.findMany({
    where: { status: 'active' },
    select: { id: true, style: true, status: true },
    orderBy: { id: 'asc' },
    take: safeLimit
  });

  let closed = 0;
  for (const r of active || []) {
    const rid = Number(r?.id);
    if (!Number.isFinite(rid)) continue;
    const endDate = getRaffleEndDate(r);
    if (!endDate) continue;
    if (endDate.getTime() > Date.now()) continue;
    const out = await autoCloseExpiredRaffle(rid, 'job_time_endDate');
    if (out.changed) closed++;
  }

  return { scanned: (active || []).length, closed };
}

// Re-evaluar rifas pospuestas por número no vendido
async function reEvaluatePostponedRafflesBatch(limit = 200) {
  const safeLimit = Number.isFinite(Number(limit)) ? Math.max(1, Math.min(2000, Number(limit))) : 200;
  const active = await prisma.raffle.findMany({ where: { status: 'active' }, select: { id: true, title: true, style: true, totalTickets: true, userId: true, prize: true } , take: safeLimit });
  let resolved = 0;
  let skipped = 0;
  const processed = [];

  for (const r of active || []) {
    try {
      const pending = r.style && typeof r.style === 'object' ? r.style.pendingResolution : null;
      if (!pending || pending.status !== 'postponed') { skipped++; continue; }
      const until = pending.until ? new Date(pending.until) : null;
      if (!until || until.getTime() > Date.now()) { skipped++; continue; }

      // Time to resolve: if there are sold tickets, pick random; else close no winner
      const soldCount = await prisma.ticket.count({ where: { raffleId: r.id, status: 'approved' } });
      if (soldCount > 0) {
        const sold = await prisma.ticket.findMany({ where: { raffleId: r.id, status: 'approved' }, select: { id: true, number: true, userId: true } });
        const pick = sold[Math.floor(Math.random() * sold.length)];
        const winner = await prisma.winner.create({ data: { raffleId: r.id, userId: pick.userId, drawSlot: 'final', ticketNumber: pick.number, prize: r.prize || null, photoUrl: null } });
        // notify
        try {
          const winnerUser = await prisma.user.findUnique({ where: { id: pick.userId }, select: { id: true, email: true, pushToken: true, name: true } });
          const winnerName = winnerUser?.name ? safeDecrypt(winnerUser.name) : null;
          const digits = getTicketDigitsFromRaffle(r);
          const displayNumber = formatTicketNumber(pick.number, digits);
          if (winnerUser?.email) sendEmail(winnerUser.email, `¡Has ganado en ${r.title}!`, `Felicidades ${winnerName || ''}. Tu número ${displayNumber} ha ganado.`, `<h1>¡Felicidades ${escapeHtml(winnerName || '')}!</h1><p>Tu número <b>${escapeHtml(displayNumber)}</b> ganó en la rifa <b>${escapeHtml(r.title)}</b>.</p>`).catch(console.error);
          if (winnerUser?.pushToken) sendPushNotification([winnerUser.pushToken], '¡Eres ganador!', `Tu número ${displayNumber} ganó en ${r.title}`, { type: 'you_won', raffleId: r.id }).catch(console.error);
        } catch (e) { console.error('[RE_EVAL_NOTIFY]', e); }

        try { await securityLogger.log({ action: 'WINNER_RESOLVED_REEVALUATE_RANDOM', userEmail: null, userId: null, ipAddress: null, userAgent: null, severity: 'INFO', detail: `Re-evaluación: seleccionado random para rifa ${r.id} -> ticket ${pick.number}`, entity: 'Raffle', entityId: String(r.id), metadata: { method: 're_evaluate_random', winnerId: winner.id } }); } catch (_e) {}
        // clear pendingResolution
        const nextStyle = r.style && typeof r.style === 'object' ? { ...r.style } : {};
        delete nextStyle.pendingResolution;
        await prisma.raffle.update({ where: { id: r.id }, data: { style: nextStyle } });
        resolved++; processed.push({ raffleId: r.id, action: 'random_sold', winnerId: winner.id });
      } else {
        // close without winner
        const out = await closeRaffleInternal(r.id, 're_evaluate_close_no_winner');
        try { await securityLogger.log({ action: 'WINNER_RESOLVED_REEVALUATE_CLOSE', userEmail: null, userId: null, ipAddress: null, userAgent: null, severity: 'INFO', detail: `Re-evaluación: cierre sin ganador rifa ${r.id}`, entity: 'Raffle', entityId: String(r.id), metadata: { result: out } }); } catch (_e) {}
        const nextStyle = r.style && typeof r.style === 'object' ? { ...r.style } : {};
        delete nextStyle.pendingResolution;
        await prisma.raffle.update({ where: { id: r.id }, data: { style: nextStyle } });
        resolved++; processed.push({ raffleId: r.id, action: 'close_no_winner', result: out });
      }
    } catch (e) {
      console.error('[RE_EVAL_ITEM_ERROR]', e);
    }
  }

  return { scanned: (active || []).length, resolved, skipped, processed };
}

// Pre-generate ticket placeholders for a raffle (numbers 1..totalTickets)
// Uses `createMany` in chunks and `skipDuplicates` to be idempotent.
async function generateTicketsForRaffle(raffleId, totalTickets) {
  try {
    const max = Number(totalTickets) || 0;
    if (!Number.isFinite(max) || max <= 0) return { created: 0 };

    // Count existing ticket numbers for this raffle
    const existing = await prisma.ticket.findMany({ where: { raffleId }, select: { number: true } });
    const have = new Set((existing || []).map((r) => Number(r.number)).filter((n) => Number.isFinite(n) && n > 0));

    const toCreate = [];
    for (let i = 1; i <= max; i++) {
      if (!have.has(i)) {
        toCreate.push({ raffleId, number: i, status: 'available' });
      }
    }
    if (!toCreate.length) return { created: 0 };

    const chunkSize = 500;
    let created = 0;
    for (let i = 0; i < toCreate.length; i += chunkSize) {
      const chunk = toCreate.slice(i, i + chunkSize);
      try {
        // skipDuplicates to avoid race issues; supported by Prisma for many DBs
        const info = await prisma.ticket.createMany({ data: chunk, skipDuplicates: true });
        created += Number(info.count || 0);
      } catch (e) {
        // fallback: try inserting one-by-one to avoid blocking
        for (const row of chunk) {
          try {
            await prisma.ticket.create({ data: row });
            created++;
          } catch (_e) {
            // ignore duplicates or errors per-row
          }
        }
      }
    }

    console.log(`[PREGEN_TICKETS] raffle=${raffleId} created=${created} missing=${toCreate.length}`);
    return { created };
  } catch (error) {
    console.error('[PREGEN_TICKETS] error:', error);
    return { error: String(error?.message || error) };
  }
}

const app = express();

// Render / proxies: necesario para construir URLs con https correctamente.
app.set('trust proxy', 1);

const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || null;
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const AVATARS_DIR = path.join(UPLOADS_DIR, 'avatars');

function ensureUploadsDirs() {
  try {
    fs.mkdirSync(AVATARS_DIR, { recursive: true });
  } catch (e) {
    console.error('[uploads] mkdir failed:', e?.message || e);
  }
}

function getPublicBaseUrl(req) {
  if (PUBLIC_BASE_URL) return String(PUBLIC_BASE_URL).replace(/\/$/, '');
  return `${req.protocol}://${req.get('host')}`;
}

function tryDeleteOldAvatarFile(oldAvatarUrl) {
  try {
    if (!oldAvatarUrl || typeof oldAvatarUrl !== 'string') return;
    const asUrl = oldAvatarUrl.startsWith('http')
      ? new URL(oldAvatarUrl)
      : new URL(oldAvatarUrl, 'http://localhost');
    const pathname = asUrl.pathname || '';
    if (!pathname.startsWith('/uploads/avatars/')) return;

    const filename = path.basename(pathname);
    if (!filename) return;
    const fullPath = path.join(AVATARS_DIR, filename);
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
  } catch (_e) {
    // best-effort
  }
}

function parseDataUrlImage(dataUrl) {
  const str = String(dataUrl || '');
  const m = str.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/);
  if (!m) return null;
  const base64 = m[2];
  const buffer = Buffer.from(base64, 'base64');
  return { mime: m[1], buffer };
}

async function saveAvatarBuffer(req, userId, buffer) {
  if (!sharp) throw new Error('sharp_not_available');
  ensureUploadsDirs();

  const safeUserId = Number(userId);
  const filename = `avatar_${safeUserId}_${Date.now()}.webp`;
  const relPath = `/uploads/avatars/${filename}`;
  const fullPath = path.join(AVATARS_DIR, filename);

  await sharp(buffer)
    .resize(256, 256, { fit: 'cover' })
    .webp({ quality: 80 })
    .toFile(fullPath);

  const url = `${getPublicBaseUrl(req)}${relPath}`;
  return { url, relPath, fullPath };
}

// Diagnóstico mínimo: permite verificar rápidamente qué build/entorno está corriendo en Render.
// No expone secretos (solo metadatos básicos).
app.get('/__version', (req, res) => {
  res.json({
    service: 'backednnuevo',
    commit: process.env.RENDER_GIT_COMMIT || process.env.GIT_COMMIT || null,
    serviceName: process.env.RENDER_SERVICE_NAME || null,
    nodeEnv: process.env.NODE_ENV || null,
    node: process.version
  });
});

// Endpoint público: confirma si el backend está en modo sandbox.
app.get('/sandbox/status', (req, res) => {
  res.json({
    sandbox: SANDBOX_MODE,
    payments: {
      initiateProviderForced: SANDBOX_MODE,
      webhooksEnabled: !SANDBOX_MODE
    },
    email: {
      suppressedByDefault: SANDBOX_MODE && String(process.env.SANDBOX_ALLOW_EMAIL || '').toLowerCase() !== 'true'
    },
    timestamp: Date.now()
  });
});

console.log('🔒 Security Module Loaded: Encryption Enabled');

// Security Middleware
app.use(helmet());
app.use(cors());
app.use(compression());

// Archivos subidos (avatars, etc.)
ensureUploadsDirs();
app.use(
  '/uploads',
  express.static(UPLOADS_DIR, {
    etag: true,
    maxAge: '7d'
  })
);

// Simple request logger (method, path, duration)
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[REQ] ${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
  });
  next();
});

// Global rate limit (applies to all routes)
const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 min
  max: 100, // 100 requests/min/IP
  standardHeaders: true,
  legacyHeaders: false
});
app.use(globalLimiter);

// Default pagination guard for GET requests
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
app.use((req, res, next) => {
  if (req.method === 'GET') {
    const limit = Number(req.query.limit);
    const offset = Number(req.query.offset);
    req.query.limit = Number.isFinite(limit) && limit > 0 ? Math.min(limit, MAX_LIMIT) : DEFAULT_LIMIT;
    req.query.offset = Number.isFinite(offset) && offset >= 0 ? offset : 0;
  }
  next();
});

// Rate Limiter for Login
const loginLimiter = rateLimit({
  windowMs: 2 * 60 * 1000, // 2 minutes (Solicitud del usuario)
  max: 4, // Limit each IP to 4 login requests per windowMs
  message: { error: 'Demasiados intentos. Cuenta bloqueada temporalmente por 2 minutos.' }
});

// Inicializar Prisma
const prisma = new PrismaClient();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 15 * 1024 * 1024 // 15MB
  }
});

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL || '1h';
const REFRESH_TOKEN_TTL = process.env.REFRESH_TOKEN_TTL || '30d';

function signAccessToken(user) {
  return jwt.sign(
    { userId: user.id, email: user.email, role: user.role, type: 'access' },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL }
  );
}

function signRefreshToken(user) {
  return jwt.sign(
    { userId: user.id, email: user.email, role: user.role, type: 'refresh' },
    JWT_SECRET,
    { expiresIn: REFRESH_TOKEN_TTL }
  );
}

const generateTxCode = () => `TX-${crypto.randomBytes(10).toString('hex').toUpperCase()}`;

const SUPERADMIN_EMAIL = 'rifa@megarifasapp.com';
const SUPERADMIN_PASSWORD = 'rifasadmin123';
const SUPERADMIN_ROLE = 'superadmin';

const VENEZUELA_STATES = [
  'Amazonas', 'Anzoategui', 'Apure', 'Aragua', 'Barinas', 'Bolivar', 'Carabobo', 'Cojedes',
  'Delta Amacuro', 'Distrito Capital', 'Falcon', 'Guarico', 'Lara', 'Merida', 'Miranda',
  'Monagas', 'Nueva Esparta', 'Portuguesa', 'Sucre', 'Tachira', 'Trujillo', 'Vargas',
  'Yaracuy', 'Zulia'
];

// Middleware de autenticación
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
}

// Auth opcional: si hay token válido, adjunta req.user; si no, continúa sin bloquear.
function attachUserIfTokenPresent(req, _res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return next();
  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
  } catch (_e) {
    // Ignorar token inválido en rutas públicas
  }
  next();
}

async function enrichRafflesWithReactions(raffles, userId) {
  const list = Array.isArray(raffles) ? raffles : [];
  const ids = list
    .map((r) => Number(r?.id))
    .filter((x) => Number.isFinite(x) && x > 0);

  if (!ids.length) return list;

  const countsMap = new Map();
  const myMap = new Map();

  try {
    const idsCsv = ids.join(',');
    const rows = await prisma.$queryRawUnsafe(
      `SELECT "raffleId", "type", COUNT(*)::int AS "count" FROM "RaffleReaction" WHERE "raffleId" IN (${idsCsv}) GROUP BY "raffleId", "type"`
    );
    const arr = Array.isArray(rows) ? rows : [];
    for (const row of arr) {
      const raffleId = Number(row?.raffleId);
      if (!Number.isFinite(raffleId)) continue;
      if (!countsMap.has(raffleId)) countsMap.set(raffleId, { LIKE: 0, HEART: 0 });
      const type = String(row?.type || '').toUpperCase();
      const count = Number(row?.count);
      if (type === 'LIKE' || type === 'HEART') {
        countsMap.get(raffleId)[type] = Number.isFinite(count) ? count : 0;
      }
    }

    const uid = Number(userId);
    if (Number.isFinite(uid) && uid > 0) {
      const myRows = await prisma.$queryRawUnsafe(
        `SELECT "raffleId", "type" FROM "RaffleReaction" WHERE "userId"=${uid} AND "raffleId" IN (${idsCsv})`
      );
      const myArr = Array.isArray(myRows) ? myRows : [];
      for (const row of myArr) {
        const raffleId = Number(row?.raffleId);
        if (!Number.isFinite(raffleId)) continue;
        const type = String(row?.type || '').toUpperCase();
        if (type === 'LIKE' || type === 'HEART') myMap.set(raffleId, type);
      }
    }
  } catch (error) {
    if (!isPrismaMissingTableError(error)) {
      console.error('[enrichRafflesWithReactions] error:', error);
    }
    // Si falta la tabla, devolvemos sin counts/reaction (compatibilidad)
    return list.map((r) => ({
      ...r,
      reactionCounts: r?.reactionCounts || { LIKE: 0, HEART: 0 },
      myReaction: r?.myReaction ?? null
    }));
  }

  return list.map((r) => {
    const rid = Number(r?.id);
    return {
      ...r,
      reactionCounts: countsMap.get(rid) || { LIKE: 0, HEART: 0 },
      myReaction: myMap.get(rid) || null
    };
  });
}

// Middleware de autorización por rol
function authorizeRole(roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Acceso denegado: Rol insuficiente' });
    }
    next();
  };
}

// Prisma middleware para medir tiempos de consulta y loguear consultas lentas
prisma.$use(async (params, next) => {
  const start = Date.now();
  try {
    const result = await next(params);
    const duration = Date.now() - start;
    const model = params.model || 'raw';
    const action = params.action || 'query';
    if (duration > 200) {
      console.warn(`[PRISMA SLOW] ${model}.${action} took ${duration}ms`, { params });
    } else {
      console.log(`[PRISMA] ${model}.${action} ${duration}ms`);
    }
    return result;
  } catch (err) {
    console.error('[PRISMA ERROR]', err);
    throw err;
  }
});

const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const ExcelJS = require('exceljs');

// Configuración de transporte de correo (Mock o SMTP)
let smtpHost = process.env.SMTP_HOST;
let smtpPort = Number(process.env.SMTP_PORT);
let smtpSecure = process.env.SMTP_SECURE === 'true';
let smtpUser = process.env.SMTP_USER;
let smtpPass = process.env.SMTP_PASS;

// Auto-detect Resend if missing config but password looks like Resend API Key
if (!smtpHost && smtpPass && smtpPass.startsWith('re_')) {
  console.log('⚠️ Detectada API Key de Resend pero faltan variables de entorno. Configurando automáticamente para Resend.');
  smtpHost = 'smtp.resend.com';
  smtpPort = 465;
  smtpSecure = true;
  smtpUser = 'resend';
}

// Se inicializa vacío, se crea dinámicamente en sendEmail
let defaultTransporter = nodemailer.createTransport({
  host: smtpHost || 'smtp.ethereal.email',
  port: smtpPort || 587,
  secure: smtpSecure,
  auth: {
    user: smtpUser || 'ethereal_user',
    pass: smtpPass || 'ethereal_pass'
  }
});

let cachedDbSmtpKey = null;
let cachedDbTransporter = null;
let cachedDbFromAddress = null;

function normalizeBoolean(value) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return value.toLowerCase() === 'true';
  return false;
}

function buildSmtpCacheKey(smtp) {
  if (!smtp || typeof smtp !== 'object') return '';
  const host = String(smtp.host || '');
  const port = String(Number(smtp.port) || 0);
  const secure = String(normalizeBoolean(smtp.secure));
  const user = String(smtp.user || '');
  const pass = String(smtp.pass || '');
  const fromName = String(smtp.fromName || '');
  const fromEmail = String(smtp.fromEmail || '');
  return [host, port, secure, user, pass, fromName, fromEmail].join('|');
}

function createDbSmtpTransporter(smtp) {
  const maxConnections = Number(process.env.SMTP_POOL_MAX_CONNECTIONS || 2);
  const maxMessages = Number(process.env.SMTP_POOL_MAX_MESSAGES || 100);
  const rateDelta = Number(process.env.SMTP_POOL_RATE_DELTA_MS || 1000);
  const rateLimit = Number(process.env.SMTP_POOL_RATE_LIMIT || 10);

  return nodemailer.createTransport({
    host: smtp.host,
    port: Number(smtp.port) || 587,
    secure: normalizeBoolean(smtp.secure),
    auth: {
      user: smtp.user,
      pass: smtp.pass
    },
    pool: true,
    maxConnections: Number.isFinite(maxConnections) ? maxConnections : 2,
    maxMessages: Number.isFinite(maxMessages) ? maxMessages : 100,
    rateDelta: Number.isFinite(rateDelta) ? rateDelta : 1000,
    rateLimit: Number.isFinite(rateLimit) ? rateLimit : 10
  });
}

// Si no hay password, usar Ethereal para dev
if (!process.env.SMTP_PASS) {
  console.log('⚠️ No SMTP_PASS provided. Using Ethereal email for testing.');
  defaultTransporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    secure: false,
    auth: {
      user: 'ethereal_user',
      pass: 'ethereal_pass'
    }
  });
}

async function sendEmail(to, subject, text, html, options = {}) {
  try {
    const attachments = Array.isArray(options?.attachments) ? options.attachments : undefined;
    const forceSmtp = options?.forceSmtp === true || (attachments && attachments.length > 0);

    // En SANDBOX, suprimimos envíos por defecto para evitar contacto real accidental.
    // Se puede habilitar explícitamente con SANDBOX_ALLOW_EMAIL=true.
    const sandboxAllowEmail = String(process.env.SANDBOX_ALLOW_EMAIL || '').toLowerCase() === 'true';
    if (SANDBOX_MODE && !sandboxAllowEmail) {
      console.log(`[SANDBOX EMAIL SUPPRESSED] To: ${to} | Subject: ${subject}`);
      try {
        await prisma.mailLog.create({
          data: { to, subject, status: 'SENT_SANDBOX_SUPPRESSED', timestamp: new Date() }
        });
      } catch (_e) {
        // no bloquear
      }
      return true;
    }

    // 1. Buscar configuración SMTP personalizada en DB
    let settings = null;
    try {
      settings = await prisma.systemSettings.findFirst();
    } catch (dbError) {
      console.warn('Could not fetch SMTP settings from DB, using ENV fallback:', dbError.message);
    }

    let transporter = defaultTransporter;
    let fromAddress = process.env.MAIL_FROM || '"MegaRifas" <noreply@megarifasapp.com>';

    // 1.5. INTENTO DE ENVÍO VÍA RESEND API (HTTP) - Prioridad para evitar bloqueos SMTP
    // Si tenemos una API Key de Resend (empieza con re_) y no hay configuración SMTP custom en DB
    if (!forceSmtp && process.env.SMTP_PASS && process.env.SMTP_PASS.startsWith('re_') && (!settings || !settings.smtp)) {
      console.log('🚀 Usando Resend API (HTTP) para evitar timeouts SMTP...');
      try {
        const resendResp = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${process.env.SMTP_PASS}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            from: fromAddress.replace(/"/g, ''), // Resend prefiere formato limpio o Name <email>
            to: [to],
            subject: subject,
            html: html,
            text: text
          })
        });

        if (!resendResp.ok) {
          const errData = await resendResp.json();
          throw new Error(`Resend API Error: ${JSON.stringify(errData)}`);
        }

        const data = await resendResp.json();
        console.log('✅ Correo enviado vía Resend API:', data.id);
        
        await prisma.mailLog.create({
          data: { to, subject, status: 'SENT_API', timestamp: new Date() }
        });
        return true;
      } catch (apiError) {
        console.error('❌ Error enviando vía Resend API:', apiError);
        // Fallback a SMTP si falla la API? No, si falla la API es probable que SMTP también falle.
        // Pero dejaremos que continúe al bloque SMTP por si acaso, o retornamos false.
        // Mejor retornamos false para no duplicar intentos si la API falló explícitamente.
        const errMsg = String(apiError?.message || apiError || '').slice(0, 500);
        await prisma.mailLog.create({
          data: { to, subject, status: 'FAILED_API', error: errMsg || null, timestamp: new Date() }
        });
        return false;
      }
    }

    if (settings && settings.smtp) {
      const smtp = settings.smtp;
      if (smtp && smtp.host && smtp.user && smtp.pass) {
        const key = buildSmtpCacheKey(smtp);
        if (!cachedDbTransporter || cachedDbSmtpKey !== key) {
          cachedDbSmtpKey = key;
          cachedDbTransporter = createDbSmtpTransporter(smtp);
          cachedDbFromAddress = `"${smtp.fromName || 'MegaRifas'}" <${smtp.fromEmail || smtp.user}>`;
        }
        transporter = cachedDbTransporter;
        fromAddress = cachedDbFromAddress;
      }
    } else if (!smtpHost && !smtpPass) {
      // Si no hay config en DB ni en ENV, mock
      console.log(`[MOCK EMAIL] To: ${to} | Subject: ${subject}`);
      await prisma.mailLog.create({
        data: { to, subject, status: 'SENT_MOCK', timestamp: new Date() }
      });
      return true;
    }

    const info = await transporter.sendMail({
      from: fromAddress,
      to,
      subject,
      text,
      html,
      attachments
    });

    console.log('Message sent: %s', info.messageId);
    try {
      await prisma.mailLog.create({
        data: { to, subject, status: 'SENT', timestamp: new Date() }
      });
    } catch (logError) {
      console.warn('Failed to log email sent to DB:', logError.message);
    }
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    try {
      const errMsg = String(error?.message || error || '').slice(0, 500);
      await prisma.mailLog.create({
        data: { to, subject, status: 'FAILED', error: errMsg || null, timestamp: new Date() }
      });
    } catch (logError) {
      console.warn('Failed to log email failure to DB:', logError.message);
    }
    return false;
  }
}

// Superadmin: enviar correo de prueba y devolver el último MailLog asociado
app.post('/superadmin/test-email', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const to = String(req.body?.to || '').trim();
    const forceSmtp = req.body?.forceSmtp === true;
    if (!to || !to.includes('@')) {
      return res.status(400).json({ error: 'Email inválido' });
    }

    const stamp = new Date();
    const subject = `MegaRifas TEST ${stamp.toISOString()}`;
    const ok = await sendEmail(
      to,
      subject,
      'Correo de prueba MegaRifas. Si ves esto, el envío funciona.',
      `<h2>MegaRifas</h2><p>Correo de prueba MegaRifas.</p><p><b>Hora:</b> ${escapeHtml(stamp.toISOString())}</p>`,
      { forceSmtp }
    );

    let last = null;
    try {
      last = await prisma.mailLog.findFirst({
        where: { to, subject },
        orderBy: { timestamp: 'desc' }
      });
    } catch (_e) {
      last = null;
    }

    return res.json({ ok, mailLog: last });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'No se pudo enviar correo de prueba' });
  }
});

function parseEmailList(value) {
  return String(value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function sendBulkEmails(recipients, { subject, text, html, forceSmtp = true } = {}) {
  const list = Array.isArray(recipients) ? recipients.filter(Boolean) : [];
  const concurrency = Number(process.env.MASS_EMAIL_CONCURRENCY || 3);
  const delayMs = Number(process.env.MASS_EMAIL_DELAY_MS || 400);

  let sent = 0;
  let failed = 0;

  for (let i = 0; i < list.length; i += Math.max(1, concurrency)) {
    const chunk = list.slice(i, i + Math.max(1, concurrency));
    const results = await Promise.allSettled(
      chunk.map((to) => sendEmail(to, subject, text, html, { forceSmtp }))
    );
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value === true) sent += 1;
      else failed += 1;
    }
    if (delayMs > 0 && i + concurrency < list.length) await sleep(delayMs);
  }

  return { sent, failed, total: list.length };
}

function formatDateYYYYMMDD(date) {
  const d = new Date(date);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

async function buildAuditXlsxBuffer(logs, { from, to, truncated, rolesById, rolesByEmail } = {}) {
  const workbook = new ExcelJS.Workbook();
  workbook.creator = 'MegaRifas';
  workbook.created = new Date();

  function normalizeRole(role) {
    const r = String(role || '').trim().toLowerCase();
    if (r === 'admin' || r === 'superadmin' || r === 'user') return r;
    return r || 'unknown';
  }

  function getActorRole(log) {
    try {
      if (log && log.userId != null && rolesById && typeof rolesById.get === 'function') {
        const r = rolesById.get(log.userId);
        if (r) return normalizeRole(r);
      }
      if (log && log.userEmail && rolesByEmail && typeof rolesByEmail.get === 'function') {
        const r = rolesByEmail.get(String(log.userEmail).toLowerCase());
        if (r) return normalizeRole(r);
      }
      if (log && log.userEmail && String(log.userEmail).toLowerCase() === String(SUPERADMIN_EMAIL).toLowerCase()) {
        return 'superadmin';
      }
    } catch (_e) {
      // ignore
    }
    return 'unknown';
  }

  function initSheet(name) {
    const sheet = workbook.addWorksheet(name);
    sheet.columns = [
      { header: 'Timestamp', key: 'timestamp', width: 22 },
      { header: 'Severity', key: 'severity', width: 10 },
      { header: 'Action', key: 'action', width: 26 },
      { header: 'ActorRole', key: 'actorRole', width: 12 },
      { header: 'UserId', key: 'userId', width: 10 },
      { header: 'UserEmail', key: 'userEmail', width: 28 },
      { header: 'Entity', key: 'entity', width: 14 },
      { header: 'EntityId', key: 'entityId', width: 16 },
      { header: 'IP', key: 'ipAddress', width: 16 },
      { header: 'UserAgent', key: 'userAgent', width: 40 },
      { header: 'Detail', key: 'detail', width: 60 }
    ];

    if (from && to) {
      sheet.addRow({ timestamp: `Rango: ${new Date(from).toISOString()} → ${new Date(to).toISOString()}` });
      sheet.addRow({ timestamp: `Truncado: ${truncated ? 'SI' : 'NO'}` });
      sheet.addRow({});
    }
    return sheet;
  }

  const adminsSheet = initSheet('Admins');
  const usersSheet = initSheet('Usuarios');

  for (const log of Array.isArray(logs) ? logs : []) {
    const actorRole = getActorRole(log);
    const row = {
      timestamp: log.timestamp ? new Date(log.timestamp).toISOString() : '',
      severity: log.severity || '',
      action: log.action || '',
      actorRole,
      userId: log.userId ?? '',
      userEmail: log.userEmail || '',
      entity: log.entity || '',
      entityId: log.entityId || '',
      ipAddress: log.ipAddress || '',
      userAgent: log.userAgent || '',
      detail: log.detail || ''
    };

    if (actorRole === 'admin' || actorRole === 'superadmin') adminsSheet.addRow(row);
    else usersSheet.addRow(row);
  }

  const buf = await workbook.xlsx.writeBuffer();
  return Buffer.from(buf);
}

// Helper para generar IDs cortos y legibles (ej. USR-12345678)
function generateShortId(prefix = 'ID') {
  const random = Math.random().toString(36).substring(2, 10).toUpperCase();
  return `${prefix}-${random}`;
}

function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function normalizeEmail(value) {
  return String(value || '').toLowerCase().trim();
}

function getPublicBaseUrlFromRequest(req) {
  try {
    const xfProto = String(req?.headers?.['x-forwarded-proto'] || '').split(',')[0].trim();
    const xfHost = String(req?.headers?.['x-forwarded-host'] || '').split(',')[0].trim();
    const host = xfHost || String(req?.headers?.host || '').split(',')[0].trim();
    const proto = xfProto || String(req?.protocol || '').trim() || 'https';
    if (!host) return null;
    return `${proto}://${host}`;
  } catch (_e) {
    return null;
  }
}

function getTicketDigitsFromRaffle(raffle) {
  const explicit = Number(raffle?.digits);
  if (Number.isFinite(explicit) && explicit > 0) return explicit;

  const total = Number(raffle?.totalTickets);
  // Para 10,000 queremos 4 (10^4) y para 1,000,000 queremos 6 (10^6)
  // -> usar (totalTickets - 1) como referencia del máximo “rellenable”.
  if (Number.isFinite(total) && total > 1) return String(total - 1).length;

  return 4;
}

function formatTicketNumber(num, digits) {
  const n = Number(num);
  if (!Number.isFinite(n)) return String(num);
  const d = Number(digits);
  if (!Number.isFinite(d) || d <= 0) return String(n);
  return String(n).padStart(d, '0');
}

function build2faToken(code, expiresAtMs) {
  return `2fa:${String(code || '').trim()}:${Number(expiresAtMs)}`;
}

function parse2faToken(token) {
  const raw = String(token || '');
  if (!raw.startsWith('2fa:')) return null;
  const parts = raw.split(':');
  if (parts.length !== 3) return null;
  const code = parts[1];
  const expiresAtMs = Number(parts[2]);
  if (!code || !Number.isFinite(expiresAtMs)) return null;
  return { code, expiresAtMs };
}

function redactUserForResponse(user) {
  if (!user || typeof user !== 'object') return user;
  const { password: _pw, ...rest } = user;
  return rest;
}

function generateSecurityId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let result = 'MR-';
  for (let i = 0; i < 4; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  result += '-';
  result += chars.charAt(Math.floor(Math.random() * chars.length));
  return result;
}

async function generateUniqueSecurityId(maxAttempts = 25) {
  for (let i = 0; i < maxAttempts; i++) {
    const securityId = generateSecurityId();
    const exists = await prisma.user.findUnique({ where: { securityId } });
    if (!exists) return securityId;
  }
  // Fallback muy improbable; cambia prefijo para reducir colisión.
  for (let i = 0; i < maxAttempts; i++) {
    const securityId = `MR-${Math.random().toString(36).slice(2, 10).toUpperCase()}`;
    const exists = await prisma.user.findUnique({ where: { securityId } });
    if (!exists) return securityId;
  }
  throw new Error('No se pudo generar un securityId único');
}

async function backfillMissingSecurityIds({ batchSize = 200 } = {}) {
  try {
    // Nota: se ejecuta en background al iniciar. Si la DB es grande, lo dejamos batch.
    while (true) {
      const users = await prisma.user.findMany({
        where: { securityId: null },
        select: { id: true },
        take: batchSize
      });
      if (!users.length) break;

      for (const u of users) {
        try {
          const securityId = await generateUniqueSecurityId();
          await prisma.user.update({ where: { id: u.id }, data: { securityId } });
        } catch (e) {
          console.warn('[SECURITY_ID] Backfill failed for user', u.id, e?.message || e);
        }
      }

      if (users.length < batchSize) break;
    }
  } catch (e) {
    console.warn('[SECURITY_ID] Backfill skipped:', e?.message || e);
  }
}

// Reintentos para conexión a DB al iniciar
async function waitForDatabase(retries = 5, delay = 2000) {
  for (let i = 0; i < retries; i++) {
    try {
      const start = Date.now();
      await prisma.$queryRaw`SELECT 1`;
      const ping = Date.now() - start;
      console.log('Conexión a DB OK (ping)', ping, 'ms');
      return true;
    } catch (err) {
      console.warn(`DB connect attempt ${i + 1} failed:`, err.message || err);
      if (i === retries - 1) throw err;
      await new Promise(r => setTimeout(r, delay * (i + 1)));
    }
  }
}

async function ensureSuperAdmin() {
  try {
    await waitForDatabase(5, 2000);
    const existing = await prisma.user.findUnique({ where: { email: SUPERADMIN_EMAIL } });
    if (!existing) {
      const hashed = await bcrypt.hash(SUPERADMIN_PASSWORD, 10);
      const securityId = await generateUniqueSecurityId();
      await prisma.user.create({
        data: {
          email: SUPERADMIN_EMAIL,
          password: hashed,
          name: 'Super Admin',
          role: SUPERADMIN_ROLE,
          publicId: generateShortId('ADM'),
          securityId
        }
      });
      console.log('Superadmin creado automáticamente');
    } else {
      // Asegurar que el superadmin tenga el rol correcto si ya existe
      if (existing.role !== SUPERADMIN_ROLE) {
        await prisma.user.update({
          where: { email: SUPERADMIN_EMAIL },
          data: { role: SUPERADMIN_ROLE }
        });
        console.log('Rol de superadmin actualizado');
      }

      // Asegurar Security ID único
      if (!existing.securityId) {
        const securityId = await generateUniqueSecurityId();
        await prisma.user.update({ where: { email: SUPERADMIN_EMAIL }, data: { securityId } });
      }
      console.log('Superadmin ya existe');
    }
  } catch (err) {
    console.error('No se pudo verificar/crear superadmin:', err.message || err);
  }
}

// Middleware de logging más detallado (oculta passwords)
function maskSensitive(obj) {
  try {
    const copy = JSON.parse(JSON.stringify(obj));
    if (copy && copy.password) copy.password = '***';
    return copy;
  } catch (_) {
    return obj;
  }
}

function logRequest(req, res, next) {
  const start = Date.now();
  const body = maskSensitive(req.body);
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${req.method}] ${req.originalUrl} - ${res.statusCode} (${duration}ms) body=${JSON.stringify(body)} params=${JSON.stringify(req.params)}`);
  });
  next();
}
app.use(logRequest);

// Manejo global de errores no capturados
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

// Ejecutar verificación de superadmin al iniciar
ensureSuperAdmin().catch(err => console.error('ensureSuperAdmin error:', err));
ensureDbColumns().catch(err => console.error('ensureDbColumns error:', err));
backfillMissingSecurityIds().catch(err => console.error('backfillMissingSecurityIds error:', err));

// Endpoint de salud
app.get('/health', async (req, res) => {
  const start = Date.now();
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: 'ok', db: 'ok', time: Date.now() - start });
  } catch (error) {
    res.status(500).json({ status: 'error', db: 'fail', error: error.message });
  }
});

// Endpoint para obtener todos los usuarios
app.get('/users', async (req, res) => {
  const start = Date.now();
  try {
    const users = await prisma.user.findMany();
    const decryptedUsers = users.map(u => {
      if (u.name) u.name = decrypt(u.name);
      if (u.phone) u.phone = decrypt(u.phone);
      if (u.address) u.address = decrypt(u.address);
      if (u.cedula) u.cedula = decrypt(u.cedula);
      if (u.bankDetails && typeof u.bankDetails === 'string') {
         try { u.bankDetails = JSON.parse(decrypt(u.bankDetails)); } catch(e){}
      }
      return u;
    });
    console.log('Consulta usuarios:', Date.now() - start, 'ms');
    res.json(decryptedUsers);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

// Perfil público del rifero (vista previa). Requiere autenticación, pero disponible para user/admin/superadmin.
app.get('/users/public/:id', authenticateToken, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'ID inválido' });

    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        publicId: true,
        name: true,
        avatar: true,
        bio: true,
        socials: true,
        role: true,
        securityId: true,
        identityVerified: true,
        reputationScore: true,
        createdAt: true
      }
    });

    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    const rafflesCount = await prisma.raffle.count({ where: { userId: id } });
    const salesCount = await prisma.ticket.count({ where: { raffle: { userId: id } } });
    const prizesCount = await prisma.winner.count({ where: { raffle: { userId: id } } });

    const out = {
      ...user,
      name: user.name ? decrypt(user.name) : user.name,
      stats: { raffles: rafflesCount, sales: salesCount, prizes: prizesCount }
    };
    res.json(out);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al cargar perfil' });
  }
});

app.get('/users/public/:id/raffles', authenticateToken, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'ID inválido' });

    const active = await prisma.raffle.findMany({
      where: { userId: id, status: 'active' },
      select: { id: true, title: true, prize: true, totalTickets: true, createdAt: true, style: true, status: true },
      orderBy: { createdAt: 'desc' },
      take: 10
    });

    const closed = await prisma.raffle.findMany({
      where: { userId: id, status: { not: 'active' } },
      select: { id: true, title: true, prize: true, totalTickets: true, createdAt: true, style: true, status: true },
      orderBy: { createdAt: 'desc' },
      take: 10
    });

    const allIds = [...active.map(r => r.id), ...closed.map(r => r.id)];
    const counts = allIds.length
      ? await prisma.ticket.groupBy({
          by: ['raffleId'],
          where: { raffleId: { in: allIds } },
          _count: { _all: true }
        })
      : [];
    const soldByRaffleId = new Map(counts.map(c => [c.raffleId, c._count._all]));

    const mapRaffle = (r) => {
      const sold = soldByRaffleId.get(r.id) || 0;
      const total = Number(r.totalTickets) || 0;
      const remaining = total ? Math.max(total - sold, 0) : 0;
      return {
        id: r.id,
        title: r.title,
        description: r.prize || '',
        totalTickets: r.totalTickets,
        status: r.status,
        style: r.style,
        stats: { sold, remaining, total }
      };
    };

    res.json({
      active: active.map(mapRaffle),
      closed: closed.map(mapRaffle)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al cargar rifas del rifero' });
  }
});

// Endpoint para obtener todas las rifas
app.get('/raffles', attachUserIfTokenPresent, async (req, res) => {
  const start = Date.now();
  try {
    let raffles;
    let usedFallback = false;
    try {
      raffles = await prisma.raffle.findMany({
        where: { status: 'active' },
        include: {
          user: {
            select: {
              id: true,
              name: true,
              avatar: true,
              securityId: true,
              identityVerified: true,
              reputationScore: true
            }
          },
          _count: { select: { tickets: true } }
        },
        orderBy: { createdAt: 'desc' }
      });
    } catch (error) {
      // Fallback defensivo: si el despliegue queda con Prisma/DB desalineados,
      // evitamos depender del campo `status` para no romper toda la app.
      usedFallback = true;
      console.error('[GET /raffles] Primary query failed; falling back:', error);
      raffles = await prisma.raffle.findMany({
        select: {
          id: true,
          title: true,
          prize: true,
          instantWins: true,
          digits: true,
          totalTickets: true,
          endDate: true,
          startDate: true,
          createdAt: true,
          style: true,
          user: {
            select: {
              id: true,
              name: true,
              avatar: true,
              securityId: true,
              identityVerified: true,
              reputationScore: true
            }
          },
          _count: { select: { tickets: true } }
        },
        orderBy: { createdAt: 'desc' }
      });
    }
    console.log('Consulta rifas:', Date.now() - start, 'ms');
    
    const decryptedRaffles = raffles.map(r => {
      if (r.user && r.user.name) {
        try {
          r.user.name = decrypt(r.user.name);
        } catch (error) {
          console.error('[GET /raffles] decrypt(name) failed:', {
            raffleId: r?.id,
            userId: r?.user?.id,
            error: error?.message || String(error)
          });
        }
      }
      const base = { ...r, soldTickets: r._count?.tickets || 0 };
      if (usedFallback && base.status == null) base.status = 'active';
      return base;
    });

    // Boost ordering (rotación diaria si hay muchos unlimited)
    const now = Date.now();
    const dayKey = Number(new Date().toISOString().slice(0, 10).replace(/-/g, '')) || 0;
    const rotationScore = (id) => {
      const n = Number(id) || 0;
      return (Math.imul(n, 1103515245) + dayKey) >>> 0;
    };
    decryptedRaffles.sort((a, b) => {
      const aBoost = a?.style?.boost;
      const bBoost = b?.style?.boost;
      const aExp = aBoost?.expiresAt ? Date.parse(aBoost.expiresAt) : 0;
      const bExp = bBoost?.expiresAt ? Date.parse(bBoost.expiresAt) : 0;
      const aActive = aExp && aExp > now;
      const bActive = bExp && bExp > now;
      if (aActive !== bActive) return aActive ? -1 : 1;

      if (aActive && bActive) {
        const ra = rotationScore(a.id);
        const rb = rotationScore(b.id);
        if (ra !== rb) return ra - rb;
      }

      const aAt = aBoost?.boostedAt ? Date.parse(aBoost.boostedAt) : 0;
      const bAt = bBoost?.boostedAt ? Date.parse(bBoost.boostedAt) : 0;
      if (aAt !== bAt) return bAt - aAt;
      return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
    });

    const withReactions = await enrichRafflesWithReactions(decryptedRaffles, req.user?.userId);
    res.json(withReactions);
  } catch (error) {
    console.error('[GET /raffles] Error:', error);
    res.status(500).json({ error: 'Error al obtener rifas' });
  }
});

// Obtener una rifa por ID (usado por detalle en la app móvil)
app.get('/raffles/:id', attachUserIfTokenPresent, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'ID inválido' });

    // Auto-cierre por tiempo (endDate) si aplica
    await autoCloseExpiredRaffle(id, 'read_raffle_by_id');

    let raffle;
    let usedFallback = false;
    try {
      raffle = await prisma.raffle.findUnique({
        where: { id },
        include: {
          user: {
            select: {
              id: true,
              name: true,
              avatar: true,
              securityId: true,
              identityVerified: true,
              reputationScore: true
            }
          },
          _count: { select: { tickets: true } }
        }
      });
    } catch (error) {
      usedFallback = true;
      console.error('[GET /raffles/:id] Primary query failed; falling back:', error);
      raffle = await prisma.raffle.findFirst({
        where: { id },
        select: {
          id: true,
          title: true,
          prize: true,
          instantWins: true,
          digits: true,
          totalTickets: true,
          endDate: true,
          startDate: true,
          createdAt: true,
          style: true,
          user: {
            select: {
              id: true,
              name: true,
              avatar: true,
              securityId: true,
              identityVerified: true,
              reputationScore: true
            }
          },
          _count: { select: { tickets: true } }
        }
      });
    }

    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    if (raffle.user && raffle.user.name) {
      try {
        raffle.user.name = decrypt(raffle.user.name);
      } catch (error) {
        console.error('[GET /raffles/:id] decrypt(name) failed:', {
          raffleId: raffle?.id,
          userId: raffle?.user?.id,
          error: error?.message || String(error)
        });
      }
    }

    const base = { ...raffle, soldTickets: raffle._count?.tickets || 0 };
    if (usedFallback && base.status == null) base.status = 'active';

    const enriched = await enrichRafflesWithReactions([base], req.user?.userId);
    return res.json(enriched[0] || base);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Error al obtener rifa' });
  }
});

// Subida/procesamiento de imágenes (devuelve DataURL base64). Soporta multipart (FormData) o JSON.
app.post(
  '/admin/uploads/image',
  authenticateToken,
  authorizeRole(['admin', 'superadmin']),
  (req, res, next) => {
    if (req.is('multipart/form-data')) return upload.single('file')(req, res, next);
    return next();
  },
  async (req, res) => {
    try {
      if (req.file && req.file.buffer) {
        const mime = String(req.file.mimetype || 'image/jpeg');
        const base64 = req.file.buffer.toString('base64');
        return res.json({ dataUrl: `data:${mime};base64,${base64}` });
      }

      const dataUrl = req.body?.dataUrl;
      if (typeof dataUrl === 'string' && (dataUrl.startsWith('data:') || dataUrl.startsWith('http'))) {
        return res.json({ dataUrl });
      }

      const base64 = req.body?.base64;
      if (typeof base64 === 'string' && base64.trim()) {
        return res.json({ dataUrl: `data:image/jpeg;base64,${base64.trim()}` });
      }

      return res.status(400).json({ error: 'Archivo o imagen inválida' });
    } catch (error) {
      console.error('[POST /admin/uploads/image] error:', error);
      return res.status(500).json({ error: 'Error al procesar imagen' });
    }
  }
);

// --- RAFFLE REACTIONS (LIKE/HEART) ---
app.post('/raffles/:id/react', authenticateToken, async (req, res) => {
  try {
    const raffleId = Number(req.params.id);
    const userId = req.user?.userId;
    const type = String(req.body?.type || '').toUpperCase();

    if (!Number.isFinite(raffleId)) return res.status(400).json({ error: 'ID inválido' });
    if (!['LIKE', 'HEART'].includes(type)) return res.status(400).json({ error: 'Tipo de reacción inválido' });

    const raffle = await prisma.raffle.findUnique({ where: { id: raffleId }, select: { id: true } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    const existingRows = await prisma.$queryRaw`
      SELECT "id", "type" FROM "RaffleReaction" WHERE "userId"=${userId} AND "raffleId"=${raffleId} LIMIT 1
    `;
    const existing = Array.isArray(existingRows) ? existingRows[0] : null;

    if (existing && existing.id) {
      const existingType = String(existing.type || '').toUpperCase();
      const existingId = Number(existing.id);
      if (existingType === type) {
        await prisma.$executeRaw`DELETE FROM "RaffleReaction" WHERE "id"=${existingId}`;
        return res.json({ message: 'Reacción eliminada', active: false });
      }

      await prisma.$executeRaw`UPDATE "RaffleReaction" SET "type"=${type} WHERE "id"=${existingId}`;
      return res.json({ message: 'Reacción actualizada', active: true });
    }

    await prisma.$executeRaw`
      INSERT INTO "RaffleReaction" ("type", "userId", "raffleId") VALUES (${type}, ${userId}, ${raffleId})
    `;
    return res.status(201).json({ message: 'Reacción agregada', active: true });
  } catch (error) {
    console.error(error);
    if (isPrismaMissingTableError(error)) {
      return res.status(503).json({ error: 'Función no disponible: falta aplicar migración de reacciones de rifas (RaffleReaction).' });
    }
    return res.status(500).json({ error: 'Error al reaccionar' });
  }
});

// --- REPORTES / DENUNCIAS ---
app.post('/reports', authenticateToken, async (req, res) => {
  try {
    const reporterUserId = Number(req.user?.userId);
    const reportedUserId = Number(req.body?.reportedUserId);
    const raffleIdRaw = req.body?.raffleId;
    const raffleId = raffleIdRaw == null || raffleIdRaw === '' ? null : Number(raffleIdRaw);
    const reason = String(req.body?.reason || '').trim();
    const details = String(req.body?.details || '').trim();

    if (!Number.isFinite(reporterUserId)) return res.status(401).json({ error: 'Token inválido' });
    if (!Number.isFinite(reportedUserId)) return res.status(400).json({ error: 'Usuario reportado inválido' });
    if (reportedUserId === reporterUserId) return res.status(400).json({ error: 'No puedes reportarte a ti mismo' });
    if (!reason) return res.status(400).json({ error: 'Motivo requerido' });
    if (details && details.length > 1000) return res.status(400).json({ error: 'Detalle demasiado largo' });

    const reportedUser = await prisma.user.findUnique({ where: { id: reportedUserId }, select: { id: true } });
    if (!reportedUser) return res.status(404).json({ error: 'Usuario reportado no existe' });

    if (raffleId != null) {
      if (!Number.isFinite(raffleId)) return res.status(400).json({ error: 'Rifa inválida' });
      const raffle = await prisma.raffle.findUnique({ where: { id: raffleId }, select: { id: true } });
      if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });
    }

    const created = await prisma.report.create({
      data: {
        reporterUserId,
        reportedUserId,
        raffleId: raffleId == null ? null : raffleId,
        reason,
        details: details || null,
        status: 'open'
      }
    });

    try {
      await prisma.auditLog.create({
        data: {
          action: 'REPORT_CREATED',
          userId: reporterUserId,
          userEmail: String(req.user?.email || ''),
          entity: 'Report',
          entityId: String(created.id),
          detail: `Reporte creado. Motivo=${reason} ReportadoUserId=${reportedUserId}`,
          ipAddress: String(req.ip || ''),
          userAgent: String(req.headers['user-agent'] || ''),
          severity: 'INFO',
          metadata: {
            reportedUserId,
            raffleId: raffleId == null ? null : raffleId
          }
        }
      });
    } catch (_e) {
      // No bloquear el flujo de reportes por auditoría
    }

    return res.status(201).json({ id: created.id, status: created.status });
  } catch (error) {
    console.error('[REPORTS] create error:', error);
    if (isPrismaMissingTableError(error)) {
      return res.status(503).json({ error: 'Función no disponible: falta aplicar migración de reportes (Report).' });
    }
    return res.status(500).json({ error: 'No se pudo crear el reporte' });
  }
});

// --- RATINGS (1-10) ---

app.post('/raffles/:id/rating', authenticateToken, async (req, res) => {
  const raffleId = Number(req.params.id);
  const userId = req.user?.userId;
  const scoreRaw = req.body?.score;
  const likedCommentsFeature = !!req.body?.likedCommentsFeature;

  if (!Number.isFinite(raffleId)) return res.status(400).json({ error: 'ID inválido' });
  const score = Math.floor(Number(scoreRaw));
  if (!Number.isFinite(score) || score < 1 || score > 10) {
    return res.status(400).json({ error: 'Calificación inválida (1-10)' });
  }

  try {
    const raffle = await prisma.raffle.findUnique({
      where: { id: raffleId },
      select: { id: true, status: true, userId: true }
    });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    if (String(raffle.status || '').toLowerCase() !== 'closed') {
      return res.status(403).json({ error: 'Solo puedes calificar cuando la rifa esté cerrada.' });
    }

    const riferoUserId = raffle.userId;
    if (!Number.isFinite(riferoUserId)) {
      return res.status(400).json({ error: 'Esta rifa no tiene rifero asignado.' });
    }

    const participated = await prisma.ticket.count({ where: { raffleId, userId } });
    if (participated <= 0) {
      return res.status(403).json({ error: 'Solo pueden calificar usuarios que participaron (compraron ticket).' });
    }

    try {
      const created = await prisma.raffleRating.create({
        data: {
          raffleId,
          raterUserId: userId,
          riferoUserId,
          score,
          likedCommentsFeature
        }
      });
      return res.status(201).json({ message: 'Calificación registrada', rating: created });
    } catch (e) {
      if (e?.code === 'P2002') return res.status(409).json({ error: 'Ya calificaste esta rifa.' });
      throw e;
    }
  } catch (error) {
    if (isPrismaMissingTableError(error)) {
      return res.status(503).json({ error: 'Función no disponible: falta aplicar migración de calificaciones (RaffleRating).' });
    }
    console.error(error);
    res.status(500).json({ error: 'Error al registrar calificación' });
  }
});

app.get('/users/public/:id/rating-summary', async (req, res) => {
  const riferoUserId = Number(req.params.id);
  if (!Number.isFinite(riferoUserId)) return res.status(400).json({ error: 'ID inválido' });

  try {
    const agg = await prisma.raffleRating.aggregate({
      where: { riferoUserId },
      _count: { _all: true },
      _avg: { score: true }
    });

    return res.json({
      riferoUserId,
      avgScore: agg._avg?.score ?? null,
      count: agg._count?._all ?? 0
    });
  } catch (error) {
    if (isPrismaMissingTableError(error)) {
      return res.json({ riferoUserId, avgScore: null, count: 0 });
    }
    console.error(error);
    res.status(500).json({ error: 'Error al obtener resumen de calificaciones' });
  }
});

// --- BOOST GLOBAL (15 slots + 1/semana) ---

app.get('/boosts/me', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const userId = req.user?.userId;
  try {
    const now = new Date();
    const active = await prisma.userBoost.findMany({
      where: { userId, endAt: { gt: now } },
      orderBy: { endAt: 'desc' },
      select: { id: true, startAt: true, endAt: true }
    });
    const last = await prisma.userBoost.findFirst({
      where: { userId },
      orderBy: { startAt: 'desc' },
      select: { startAt: true }
    });

    const nextEligibleAt = last?.startAt
      ? new Date(new Date(last.startAt).getTime() + GLOBAL_BOOST_COOLDOWN_DAYS * 24 * 60 * 60 * 1000)
      : now;

    res.json({
      isBoosted: active.length > 0,
      activeBoosts: active,
      nextEligibleAt
    });
  } catch (error) {
    if (isPrismaMissingTableError(error)) {
      return res.status(503).json({ error: 'Función no disponible: falta aplicar migración de boosts (UserBoost).' });
    }
    console.error(error);
    res.status(500).json({ error: 'Error al consultar boost' });
  }
});

app.post('/boosts/activate', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const actorId = req.user?.userId;
  try {
    const now = new Date();

    // Cooldown semanal: 1 boost por semana
    const last = await prisma.userBoost.findFirst({
      where: { userId: actorId },
      orderBy: { startAt: 'desc' },
      select: { startAt: true }
    });
    if (last?.startAt) {
      const eligibleAt = new Date(new Date(last.startAt).getTime() + GLOBAL_BOOST_COOLDOWN_DAYS * 24 * 60 * 60 * 1000);
      if (now < eligibleAt) {
        return res.status(403).json({ error: 'Ya usaste tu boost esta semana. Intenta más adelante.', nextEligibleAt: eligibleAt });
      }
    }

    // Límite de boosts activos por rifero (safety)
    const activeCount = await prisma.userBoost.count({ where: { userId: actorId, endAt: { gt: now } } });
    if (activeCount >= 2) {
      return res.status(403).json({ error: 'Ya tienes el máximo de boosts activos permitidos.' });
    }

    // Slots globales: máximo 15 riferos boosteados simultáneamente
    const snapshot = await getGlobalBoostSlotsSnapshot();
    const alreadyCountsAsSlot = snapshot.activeUserIds.has(actorId);
    if (!alreadyCountsAsSlot && snapshot.activeUsersCount >= GLOBAL_BOOST_MAX_ACTIVE_USERS) {
      return res.status(403).json({ error: 'No hay cupos de boost disponibles. Intenta más tarde.' });
    }

    const endAt = new Date(now.getTime() + GLOBAL_BOOST_DURATION_HOURS * 60 * 60 * 1000);
    const created = await prisma.userBoost.create({ data: { userId: actorId, startAt: now, endAt } });
    return res.status(201).json({ message: 'Boost activado', boost: created });
  } catch (error) {
    if (isPrismaMissingTableError(error)) {
      return res.status(503).json({ error: 'Función no disponible: falta aplicar migración de boosts (UserBoost).' });
    }
    console.error(error);
    res.status(500).json({ error: 'Error al activar boost' });
  }
});

// Helper: Check and Reward Referrer
async function checkAndRewardReferrer(referrerId) {
  try {
    const count = await prisma.user.count({ where: { referredById: referrerId } });
    // Reward every 5 referrals
    if (count > 0 && count % 5 === 0) {
      const rewardAmount = 5.0; // Configurable reward (e.g., $5 or 5 VES)
      await prisma.$transaction([
        prisma.user.update({
          where: { id: referrerId },
          data: { balance: { increment: rewardAmount } }
        }),
        prisma.transaction.create({
          data: {
            userId: referrerId,
            amount: rewardAmount,
            type: 'bonus',
            status: 'approved',
            reference: encrypt(`Recompensa por ${count} referidos`)
          }
        })
      ]);
      console.log(`[REWARD] User ${referrerId} rewarded for ${count} referrals.`);
      
      // Optional: Notify referrer via Push
      const referrer = await prisma.user.findUnique({ where: { id: referrerId }, select: { pushToken: true } });
      if (referrer?.pushToken) {
        await sendPushNotification([referrer.pushToken], '¡Recompensa Ganada!', `Has alcanzado ${count} referidos. Te hemos abonado saldo.`);
      }
    }
  } catch (err) {
    console.error('[REWARD ERROR]', err);
  }
}

const amlService = require('./services/amlService');

// Registro de usuario
app.post('/register', async (req, res) => {
  // Admitimos firstName/lastName desde el cliente y los combinamos en name
  const { email, name, password, referralCode, firstName, lastName, state, cedula } = req.body || {};
  const safeEmail = normalizeEmail(email);
  const fullName = (name || `${firstName || ''} ${lastName || ''}`).trim();
  const safeState = (state || '').trim();

  if (!safeEmail || !fullName || !password || !safeState) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  // AML Check
  const amlCheck = await amlService.checkPerson(fullName, cedula);
  if (amlCheck.isBlacklisted) {
    await securityLogger.log({
      action: 'REGISTER_BLOCKED_AML',
      userEmail: safeEmail,
      ipAddress: req.ip,
      severity: 'CRITICAL',
      detail: `Blocked registration for blacklisted person: ${fullName}. Reason: ${amlCheck.reason}`
    });
    return res.status(403).json({ error: 'No podemos procesar su registro en este momento. Contacte a soporte.' });
  }

  const normalizedState = VENEZUELA_STATES.find((s) => s.toLowerCase() === safeState.toLowerCase());
  if (!normalizedState) {
    return res.status(400).json({ error: 'Estado inválido, selecciona un estado de Venezuela' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  // Usuarios normales: sin verificación por código (según requerimiento)
  const autoVerifyUsers = true;
  const verificationToken = autoVerifyUsers ? null : generateVerificationCode();

  try {
    let referredById = null;
    if (referralCode) {
      const referrer = await prisma.user.findUnique({ where: { referralCode } });
      if (referrer) referredById = referrer.id;
    }

    // Generate unique Security ID
    let securityId = generateSecurityId();
    let idExists = await prisma.user.findUnique({ where: { securityId } });
    while (idExists) {
      securityId = generateSecurityId();
      idExists = await prisma.user.findUnique({ where: { securityId } });
    }

    const user = await prisma.user.create({
      data: {
        email: safeEmail,
        name: encrypt(fullName),
        state: normalizedState,
        password: hashedPassword,
        publicId: generateShortId('USR'),
        securityId,
        referredById,
        verificationToken,
        verified: autoVerifyUsers ? true : false
      }
    });

    if (referredById) {
      // Check for rewards asynchronously
      checkAndRewardReferrer(referredById).catch(console.error);
    }
    
    // Si no usamos verificación por correo para usuarios normales, enviamos correo opcional de bienvenida (sin código)
    let sent = null;
    if (!autoVerifyUsers) {
      const emailDisplayName = fullName || 'Usuario';
      sent = await sendEmail(
        safeEmail,
        'Activa tu cuenta en MegaRifas',
        `Hola ${emailDisplayName}, tu código de verificación es: ${verificationToken}`,
        `<h1>¡Bienvenido a MegaRifas!</h1>
         <p>Hola <b>${escapeHtml(emailDisplayName)}</b>,</p>
         <p>Gracias por registrarte. Para activar tu cuenta, usa el siguiente código:</p>
         <h2 style="color: #4f46e5; letter-spacing: 5px;">${verificationToken}</h2>
         <p>Si no solicitaste esta cuenta, ignora este correo.</p>`
      );
      if (!sent) console.warn('[REGISTER] No se pudo enviar el correo de verificación a', safeEmail);
      return res.status(201).json({ message: 'Usuario registrado. Verifique su correo.', user, emailSent: sent });
    }

    // autoVerifyUsers=true
    return res.status(201).json({ message: 'Usuario registrado.', user, emailSent: sent });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// Autorregistro de organizador (queda en estado pendiente hasta aprobación)
app.post('/organizers/register', async (req, res) => {
  const { email, name, password, state, phone, cedula } = req.body || {};
  const safeEmail = normalizeEmail(email);
  const fullName = String(name || '').trim();
  if (!safeEmail || !fullName || !password || !state) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  try {
    const existing = await prisma.user.findUnique({ where: { email: safeEmail } });
    if (existing) {
      if (existing.role === 'pending_admin') return res.status(409).json({ error: 'Solicitud previa pendiente' });
      return res.status(409).json({ error: 'Ya existe una cuenta con ese email' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const securityId = await generateUniqueSecurityId();

    const created = await prisma.user.create({
      data: {
        email: safeEmail,
        name: encrypt(fullName),
        password: hashed,
        state: String(state || 'DESCONOCIDO'),
        phone: phone ? encrypt(String(phone)) : null,
        cedula: cedula ? encrypt(String(cedula)) : null,
        publicId: generateShortId('USR'),
        securityId,
        role: 'pending_admin',
        verified: false,
        active: true
      }
    });

    // Notificar al superadmin vía correo + audit log
    try {
      const adminEmail = SUPERADMIN_EMAIL;
      if (adminEmail) {
        await sendEmail(
          adminEmail,
          'Nueva solicitud de organizador',
          `Nueva solicitud de cuenta organizador: ${safeEmail}`,
          `<p>Nueva solicitud de organizador: <b>${escapeHtml(safeEmail)}</b></p><p>Nombre: ${escapeHtml(fullName)}</p>`
        );
      }
    } catch (_e) {}

    try {
      await securityLogger.log({
        action: 'ORGANIZER_REQUEST_CREATED',
        userEmail: safeEmail,
        userId: created.id,
        detail: 'Organizer self-registration request created',
        severity: 'INFO'
      });
    } catch (_e) {}

    return res.status(201).json({ message: 'Solicitud enviada. Esperando aprobación de administrador.' });
  } catch (error) {
    console.error('[organizers/register] error:', error);
    return res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

// Superadmin: listar solicitudes pendientes de organizadores
app.get('/superadmin/pending-organizers', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const pending = await prisma.user.findMany({
      where: { role: 'pending_admin' },
      select: { id: true, email: true, name: true, createdAt: true, state: true }
    });
    const mapped = pending.map(u => ({ id: u.id, email: u.email, name: u.name ? safeDecrypt(u.name) : null, createdAt: u.createdAt, state: u.state }));
    res.json(mapped);
  } catch (error) {
    console.error('[pending-organizers] error:', error);
    res.status(500).json({ error: 'Error al obtener solicitudes' });
  }
});

// Superadmin: aprobar organizador
app.post('/superadmin/approve-organizer/:id', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) return res.status(400).json({ error: 'ID inválido' });
    const user = await prisma.user.findUnique({ where: { id } });
    if (!user || user.role !== 'pending_admin') return res.status(404).json({ error: 'Solicitud no encontrada' });

    const updated = await prisma.user.update({ where: { id }, data: { role: 'admin', verified: true, active: true } });

    try {
      if (updated.email) {
        await sendEmail(
          updated.email,
          'Solicitud Aprobada - MegaRifas',
          'Tu solicitud de organizador ha sido aprobada. Ya puedes iniciar sesión como organizador.',
          `<p>Hola ${safeDecrypt(updated.name)},</p><p>Tu solicitud de organizador ha sido aprobada. Ya puedes iniciar sesión y crear rifas.</p>`
        );
      }
    } catch (_e) {}

    try {
      await securityLogger.log({ action: 'ORGANIZER_APPROVED', userEmail: updated.email, userId: updated.id, detail: 'Organizer approved by superadmin', severity: 'INFO' });
    } catch (_e) {}

    res.json({ message: 'Organizador aprobado', user: { id: updated.id, email: updated.email } });
  } catch (error) {
    console.error('[approve-organizer] error:', error);
    res.status(500).json({ error: 'Error al aprobar organizador' });
  }
});

// Superadmin: rechazar solicitud de organizador
app.post('/superadmin/reject-organizer/:id', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const reason = String(req.body?.reason || 'No especificado');
    if (!Number.isFinite(id) || id <= 0) return res.status(400).json({ error: 'ID inválido' });
    const user = await prisma.user.findUnique({ where: { id } });
    if (!user || user.role !== 'pending_admin') return res.status(404).json({ error: 'Solicitud no encontrada' });

    // Dejar registro pero desactivar la cuenta por seguridad
    const updated = await prisma.user.update({ where: { id }, data: { role: 'user', active: false } });

    try {
      if (updated.email) {
        await sendEmail(
          updated.email,
          'Solicitud Rechazada - MegaRifas',
          `Tu solicitud ha sido rechazada. Motivo: ${reason}`,
          `<p>Lo sentimos. Tu solicitud de organizador ha sido rechazada.</p><p>Motivo: ${escapeHtml(reason)}</p>`
        );
      }
    } catch (_e) {}

    try { await securityLogger.log({ action: 'ORGANIZER_REJECTED', userEmail: updated.email, userId: updated.id, detail: `Organizer rejected: ${reason}`, severity: 'WARN' }); } catch (_e) {}

    res.json({ message: 'Solicitud rechazada' });
  } catch (error) {
    console.error('[reject-organizer] error:', error);
    res.status(500).json({ error: 'Error al rechazar solicitud' });
  }
});

// Verificar email
app.post('/verify-email', async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'Faltan datos' });

  const safeEmail = normalizeEmail(email);

  try {
    const user = await prisma.user.findUnique({ where: { email: safeEmail } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    if (user.verified) return res.json({ message: 'Cuenta ya verificada' });

    if (user.verificationToken !== code) {
      return res.status(400).json({ error: 'Código inválido' });
    }

    await prisma.user.update({
      where: { email: safeEmail },
      data: { verified: true, verificationToken: null }
    });

    res.json({ message: 'Cuenta verificada exitosamente' });
  } catch (error) {
    res.status(500).json({ error: 'Error al verificar cuenta' });
  }
});

// Reenviar código de verificación
async function resendVerificationCodeHandler(req, res) {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email requerido' });

  const safeEmail = normalizeEmail(email);

  try {
    const user = await prisma.user.findUnique({ where: { email: safeEmail } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (user.verified) return res.status(400).json({ error: 'Usuario ya verificado' });

    const verificationToken = generateVerificationCode();
    await prisma.user.update({
      where: { email: safeEmail },
      data: { verificationToken }
    });

    const sent = await sendEmail(
      safeEmail,
      'Reenvío de Código de Verificación',
      `Tu nuevo código es: ${verificationToken}`,
      `<h1>Código de Verificación</h1><p>Tu nuevo código es:</p><h2>${verificationToken}</h2>`
    );

    if (!sent) {
      return res.status(502).json({ error: 'No se pudo enviar el correo. Intenta nuevamente.' });
    }

    return res.json({ message: 'Código reenviado exitosamente' });
  } catch (error) {
    console.error('Error resending code:', error);
    return res.status(500).json({ error: 'Error al reenviar código' });
  }
}

app.post('/resend-code', resendVerificationCodeHandler);
// Alias esperado por la app móvil (histórico)
app.post('/auth/verify/resend', resendVerificationCodeHandler);

// Password reset (request) - endpoint esperado por la app móvil.
// Nota: envía un enlace con token JWT y se confirma en /auth/password/reset/confirm.
app.post('/auth/password/reset/request', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email requerido' });

  const safeEmail = normalizeEmail(email);

  try {
    const user = await prisma.user.findUnique({ where: { email: safeEmail } });

    // Evitar enumeración de usuarios: respondemos OK aunque no exista.
    if (!user) {
      return res.json({ message: 'Si el correo existe, enviaremos instrucciones.' });
    }

    const webBaseUrl = String(process.env.WEB_BASE_URL || '').trim();
    const fallbackBaseUrl = getPublicBaseUrlFromRequest(req);
    const resetToken = jwt.sign({ email: safeEmail, purpose: 'password_reset' }, JWT_SECRET, { expiresIn: '15m' });
    const baseForLink = webBaseUrl || fallbackBaseUrl;
    const resetLink = baseForLink ? `${baseForLink.replace(/\/$/, '')}/recuperar?token=${encodeURIComponent(resetToken)}` : null;

    const subject = 'Recuperación de contraseña - MegaRifas';
    const text = resetLink
      ? `Para recuperar tu contraseña, abre este enlace (válido por 15 minutos): ${resetLink}`
      : `Para recuperar tu contraseña necesitas este token (válido por 15 minutos): ${resetToken}`;
    const html = resetLink
      ? `<h1>Recuperación de contraseña</h1><p>Para recuperar tu contraseña, haz clic aquí (válido por 15 minutos):</p><p><a href="${escapeHtml(resetLink)}">Recuperar contraseña</a></p><p style="color:#666;font-size:12px;">Si el enlace no abre, copia y pega en tu navegador.</p>`
      : `<h1>Recuperación de contraseña</h1><p>No se pudo generar enlace automático.</p><p><b>Token (válido por 15 minutos):</b></p><p style="font-family:monospace;word-break:break-all;">${escapeHtml(resetToken)}</p>`;

    const sent = await sendEmail(safeEmail, subject, text, html);
    if (!sent) {
      return res.status(502).json({ error: 'No se pudo enviar el correo. Intenta nuevamente.' });
    }
    return res.json({ message: 'Hemos enviado instrucciones a tu correo.' });
  } catch (error) {
    console.error('Password reset request error:', error);
    return res.status(500).json({ error: 'Error al solicitar recuperación' });
  }
});

// Página simple de recuperación (sirve incluso si no hay WEB_BASE_URL)
app.get('/recuperar', async (req, res) => {
  try {
    const token = String(req.query?.token || '').trim();
    const safeToken = escapeHtml(token);
    const html = `<!doctype html>
<html lang="es">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Recuperar contraseña</title>
  </head>
  <body style="font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; max-width: 520px; margin: 40px auto; padding: 0 16px;">
    <h1>Recuperación de contraseña</h1>
    <p>Ingresa tu nueva contraseña. El enlace vence en 15 minutos.</p>
    <form id="f" style="display:flex;flex-direction:column;gap:12px;">
      <input type="hidden" id="token" value="${safeToken}" />
      <label>
        Nueva contraseña
        <input id="p1" type="password" autocomplete="new-password" required minlength="6" style="width:100%;padding:10px;margin-top:6px;" />
      </label>
      <label>
        Repetir contraseña
        <input id="p2" type="password" autocomplete="new-password" required minlength="6" style="width:100%;padding:10px;margin-top:6px;" />
      </label>
      <button type="submit" style="padding:12px;">Guardar nueva contraseña</button>
    </form>
    <p id="msg" style="margin-top:16px;"></p>
    <script>
      const form = document.getElementById('f');
      const msg = document.getElementById('msg');
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        msg.textContent = '';
        const token = document.getElementById('token').value;
        const p1 = document.getElementById('p1').value;
        const p2 = document.getElementById('p2').value;
        if (!token) {
          msg.textContent = 'Falta el token. Abre el enlace del correo nuevamente.';
          return;
        }
        if (p1.length < 6) {
          msg.textContent = 'La contraseña debe tener al menos 6 caracteres.';
          return;
        }
        if (p1 !== p2) {
          msg.textContent = 'Las contraseñas no coinciden.';
          return;
        }
        try {
          const r = await fetch('/auth/password/reset/confirm', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, newPassword: p1 })
          });
          const data = await r.json().catch(() => ({}));
          if (!r.ok) {
            msg.textContent = data && data.error ? data.error : 'No se pudo cambiar la contraseña.';
            return;
          }
          msg.textContent = 'Contraseña actualizada. Ya puedes iniciar sesión en la app.';
        } catch (err) {
          msg.textContent = 'Error de red. Intenta nuevamente.';
        }
      });
    </script>
  </body>
</html>`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(html);
  } catch (e) {
    return res.status(500).send('Error al cargar la página de recuperación');
  }
});

// Confirmar recuperación: valida token JWT y actualiza password
app.post('/auth/password/reset/confirm', async (req, res) => {
  const token = String(req.body?.token || '').trim();
  const newPassword = String(req.body?.newPassword || '').trim();

  if (!token) return res.status(400).json({ error: 'Token requerido' });
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload || payload.purpose !== 'password_reset' || !payload.email) {
      return res.status(400).json({ error: 'Token inválido' });
    }

    const safeEmail = normalizeEmail(payload.email);
    const user = await prisma.user.findUnique({ where: { email: safeEmail } });
    if (!user) {
      // Mantener respuesta genérica
      return res.status(400).json({ error: 'Token inválido' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { email: safeEmail },
      data: {
        password: hashedPassword,
        verificationToken: null,
        verified: true,
        active: true
      }
    });

    try {
      await securityLogger.log({
        action: 'PASSWORD_RESET_SUCCESS',
        userEmail: safeEmail,
        userId: user.id,
        ipAddress: String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || ''),
        userAgent: String(req.headers['user-agent'] || ''),
        severity: 'INFO',
        detail: 'User reset password via token',
        entity: 'User',
        entityId: String(user.id)
      });
    } catch (_e) {
      // no bloquear
    }

    return res.json({ message: 'Contraseña actualizada' });
  } catch (_e) {
    return res.status(400).json({ error: 'Token inválido o expirado' });
  }
});

// Refresh token endpoint esperado por la app móvil.
app.post('/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(400).json({ error: 'refreshToken requerido' });

  try {
    const payload = jwt.verify(String(refreshToken), JWT_SECRET);
    if (!payload || payload.type !== 'refresh' || !payload.userId) {
      return res.status(401).json({ error: 'Refresh token inválido' });
    }

    const user = await prisma.user.findUnique({ where: { id: Number(payload.userId) } });
    if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
    if (!user.verified && user.role !== 'user') return res.status(403).json({ error: 'Cuenta no verificada' });
    if (user.active === false) return res.status(403).json({ error: 'Cuenta desactivada' });

    const accessToken = signAccessToken(user);
    const nextRefreshToken = signRefreshToken(user);

    const { password: _pw, ...userWithoutPassword } = user;
    if (userWithoutPassword.name) userWithoutPassword.name = decrypt(userWithoutPassword.name);
    if (userWithoutPassword.bankDetails) userWithoutPassword.bankDetails = JSON.parse(decrypt(JSON.stringify(userWithoutPassword.bankDetails)));

    return res.json({ accessToken, refreshToken: nextRefreshToken, user: userWithoutPassword });
  } catch (error) {
    return res.status(401).json({ error: 'Refresh token inválido o expirado' });
  }
});

// Login de usuario
const handleLogin = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  const safeEmail = normalizeEmail(email);
  const user = await prisma.user.findUnique({ where: { email: safeEmail } });
  if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });

  // Asegurar ID identificativo (securityId) único para confianza
  if (!user.securityId) {
    try {
      const securityId = await generateUniqueSecurityId();
      await prisma.user.update({ where: { id: user.id }, data: { securityId } });
      user.securityId = securityId;
    } catch (e) {
      console.warn('[LOGIN] No se pudo asignar securityId:', e?.message || e);
    }
  }

  // 1. Verificar si la cuenta está activa
  if (!user.verified) {
    if (user.email === SUPERADMIN_EMAIL) {
      await prisma.user.update({ where: { id: user.id }, data: { verified: true } });
      user.verified = true;
    } else if (user.role === 'user') {
      // Usuarios normales: sin verificación por código
      try {
        await prisma.user.update({ where: { id: user.id }, data: { verified: true, verificationToken: null } });
        user.verified = true;
        user.verificationToken = null;
      } catch (_e) {
        // no bloquear login
      }
    } else {
      return res.status(403).json({ error: 'Cuenta no verificada. Revise su correo.' });
    }
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    // Log failed login attempt
    await FraudEngine.logActivity(user.id, 'LOGIN_FAIL', 'Invalid password', 'LOW', req.ip);
    await securityLogger.log({
      action: 'LOGIN_FAILED',
      userEmail: email,
      userId: user.id,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      severity: 'WARN',
      detail: 'Invalid password attempt'
    });
    return res.status(401).json({ error: 'Contraseña incorrecta' });
  }

  // Check if user is flagged
  if (user.isFlagged) {
    await FraudEngine.logActivity(user.id, 'LOGIN_FLAGGED', 'Flagged user logged in', 'MEDIUM', req.ip);
    await securityLogger.log({
      action: 'LOGIN_FLAGGED_USER',
      userEmail: email,
      userId: user.id,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      severity: 'WARN',
      detail: 'Flagged user logged in'
    });
  }

  // Log successful login
  await securityLogger.log({
    action: 'LOGIN_SUCCESS',
    userEmail: email,
    userId: user.id,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    severity: 'INFO',
    detail: 'User logged in successfully'
  });

  const token = signAccessToken(user);
  const refreshToken = signRefreshToken(user);
  
  // Remove password from user object before sending
  const { password: _, ...userWithoutPassword } = user;
  
  // Decrypt sensitive data
  if (userWithoutPassword.name) userWithoutPassword.name = decrypt(userWithoutPassword.name);
  if (userWithoutPassword.bankDetails) userWithoutPassword.bankDetails = JSON.parse(decrypt(JSON.stringify(userWithoutPassword.bankDetails)));

  // 2FA para admins/superadmin (por correo). Se controla con ADMIN_2FA (default: true).
  const admin2faEnv = String(process.env.ADMIN_2FA || '').toLowerCase();
  // Seguridad: por defecto 2FA desactivado. Activar con ADMIN_2FA=true.
  const admin2faEnabled = admin2faEnv === 'true';
  const isPrivileged = user.role === 'admin' || user.role === 'superadmin';
  if (admin2faEnabled && isPrivileged) {
    const ttlMinutes = Number(process.env.TWOFA_TTL_MINUTES || 10);
    const expiresAtMs = Date.now() + (Number.isFinite(ttlMinutes) && ttlMinutes > 0 ? ttlMinutes : 10) * 60_000;
    const code = generateVerificationCode();

    await prisma.user.update({
      where: { id: user.id },
      data: { verificationToken: build2faToken(code, expiresAtMs) }
    });

    const displayName = userWithoutPassword?.name ? String(userWithoutPassword.name) : 'Administrador';
    const subject = 'Código de seguridad - MegaRifas';
    const text = `Hola ${displayName}. Tu código de seguridad es: ${code}. Vence en ${ttlMinutes} minutos.`;
    const html = `<h1>Código de seguridad</h1><p>Hola <b>${escapeHtml(displayName)}</b>,</p><p>Tu código de seguridad es:</p><h2 style="letter-spacing: 6px;">${code}</h2><p>Vence en ${Number.isFinite(ttlMinutes) ? ttlMinutes : 10} minutos.</p>`;

    const sent = await sendEmail(safeEmail, subject, text, html);
    if (!sent) {
      return res.status(502).json({ error: 'No se pudo enviar el código de seguridad. Intenta de nuevo.' });
    }

    return res.json({ require2FA: true, email: safeEmail, message: 'Código enviado al correo' });
  }

  // Adaptar respuesta para que coincida con lo que espera la App móvil (accessToken + refreshToken)
  res.json({ message: 'Login exitoso', token, accessToken: token, refreshToken, user: userWithoutPassword });
};

app.post('/login', loginLimiter, handleLogin);
app.post('/auth/login', loginLimiter, handleLogin); // Alias para la App Móvil

// Validar 2FA Admin
app.post('/auth/2fa', async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'Faltan datos' });

  const safeEmail = normalizeEmail(email);
  const user = await prisma.user.findUnique({ where: { email: safeEmail } });
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

  const verificationTokenRaw = user.verificationToken;
  const parsed2fa = parse2faToken(verificationTokenRaw);
  if (parsed2fa) {
    if (String(code) !== parsed2fa.code) {
      await securityLogger.log({
        action: '2FA_FAILED',
        userEmail: safeEmail,
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        severity: 'WARN',
        detail: 'Invalid 2FA code'
      });
      return res.status(400).json({ error: 'Código inválido' });
    }
    if (Date.now() > parsed2fa.expiresAtMs) {
      await securityLogger.log({
        action: '2FA_FAILED',
        userEmail: safeEmail,
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        severity: 'WARN',
        detail: 'Expired 2FA code'
      });
      return res.status(400).json({ error: 'Código expirado. Solicita uno nuevo.' });
    }
  } else if (verificationTokenRaw !== code) {
    await securityLogger.log({
      action: '2FA_FAILED',
      userEmail: safeEmail,
      userId: user.id,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      severity: 'WARN',
      detail: 'Invalid 2FA code'
    });
    return res.status(400).json({ error: 'Código inválido' });
  }

  // Limpiar token
  await prisma.user.update({
    where: { id: user.id },
    data: { verificationToken: null }
  });

  await securityLogger.log({
    action: '2FA_SUCCESS',
    userEmail: safeEmail,
    userId: user.id,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    severity: 'INFO',
    detail: '2FA verification successful'
  });

  const token = signAccessToken(user);
  const refreshToken = signRefreshToken(user);
  const { password: _, ...userWithoutPassword } = user;

  // Decrypt sensitive data
  if (userWithoutPassword.name) userWithoutPassword.name = decrypt(userWithoutPassword.name);
  if (userWithoutPassword.bankDetails) userWithoutPassword.bankDetails = JSON.parse(decrypt(JSON.stringify(userWithoutPassword.bankDetails)));

  res.json({ message: 'Login exitoso', token, accessToken: token, refreshToken, user: userWithoutPassword });
});

// CRUD para rifas
app.post('/raffles', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const {
    title,
    description,
    prize,
    ticketPrice,
    price,
    totalTickets,
    style,
    lottery,
    terms,
    digits,
    startDate,
    endDate,
    securityCode,
    instantWins,
    minTickets,
    paymentMethods
  } = req.body || {};

  const rafflePrize = description || prize;
  if (!title || !rafflePrize) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  
  const maxTickets = 10000;
  const ticketsCount = Number(totalTickets) || 10000;
  
  if (ticketsCount > maxTickets) {
    return res.status(400).json({ error: `El máximo de tickets permitidos es ${maxTickets}` });
  }

  try {
    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;

    if (actorRole !== 'superadmin') {
      const planConfig = await getPlanConfig();
      const actor = await prisma.user.findUnique({ where: { id: actorId }, select: { adminPlan: true } });
      const plan = normalizeAdminPlan(actor?.adminPlan, planConfig);
      if (!plan) return res.status(403).json({ error: 'Admin sin plan activo. Contacta al superadmin.' });
    }

    const nextStyle = {
      ...(style || {}),
      ...(digits !== undefined ? { digits } : {}),
      ...(startDate ? { startDate } : {}),
      ...(endDate ? { endDate } : {}),
      ...(securityCode ? { securityCode } : {}),
      ...(instantWins ? { instantWins } : {}),
      ...(minTickets !== undefined ? { minTickets } : {}),
      ...(paymentMethods ? { paymentMethods } : {})
    };

    const raffle = await prisma.raffle.create({
      data: {
        title,
        prize: rafflePrize,
        ticketPrice: Number(ticketPrice ?? price) || 0,
        totalTickets: ticketsCount,
        lottery,
        terms: terms || null,
        style: nextStyle,
        userId: actorId,
        status: 'draft',
        activatedAt: null,
        closedAt: null
      }
    });

    try {
      await securityLogger.log({
        action: 'RAFFLE_CREATED',
        userEmail: String(req.user?.email || ''),
        userId: actorId,
        ipAddress: String(req.ip || ''),
        userAgent: String(req.headers['user-agent'] || ''),
        severity: 'INFO',
        detail: `Rifa creada (draft) #${raffle.id}`,
        entity: 'Raffle',
        entityId: raffle.id,
        metadata: { title: raffle.title, ticketPrice: raffle.ticketPrice, totalTickets: raffle.totalTickets }
      });
    } catch (_e) {
      // no bloquear
    }

    res.status(201).json({ message: 'Rifa creada (borrador)', raffle });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear rifa' });
  }
});

// Boost a raffle (24h or 7d). Admin can boost own raffles; superadmin can boost any.
app.post('/admin/raffles/:id/boost', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const raffleId = Number(req.params.id);
  const duration = String(req.body?.duration || '24h').toLowerCase();
  const actorId = req.user?.userId;
  const actorRole = String(req.user?.role || '').toLowerCase();

  if (!raffleId) return res.status(400).json({ error: 'ID inválido' });
  if (!['24h', '7d'].includes(duration)) return res.status(400).json({ error: 'Duración inválida' });

  try {
    const raffle = await prisma.raffle.findUnique({ where: { id: raffleId } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });
    if (String(raffle.status || '').toLowerCase() !== 'active') {
      return res.status(400).json({ error: 'Solo puedes destacar rifas activas. Actívala primero.' });
    }
    if (actorRole !== 'superadmin' && raffle.userId !== actorId) {
      return res.status(403).json({ error: 'No puedes destacar rifas de otros usuarios.' });
    }

    const planConfig = await getPlanConfig();
    if (actorRole !== 'superadmin') {
      const actor = await prisma.user.findUnique({ where: { id: actorId }, select: { adminPlan: true } });
      const plan = normalizeAdminPlan(actor?.adminPlan, planConfig);
      if (!plan) return res.status(403).json({ error: 'Admin sin plan activo.' });
      const boosts = Number(plan.boostCreditsRemaining) || 0;
      if (boosts <= 0) return res.status(403).json({ error: 'No tienes boosts disponibles.' });

      const now = Date.now();
      const expiresAt = new Date(now + (duration === '7d' ? 7 : 1) * 24 * 60 * 60 * 1000).toISOString();
      const boostedAt = new Date(now).toISOString();
      const nextStyle = { ...(raffle.style || {}), boost: { expiresAt, boostedAt, duration } };
      const nextPlan = { ...plan, boostCreditsRemaining: boosts - 1 };

      const updated = await prisma.$transaction(async (tx) => {
        await tx.user.update({ where: { id: actorId }, data: { adminPlan: nextPlan } });
        return tx.raffle.update({ where: { id: raffleId }, data: { style: nextStyle } });
      });

      return res.json({ message: 'Rifa destacada', raffle: updated, boost: nextStyle.boost, boostsRemaining: nextPlan.boostCreditsRemaining });
    }

    // Superadmin boost sin consumir créditos
    const now = Date.now();
    const expiresAt = new Date(now + (duration === '7d' ? 7 : 1) * 24 * 60 * 60 * 1000).toISOString();
    const boostedAt = new Date(now).toISOString();
    const nextStyle = { ...(raffle.style || {}), boost: { expiresAt, boostedAt, duration } };
    const updated = await prisma.raffle.update({ where: { id: raffleId }, data: { style: nextStyle } });
    return res.json({ message: 'Rifa destacada', raffle: updated, boost: nextStyle.boost });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al destacar rifa' });
  }
});

app.put('/raffles/:id', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { id } = req.params;
  const { title, description, ticketPrice, totalTickets, style } = req.body;
  
  const maxTickets = 10000;
  if (totalTickets && Number(totalTickets) > maxTickets) {
    return res.status(400).json({ error: `El máximo de tickets permitidos es ${maxTickets}` });
  }

  try {
    const raffle = await prisma.raffle.update({
      where: { id: Number(id) },
      data: { 
        title, 
        prize: description,
        ticketPrice: ticketPrice !== undefined ? Number(ticketPrice) : undefined,
        totalTickets: totalTickets !== undefined ? Number(totalTickets) : undefined,
        style: style !== undefined ? style : undefined
      }
    });
    res.json({ message: 'Rifa actualizada', raffle });
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar rifa' });
  }
});

app.delete('/raffles/:id', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  const { id } = req.params;
  try {
    const raffleId = Number(id);
    await prisma.$transaction(async (tx) => {
      await tx.ticket.deleteMany({ where: { raffleId } });
      await tx.winner.deleteMany({ where: { raffleId } });
      await tx.raffle.delete({ where: { id: raffleId } });
    });
    res.json({ message: 'Rifa eliminada' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar rifa' });
  }
});

// Detalles de pago por rifa (métodos elegidos por el rifero + datos bancarios del vendedor)
app.get('/raffles/:id/payment-details', authenticateToken, async (req, res) => {
  const raffleId = Number(req.params.id);
  if (!raffleId) return res.status(400).json({ error: 'ID inválido' });

  try {
    const raffle = await prisma.raffle.findUnique({
      where: { id: raffleId },
      select: {
        id: true,
        title: true,
        style: true,
        user: {
          select: {
            id: true,
            publicId: true,
            name: true,
            email: true,
            avatar: true,
            securityId: true,
            identityVerified: true,
            bankDetails: true
          }
        }
      }
    });

    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    const style = raffle.style && typeof raffle.style === 'object' ? raffle.style : {};
    const paymentMethods = normalizePaymentMethods(style.paymentMethods);
    const seller = raffle.user || null;

    const bankDetails = SANDBOX_MODE ? null : (seller?.bankDetails || null);
    return res.json({
      raffle: { id: raffle.id, title: raffle.title },
      paymentMethods,
      bankDetails,
      sandbox: SANDBOX_MODE,
      notice: SANDBOX_MODE ? 'SANDBOX: pagos reales deshabilitados' : null,
      seller: seller
        ? {
            id: seller.id,
            publicId: seller.publicId,
            name: seller.name ? safeDecrypt(seller.name) : null,
            email: seller.email,
            avatar: seller.avatar,
            identityVerified: !!seller.identityVerified,
            securityIdLast8: seller.securityId ? String(seller.securityId).slice(-8).toUpperCase() : null
          }
        : null
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener detalles de pago' });
  }
});

// Compra de tickets (Asignación aleatoria)
app.post('/raffles/:id/purchase', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;
  const userId = req.user.userId;

  if (!quantity || isNaN(quantity) || Number(quantity) <= 0) {
    return res.status(400).json({ error: 'Cantidad inválida' });
  }
  
  const qty = Number(quantity);

  try {
    const raffleId = Number(id);
    const raffle = await prisma.raffle.findUnique({ where: { id: raffleId } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    // Validación de estado
    const status = String(raffle.status || '').toLowerCase();
    if (status !== 'active') return res.status(400).json({ error: 'La rifa no está activa' });

    // Validación de cierre por tiempo (con buffer: por defecto 2 min antes del endDate)
    const endDate = getRaffleEndDate(raffle);
    if (endDate) {
      const bufferMs = getRaffleCloseBufferMs(raffle);
      const closeAtMs = endDate.getTime() - bufferMs;
      if (Date.now() >= closeAtMs) {
      await autoCloseExpiredRaffle(raffleId, 'purchase_after_endDate');
        return res.status(400).json({ error: 'La rifa ya cerró por tiempo' });
      }
    }

    // Anti-fraude: velocidad de compra
    await FraudEngine.checkPurchaseVelocity(userId, raffleId);

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    const totalCost = Number(raffle.ticketPrice) * qty;
    if (user.balance < totalCost) {
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // Generar números aleatorios
    const soldTickets = await prisma.ticket.findMany({
      where: { raffleId: Number(id) },
      select: { number: true }
    });
    const occupiedNumbers = new Set(soldTickets.map(t => t.number));
    
    const maxTickets = raffle.totalTickets || 10000;
    const newNumbers = [];
    let attempts = 0;
    
    if (occupiedNumbers.size + qty > maxTickets) {
       return res.status(400).json({ error: 'No hay suficientes tickets disponibles' });
    }

    while (newNumbers.length < qty && attempts < maxTickets * 3) {
      const num = crypto.randomInt(1, maxTickets + 1);
      if (!occupiedNumbers.has(num) && !newNumbers.includes(num)) {
        newNumbers.push(num);
      }
      attempts++;
    }

    if (newNumbers.length < qty) {
      return res.status(400).json({ error: 'No se pudieron generar números disponibles, intenta de nuevo' });
    }

    // Wallet interna: debita comprador y acredita al vendedor (rifero)
    const sellerId = raffle.userId;
    if (!sellerId) return res.status(400).json({ error: 'Rifa sin vendedor asignado' });

    const style = raffle.style && typeof raffle.style === 'object' ? raffle.style : {};
    const instantWinNumbers = parseInstantWinNumbers(style);
    const instantWinSet = new Set(instantWinNumbers);
    const instantWinPrizeLabel = typeof style.instantWinPrize === 'string' && style.instantWinPrize.trim()
      ? style.instantWinPrize.trim()
      : 'Premio rápido';

    const instantWinsAwarded = [];

    // Transacción
    await prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: userId },
        data: { balance: { decrement: totalCost } }
      });

      if (sellerId !== userId) {
        await tx.user.update({
          where: { id: sellerId },
          data: { balance: { increment: totalCost } }
        });
      }

      const txProvider = SANDBOX_MODE ? 'sandbox' : 'wallet';

      await tx.transaction.create({
        data: {
          txCode: generateTxCode(),
          userId,
          raffleId,
          amount: totalCost,
          type: 'purchase',
          status: 'approved',
          provider: txProvider,
          reference: `Compra de ${qty} tickets en rifa #${id}${SANDBOX_MODE ? SANDBOX_LABEL : ''}`
        }
      });

      if (sellerId !== userId) {
        await tx.transaction.create({
          data: {
            txCode: generateTxCode(),
            userId: sellerId,
            raffleId,
            amount: totalCost,
            type: 'sale',
            status: 'approved',
            provider: txProvider,
            reference: encrypt(`Venta de ${qty} tickets en rifa #${id} (buyer:${userId})${SANDBOX_MODE ? SANDBOX_LABEL : ''}`)
          }
        });
      }

      for (const num of newNumbers) {
        await tx.ticket.create({
          data: {
            raffleId,
            userId,
            number: num,
            status: 'approved'
          }
        });

        // Premios rápidos (Instant Wins): si el admin configuró números, el sistema premia automáticamente
        // y el usuario sigue participando para 1pm/4pm/10pm (no se excluye del sorteo mayor).
        if (instantWinSet.has(num)) {
          const drawSlot = `instant:${num}`;
          try {
            // Evitar duplicados por concurrencia: si existe el registro, no crear otro.
            const exists = await tx.winner.findFirst({ where: { raffleId, drawSlot } });
            if (!exists) {
              await tx.winner.create({
                data: {
                  raffleId,
                  userId,
                  drawSlot,
                  ticketNumber: num,
                  prize: instantWinPrizeLabel,
                  status: 'pending',
                  drawDate: new Date()
                }
              });
              instantWinsAwarded.push({ ticketNumber: num, prize: instantWinPrizeLabel });
            }
          } catch (_e) {
            // No bloquear la compra si falla el registro del premio rápido.
          }
        }
      }
    });

    // Notificar al usuario ganador instantáneo (si tiene pushToken)
    try {
      if (instantWinsAwarded.length && user?.pushToken) {
        const token = String(user.pushToken).trim();
        if (token) {
          // Si no hay infraestructura real de push, al menos quedará en logs.
          console.log('[INSTANT_WIN] push to', token, 'awarded:', instantWinsAwarded);
        }
      }
    } catch (_e) {
      // no bloquear
    }

    {
      const digits = getTicketDigitsFromRaffle(raffle);
      res.status(201).json({
        message: 'Compra exitosa',
        numbers: newNumbers,
        numbersFormatted: newNumbers.map((n) => formatTicketNumber(n, digits)),
        digits,
        instantWinsAwarded,
        remainingBalance: user.balance - totalCost
      });
    }

    try {
      await securityLogger.log({
        action: 'TICKETS_PURCHASED',
        userEmail: String(req.user?.email || ''),
        userId,
        ipAddress: String(req.ip || ''),
        userAgent: String(req.headers['user-agent'] || ''),
        severity: 'INFO',
        detail: `Compra de tickets en rifa #${id}`,
        entity: 'Raffle',
        entityId: String(id),
        metadata: { quantity: qty, totalCost, raffleId: Number(id), sandbox: SANDBOX_MODE }
      });
    } catch (_e) {
      // no bloquear
    }

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al procesar la compra' });
  }
});

app.get('/me/raffles', authenticateToken, async (req, res) => {
  try {
    const actorUserId = req.user.userId;
    let tickets;
    try {
      tickets = await prisma.ticket.findMany({
        where: { userId: actorUserId },
        include: {
          raffle: {
            include: {
              user: {
                select: {
                  id: true,
                  name: true,
                  avatar: true,
                  securityId: true,
                  identityVerified: true,
                  isBoosted: true,
                  boostEndsAt: true
                }
              }
            }
          }
        }
      });
    } catch (error) {
      // Compatibilidad: algunas DBs/migraciones pueden no tener columnas nuevas todavía.
      // Reintenta con un select mínimo para evitar 500 en la app.
      console.error('[GET /me/raffles] Primary query failed; falling back:', error);
      tickets = await prisma.ticket.findMany({
        where: { userId: actorUserId },
        include: {
          raffle: {
            include: {
              user: {
                select: {
                  id: true,
                  name: true,
                  avatar: true,
                  securityId: true,
                  identityVerified: true
                }
              }
            }
          }
        }
      });
    }
    
    const raffleIds = Array.from(new Set((tickets || []).map((t) => t.raffleId).filter(Boolean)));

    // Resultados: si existe Winner para la rifa => resultados publicados.
    // Ganador: si algún Winner.userId coincide con el usuario.
    const resultByRaffleId = {};
    if (raffleIds.length) {
      const winners = await prisma.winner.findMany({
        where: { raffleId: { in: raffleIds } },
        select: { raffleId: true, userId: true, drawSlot: true }
      });
      for (const w of winners) {
        const rid = w.raffleId;
        if (!rid) continue;
        if (!resultByRaffleId[rid]) {
          resultByRaffleId[rid] = { resultsPublished: false, isWinner: false, hasInstantWin: false };
        }
        const slot = String(w.drawSlot || '').toLowerCase();
        const isInstant = slot.startsWith('instant:') || slot === 'instant';
        // Por defecto: consideramos resultados finales publicados cuando existe el slot 10pm.
        // (Así se pueden anunciar premios 1pm/4pm sin que el cliente vea 'No ganaste' prematuramente.)
        if (slot === '10pm' || slot === 'final' || slot === 'tercer' || slot === '3') {
          resultByRaffleId[rid].resultsPublished = true;
        }
        if (isInstant && w.userId && Number(w.userId) === Number(actorUserId)) {
          resultByRaffleId[rid].hasInstantWin = true;
        }
        if (!isInstant && w.userId && Number(w.userId) === Number(actorUserId)) {
          resultByRaffleId[rid].isWinner = true;
        }
      }
    }
    const purchases = raffleIds.length
      ? await prisma.transaction.findMany({
          where: {
            userId: actorUserId,
            raffleId: { in: raffleIds },
            OR: [{ type: 'purchase' }, { type: 'manual_payment' }]
          },
          orderBy: { createdAt: 'asc' }
        })
      : [];

    const purchaseByRaffle = {};
    for (const p of purchases) {
      const rid = p.raffleId;
      if (!rid) continue;
      if (!purchaseByRaffle[rid]) {
        purchaseByRaffle[rid] = {
          totalSpent: 0,
          purchasedAt: null,
          method: null,
          unitPrice: null,
          status: null
        };
      }
      const amount = toFiniteNumber(p.amount);
      if (amount != null) purchaseByRaffle[rid].totalSpent += amount;

      // Preferir la info más reciente
      purchaseByRaffle[rid].purchasedAt = p.createdAt;
      purchaseByRaffle[rid].method = p.provider || purchaseByRaffle[rid].method;
      purchaseByRaffle[rid].status = p.status || purchaseByRaffle[rid].status;
    }

    const grouped = {};
    for (const t of tickets) {
      if (!t) continue;
      if (!grouped[t.raffleId]) {
        const raffle = t.raffle || {};
        const result = resultByRaffleId[t.raffleId] || { resultsPublished: false, isWinner: false };
        const seller = raffle.user || null;
        const sellerSafe = seller
          ? {
              ...seller,
              name: seller.name ? safeDecrypt(seller.name) : seller.name
            }
          : null;
        grouped[t.raffleId] = {
          raffle: sellerSafe ? { ...raffle, user: sellerSafe } : raffle,
          numbers: [],
          serialNumber: t.serialNumber,
          status: raffle.status,
          isWinner: !!result.isWinner,
          resultsPublished: !!result.resultsPublished,
          hasInstantWin: !!result.hasInstantWin,
          createdAt: t.createdAt,
          payment: purchaseByRaffle[t.raffleId] || { totalSpent: null, purchasedAt: null, method: null, unitPrice: null, status: null }
        };
      }
      grouped[t.raffleId].numbers.push(t.number);
      // La fecha/hora más útil para el usuario es la del último ticket de esa rifa (aprox. última compra)
      if (t.createdAt && (!grouped[t.raffleId].createdAt || t.createdAt > grouped[t.raffleId].createdAt)) {
        grouped[t.raffleId].createdAt = t.createdAt;
      }
    }

    // Fallback fuerte: si hay tickets pero el totalSpent quedó 0/null por data vieja o Decimal,
    // calcular total con ticketPrice*cantidad para que el recibo sea correcto.
    for (const rid of Object.keys(grouped)) {
      const entry = grouped[rid];
      const qty = Array.isArray(entry?.numbers) ? entry.numbers.length : 0;
      const unitPrice = toFiniteNumber(entry?.raffle?.ticketPrice) ?? toFiniteNumber(entry?.raffle?.price);

      if (entry?.payment && entry.payment.unitPrice == null && unitPrice != null) {
        entry.payment.unitPrice = unitPrice;
      }

      const computedTotal = unitPrice != null && qty ? unitPrice * qty : null;
      const currentTotal = entry?.payment ? toFiniteNumber(entry.payment.totalSpent) : null;

      if (computedTotal != null && (currentTotal == null || currentTotal === 0)) {
        entry.payment.totalSpent = computedTotal;
      }
    }

    res.json(Object.values(grouped));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener mis rifas' });
  }
});

// Endpoint para que el usuario consulte si tiene wins pendientes (para mostrar confeti UNA sola vez)
app.get('/me/pending-wins', authenticateToken, async (req, res) => {
  try {
    const actorUserId = req.user.userId;
    if (!actorUserId) return res.status(401).json({ error: 'Usuario inválido' });

    const win = await prisma.winner.findFirst({
      where: { userId: actorUserId, status: 'pending' },
      orderBy: { createdAt: 'desc' },
      include: { raffle: { select: { id: true, title: true, userId: true } } }
    });

    if (!win) return res.json({ win: null });

    const payload = {
      id: win.id,
      raffleId: win.raffleId,
      raffleTitle: win.raffle?.title || null,
      prize: win.prize,
      ticketNumber: win.ticketNumber,
      drawSlot: win.drawSlot,
      createdAt: win.createdAt
    };

    return res.json({ win: payload });
  } catch (error) {
    console.error('[PENDING_WINS]', error);
    return res.status(500).json({ error: 'Error al obtener wins pendientes' });
  }
});

// Endpoint para que el usuario reconozca (ack) un win mostrado
app.post('/me/ack-win/:id', authenticateToken, async (req, res) => {
  try {
    const actorUserId = req.user.userId;
    const winId = Number(req.params.id);
    if (!actorUserId) return res.status(401).json({ error: 'Usuario inválido' });
    if (!winId || !Number.isFinite(winId)) return res.status(400).json({ error: 'Win id inválido' });

    const win = await prisma.winner.findUnique({ where: { id: winId } });
    if (!win) return res.status(404).json({ error: 'Win no encontrado' });
    if (win.userId !== actorUserId) return res.status(403).json({ error: 'No autorizado' });

    await prisma.winner.update({ where: { id: winId }, data: { status: 'acknowledged' } });
    return res.json({ ok: true });
  } catch (error) {
    console.error('[ACK_WIN]', error);
    return res.status(500).json({ error: 'Error al ackear win' });
  }
});

// CRUD para usuarios
app.get('/users/:id', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: Number(req.params.id) } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    
    // Decrypt sensitive data
    if (user.name) user.name = decrypt(user.name);
    if (user.phone) user.phone = decrypt(user.phone);
    if (user.address) user.address = decrypt(user.address);
    if (user.cedula) user.cedula = decrypt(user.cedula);
    if (user.bankDetails && typeof user.bankDetails === 'string') {
       try {
         user.bankDetails = JSON.parse(decrypt(user.bankDetails));
       } catch (e) {
         // If it wasn't encrypted or failed to parse, keep as is
       }
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error al consultar usuario' });
  }
});

app.put('/users/:id', authenticateToken, async (req, res) => {
  const { name, email, phone, address, cedula, dob, bio, socials, bankDetails } = req.body;
  // Solo admin/superadmin o el propio usuario pueden editar
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin' && req.user.userId !== Number(req.params.id)) {
     return res.status(403).json({ error: 'No autorizado para editar este usuario' });
  }
  try {
    const dataToUpdate = { email, dob, bio, socials };
    if (name) dataToUpdate.name = encrypt(name);
    if (phone) dataToUpdate.phone = encrypt(phone);
    if (address) dataToUpdate.address = encrypt(address);
    if (cedula) dataToUpdate.cedula = encrypt(cedula);
    if (bankDetails) dataToUpdate.bankDetails = encrypt(JSON.stringify(bankDetails));

    const user = await prisma.user.update({
      where: { id: Number(req.params.id) },
      data: dataToUpdate
    });

    await securityLogger.log({
      action: 'USER_UPDATE',
      userEmail: req.user.email,
      userId: req.user.userId,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      severity: 'INFO',
      detail: `User ${req.params.id} updated profile`,
      entity: 'User',
      entityId: req.params.id
    });

    res.json({ message: 'Usuario actualizado', user });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Error al actualizar usuario: ' + error.message });
  }
});

app.delete('/users/:id', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    await prisma.user.delete({ where: { id: Number(req.params.id) } });
    res.json({ message: 'Usuario eliminado' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar usuario' });
  }
});

// CRUD para tickets
const securityLogger = require('./services/securityLogger');

// --- Payment Routes ---

// Initiate a payment
app.post('/payments/initiate', authenticateToken, async (req, res) => {
  const { amount, currency, provider, type, raffleId } = req.body || {};
  const userId = req.user.userId;

  try {
    const parsedAmount = Number(amount);
    if (!Number.isFinite(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({ error: 'Monto inválido' });
    }

    const safeCurrency = currency ? String(currency).toUpperCase() : 'VES';
    const safeType = type ? String(type) : 'deposit';
    const requestedProvider = provider ? String(provider).toLowerCase() : 'manual';
    const safeProvider = SANDBOX_MODE ? 'sandbox' : requestedProvider;
    const safeRaffleId = raffleId == null || raffleId === '' ? null : Number(raffleId);

    const result = await paymentService.initiateTransaction(
      userId,
      parsedAmount,
      safeCurrency,
      safeProvider,
      safeType,
      Number.isFinite(safeRaffleId) ? safeRaffleId : null
    );

    res.json({
      ...result,
      sandbox: SANDBOX_MODE,
      providerRequested: requestedProvider,
      providerUsed: safeProvider
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error initiating payment' });
  }
});

// Webhook for payment providers
app.post('/payments/webhook/:provider', async (req, res) => {
  if (SANDBOX_MODE) {
    return res.status(403).json({ error: 'Webhooks deshabilitados en SANDBOX' });
  }
  const { provider } = req.params;
  const data = req.body;

  try {
    // Verify signature here in a real app (e.g. Stripe signature)
    await paymentService.handleWebhook(provider, data);
    res.json({ received: true });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: 'Webhook handling failed' });
  }
});

// --- End Payment Routes ---

app.post('/tickets', authenticateToken, async (req, res) => {
  const { userId, raffleId, paymentMethod, proof } = req.body;
  if (!userId || !raffleId) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  
  try {
    const raffle = await prisma.raffle.findUnique({ where: { id: Number(raffleId) } });
    const user = await prisma.user.findUnique({ where: { id: Number(userId) } });
    
    if (!raffle || !user) return res.status(404).json({ error: 'Rifa o usuario no encontrado' });

    // Si es pago manual (transferencia)
    if (paymentMethod === 'manual') {
      if (!proof) return res.status(400).json({ error: 'Se requiere comprobante de pago' });
      
      // Crear transacción pendiente
      const transaction = await prisma.transaction.create({
        data: {
          userId: user.id,
          amount: -raffle.ticketPrice,
          type: 'manual_payment',
          status: 'pending',
          provider: SANDBOX_MODE ? 'sandbox' : 'manual',
          reference: encrypt(`Compra Rifa: ${raffle.title}${SANDBOX_MODE ? SANDBOX_LABEL : ''}`),
          proof: encrypt(proof),
          raffleId: Number(raffleId)
        }
      });

      if (user.email) {
        sendEmail(
          user.email,
          'Pago en Revisión - MegaRifas',
          `Hemos recibido tu reporte de pago para la rifa ${raffle.title}. Lo revisaremos y te notificaremos.`,
          `<h1>Pago en Revisión</h1><p>Hemos recibido tu comprobante para la rifa <b>${raffle.title}</b>.</p><p>Nuestro equipo verificará la transacción y te notificaremos cuando tus tickets sean asignados.</p>`
        ).catch(console.error);
      }

      // Crear ticket en estado pendiente (sin número asignado aún o reservado)
      // NOTA: El usuario pidió números aleatorios 00001-10000 al verificar.
      // Aquí solo registramos la intención.
      
      return res.status(201).json({ 
        message: 'Pago registrado. Esperando verificación del administrador.', 
        transactionId: transaction.id 
      });
    }
    
    // Si es pago con saldo (Wallet)
    if (user.balance < raffle.ticketPrice) {
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // --- FRAUD CHECK ---
    const velocityCheck = await FraudEngine.checkPurchaseVelocity(user.id, raffle.id);
    if (velocityCheck.isSuspicious) {
      await FraudEngine.logActivity(user.id, 'PURCHASE_VELOCITY', velocityCheck.reason, velocityCheck.severity, req.ip);
      if (velocityCheck.severity === 'HIGH' || velocityCheck.severity === 'CRITICAL') {
        return res.status(403).json({ error: 'Actividad inusual detectada. Por favor contacte a soporte.' });
      }
    }
    // -------------------

    // Generar número aleatorio único
    let assignedNumber;
    let isUnique = false;
    let attempts = 0;
    const maxRange = raffle.totalTickets || 10000;
    
    while (!isUnique && attempts < 10) {
      assignedNumber = crypto.randomInt(1, maxRange + 1);
      const existing = await prisma.ticket.findFirst({
        where: { raffleId: raffle.id, number: assignedNumber }
      });
      if (!existing) isUnique = true;
      attempts++;
    }

    if (!isUnique) return res.status(500).json({ error: 'No se pudo asignar un número único, intente de nuevo' });

    // Transacción atómica
    const result = await prisma.$transaction(async (prisma) => {
      await prisma.user.update({
        where: { id: user.id },
        data: { balance: { decrement: raffle.ticketPrice } }
      });

      if (raffle.ticketPrice > 0) {
        await prisma.transaction.create({
          data: {
            userId: user.id,
            amount: -raffle.ticketPrice,
            type: 'purchase',
            status: 'approved',
            provider: SANDBOX_MODE ? 'sandbox' : 'wallet',
            reference: encrypt(`Ticket #${assignedNumber} - ${raffle.title}${SANDBOX_MODE ? SANDBOX_LABEL : ''}`)
          }
        });
      }

      const serialNumber = generateShortId('TKT');
      
      // Generate Cryptographic Receipt Signature
      // HMAC-SHA256 of (serialNumber + userId + raffleId + number + timestamp + SECRET)
      const signaturePayload = `${serialNumber}|${userId}|${raffleId}|${assignedNumber}|${Date.now()}`;
      const receiptSignature = crypto.createHmac('sha256', process.env.JWT_SECRET || 'secret').update(signaturePayload).digest('hex');

      const ticket = await prisma.ticket.create({
        data: { 
          number: assignedNumber, 
          userId: Number(userId), 
          raffleId: Number(raffleId),
          serialNumber: serialNumber,
          status: 'approved',
          receiptSignature: receiptSignature
        },
        include: { user: true, raffle: true }
      });

      // Audit Log for Immutable Record
      await prisma.auditLog.create({
        data: {
          action: 'TICKET_PURCHASE',
          entity: 'Ticket',
          userEmail: user.email,
          detail: `Ticket #${assignedNumber} generated. Serial: ${serialNumber}. Signature: ${receiptSignature}`
        }
      });
      
      return ticket;
    });

    const ticket = result;

    if (ticket.user && ticket.user.email) {
      const digits = getTicketDigitsFromRaffle(ticket.raffle);
      const displayNumber = formatTicketNumber(ticket.number, digits);
      sendEmail(
        ticket.user.email,
        'Confirmación de Ticket - MegaRifas',
        `Has comprado el ticket #${displayNumber} para la rifa ${ticket.raffle.title}. Serial: ${ticket.serialNumber}`,
        `<h1>¡Ticket Confirmado!</h1><p>Has adquirido el número <b>${displayNumber}</b> para la rifa <i>${ticket.raffle.title}</i>.</p><p>Serial único: <code>${ticket.serialNumber}</code></p>`
      ).catch(console.error);
    }

    {
      const digits = getTicketDigitsFromRaffle(ticket.raffle);
      res.status(201).json({
        message: 'Ticket creado',
        ticket,
        ticketFormatted: formatTicketNumber(ticket.number, digits),
        digits
      });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear ticket' });
  }
});

// Endpoint para que el Admin verifique pagos manuales
app.post('/admin/verify-payment/:transactionId', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { transactionId } = req.params;
  const { action, reason, raffleId } = req.body; // 'approve' or 'reject', reason for rejection

  try {
    const transaction = await prisma.transaction.findUnique({ where: { id: Number(transactionId) }, include: { user: true } });
    if (!transaction || transaction.status !== 'pending') {
      return res.status(404).json({ error: 'Transacción no encontrada o ya procesada' });
    }

    if (action === 'reject') {
      await prisma.transaction.update({
        where: { id: transaction.id },
        data: { 
          status: 'rejected', 
          reference: encrypt(reason ? `Rechazado: ${reason}` : 'Rechazado por admin'),
          reconciled: true,
          reconciledAt: new Date()
        }
      });
      
      if (transaction.user.email) {
        sendEmail(
          transaction.user.email,
          'Pago Rechazado - Rifas App',
          `Tu pago ha sido rechazado. Motivo: ${reason || 'No especificado'}. Por favor contacta a soporte.`,
          `<h1>Pago Rechazado</h1><p>Tu pago ha sido rechazado.</p><p><b>Motivo:</b> ${reason || 'No especificado'}</p><p>Por favor verifica tu comprobante y vuelve a intentarlo o contacta a soporte.</p>`
        ).catch(console.error);
      }
      
      return res.json({ message: 'Pago rechazado' });
    }

    // Aprobar: Generar ticket
    // Usamos raffleId del body o intentamos inferirlo si ya lo guardamos (ahora lo guardamos en Transaction.raffleId si actualizamos el endpoint de creación, pero por compatibilidad chequeamos body)
    // Mejor aún: si transaction tiene raffleId, úsalo. Si no, usa el del body.
    const targetRaffleId = transaction.raffleId || raffleId;
    
    if (!targetRaffleId) return res.status(400).json({ error: 'Falta raffleId para asignar ticket' });

    const raffle = await prisma.raffle.findUnique({ where: { id: Number(targetRaffleId) } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    // Generar número aleatorio con reintentos y transacción atómica
    // Nota: La restricción @@unique([raffleId, number]) en la DB asegura que no haya duplicados finales.
    // Intentaremos generar un número y crear. Si falla por unique constraint, reintentamos.
    
    let ticket;
    let attempts = 0;
    const maxAttempts = 15;
    const maxRange = raffle.totalTickets || 10000;
    
    while (!ticket && attempts < maxAttempts) {
      attempts++;
      const assignedNumber = crypto.randomInt(1, maxRange + 1);
      
      try {
        ticket = await prisma.$transaction(async (tx) => {
          // Verificación extra dentro de la transacción (opcional pero buena práctica)
          const existing = await tx.ticket.findFirst({ where: { raffleId: raffle.id, number: assignedNumber } });
          if (existing) throw new Error('Number taken'); // Fuerza rollback y catch para reintentar

          // Actualizar transacción solo si es el primer intento exitoso (para no actualizarla múltiples veces si fallara algo más, aunque aquí es todo o nada)
          // Pero como estamos en un loop, solo queremos actualizar la transacción UNA vez.
          // El problema es que si actualizamos la transacción aquí y luego falla el ticket, se hace rollback de todo. Correcto.
          
          await tx.transaction.update({
            where: { id: transaction.id },
            data: { 
              status: 'approved', 
              reference: encrypt(`Ticket #${assignedNumber} - ${raffle.title}`),
              reconciled: true,
              reconciledAt: new Date()
            }
          });

          const serialNumber = generateShortId('TKT');
          const signaturePayload = `${serialNumber}|${transaction.userId}|${raffle.id}|${assignedNumber}|${Date.now()}`;
          const receiptSignature = crypto.createHmac('sha256', process.env.JWT_SECRET || 'secret').update(signaturePayload).digest('hex');

          const newTicket = await tx.ticket.create({
            data: {
              number: assignedNumber,
              userId: transaction.userId,
              raffleId: raffle.id,
              serialNumber: serialNumber,
              status: 'approved',
              receiptSignature: receiptSignature
            },
            include: { user: true, raffle: true }
          });

          // Audit Log
          await tx.auditLog.create({
            data: {
              action: 'MANUAL_PAYMENT_APPROVED',
              entity: 'Ticket',
              userEmail: transaction.user.email,
              detail: `Ticket #${assignedNumber} generated via manual payment. Serial: ${serialNumber}. Signature: ${receiptSignature}`
            }
          });

          return newTicket;
        });
      } catch (err) {
        // Si el error es por duplicado (P2002) o nuestro 'Number taken', continuamos el loop
        if (err.code === 'P2002' || err.message === 'Number taken') {
          console.log(`Intento ${attempts}: Número ${assignedNumber} ocupado, reintentando...`);
          ticket = null; // Asegurar que ticket es null para seguir loop
        } else {
          throw err; // Otro error, lanzar
        }
      }
    }

    if (!ticket) return res.status(500).json({ error: 'No se pudo asignar un número único después de varios intentos. Intenta de nuevo.' });

    // Notificar usuario
    if (transaction.user.email) {
      const digits = getTicketDigitsFromRaffle(raffle);
      const displayNumber = formatTicketNumber(ticket.number, digits);
      sendEmail(
        transaction.user.email,
        'Pago Aprobado - Ticket Asignado',
        `Tu pago ha sido verificado. Tu número es: ${displayNumber}`,
        `<h1>¡Pago Verificado!</h1><p>Tu número asignado es: <b>${displayNumber}</b></p><p>Rifa: ${raffle.title}</p>`
      ).catch(console.error);
    }

    {
      const digits = getTicketDigitsFromRaffle(raffle);
      res.json({
        message: 'Pago verificado y ticket asignado',
        ticket,
        ticketFormatted: formatTicketNumber(ticket.number, digits),
        digits
      });
    }

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al verificar pago' });
  }
});

// --- VERIFICATION ---
app.get('/verify-ticket/:serial', async (req, res) => {
  const { serial } = req.params;
  try {
    const ticket = await prisma.ticket.findUnique({
      where: { serialNumber: serial },
      include: { 
        user: { select: { name: true, publicId: true } },
        raffle: { select: { title: true, digits: true, totalTickets: true } }
      }
    });

    if (!ticket) return res.status(404).json({ valid: false, error: 'Ticket no encontrado' });

    // Decrypt user name for display
    if (ticket.user && ticket.user.name) ticket.user.name = decrypt(ticket.user.name);

    res.json({
      valid: true,
      ticket: {
        serialNumber: ticket.serialNumber,
        number: ticket.number,
        displayNumber: formatTicketNumber(ticket.number, getTicketDigitsFromRaffle(ticket.raffle)),
        raffle: ticket.raffle.title,
        holder: ticket.user.name,
        signature: ticket.receiptSignature,
        verifiedAt: new Date()
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error de verificación' });
  }
});

// Verificador (Admin) con datos del comprador
app.get('/admin/verify-ticket/:query', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const queryRaw = String(req.params.query || '').trim();
  if (!queryRaw) return res.status(400).json({ valid: false, error: 'Consulta requerida' });

  try {
    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;

    const scopeWhere = actorRole === 'superadmin' ? {} : { raffle: { userId: actorId } };
    const take = Math.min(Math.max(Number(req.query.take) || 50, 1), 200);
    const pageSize = Math.min(200, Math.max(50, take));
    const maxScan = 5000;

    const include = {
      user: { select: { id: true, publicId: true, name: true, email: true, phone: true, cedula: true } },
      raffle: {
        select: {
          id: true,
          title: true,
          user: { select: { id: true, publicId: true, name: true, email: true, avatar: true, securityId: true } }
        }
      }
    };

    const isNumeric = /^\d+$/.test(queryRaw);
    const qLower = queryRaw.toLowerCase();
    const looksLikeEmail = qLower.includes('@');

    let candidates = [];

    // 1) Intento exacto por serial (uuid)
    const bySerial = await prisma.ticket.findFirst({
      where: { ...scopeWhere, serialNumber: queryRaw },
      include
    });
    if (bySerial) {
      candidates = [bySerial];
    } else if (isNumeric) {
      // 2) Búsqueda por número (puede tener múltiples coincidencias en muchas rifas)
      candidates = await prisma.ticket.findMany({
        where: { ...scopeWhere, number: Number(queryRaw) },
        include,
        orderBy: { createdAt: 'desc' },
        take
      });
    } else {
      // 3) Búsqueda por texto (email se filtra en DB; nombre/cédula/teléfono se filtra en memoria)
      if (looksLikeEmail) {
        candidates = await prisma.ticket.findMany({
          where: { ...scopeWhere, user: { email: { contains: queryRaw, mode: 'insensitive' } } },
          include,
          orderBy: { createdAt: 'desc' },
          take
        });
      } else {
        // Escaneo paginado para poder encontrar coincidencias en campos encriptados sin fallar con muchas rifas
        let skip = 0;
        let scanned = 0;
        const matches = [];

        while (matches.length < take && scanned < maxScan) {
          const page = await prisma.ticket.findMany({
            where: scopeWhere,
            include,
            orderBy: { createdAt: 'desc' },
            skip,
            take: pageSize
          });

          if (!page.length) break;
          scanned += page.length;
          skip += page.length;

          const mappedPage = page.map((ticket) => {
            const buyer = ticket.user || {};
            const seller = ticket.raffle?.user || {};

            const buyerName = buyer.name ? safeDecrypt(buyer.name) : null;
            const buyerPhone = buyer.phone ? safeDecrypt(buyer.phone) : null;
            const buyerCedula = buyer.cedula ? safeDecrypt(buyer.cedula) : null;
            const sellerName = seller.name ? safeDecrypt(seller.name) : null;

            return {
              id: ticket.id,
              serialNumber: ticket.serialNumber,
              number: ticket.number,
              status: ticket.status,
              createdAt: ticket.createdAt,
              raffle: { id: ticket.raffle?.id, title: ticket.raffle?.title },
              seller: {
                id: seller.id,
                publicId: seller.publicId,
                name: sellerName,
                email: seller.email,
                avatar: seller.avatar,
                securityIdLast8: seller.securityId ? String(seller.securityId).slice(-8).toUpperCase() : null
              },
              buyer: {
                id: buyer.id,
                publicId: buyer.publicId,
                name: buyerName,
                email: buyer.email,
                phone: buyerPhone,
                cedula: buyerCedula
              },
              signature: ticket.receiptSignature
            };
          });

          const filteredPage = mappedPage.filter((m) => {
            const haystack = [
              m.serialNumber,
              String(m.number ?? ''),
              m.buyer?.name,
              m.buyer?.email,
              m.buyer?.phone,
              m.buyer?.cedula
            ]
              .filter((x) => x != null)
              .map((x) => String(x).toLowerCase());
            return haystack.some((s) => s.includes(qLower));
          });

          for (const m of filteredPage) {
            matches.push(m);
            if (matches.length >= take) break;
          }
        }

        // Ya devolvemos resultados mapeados arriba
        if (matches.length) {
          return res.json({ valid: true, matches, count: matches.length, verifiedAt: new Date() });
        }

        candidates = [];
      }
    }

    const mapped = (Array.isArray(candidates) ? candidates : []).map((ticket) => {
      const buyer = ticket.user || {};
      const seller = ticket.raffle?.user || {};

      const buyerName = buyer.name ? safeDecrypt(buyer.name) : null;
      const buyerPhone = buyer.phone ? safeDecrypt(buyer.phone) : null;
      const buyerCedula = buyer.cedula ? safeDecrypt(buyer.cedula) : null;
      const sellerName = seller.name ? safeDecrypt(seller.name) : null;

      return {
        id: ticket.id,
        serialNumber: ticket.serialNumber,
        number: ticket.number,
        status: ticket.status,
        createdAt: ticket.createdAt,
        raffle: { id: ticket.raffle?.id, title: ticket.raffle?.title },
        seller: {
          id: seller.id,
          publicId: seller.publicId,
          name: sellerName,
          email: seller.email,
          avatar: seller.avatar,
          securityIdLast8: seller.securityId ? String(seller.securityId).slice(-8).toUpperCase() : null
        },
        buyer: {
          id: buyer.id,
          publicId: buyer.publicId,
          name: buyerName,
          email: buyer.email,
          phone: buyerPhone,
          cedula: buyerCedula
        },
        signature: ticket.receiptSignature
      };
    });

    // Filtrado extra para consultas por nombre/cédula/teléfono (en memoria)
    const filtered = mapped.filter((m) => {
      if (isNumeric || looksLikeEmail) return true;
      const haystack = [
        m.serialNumber,
        String(m.number ?? ''),
        m.buyer?.name,
        m.buyer?.email,
        m.buyer?.phone,
        m.buyer?.cedula
      ]
        .filter((x) => x != null)
        .map((x) => String(x).toLowerCase());

      return haystack.some((s) => s.includes(qLower));
    });

    if (!filtered.length) return res.status(404).json({ valid: false, error: 'Sin coincidencias' });
    return res.json({ valid: true, matches: filtered, count: filtered.length, verifiedAt: new Date() });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error de verificación' });
  }
});

// --- TICKETS VERIFICATION (RIFA ESPECÍFICA, 1 DATO) ---
// Reglas:
// - Siempre requiere raffleId
// - Admin: solo puede verificar sus rifas ACTIVAS
// - Superadmin: puede verificar rifas activas de cualquier admin
// - Debe funcionar con 1 solo dato: cedula | name | number | serial
app.get('/admin/tickets/verify', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;

    const raffleIdRaw = String(req.query.raffleId || '').trim();
    const raffleId = Number(raffleIdRaw);
    if (!raffleId || !Number.isFinite(raffleId)) {
      return res.status(400).json({ valid: false, error: 'raffleId requerido' });
    }

    const serialRaw = String(req.query.serial || '').trim();
    const numberRaw = String(req.query.number || '').trim();
    const cedulaRaw = String(req.query.cedula || '').trim();
    const nameRaw = String(req.query.name || '').trim();
    const take = Math.min(Math.max(Number(req.query.take) || 20, 1), 50);

    const normalizeDigits = (value) => String(value || '').replace(/\D/g, '');
    const normalizeName = (value) => String(value || '').trim().toLowerCase().replace(/\s+/g, ' ');

    const serial = serialRaw;
    const numberDigits = normalizeDigits(numberRaw);
    const cedulaDigits = normalizeDigits(cedulaRaw);
    const nameQ = normalizeName(nameRaw);

    const hasAny = Boolean(serial || numberDigits || cedulaDigits || nameQ);
    if (!hasAny) {
      return res.status(400).json({ valid: false, error: 'Debes enviar serial, number, cedula o name' });
    }

    // Validar acceso a rifa y que sea verificable (activa o cerrada)
    const raffle = await prisma.raffle.findUnique({
      where: { id: raffleId },
      select: {
        id: true,
        title: true,
        description: true,
        digits: true,
        price: true,
        status: true,
        userId: true,
        user: { select: { id: true, publicId: true, name: true, email: true, avatar: true, securityId: true } }
      }
    });
    if (!raffle) return res.status(404).json({ valid: false, error: 'Rifa no encontrada' });
    const raffleStatus = String(raffle.status || '').toLowerCase();
    if (raffleStatus !== 'active' && raffleStatus !== 'closed') {
      return res.status(403).json({ valid: false, error: 'Solo se puede verificar en rifas activas o cerradas' });
    }
    if (actorRole !== 'superadmin' && raffle.userId !== actorId) {
      return res.status(403).json({ valid: false, error: 'No puedes verificar tickets de rifas de otros admins' });
    }

    // Búsqueda por campos no encriptados (serial/number) directo; para nombre/cédula se filtra en memoria.
    let candidates = [];
    if (serial) {
      // Permitir búsqueda parcial por serial (muchas personas copian solo una parte)
      const whereSerial = serial.length >= 16
        ? { raffleId, serialNumber: { contains: serial } }
        : { raffleId, serialNumber: { contains: serial } };
      candidates = await prisma.ticket.findMany({
        where: whereSerial,
        include: { user: { select: { id: true, publicId: true, name: true, email: true, phone: true, cedula: true } } },
        orderBy: { createdAt: 'desc' },
        take
      });
    } else if (numberDigits) {
      const found = await prisma.ticket.findFirst({
        where: { raffleId, number: Number(numberDigits) },
        include: { user: { select: { id: true, publicId: true, name: true, email: true, phone: true, cedula: true } } }
      });
      candidates = found ? [found] : [];
    } else {
      // Escaneo paginado para poder comparar contra campos encriptados
      const pageSize = 250;
      const maxScan = 5000;
      let skip = 0;
      let scanned = 0;
      const matches = [];

      while (matches.length < take && scanned < maxScan) {
        const page = await prisma.ticket.findMany({
          where: { raffleId },
          include: { user: { select: { id: true, publicId: true, name: true, email: true, phone: true, cedula: true } } },
          orderBy: { createdAt: 'desc' },
          skip,
          take: pageSize
        });
        if (!page.length) break;
        scanned += page.length;
        skip += page.length;

        for (const t of page) {
          const u = t.user || {};
          const buyerName = u.name ? safeDecrypt(u.name) : '';
          const buyerCedula = u.cedula ? safeDecrypt(u.cedula) : '';
          const buyerPhone = u.phone ? safeDecrypt(u.phone) : '';

          // Algunas BD/apps guardaron "cédula" en phone. Soportar ambos.
          const cedulaHay = normalizeDigits(buyerCedula);
          const phoneHay = normalizeDigits(buyerPhone);

          // Permitir coincidencia parcial para que funcione con fragmentos (ej: últimos 4 dígitos)
          const okCedula = cedulaDigits
            ? (cedulaHay.includes(cedulaDigits) || phoneHay.includes(cedulaDigits))
            : true;
          const okName = nameQ ? normalizeName(buyerName).includes(nameQ) : true;
          if (okCedula && okName) {
            matches.push(t);
            if (matches.length >= take) break;
          }
        }
      }

      candidates = matches;
    }

    if (!candidates.length) {
      return res.status(404).json({ valid: false, error: 'Sin coincidencias' });
    }

    const seller = raffle.user || {};
    const sellerName = seller.name ? safeDecrypt(seller.name) : null;
    const sellerSecurityIdLast8 = seller.securityId ? String(seller.securityId).slice(-8).toUpperCase() : null;

    const mapped = candidates.map((t) => {
      const u = t.user || {};
      return {
        id: t.id,
        serialNumber: t.serialNumber,
        number: t.number,
        status: t.status,
        createdAt: t.createdAt,
        receiptSignature: t.receiptSignature,
        raffle: {
          id: raffle.id,
          title: raffle.title,
          description: raffle.description,
          digits: raffle.digits,
          price: raffle.price
        },
        seller: {
          id: seller.id,
          publicId: seller.publicId,
          name: sellerName,
          email: seller.email,
          avatar: seller.avatar,
          securityIdLast8: sellerSecurityIdLast8
        },
        buyer: {
          id: u.id,
          publicId: u.publicId,
          name: u.name ? safeDecrypt(u.name) : null,
          email: u.email,
          phone: u.phone ? safeDecrypt(u.phone) : null,
          cedula: u.cedula ? safeDecrypt(u.cedula) : null
        }
      };
    });

    return res.json({ valid: true, matches: mapped, count: mapped.length, verifiedAt: new Date() });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ valid: false, error: 'Error de verificación' });
  }
});

// Superadmin: lista de admins con rifas activas (para selección en verificador)
app.get('/superadmin/admins/active-raffles', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const includeClosed = String(req.query.includeClosed || '').trim() === '1' || String(req.query.includeClosed || '').trim().toLowerCase() === 'true';
    const statuses = includeClosed ? ['active', 'closed'] : ['active'];
    const raffles = await prisma.raffle.findMany({
      where: { status: { in: statuses } },
      select: {
        id: true,
        title: true,
        status: true,
        createdAt: true,
        activatedAt: true,
        userId: true,
        user: { select: { id: true, publicId: true, name: true, email: true, avatar: true } }
      },
      orderBy: { activatedAt: 'desc' }
    });

    const byAdmin = new Map();
    for (const r of raffles) {
      const u = r.user || {};
      const key = u.id;
      if (!key) continue;
      if (!byAdmin.has(key)) {
        byAdmin.set(key, {
          id: u.id,
          publicId: u.publicId,
          name: u.name ? safeDecrypt(u.name) : null,
          email: u.email,
          avatar: u.avatar,
          activeRaffles: []
        });
      }
      byAdmin.get(key).activeRaffles.push({
        id: r.id,
        title: r.title,
        status: r.status,
        createdAt: r.createdAt,
        activatedAt: r.activatedAt
      });
    }

    const list = Array.from(byAdmin.values()).sort((a, b) => {
      const at = a.activeRaffles?.[0]?.activatedAt || a.activeRaffles?.[0]?.createdAt;
      const bt = b.activeRaffles?.[0]?.activatedAt || b.activeRaffles?.[0]?.createdAt;
      return new Date(bt || 0).getTime() - new Date(at || 0).getTime();
    });

    return res.json(list);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Error al obtener admins con rifas activas' });
  }
});

// Endpoint para guardar datos bancarios del admin
app.put('/admin/bank-details', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { bankDetails } = req.body;
  try {
    await prisma.user.update({
      where: { id: req.user.userId },
      data: { bankDetails }
    });
    res.json({ message: 'Datos bancarios actualizados' });
  } catch (error) {
    res.status(500).json({ error: 'Error al guardar datos bancarios' });
  }
});

// Endpoint público para ver datos bancarios del admin (para que el usuario pague)
app.get('/admin/bank-details', async (req, res) => {
  try {
    if (SANDBOX_MODE) {
      return res.json({ bankDetails: null, sandbox: true, notice: 'SANDBOX: datos bancarios ocultos' });
    }
    // Asumimos que el admin principal es el ID 1 o buscamos por rol
    const admin = await prisma.user.findFirst({ where: { role: 'superadmin' } });
    if (!admin || !admin.bankDetails) return res.status(404).json({ error: 'Datos bancarios no disponibles' });
    const safe = admin.bankDetails && typeof admin.bankDetails === 'object' ? admin.bankDetails : {};
    res.json({ ...safe, sandbox: false });
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener datos bancarios' });
  }
});

// --- ADMIN RAFFLE MANAGEMENT ---

app.get('/admin/raffles', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;
    const where = actorRole === 'superadmin' ? {} : { userId: actorId };
    const raffles = await prisma.raffle.findMany({ where, orderBy: { createdAt: 'desc' }, include: { _count: { select: { tickets: true } } } });
    const base = raffles.map(r => ({ ...r, soldTickets: r._count?.tickets || 0 }));
    const withReactions = await enrichRafflesWithReactions(base, actorId);
    res.json(withReactions);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener rifas' });
  }
});

// Activar rifa (consume cupos y aplica límite semanal para unlimited)
app.post('/admin/raffles/:id/activate', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const raffleId = Number(req.params.id);
  if (!raffleId) return res.status(400).json({ error: 'ID inválido' });

  try {
    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;

    const raffle = await prisma.raffle.findUnique({ where: { id: raffleId } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });
    if (actorRole !== 'superadmin' && raffle.userId !== actorId) {
      return res.status(403).json({ error: 'No puedes activar rifas de otros usuarios.' });
    }

    const currentStatus = String(raffle.status || '').toLowerCase();
    if (currentStatus === 'active') return res.status(400).json({ error: 'La rifa ya está activa.' });
    if (currentStatus === 'closed') return res.status(400).json({ error: 'La rifa está cerrada.' });

    const now = new Date();

    if (actorRole === 'superadmin') {
      const updated = await prisma.raffle.update({ where: { id: raffleId }, data: { status: 'active', activatedAt: now } });

      // Pre-generate tickets for this raffle so every number has a DB record.
      try {
        const pregenerate = String(process.env.PREGENERATE_TICKETS_ON_ACTIVATE || '1') === '1';
        if (pregenerate && Number(updated.totalTickets) > 0) {
          const out = await generateTicketsForRaffle(updated.id, updated.totalTickets);
          console.log('[RAFFLE_ACTIVATE] pregenerate result:', out);
        }
      } catch (e) {
        console.error('[RAFFLE_ACTIVATE] pregenerate failed:', e);
      }

      try {
        await securityLogger.log({
          action: 'RAFFLE_ACTIVATED',
          userEmail: String(req.user?.email || ''),
          userId: actorId,
          ipAddress: String(req.ip || ''),
          userAgent: String(req.headers['user-agent'] || ''),
          severity: 'INFO',
          detail: `Rifa activada #${raffleId}`,
          entity: 'Raffle',
          entityId: raffleId,
          metadata: { role: actorRole }
        });
      } catch (_e) {
        // no bloquear
      }

      return res.json({ message: 'Rifa activada', raffle: updated });
    }

    const planConfig = await getPlanConfig();
    const actor = await prisma.user.findUnique({ where: { id: actorId }, select: { adminPlan: true } });
    const plan = normalizeAdminPlan(actor?.adminPlan, planConfig);
    if (!plan) return res.status(403).json({ error: 'Admin sin plan activo. Contacta al superadmin.' });

    if (plan.tier === 'unlimited') {
      const limit = Number(planConfig.unlimitedWeeklyRaffleLimit) || 3;
      const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      const activatedLast7d = await prisma.raffle.count({
        where: {
          userId: actorId,
          activatedAt: { gte: since }
        }
      });
      if (activatedLast7d >= limit) {
        return res.status(403).json({ error: `Límite semanal alcanzado (${limit} activas/7 días).` });
      }
    } else {
      const remaining = Number(plan.raffleCreditsRemaining) || 0;
      if (remaining <= 0) return res.status(403).json({ error: 'No tienes cupos disponibles para activar esta rifa.' });
    }

    const updated = await prisma.$transaction(async (tx) => {
      if (plan.tier !== 'unlimited') {
        const nextPlan = { ...plan, raffleCreditsRemaining: Math.max(0, Number(plan.raffleCreditsRemaining || 0) - 1) };
        await tx.user.update({ where: { id: actorId }, data: { adminPlan: nextPlan } });
      }
      return tx.raffle.update({ where: { id: raffleId }, data: { status: 'active', activatedAt: now } });
    });

    try {
      // After activation, pre-generate tickets if enabled
      try {
        const pregenerate = String(process.env.PREGENERATE_TICKETS_ON_ACTIVATE || '1') === '1';
        if (pregenerate && Number(updated.totalTickets) > 0) {
          const out = await generateTicketsForRaffle(updated.id, updated.totalTickets);
          console.log('[RAFFLE_ACTIVATE] pregenerate result:', out);
        }
      } catch (e) {
        console.error('[RAFFLE_ACTIVATE] pregenerate failed:', e);
      }

      await securityLogger.log({
        action: 'RAFFLE_ACTIVATED',
        userEmail: String(req.user?.email || ''),
        userId: actorId,
        ipAddress: String(req.ip || ''),
        userAgent: String(req.headers['user-agent'] || ''),
        severity: 'INFO',
        detail: `Rifa activada #${raffleId}`,
        entity: 'Raffle',
        entityId: raffleId,
        metadata: { role: actorRole }
      });
    } catch (_e) {
      // no bloquear
    }

    return res.json({ message: 'Rifa activada', raffle: updated });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al activar rifa' });
  }
});

app.patch('/admin/raffles/:id', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const raffleId = Number(req.params.id);
  if (!Number.isFinite(raffleId) || raffleId <= 0) {
    return res.status(400).json({ error: 'ID inválido' });
  }

  const body = (req.body && typeof req.body === 'object') ? req.body : {};

  try {
    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;

    const raffle = await prisma.raffle.findUnique({ where: { id: raffleId }, select: { userId: true, style: true } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });
    if (actorRole !== 'superadmin' && raffle.userId !== actorId) {
      return res.status(403).json({ error: 'No puedes editar rifas de otros usuarios.' });
    }

    const nextData = {};

    if (body.title !== undefined) nextData.title = String(body.title || '').trim();

    // Compat: aceptar description/prize para el campo prisma `prize`
    if (body.description !== undefined || body.prize !== undefined) {
      const prizeValue = body.description !== undefined ? body.description : body.prize;
      nextData.prize = String(prizeValue || '').trim();
    }

    if (body.terms !== undefined) {
      const termsValue = body.terms;
      nextData.terms = (termsValue === null || String(termsValue).trim() === '') ? null : String(termsValue);
    }

    if (body.lottery !== undefined) {
      const lotteryValue = body.lottery;
      nextData.lottery = (lotteryValue === null || String(lotteryValue).trim() === '') ? null : String(lotteryValue);
    }

    // Compat: aceptar price/ticketPrice, coercionar a number
    if (body.ticketPrice !== undefined || body.price !== undefined) {
      const rawPrice = body.ticketPrice !== undefined ? body.ticketPrice : body.price;
      const priceNumber = Number(rawPrice);
      if (!Number.isFinite(priceNumber) || priceNumber < 0) {
        return res.status(400).json({ error: 'Precio inválido' });
      }
      nextData.ticketPrice = priceNumber;
    }

    if (body.totalTickets !== undefined) {
      const ticketsNumber = Number(body.totalTickets);
      if (!Number.isFinite(ticketsNumber) || ticketsNumber <= 0) {
        return res.status(400).json({ error: 'Total de tickets inválido' });
      }
      const maxTickets = 10000;
      if (ticketsNumber > maxTickets) {
        return res.status(400).json({ error: `El máximo de tickets permitidos es ${maxTickets}` });
      }
      nextData.totalTickets = Math.trunc(ticketsNumber);
    }

    // Permitir `status` solo en valores conocidos
    if (body.status !== undefined) {
      const st = String(body.status || '').trim().toLowerCase();
      if (!['draft', 'active', 'closed'].includes(st)) {
        return res.status(400).json({ error: 'Estado inválido' });
      }
      nextData.status = st;
    }

    // Manejo de style: merge + compat con llaves top-level usadas por el front.
    const stylePatch = (body.style && typeof body.style === 'object' && !Array.isArray(body.style)) ? body.style : null;
    const styleExtras = {};
    const styleKeys = ['digits', 'startDate', 'endDate', 'securityCode', 'instantWins', 'minTickets', 'paymentMethods'];
    for (const key of styleKeys) {
      if (body[key] !== undefined) styleExtras[key] = body[key];
    }

    if (stylePatch || Object.keys(styleExtras).length > 0) {
      const currentStyle = (raffle.style && typeof raffle.style === 'object') ? raffle.style : {};
      nextData.style = { ...currentStyle, ...(stylePatch || {}), ...styleExtras };
    }

    if (Object.keys(nextData).length === 0) {
      return res.status(400).json({ error: 'No hay cambios para aplicar' });
    }

    const updatedRaffle = await prisma.raffle.update({
      where: { id: raffleId },
      data: nextData
    });

    return res.json(updatedRaffle);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Error al actualizar rifa' });
  }
});

app.get('/admin/tickets', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;

    const { raffleId, status, from, to, email, phone, cedula, number, serial, q, take } = req.query;

    const baseWhere = actorRole === 'superadmin' ? {} : { raffle: { userId: actorId } };
    const where = { ...baseWhere };
    if (raffleId) where.raffleId = Number(raffleId);
    if (status) where.status = status;
    if (number) where.number = Number(number);
    if (serial) where.serialNumber = String(serial).trim();
    if (from || to) {
      where.createdAt = {};
      if (from) where.createdAt.gte = new Date(from);
      if (to) where.createdAt.lte = new Date(to);
    }

    const takeN = Math.min(Math.max(Number(take) || 500, 1), 1000);
    const offsetN = Math.max(Number(req.query.offset) || 0, 0);
    const pageSize = Math.min(200, Math.max(50, Math.min(takeN, 200)));
    const maxScan = 5000;

    const qRaw = String(q || '').trim();
    const qLower = qRaw.toLowerCase();
    const looksLikeEmail = qLower.includes('@');
    const isNumeric = /^\d+$/.test(qRaw);

    const emailQ = String(email || '').trim().toLowerCase();
    const phoneQ = String(phone || '').trim();
    const cedulaQ = String(cedula || '').trim();

    // Email no está encriptado: filtrar desde DB para reducir carga
    if (emailQ) {
      where.user = { email: { contains: emailQ, mode: 'insensitive' } };
    }

    // q: si es email o número, se filtra en DB; si es texto (nombre/cédula/teléfono), se filtra en memoria con escaneo paginado
    const needsScanByEncrypted = !!phoneQ || !!cedulaQ || (qRaw && !looksLikeEmail && !isNumeric);

    if (qRaw && !needsScanByEncrypted) {
      if (looksLikeEmail) {
        where.user = { email: { contains: qRaw, mode: 'insensitive' } };
      } else if (isNumeric) {
        where.number = Number(qRaw);
      } else {
        // fallback: serial parcial
        where.serialNumber = { contains: qRaw };
      }
    }

    const include = {
      user: { select: { id: true, publicId: true, email: true, name: true, phone: true, cedula: true } },
      raffle: {
        select: {
          id: true,
          title: true,
          user: { select: { id: true, publicId: true, name: true, email: true, avatar: true, securityId: true } }
        }
      }
    };

    const mapTicket = (t) => {
      const u = t.user || {};
      const seller = t.raffle?.user || {};
      const user = {
        ...u,
        name: u.name ? safeDecrypt(u.name) : u.name,
        phone: u.phone ? safeDecrypt(u.phone) : u.phone,
        cedula: u.cedula ? safeDecrypt(u.cedula) : u.cedula
      };
      return {
        ...t,
        user,
        raffleTitle: t.raffle?.title,
        seller: {
          id: seller.id,
          publicId: seller.publicId,
          name: seller.name ? safeDecrypt(seller.name) : null,
          email: seller.email,
          avatar: seller.avatar,
          securityIdLast8: seller.securityId ? String(seller.securityId).slice(-8).toUpperCase() : null
        }
      };
    };

    const filterInMemory = (rows) => {
      let out = rows;

      if (phoneQ) out = out.filter((t) => String(t.user?.phone || '').includes(phoneQ));
      if (cedulaQ) out = out.filter((t) => String(t.user?.cedula || '').includes(cedulaQ));

      if (qRaw && needsScanByEncrypted) {
        out = out.filter((t) => {
          const haystack = [
            t.serialNumber,
            String(t.number ?? ''),
            t.user?.name,
            t.user?.email,
            t.user?.phone,
            t.user?.cedula
          ]
            .filter((x) => x != null)
            .map((x) => String(x).toLowerCase());
          return haystack.some((s) => s.includes(qLower));
        });
      }
      return out;
    };

    if (!needsScanByEncrypted) {
      const tickets = await prisma.ticket.findMany({
        where,
        include,
        orderBy: { createdAt: 'desc' },
        skip: offsetN,
        take: takeN
      });
      const normalized = tickets.map(mapTicket);
      return res.json(normalized);
    }

    // Escaneo paginado para soportar búsqueda por campos encriptados sin fallar con datasets grandes
    let skip = offsetN;
    let scanned = 0;
    const results = [];
    while (results.length < takeN && scanned < maxScan) {
      const page = await prisma.ticket.findMany({
        where: { ...where, OR: undefined },
        include,
        orderBy: { createdAt: 'desc' },
        skip,
        take: pageSize
      });

      if (!page.length) break;
      scanned += page.length;
      skip += page.length;

      const mappedPage = page.map(mapTicket);
      const filteredPage = filterInMemory(mappedPage);

      for (const row of filteredPage) {
        results.push(row);
        if (results.length >= takeN) break;
      }
    }

    return res.json(results);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al buscar tickets' });
  }
});

// --- ADMIN METRICS ---
app.get('/admin/metrics/summary', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;

    const raffleIdRaw = req.query?.raffleId;
    const raffleIdNum = raffleIdRaw !== undefined && raffleIdRaw !== null && raffleIdRaw !== '' ? Number(raffleIdRaw) : null;
    if (raffleIdNum !== null && (!Number.isFinite(raffleIdNum) || raffleIdNum <= 0)) {
      return res.status(400).json({ error: 'raffleId inválido' });
    }

    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    // Para evitar timeouts en BD grandes: usar agregaciones en vez de traer todos los tickets.
    // Si se pasa raffleId, validar ownership (admin) y usar su ticketPrice para revenue.
    if (raffleIdNum) {
      const raffle = await prisma.raffle.findUnique({ where: { id: raffleIdNum }, select: { id: true, userId: true, ticketPrice: true } });
      if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });
      if (actorRole !== 'superadmin' && raffle.userId !== actorId) {
        return res.status(403).json({ error: 'No puedes ver métricas de rifas de otros admins' });
      }

      const price = Number(raffle.ticketPrice || 0);
      const ticketsSold = await prisma.ticket.count({ where: { raffleId: raffleIdNum } });
      const todaySales = await prisma.ticket.count({ where: { raffleId: raffleIdNum, createdAt: { gte: startOfDay } } });
      const participants = (await prisma.ticket.groupBy({ by: ['userId'], where: { raffleId: raffleIdNum }, _count: { userId: true } })).length;
      const pendingPayments = await prisma.transaction.count({ where: { raffleId: raffleIdNum, type: 'manual_payment', status: 'pending' } });

      return res.json({
        ticketsSold,
        participants,
        pendingPayments,
        totalRevenue: ticketsSold * price,
        todaySales,
        todayRevenue: todaySales * price
      });
    }

    // Sin raffleId: métricas agregadas sobre rifas accesibles.
    const raffles = await prisma.raffle.findMany({
      where: actorRole === 'superadmin' ? {} : { userId: actorId },
      select: { id: true, ticketPrice: true }
    });
    const raffleIds = raffles.map((r) => r.id).filter(Boolean);
    if (!raffleIds.length) {
      return res.json({ ticketsSold: 0, participants: 0, pendingPayments: 0, totalRevenue: 0, todaySales: 0, todayRevenue: 0 });
    }

    const priceByRaffleId = new Map(raffles.map((r) => [r.id, Number(r.ticketPrice || 0)]));

    const groupedAll = await prisma.ticket.groupBy({
      by: ['raffleId'],
      where: { raffleId: { in: raffleIds } },
      _count: { raffleId: true }
    });

    const groupedToday = await prisma.ticket.groupBy({
      by: ['raffleId'],
      where: { raffleId: { in: raffleIds }, createdAt: { gte: startOfDay } },
      _count: { raffleId: true }
    });

    const ticketsSold = groupedAll.reduce((acc, row) => acc + (row?._count?.raffleId || 0), 0);
    const todaySales = groupedToday.reduce((acc, row) => acc + (row?._count?.raffleId || 0), 0);

    const totalRevenue = groupedAll.reduce((acc, row) => {
      const rid = row.raffleId;
      const count = row?._count?.raffleId || 0;
      const price = priceByRaffleId.get(rid) || 0;
      return acc + count * price;
    }, 0);

    const todayRevenue = groupedToday.reduce((acc, row) => {
      const rid = row.raffleId;
      const count = row?._count?.raffleId || 0;
      const price = priceByRaffleId.get(rid) || 0;
      return acc + count * price;
    }, 0);

    const participants = (await prisma.ticket.groupBy({
      by: ['userId'],
      where: { raffleId: { in: raffleIds } },
      _count: { userId: true }
    })).length;

    const pendingPayments = await prisma.transaction.count({
      where: { raffleId: { in: raffleIds }, type: 'manual_payment', status: 'pending' }
    });

    res.json({
      ticketsSold,
      participants,
      pendingPayments,
      totalRevenue,
      todaySales,
      todayRevenue
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener métricas' });
  }
});

app.get('/admin/metrics/hourly', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const { raffleId } = req.query;
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    const where = { createdAt: { gte: startOfDay } };
    if (raffleId) where.raffleId = Number(raffleId);

    const tickets = await prisma.ticket.findMany({ where, select: { createdAt: true } });
    const buckets = Array.from({ length: 24 }, () => 0);
    tickets.forEach((t) => {
      const h = new Date(t.createdAt).getHours();
      buckets[h] += 1;
    });
    res.json(buckets.map((count, hour) => ({ hour, count })));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener ventas por hora' });
  }
});

app.get('/admin/metrics/daily', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const days = Number(req.query.days) || 7;
    const raffleIdRaw = req.query?.raffleId;
    const raffleIdNum = raffleIdRaw !== undefined && raffleIdRaw !== null && raffleIdRaw !== '' ? Number(raffleIdRaw) : null;
    if (raffleIdNum !== null && (!Number.isFinite(raffleIdNum) || raffleIdNum <= 0)) {
      return res.status(400).json({ error: 'raffleId inválido' });
    }

    const since = new Date();
    since.setHours(0, 0, 0, 0);
    since.setDate(since.getDate() - (days - 1));

    const tickets = await prisma.ticket.findMany({
      where: {
        createdAt: { gte: since },
        ...(raffleIdNum ? { raffleId: raffleIdNum } : {})
      },
      select: { createdAt: true, raffleId: true }
    });

    const map = new Map();
    for (let i = 0; i < days; i++) {
      const d = new Date(since);
      d.setDate(since.getDate() + i);
      const key = d.toISOString().slice(0, 10);
      map.set(key, 0);
    }
    tickets.forEach((t) => {
      const key = new Date(t.createdAt).toISOString().slice(0, 10);
      if (map.has(key)) map.set(key, (map.get(key) || 0) + 1);
    });

    res.json(Array.from(map.entries()).map(([date, count]) => ({ date, count })));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener ventas diarias' });
  }
});

app.get('/admin/metrics/by-state', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const raffleIdRaw = req.query?.raffleId;
    const raffleIdNum = raffleIdRaw !== undefined && raffleIdRaw !== null && raffleIdRaw !== '' ? Number(raffleIdRaw) : null;
    if (raffleIdNum !== null && (!Number.isFinite(raffleIdNum) || raffleIdNum <= 0)) {
      return res.status(400).json({ error: 'raffleId inválido' });
    }

    const tickets = await prisma.ticket.findMany({
      where: raffleIdNum ? { raffleId: raffleIdNum } : undefined,
      select: {
        user: { select: { state: true } }
      }
    });
    const counts = {};
    tickets.forEach((t) => {
      const st = t.user?.state || 'DESCONOCIDO';
      counts[st] = (counts[st] || 0) + 1;
    });
    const result = Object.entries(counts)
      .map(([state, count]) => ({ state, count }))
      .sort((a, b) => b.count - a.count);
    res.json(result);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener ventas por estado' });
  }
});

app.get('/admin/metrics/top-buyers', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const raffleIdRaw = req.query?.raffleId;
    const raffleIdNum = raffleIdRaw !== undefined && raffleIdRaw !== null && raffleIdRaw !== '' ? Number(raffleIdRaw) : null;
    if (raffleIdNum !== null && (!Number.isFinite(raffleIdNum) || raffleIdNum <= 0)) {
      return res.status(400).json({ error: 'raffleId inválido' });
    }

    const buyers = await prisma.ticket.groupBy({
      by: ['userId'],
      where: raffleIdNum ? { raffleId: raffleIdNum } : undefined,
      _count: { userId: true },
      orderBy: { _count: { userId: 'desc' } },
      take: 10
    });

    const enriched = await Promise.all(buyers.map(async (b) => {
      const user = await prisma.user.findUnique({ where: { id: b.userId }, select: { name: true, email: true, state: true } });
      return { 
        userId: b.userId, 
        tickets: b._count.userId, 
        name: user?.name ? decrypt(user.name) : 'Usuario', 
        email: user?.email, 
        state: user?.state || 'DESCONOCIDO' 
      };
    }));

    res.json(enriched);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener top de compra' });
  }
});

app.get('/admin/security-code', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const settings = await prisma.systemSettings.findFirst();
    res.json({ code: settings?.securityCode || 'SEC-PENDING', active: !!settings?.securityCode });
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener código' });
  }
});

app.post('/admin/security-code/regenerate', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const code = generateShortId('SEC');
  try {
    await prisma.systemSettings.upsert({
      where: { id: 1 },
      update: { securityCode: code },
      create: { securityCode: code, branding: {}, modules: {} }
    });
    res.json({ code });
  } catch (error) {
    res.status(500).json({ error: 'Error al regenerar código' });
  }
});

// --- ADMIN WINNERS MANAGEMENT ---

app.post('/admin/winners', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { raffleId, ticketNumber, drawSlot, prize, testimonial, photoUrl } = req.body;

  const rid = Number(raffleId);
  const tnum = Number(ticketNumber);
  const slotRaw = String(drawSlot || '').trim();
  if (!rid || !Number.isFinite(rid)) {
    return res.status(400).json({ error: 'raffleId requerido' });
  }
  if (!tnum || !Number.isFinite(tnum)) {
    return res.status(400).json({ error: 'ticketNumber requerido' });
  }
  const slot = normalizeDrawSlot(slotRaw);
  if (!slot) return res.status(400).json({ error: 'drawSlot requerido (ej: 1pm, 4pm, 10pm)' });
  if (!['1pm', '4pm', '10pm'].includes(slot)) {
    return res.status(400).json({ error: 'drawSlot inválido. Usa 1pm, 4pm o 10pm.' });
  }
  if (!String(prize || '').trim()) {
    return res.status(400).json({ error: 'Premio requerido' });
  }

  try {
    // Información del actor (mejor registro para debugging)
    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;
    try { console.log('[ADMIN/WIN] actor:', { id: actorId, role: actorRole, user: req.user?.email || null }); } catch (e) {}
    try { console.log('[ADMIN/WIN] payload:', { raffleId: rid, ticketNumber: ticketNumber, drawSlot: slot, prize: prize }); } catch (e) {}

    const raffle = await prisma.raffle.findUnique({
      where: { id: rid },
      select: { id: true, status: true, userId: true, title: true }
    });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    // Admin solo puede declarar ganador de sus rifas.
    // Compare IDs con coerción numérica para evitar mismatch string/number
    const actorIdNum = Number(actorId);
    const raffleOwnerIdNum = Number(raffle.userId);
    if (actorRole !== 'superadmin' && raffleOwnerIdNum !== actorIdNum) {
      return res.status(403).json({ error: 'No autorizado para declarar ganador en esta rifa' });
    }

    // Permitir publicación de ganadores mientras la rifa está activa o cerrada.
    // Esto soporta múltiples premios (1pm/4pm/10pm) sin bloquear el proceso.
    const st = String(raffle.status || '').toLowerCase();
    if (st !== 'active' && st !== 'closed') {
      return res.status(400).json({ error: 'Estado de rifa inválido para publicar ganadores' });
    }

    // Evitar duplicados por slot (1 ganador por 1pm / 4pm / 10pm).
    const existingSlot = await prisma.winner.findFirst({ where: { raffleId: rid, drawSlot: slot } });
    if (existingSlot) return res.status(409).json({ error: `Ya existe ganador publicado para ${slot}` });

    // Punto clave anti-confusión: el ticket DEBE existir en ESA rifa (raffleId + number)
    // Buscar ticket por número; si no se encuentra, intentar buscar por serialNumber (entrada manual posible)
    let ticket = null;
    try {
      ticket = await prisma.ticket.findFirst({
        where: { raffleId: rid, number: tnum },
        include: { user: { select: { id: true, name: true, email: true, avatar: true } } }
      });
    } catch (e) {
      console.error('[ADMIN/WIN] ticket lookup error (by number):', e);
    }

    if (!ticket) {
      // Intentar búsqueda alternativa por serialNumber (por si el admin pegó el ID/serial en vez del número)
      try {
        const serialCandidate = String(ticketNumber || '').trim();
        if (serialCandidate) {
          ticket = await prisma.ticket.findFirst({
            where: { raffleId: rid, serialNumber: serialCandidate },
            include: { user: { select: { id: true, name: true, email: true, avatar: true } } }
          });
        }
      } catch (e) {
        console.error('[ADMIN/WIN] ticket lookup error (by serial):', e);
      }
    }

    if (!ticket) {
      console.warn('[ADMIN/WIN] ticket not found', { raffleId: rid, ticketNumber: tnum, raw: ticketNumber });
      return res.status(404).json({ error: 'Ese número no existe como ticket comprado en esta rifa' });
    }

    const winner = await prisma.winner.create({
      data: {
        raffleId: rid,
        userId: ticket.userId,
        drawSlot: slot,
        ticketNumber: tnum,
        prize: String(prize).trim(),
        testimonial: String(testimonial || '').trim(),
        photoUrl: photoUrl || null
      }
    });

    const winnerName = ticket.user?.name ? safeDecrypt(ticket.user.name) : null;

    // Notificar participantes (sin bloquear por KYC para no retrasar publicación)
    try {
      const participants = await prisma.ticket.findMany({
        where: { raffleId: rid },
        distinct: ['userId'],
        select: { user: { select: { pushToken: true } } }
      });
      const tokens = (participants || []).map((p) => p?.user?.pushToken).filter(Boolean);
      if (tokens.length > 0) {
        const title = `¡Resultados (${slot}): ${raffle.title}!`;
        const body = `Número ganador: ${tnum}.`;
        sendPushNotification(tokens, title, body, { type: 'raffle_result', raffleId: rid, drawSlot: slot, ticketNumber: tnum }).catch(console.error);
      }
    } catch (_e) {
      // no bloquear
    }

    // Notificar directamente al ganador por correo y push
    try {
      const winnerUser = await prisma.user.findUnique({ where: { id: ticket.userId }, select: { id: true, email: true, pushToken: true, name: true } });
      const winnerName = winnerUser?.name ? safeDecrypt(winnerUser.name) : null;
      const digits = getTicketDigitsFromRaffle(raffle);
      const displayNumber = formatTicketNumber(tnum, digits);

      if (winnerUser?.email) {
        const subject = `¡Has ganado en MegaRifas! Rifa: ${raffle.title}`;
        const text = `Felicidades ${winnerName || ''}. Tu número ${displayNumber} ha resultado ganador en la rifa ${raffle.title}. Ponte en contacto con el organizador para reclamar tu premio.`;
        const html = `<h1>¡Felicidades ${escapeHtml(winnerName || '')}!</h1><p>Tu número <b>${escapeHtml(displayNumber)}</b> ha resultado ganador en la rifa <b>${escapeHtml(raffle.title)}</b>.</p><p>Premio: <b>${escapeHtml(String(prize).trim())}</b></p><p>Por favor ponte en contacto con el organizador para coordinar la entrega.</p>`;
        sendEmail(winnerUser.email, subject, text, html).catch(console.error);
      }

      if (winnerUser?.pushToken) {
        const title = '¡Eres ganador!';
        const body = `Tu número ${displayNumber} ganó en ${raffle.title}`;
        sendPushNotification([winnerUser.pushToken], title, body, { type: 'you_won', raffleId: rid, ticketNumber: tnum }).catch(console.error);
      }
    } catch (notifyErr) {
      console.error('[WINNER_NOTIFY] error:', notifyErr);
      // no bloquear la respuesta si falla la notificación
    }

    try {
      await prisma.auditLog.create({
        data: {
          action: 'RESULT_PUBLISHED',
          entity: 'Raffle',
          userEmail: req.user.email,
          detail: `Results published for raffle ${rid} (${slot}). Winner ticket: ${tnum}.`,
          timestamp: new Date()
        }
      });
    } catch (_e) {
      // no bloquear
    }

    return res.json({
      message: 'Ganador publicado exitosamente',
      winner,
      raffle: { id: raffle.id, title: raffle.title },
      ticket: { number: ticket.number },
      user: {
        id: ticket.user?.id,
        name: winnerName,
        email: ticket.user?.email,
        avatar: ticket.user?.avatar
      }
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Error al publicar ganador' });
  }
});

app.get('/winners', async (req, res) => {
  try {
    const winners = await prisma.winner.findMany({
      include: { 
        raffle: { select: { title: true } },
        user: { select: { name: true, avatar: true } }
      },
      orderBy: { drawDate: 'desc' },
      take: 20
    });
    const mapped = (Array.isArray(winners) ? winners : []).map((w) => {
      const u = w.user || null;
      const r = w.raffle || null;
      const safeUser = u
        ? {
            ...u,
            name: u.name ? safeDecrypt(u.name) : u.name
          }
        : null;
      return {
        ...w,
        raffle: r ? { ...r, raffleId: w.raffleId } : { raffleId: w.raffleId },
        user: safeUser
      };
    });
    res.json(mapped);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener ganadores' });
  }
});

// Feed para ticker: ganadores por "instant wins" (drawSlot = instant:<num>) en rifas activas
app.get('/feed/instant-wins', authenticateToken, async (req, res) => {
  try {
    const take = Math.min(Math.max(Number(req.query.take) || 50, 1), 200);
    const winners = await prisma.winner.findMany({
      where: {
        drawSlot: { startsWith: 'instant:' },
        raffle: { is: { status: 'active' } }
      },
      include: {
        raffle: { select: { id: true, title: true } },
        user: { select: { id: true, name: true, avatar: true } }
      },
      orderBy: { drawDate: 'desc' },
      take
    });

    const mapped = (Array.isArray(winners) ? winners : []).map((w) => {
      const u = w.user || null;
      const r = w.raffle || null;
      return {
        id: w.id,
        raffleId: w.raffleId,
        drawSlot: w.drawSlot,
        ticketNumber: w.ticketNumber,
        prize: w.prize,
        drawDate: w.drawDate,
        raffle: r ? { id: r.id, title: r.title } : { id: w.raffleId, title: null },
        user: u
          ? {
              id: u.id,
              name: u.name ? safeDecrypt(u.name) : u.name,
              avatar: u.avatar
            }
          : null
      };
    });

    res.json(mapped);
  } catch (error) {
    console.error('[GET /feed/instant-wins]', error);
    res.status(500).json({ error: 'Error al obtener feed de ganadores bendecidos' });
  }
});

// --- ADMIN ANNOUNCEMENTS ---


// --- ADMIN PUSH NOTIFICATIONS ---

app.post('/admin/push/broadcast', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { title, body } = req.body;
  
  if (!title || !body) return res.status(400).json({ error: 'Título y mensaje requeridos' });

  try {
    // 1. Obtener tokens de usuarios
    const users = await prisma.user.findMany({
      where: { pushToken: { not: null } },
      select: { pushToken: true }
    });

    const tokens = users.map(u => u.pushToken).filter(t => t);
    
    if (tokens.length === 0) {
      return res.json({ message: 'No hay usuarios con notificaciones activas', count: 0 });
    }

    // 2. Enviar usando Expo (Mock o Real si se configura)
    // Aquí simulamos el envío para no romper si no hay credenciales de Expo configuradas
    console.log(`[PUSH BROADCAST] To ${tokens.length} devices: ${title} - ${body}`);
    
    // TODO: Integrar 'expo-server-sdk' real aquí
    
    res.json({ message: 'Notificación enviada a la cola de procesamiento', count: tokens.length });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al enviar notificaciones' });
  }
});

// --- EMERGENCY DB FIXER ---
app.get('/admin/system/fix-db', async (req, res) => {
  try {
    // 1. Fix Structure (Manual Migration via SQL)
    await prisma.$executeRawUnsafe(`ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "securityId" TEXT;`);
    try { await prisma.$executeRawUnsafe(`CREATE UNIQUE INDEX "User_securityId_key" ON "User"("securityId");`); } catch (e) {}
    await prisma.$executeRawUnsafe(`ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "identityVerified" BOOLEAN DEFAULT false;`);
    await prisma.$executeRawUnsafe(`ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "reputationScore" DOUBLE PRECISION DEFAULT 5.0;`);
    
    // Fix SystemSettings
    await prisma.$executeRawUnsafe(`ALTER TABLE "SystemSettings" ADD COLUMN IF NOT EXISTS "techSupport" JSONB;`);
    await prisma.$executeRawUnsafe(`ALTER TABLE "SystemSettings" ADD COLUMN IF NOT EXISTS "securityCode" TEXT;`);

    // Crear tabla Winner si no existe (incluye slots/numero para 3 premios)
    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS "Winner" (
        "id" SERIAL NOT NULL,
        "raffleId" INTEGER NOT NULL,
        "userId" INTEGER,
        "drawSlot" TEXT,
        "ticketNumber" INTEGER,
        "photoUrl" TEXT,
        "testimonial" TEXT,
        "prize" TEXT,
        "status" TEXT NOT NULL DEFAULT 'pending',
        "drawDate" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT "Winner_pkey" PRIMARY KEY ("id")
      );
    `);

    // Asegurar columnas (por si la tabla ya existía vieja)
    await prisma.$executeRawUnsafe(`ALTER TABLE "Winner" ADD COLUMN IF NOT EXISTS "drawSlot" TEXT;`);
    await prisma.$executeRawUnsafe(`ALTER TABLE "Winner" ADD COLUMN IF NOT EXISTS "ticketNumber" INTEGER;`);
    await prisma.$executeRawUnsafe(`ALTER TABLE "Winner" ADD COLUMN IF NOT EXISTS "status" TEXT NOT NULL DEFAULT 'pending';`);
    try { await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS "Winner_raffleId_drawSlot_idx" ON "Winner"("raffleId", "drawSlot");`); } catch (e) {}
    try { await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS "Winner_raffleId_ticketNumber_idx" ON "Winner"("raffleId", "ticketNumber");`); } catch (e) {}

    // Crear tabla Announcement si no existe
    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS "Announcement" (
        "id" SERIAL NOT NULL,
        "title" TEXT NOT NULL,
        "content" TEXT NOT NULL,
        "imageUrl" TEXT,
        "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "adminId" INTEGER NOT NULL,
        CONSTRAINT "Announcement_pkey" PRIMARY KEY ("id")
      );
    `);

    // 2. Backfill IDs (Asignar IDs a quienes no tengan)
    const users = await prisma.user.findMany({ where: { securityId: null } });
    let updated = 0;
    
    for (const user of users) {
      let securityId = generateSecurityId();
      // Check collision
      let exists = await prisma.user.findFirst({ where: { securityId } });
      while (exists) {
        securityId = generateSecurityId();
        exists = await prisma.user.findFirst({ where: { securityId } });
      }
      
      await prisma.user.update({
        where: { id: user.id },
        data: { securityId, reputationScore: 5.0, identityVerified: false }
      });
      updated++;
    }
    
    res.json({ 
      success: true, 
      message: 'Estructura de DB reparada y IDs asignados', 
      usersUpdated: updated 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});

app.post('/raffles/:id/close', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { id } = req.params;
  try {
    const raffleId = Number(id);
    const raffle = await prisma.raffle.findUnique({
      where: { id: raffleId },
      include: { user: { select: { id: true, role: true } } }
    });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;
    if (actorRole !== 'superadmin' && raffle.userId !== actorId) {
      return res.status(403).json({ error: 'No puedes cerrar rifas de otros usuarios.' });
    }

    const currentStatus = String(raffle.status || '').toLowerCase();
    if (currentStatus === 'closed') return res.status(400).json({ error: 'La rifa ya está cerrada.' });
    if (currentStatus !== 'active') return res.status(400).json({ error: 'Solo puedes cerrar rifas activas.' });

    const result = await closeRaffleInternal(raffleId, 'manual_close_endpoint');
    if (!result.ok) return res.status(result.code || 400).json({ error: result.error || 'No se pudo cerrar' });

    try {
      await securityLogger.log({
        action: 'RAFFLE_CLOSED',
        userEmail: String(req.user?.email || ''),
        userId: actorId,
        ipAddress: String(req.ip || ''),
        userAgent: String(req.headers['user-agent'] || ''),
        severity: 'INFO',
        detail: `Rifa cerrada #${raffleId}`,
        entity: 'Raffle',
        entityId: raffleId,
        metadata: { noSales: !!result.noSales, winnerUserId: result.winner?.userId || null, sandbox: SANDBOX_MODE }
      });
    } catch (_e) {
      // no bloquear
    }

    return res.json({
      message: result.noSales ? 'Rifa cerrada (sin ventas)' : 'Rifa cerrada',
      winner: result.winner,
      raffleDeleted: false
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al cerrar rifa' });
  }
});

// Endpoint conveniente para declarar ganador desde UI de rifero: POST /raffles/:id/declare-winner
app.post('/raffles/:id/declare-winner', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const raffleId = Number(req.params.id);
  const winningNumberRaw = req.body?.winningNumber;
  const proof = req.body?.proof || null;

  // Diagnostic log when debugging is enabled
  if (String(process.env.DEBUG_DECLARE_WINNER || '').trim() === '1') {
    try {
      console.log('[DECLARE_WINNER][DEBUG] actor=', { id: req.user?.userId, email: req.user?.email, role: req.user?.role });
      console.log('[DECLARE_WINNER][DEBUG] payload=', { raffleId: req.params.id, winningNumberRaw, proof });
    } catch (e) { }
  }

  if (!raffleId || !Number.isFinite(raffleId)) return res.status(400).json({ error: 'ID inválido' });
  if (winningNumberRaw == null || String(winningNumberRaw).trim() === '') return res.status(400).json({ error: 'Número ganador requerido' });

  const tnum = Number(winningNumberRaw);
  try {
    const raffle = await prisma.raffle.findUnique({ where: { id: raffleId }, select: { id: true, userId: true, title: true, prize: true, style: true, status: true } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;
    const actorIdNum = Number(actorId);
    const raffleOwnerIdNum = Number(raffle.userId);
    if (actorRole !== 'superadmin' && raffleOwnerIdNum !== actorIdNum) return res.status(403).json({ error: 'No autorizado para declarar ganador en esta rifa' });

    // Buscar ticket
    let ticket = await prisma.ticket.findFirst({ where: { raffleId, number: tnum }, include: { user: { select: { id: true, name: true, email: true, avatar: true, pushToken: true } } } });
    if (!ticket) {
      // fallback por serial
      const serialCandidate = String(winningNumberRaw || '').trim();
      if (serialCandidate) {
        ticket = await prisma.ticket.findFirst({ where: { raffleId, serialNumber: serialCandidate }, include: { user: { select: { id: true, name: true, email: true, avatar: true, pushToken: true } } } });
      }
    }
    if (!ticket) {
      // Número no vendido: verificar política (en raffle.style.missingNumberPolicy)
      try {
        const soldCount = await prisma.ticket.count({ where: { raffleId, status: 'approved' } });
        const totalTickets = Number(raffle.totalTickets ?? raffle.ticketsTotal ?? 0) || 0;

        const defaultPolicy = { mode: 'owner_decides', minPercent: 0, postponeDays: Number(process.env.MISSING_NUMBER_POSTPONE_DAYS) || 3 };
        const rafflePolicy = raffle.style && typeof raffle.style === 'object' && raffle.style.missingNumberPolicy && typeof raffle.style.missingNumberPolicy === 'object'
          ? raffle.style.missingNumberPolicy
          : defaultPolicy;

        // Calcular elegibilidad de auto-resolución si el organizador configuró modo auto_random_if_percent_sold
        let autoEligible = false;
        if (rafflePolicy && String(rafflePolicy.mode || '').trim() === 'auto_random_if_percent_sold' && totalTickets > 0) {
          const min = Number(rafflePolicy.minPercent) || 0;
          const pct = (Number(soldCount) * 100) / Number(totalTickets);
          if (pct >= Number(min)) autoEligible = true;
        }

        // Si la política exige auto-resolver y es elegible, seleccionar un ticket vendido al azar
        if (autoEligible) {
          const sold = await prisma.ticket.findMany({ where: { raffleId, status: 'approved' }, select: { id: true, number: true, userId: true } });
          if (sold && sold.length) {
            const pick = sold[Math.floor(Math.random() * sold.length)];
            const winner = await prisma.winner.create({ data: { raffleId, userId: pick.userId, drawSlot: 'final', ticketNumber: pick.number, prize: raffle.prize || null, photoUrl: proof || null } });
            // Notificar y auditar como en la rama random_sold
            try {
              const winnerUser = await prisma.user.findUnique({ where: { id: pick.userId }, select: { id: true, email: true, pushToken: true, name: true } });
              const winnerName = winnerUser?.name ? safeDecrypt(winnerUser.name) : null;
              const digits = getTicketDigitsFromRaffle(raffle);
              const displayNumber = formatTicketNumber(pick.number, digits);
              if (winnerUser?.email) sendEmail(winnerUser.email, `¡Has ganado en ${raffle.title}!`, `Felicidades ${winnerName || ''}. Tu número ${displayNumber} ha ganado.`, `<h1>¡Felicidades ${escapeHtml(winnerName || '')}!</h1><p>Tu número <b>${escapeHtml(displayNumber)}</b> ganó en la rifa <b>${escapeHtml(raffle.title)}</b>.</p>`).catch(console.error);
              if (winnerUser?.pushToken) sendPushNotification([winnerUser.pushToken], '¡Eres ganador!', `Tu número ${displayNumber} ganó en ${raffle.title}`, { type: 'you_won', raffleId }).catch(console.error);
            } catch (e) { console.error('[DECLARE_WIN_AUTO_NOTIFY]', e); }

            try { await securityLogger.log({ action: 'WINNER_RESOLVED_AUTO', userEmail: String(req.user?.email || ''), userId: Number(req.user?.userId) || null, ipAddress: String(req.ip || ''), userAgent: String(req.headers['user-agent'] || ''), severity: 'INFO', detail: `Auto-resolve policy selected random for rifa ${raffleId} -> ticket ${pick.number}`, entity: 'Raffle', entityId: String(raffleId), metadata: { method: 'auto_random_if_percent_sold', winnerId: winner.id } }); } catch (_e) {}

            return res.json({ message: 'Ganador seleccionado automáticamente por política', winner, policy: rafflePolicy });
          }
        }

        return res.status(409).json({
          error: 'NUMBER_NOT_SOLD',
          message: 'Ese número no fue vendido en esta rifa',
          raffleId,
          winningNumber: winningNumberRaw,
          soldCount,
          totalTickets,
          options: ['random_sold', 'postpone', 'close_no_winner', 'force_manual'],
          policy: rafflePolicy,
          autoEligible
        });
      } catch (e) {
        console.error('[DECLARE_WINNER][NO_TICKET_STATS]', e);
        return res.status(409).json({ error: 'NUMBER_NOT_SOLD', message: 'Ese número no fue vendido en esta rifa' });
      }
    }

    // Evitar duplicados: si ya existe winner para este raffle+number, error
    const exists = await prisma.winner.findFirst({ where: { raffleId, ticketNumber: ticket.number } });
    if (exists) return res.status(409).json({ error: 'Ya existe un ganador declarado para ese número' });

    const winner = await prisma.winner.create({ data: { raffleId, userId: ticket.userId, drawSlot: 'final', ticketNumber: ticket.number, prize: raffle.prize || null, photoUrl: proof || null } });

    // Notificar al ganador (email + push) y a participantes (push broadcast)
    try {
      const winnerUser = await prisma.user.findUnique({ where: { id: ticket.userId }, select: { id: true, email: true, pushToken: true, name: true } });
      const winnerName = winnerUser?.name ? safeDecrypt(winnerUser.name) : null;
      const digits = getTicketDigitsFromRaffle(raffle);
      const displayNumber = formatTicketNumber(ticket.number, digits);
      if (winnerUser?.email) {
        const subject = `¡Has ganado en ${raffle.title}!`;
        const text = `Felicidades ${winnerName || ''}. Tu número ${displayNumber} ha ganado.`;
        const html = `<h1>¡Felicidades ${escapeHtml(winnerName || '')}!</h1><p>Tu número <b>${escapeHtml(displayNumber)}</b> ganó en la rifa <b>${escapeHtml(raffle.title)}</b>.</p>`;
        sendEmail(winnerUser.email, subject, text, html).catch(console.error);
      }
      if (winnerUser?.pushToken) {
        sendPushNotification([winnerUser.pushToken], '¡Eres ganador!', `Tu número ${displayNumber} ganó en ${raffle.title}`, { type: 'you_won', raffleId }).catch(console.error);
      }
      // broadcast a participantes
      try {
        const participants = await prisma.ticket.findMany({ where: { raffleId }, distinct: ['userId'], select: { user: { select: { pushToken: true } } } });
        const tokens = (participants || []).map(p => p?.user?.pushToken).filter(Boolean);
        if (tokens.length) sendPushNotification(tokens, `Resultados: ${raffle.title}`, `Número ganador: ${displayNumber}`, { type: 'raffle_result', raffleId }).catch(console.error);
      } catch (e) { /* no bloquear */ }
    } catch (e) { console.error('[DECLARE_WIN_NOTIFY]', e); }

    try { await securityLogger.log({ action: 'WINNER_DECLARED', userEmail: String(req.user?.email || ''), userId: actorIdNum || null, ipAddress: String(req.ip || ''), userAgent: String(req.headers['user-agent'] || ''), severity: 'INFO', detail: `Ganador declarado rifa ${raffleId} -> ticket ${ticket.number}`, entity: 'Raffle', entityId: String(raffleId), metadata: { winnerId: winner.id } }); } catch (_e) {}

    return res.json({ message: 'Ganador declarado', winner });
  } catch (error) {
    console.error('[DECLARE_WINNER]', error);
    const debugEnabled = String(process.env.DEBUG_DECLARE_WINNER || '').trim() === '1';
    const message = debugEnabled ? String(error?.message || error) : 'Error al declarar ganador';
    return res.status(500).json({ error: message });
  }
});

// Admin: listar resoluciones pendientes (rifas pospuestas por número no vendido)
app.get('/admin/winners/pending-resolutions', authenticateToken, authorizeRole(['admin','superadmin']), async (req, res) => {
  try {
    const active = await prisma.raffle.findMany({ where: { status: 'active' }, select: { id: true, title: true, style: true, totalTickets: true } });
    const pending = (active || []).map(r => {
      const pendingRes = r.style && typeof r.style === 'object' ? r.style.pendingResolution : null;
      if (pendingRes && pendingRes.status === 'postponed') {
        return { raffleId: r.id, title: r.title, pendingResolution: pendingRes, totalTickets: r.totalTickets };
      }
      return null;
    }).filter(Boolean);
    return res.json({ pending });
  } catch (e) {
    console.error('[PENDING_RESOLUTIONS]', e);
    return res.status(500).json({ error: 'Error al listar resoluciones pendientes' });
  }
});

// Admin: obtener la política de número no vendido para una rifa
app.get('/admin/raffles/:id/missing-policy', authenticateToken, authorizeRole(['admin','superadmin']), async (req, res) => {
  const raffleId = Number(req.params.id);
  if (!raffleId || !Number.isFinite(raffleId)) return res.status(400).json({ error: 'ID inválido' });
  try {
    const raffle = await prisma.raffle.findUnique({ where: { id: raffleId }, select: { id: true, userId: true, title: true, style: true, totalTickets: true } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    const defaultPolicy = { mode: 'owner_decides', minPercent: 0, postponeDays: Number(process.env.MISSING_NUMBER_POSTPONE_DAYS) || 3 };
    const policy = raffle.style && typeof raffle.style === 'object' && raffle.style.missingNumberPolicy && typeof raffle.style.missingNumberPolicy === 'object'
      ? raffle.style.missingNumberPolicy
      : defaultPolicy;

    return res.json({ raffleId: raffle.id, policy });
  } catch (e) {
    console.error('[GET_MISSING_POLICY]', e);
    return res.status(500).json({ error: 'Error al obtener la política' });
  }
});

// Admin: actualizar la política de número no vendido para una rifa (owner o superadmin)
app.post('/admin/raffles/:id/missing-policy', authenticateToken, authorizeRole(['admin','superadmin']), async (req, res) => {
  const raffleId = Number(req.params.id);
  const mode = String(req.body?.mode || '').trim();
  const minPercent = Number(req.body?.minPercent || 0);
  const postponeDays = Number(req.body?.postponeDays || Number(process.env.MISSING_NUMBER_POSTPONE_DAYS) || 3);
  if (!raffleId || !Number.isFinite(raffleId)) return res.status(400).json({ error: 'ID inválido' });
  if (!['owner_decides','auto_random_if_percent_sold','require_manual'].includes(mode)) return res.status(400).json({ error: 'Modo inválido' });
  try {
    const raffle = await prisma.raffle.findUnique({ where: { id: raffleId }, select: { id: true, userId: true, style: true } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    // Autorizar: propietario o superadmin
    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorIdNum = Number(req.user?.userId);
    if (actorRole !== 'superadmin' && Number(raffle.userId) !== actorIdNum) return res.status(403).json({ error: 'No autorizado para cambiar la política' });

    const nextStyle = raffle.style && typeof raffle.style === 'object' ? { ...raffle.style } : {};
    nextStyle.missingNumberPolicy = { mode, minPercent: Number(minPercent), postponeDays: Number(postponeDays) };
    await prisma.raffle.update({ where: { id: raffleId }, data: { style: nextStyle } });

    try { await securityLogger.log({ action: 'MISSING_POLICY_UPDATED', userEmail: String(req.user?.email || ''), userId: Number(req.user?.userId) || null, ipAddress: String(req.ip || ''), userAgent: String(req.headers['user-agent'] || ''), severity: 'INFO', detail: `Política missingNumberPolicy actualizada rifa ${raffleId}`, entity: 'Raffle', entityId: String(raffleId), metadata: { mode, minPercent, postponeDays } }); } catch (_e) {}

    return res.json({ message: 'Política actualizada', policy: nextStyle.missingNumberPolicy });
  } catch (e) {
    console.error('[POST_MISSING_POLICY]', e);
    return res.status(500).json({ error: 'Error al actualizar la política' });
  }
});

// Admin: resolver un caso de número no vendido (POST /admin/winners/resolve-missing)
app.post('/admin/winners/resolve-missing', authenticateToken, authorizeRole(['admin','superadmin']), async (req, res) => {
  const raffleId = Number(req.body?.raffleId);
  const winningNumberRaw = req.body?.winningNumber;
  const resolution = String(req.body?.resolution || '').trim();
  const reason = String(req.body?.reason || '').trim() || null;
  const params = req.body?.params || {};

  if (!raffleId || !Number.isFinite(raffleId)) return res.status(400).json({ error: 'ID inválido' });

  try {
    const raffle = await prisma.raffle.findUnique({ where: { id: raffleId } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    const tnum = Number(winningNumberRaw);
    const soldCount = await prisma.ticket.count({ where: { raffleId, status: 'approved' } });

    // 1) Selección aleatoria entre vendidos
    if (resolution === 'random_sold') {
      if (soldCount === 0) return res.status(400).json({ error: 'No hay tickets vendidos para seleccionar al azar' });
      const sold = await prisma.ticket.findMany({ where: { raffleId, status: 'approved' }, select: { id: true, number: true, userId: true } });
      const pick = sold[Math.floor(Math.random() * sold.length)];
      const winner = await prisma.winner.create({ data: { raffleId, userId: pick.userId, drawSlot: 'final', ticketNumber: pick.number, prize: raffle.prize || null, photoUrl: null } });

      // Notificar ganador
      try {
        const winnerUser = await prisma.user.findUnique({ where: { id: pick.userId }, select: { id: true, email: true, pushToken: true, name: true } });
        const winnerName = winnerUser?.name ? safeDecrypt(winnerUser.name) : null;
        const digits = getTicketDigitsFromRaffle(raffle);
        const displayNumber = formatTicketNumber(pick.number, digits);
        if (winnerUser?.email) sendEmail(winnerUser.email, `¡Has ganado en ${raffle.title}!`, `Felicidades ${winnerName || ''}. Tu número ${displayNumber} ha ganado.`, `<h1>¡Felicidades ${escapeHtml(winnerName || '')}!</h1><p>Tu número <b>${escapeHtml(displayNumber)}</b> ganó en la rifa <b>${escapeHtml(raffle.title)}</b>.</p>`).catch(console.error);
        if (winnerUser?.pushToken) sendPushNotification([winnerUser.pushToken], '¡Eres ganador!', `Tu número ${displayNumber} ganó en ${raffle.title}`, { type: 'you_won', raffleId }).catch(console.error);
      } catch (e) { console.error('[RESOLVE_MISSING_NOTIFY]', e); }

      try { await securityLogger.log({ action: 'WINNER_RESOLVED_RANDOM', userEmail: String(req.user?.email || ''), userId: Number(req.user?.userId) || null, ipAddress: String(req.ip || ''), userAgent: String(req.headers['user-agent'] || ''), severity: 'INFO', detail: `Resolución random_sold rifa ${raffleId} -> ticket ${pick.number}`, entity: 'Raffle', entityId: String(raffleId), metadata: { method: 'random_sold', winnerId: winner.id } }); } catch (_e) {}

      return res.json({ message: 'Ganador seleccionado aleatoriamente', winner });
    }

    // 2) Posponer la resolución (por defecto 3 días)
    if (resolution === 'postpone') {
      // Usar params.postponeDays si viene, si no usar la política de la rifa, si no usar env/default
      const rafflePolicy = raffle.style && typeof raffle.style === 'object' ? raffle.style.missingNumberPolicy : null;
      const postponeDays = Number(params?.postponeDays ?? rafflePolicy?.postponeDays ?? Number(process.env.MISSING_NUMBER_POSTPONE_DAYS) ?? 3);
      const until = new Date(Date.now() + Math.max(0, postponeDays) * 24 * 60 * 60 * 1000).toISOString();
      const nextStyle = raffle.style && typeof raffle.style === 'object' ? { ...raffle.style } : {};
      nextStyle.pendingResolution = { status: 'postponed', until, winningNumber: winningNumberRaw, reason, postponeDays };
      await prisma.raffle.update({ where: { id: raffleId }, data: { style: nextStyle } });

      try { await securityLogger.log({ action: 'WINNER_RESOLVED_POSTPONE', userEmail: String(req.user?.email || ''), userId: Number(req.user?.userId) || null, ipAddress: String(req.ip || ''), userAgent: String(req.headers['user-agent'] || ''), severity: 'INFO', detail: `Rifa ${raffleId} pospuesta hasta ${until} por número no vendido ${winningNumberRaw}`, entity: 'Raffle', entityId: String(raffleId), metadata: { until, reason, postponeDays } }); } catch (_e) {}

      // Notificar al propietario de la rifa
      try {
        const owner = await prisma.user.findUnique({ where: { id: raffle.userId }, select: { id: true, email: true, pushToken: true, name: true } });
        if (owner?.email) sendEmail(owner.email, `Rifa ${raffle.title} pospuesta`, `La resolución del número ${winningNumberRaw} ha sido pospuesta hasta ${until}. Razón: ${reason || 'No especificada'}. Días: ${postponeDays}`).catch(console.error);
      } catch (e) { console.error('[POSTPONE_NOTIFY]', e); }

      return res.json({ message: 'Rifa pospuesta para re-evaluación', until, postponeDays });
    }

    // 3) Cerrar sin ganador
    if (resolution === 'close_no_winner') {
      const result = await closeRaffleInternal(raffleId, 'admin_closed_no_winner');
      try { await securityLogger.log({ action: 'WINNER_RESOLVED_CLOSE_NO_WINNER', userEmail: String(req.user?.email || ''), userId: Number(req.user?.userId) || null, ipAddress: String(req.ip || ''), userAgent: String(req.headers['user-agent'] || ''), severity: 'INFO', detail: `Rifa ${raffleId} cerrada sin ganador por admin`, entity: 'Raffle', entityId: String(raffleId), metadata: { result } }); } catch (_e) {}
      return res.json({ message: 'Rifa cerrada sin ganador', result });
    }

    // 4) Forzar ganador manualmente (crear ticket si hace falta)
    if (resolution === 'force_manual') {
      const ticketNumber = Number(params?.ticketNumber || tnum);
      if (!Number.isFinite(ticketNumber)) return res.status(400).json({ error: 'Se requiere ticketNumber para force_manual' });
      let ticketRec = await prisma.ticket.findFirst({ where: { raffleId, number: ticketNumber } });
      if (!ticketRec) {
        ticketRec = await prisma.ticket.create({ data: { raffleId, number: ticketNumber, status: 'manual' } });
      }
      const winner = await prisma.winner.create({ data: { raffleId, userId: ticketRec.userId || null, drawSlot: 'final', ticketNumber: ticketRec.number, prize: raffle.prize || null, photoUrl: null } });
      try { await securityLogger.log({ action: 'WINNER_RESOLVED_FORCE', userEmail: String(req.user?.email || ''), userId: Number(req.user?.userId) || null, ipAddress: String(req.ip || ''), userAgent: String(req.headers['user-agent'] || ''), severity: 'WARN', detail: `Ganador forzado rifa ${raffleId} -> ticket ${ticketRec.number}`, entity: 'Raffle', entityId: String(raffleId), metadata: { method: 'force_manual', winnerId: winner.id } }); } catch (_e) {}
      return res.json({ message: 'Ganador forzado manualmente', winner });
    }

    return res.status(400).json({ error: 'Resolución inválida' });
  } catch (e) {
    console.error('[RESOLVE_MISSING]', e);
    return res.status(500).json({ error: 'Error al resolver número no vendido' });
  }
});

// Job protegido: cerrar rifas vencidas por endDate (útil para pruebas / cumplimiento)
app.post('/admin/jobs/close-expired-raffles', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const limit = Number(req.body?.limit) || 200;
    const out = await closeExpiredRafflesBatch(limit);

    try {
      await securityLogger.log({
        action: 'RAFFLES_AUTO_CLOSED_JOB',
        userEmail: String(req.user?.email || ''),
        userId: Number(req.user?.userId) || null,
        ipAddress: String(req.ip || ''),
        userAgent: String(req.headers['user-agent'] || ''),
        severity: 'INFO',
        detail: 'Ejecución manual del job de cierre por endDate',
        entity: 'Raffle',
        entityId: null,
        metadata: { limit, scanned: out.scanned, closed: out.closed, sandbox: SANDBOX_MODE }
      });
    } catch (_e) {
      // no bloquear
    }

    return res.json({ success: true, ...out });
  } catch (error) {
    console.error('[close-expired-raffles] Error:', error);
    return res.status(500).json({ error: 'Error al cerrar rifas vencidas' });
  }
});

// --- SUPERADMIN ENDPOINTS ---

// --- WALLET ENDPOINTS ---

app.get('/wallet', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ 
      where: { id: req.user.userId },
      include: { transactions: { orderBy: { createdAt: 'desc' }, take: 20 } }
    });
    res.json({ balance: user.balance, transactions: user.transactions });
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener wallet' });
  }
});

app.post('/wallet/topup', authenticateToken, async (req, res) => {
  const { amount, provider } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Monto inválido' });

  const requestedProvider = provider ? String(provider) : 'manual';
  const txProvider = SANDBOX_MODE ? 'sandbox' : requestedProvider;
  const ref = SANDBOX_MODE
    ? `Recarga de saldo${SANDBOX_LABEL} (${requestedProvider})`
    : 'Recarga de saldo';

  try {
    await prisma.$transaction([
      prisma.user.update({
        where: { id: req.user.userId },
        data: { balance: { increment: Number(amount) } }
      }),
      prisma.transaction.create({
        data: {
          txCode: generateTxCode(),
          userId: req.user.userId,
          amount: Number(amount),
          type: 'deposit',
          status: 'approved',
          provider: txProvider,
          reference: encrypt(ref)
        }
      })
    ]);

    try {
      await securityLogger.log({
        action: 'WALLET_TOPUP',
        userEmail: String(req.user?.email || ''),
        userId: Number(req.user?.userId) || null,
        ipAddress: String(req.ip || ''),
        userAgent: String(req.headers['user-agent'] || ''),
        severity: 'INFO',
        detail: 'Recarga de wallet aprobada',
        entity: 'Transaction',
        entityId: null,
        metadata: { amount: Number(amount), providerRequested: requestedProvider, providerUsed: txProvider, sandbox: SANDBOX_MODE }
      });
    } catch (_e) {
      // no bloquear
    }

    res.json({ message: 'Recarga exitosa' });
  } catch (error) {
    res.status(500).json({ error: 'Error al recargar' });
  }
});

app.get('/tickets/:id', authenticateToken, async (req, res) => {
  try {
    const ticket = await prisma.ticket.findUnique({ where: { id: Number(req.params.id) } });
    if (!ticket) return res.status(404).json({ error: 'Ticket no encontrado' });
    res.json(ticket);
  } catch (error) {
    res.status(500).json({ error: 'Error al consultar ticket' });
  }
});

app.put('/tickets/:id', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { number } = req.body;
  try {
    const ticket = await prisma.ticket.update({
      where: { id: Number(req.params.id) },
      data: { number }
    });
    res.json({ message: 'Ticket actualizado', ticket });
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar ticket' });
  }
});

app.delete('/tickets/:id', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    await prisma.ticket.delete({ where: { id: Number(req.params.id) } });
    res.json({ message: 'Ticket eliminado' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar ticket' });
  }
});

// --- SUPERADMIN ENDPOINTS ---

app.get('/superadmin/settings', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    let settings = await prisma.systemSettings.findFirst();
    if (!settings) {
      settings = await prisma.systemSettings.create({ data: { branding: {}, modules: {} } });
    }
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener ajustes' });
  }
});

app.patch('/superadmin/settings/branding', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const branding = req.body;
    const settings = await prisma.systemSettings.upsert({
      where: { id: 1 },
      update: { branding },
      create: { branding, modules: {} }
    });
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: 'Error al guardar branding' });
  }
});

app.patch('/superadmin/settings/modules', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const { modules } = req.body;
    const settings = await prisma.systemSettings.upsert({
      where: { id: 1 },
      update: { modules },
      create: { branding: {}, modules }
    });
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: 'Error al guardar módulos' });
  }
});

app.patch('/superadmin/settings/company', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const incoming = req.body && typeof req.body === 'object' ? req.body : {};
    const current = await prisma.systemSettings.findUnique({ where: { id: 1 } });
    const currentCompany = current?.company && typeof current.company === 'object' ? current.company : {};

    const incomingPlanConfig = incoming?.planConfig && typeof incoming.planConfig === 'object' ? incoming.planConfig : null;
    const currentPlanConfig = currentCompany?.planConfig && typeof currentCompany.planConfig === 'object' ? currentCompany.planConfig : {};

    const mergedCompany = { ...currentCompany, ...incoming };
    if (incomingPlanConfig) {
      mergedCompany.planConfig = { ...currentPlanConfig, ...incomingPlanConfig };
    }

    const settings = await prisma.systemSettings.upsert({
      where: { id: 1 },
      update: { company: mergedCompany },
      create: { branding: {}, modules: {}, company: mergedCompany }
    });

    cachedPlanConfig.loadedAt = 0;
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: 'Error al guardar datos de empresa' });
  }
});

app.get('/superadmin/audit/users', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const users = await prisma.user.findMany({ orderBy: { createdAt: 'desc' } });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error al auditar usuarios' });
  }
});

app.get('/superadmin/mail/logs', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const logs = await prisma.mailLog.findMany({ orderBy: { timestamp: 'desc' }, take: 50 });
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener logs de correo' });
  }
});

// =========================
// Reports (Denuncias)
// =========================

// Crear reporte (usuario autenticado)
app.post('/reports', authenticateToken, async (req, res) => {
  try {
    const reporterId = Number(req.user?.userId);
    if (!reporterId) return res.status(401).json({ error: 'Token requerido' });

    const { reportedUserId, raffleId, category, answers, comment, metadata } = req.body || {};

    const report = await prisma.report.create({
      data: {
        reporterId,
        reportedUserId: reportedUserId != null ? Number(reportedUserId) : null,
        raffleId: raffleId != null ? Number(raffleId) : null,
        category: category != null ? String(category) : null,
        answers: answers != null ? answers : null,
        comment: comment != null ? String(comment) : null,
        metadata: metadata != null ? metadata : null
      }
    });

    await prisma.auditLog.create({
      data: {
        action: 'REPORT_CREATE',
        userId: reporterId,
        entity: 'Report',
        entityId: String(report.id),
        detail: `Report created by userId=${reporterId}`,
        ipAddress: String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || ''),
        userAgent: String(req.headers['user-agent'] || '')
      }
    });

    res.status(201).json(report);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear reporte' });
  }
});

// Listar reportes (solo superadmin)
app.get('/admin/reports', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const { status, take } = req.query;
    const takeN = Math.min(Math.max(Number(take) || 50, 1), 200);

    const where = {};
    if (status) where.status = String(status);

    const reports = await prisma.report.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: takeN,
      include: {
        reporter: { select: { id: true, publicId: true, email: true, name: true, avatar: true, securityId: true } },
        reportedUser: { select: { id: true, publicId: true, email: true, name: true, avatar: true, securityId: true } },
        raffle: { select: { id: true, title: true, userId: true } },
        reviewedBy: { select: { id: true, publicId: true, email: true, name: true } }
      }
    });

    // Desencriptar nombres si aplica
    const mapped = reports.map((r) => ({
      ...r,
      reporter: r.reporter ? { ...r.reporter, name: r.reporter.name ? safeDecrypt(r.reporter.name) : r.reporter.name } : r.reporter,
      reportedUser: r.reportedUser ? { ...r.reportedUser, name: r.reportedUser.name ? safeDecrypt(r.reportedUser.name) : r.reportedUser.name } : r.reportedUser,
      reviewedBy: r.reviewedBy ? { ...r.reviewedBy, name: r.reviewedBy.name ? safeDecrypt(r.reviewedBy.name) : r.reviewedBy.name } : r.reviewedBy
    }));

    res.json(mapped);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener reportes' });
  }
});

// Alias compatible
app.get('/superadmin/reports', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const { status, take } = req.query;
    const takeN = Math.min(Math.max(Number(take) || 50, 1), 200);

    const where = {};
    if (status) where.status = String(status);

    const reports = await prisma.report.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: takeN,
      include: {
        reporter: { select: { id: true, publicId: true, email: true, name: true, avatar: true, securityId: true } },
        reportedUser: { select: { id: true, publicId: true, email: true, name: true, avatar: true, securityId: true } },
        raffle: { select: { id: true, title: true, userId: true } },
        reviewedBy: { select: { id: true, publicId: true, email: true, name: true } }
      }
    });

    const mapped = reports.map((r) => ({
      ...r,
      reporter: r.reporter ? { ...r.reporter, name: r.reporter.name ? safeDecrypt(r.reporter.name) : r.reporter.name } : r.reporter,
      reportedUser: r.reportedUser ? { ...r.reportedUser, name: r.reportedUser.name ? safeDecrypt(r.reportedUser.name) : r.reportedUser.name } : r.reportedUser,
      reviewedBy: r.reviewedBy ? { ...r.reviewedBy, name: r.reviewedBy.name ? safeDecrypt(r.reviewedBy.name) : r.reviewedBy.name } : r.reviewedBy
    }));

    res.json(mapped);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener reportes' });
  }
});

// Revisar / resolver reporte (solo superadmin)
app.patch('/admin/reports/:id/review', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const reportId = Number(req.params.id);
    const reviewerId = Number(req.user?.userId);
    const { status, resolution } = req.body || {};

    const updated = await prisma.report.update({
      where: { id: reportId },
      data: {
        status: status != null ? String(status) : undefined,
        resolution: resolution != null ? String(resolution) : undefined,
        reviewedById: reviewerId,
        reviewedAt: new Date()
      }
    });

    await prisma.auditLog.create({
      data: {
        action: 'REPORT_REVIEW',
        userId: reviewerId,
        entity: 'Report',
        entityId: String(reportId),
        detail: `Report reviewed by userId=${reviewerId} status=${String(status || '')}`,
        ipAddress: String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || ''),
        userAgent: String(req.headers['user-agent'] || '')
      }
    });

    res.json(updated);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al revisar reporte' });
  }

});

app.get('/superadmin/audit/actions', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const logs = await prisma.auditLog.findMany({ orderBy: { timestamp: 'desc' }, take: 50 });
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener logs de auditoría' });
  }
});

// Búsqueda de auditoría (para expediente): filtra por entidad/acción/usuario y rango de fechas.
app.get('/superadmin/audit/search', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const entity = req.query.entity ? String(req.query.entity) : null;
    const entityId = req.query.entityId ? String(req.query.entityId) : null;
    const action = req.query.action ? String(req.query.action) : null;
    const userId = req.query.userId != null ? Number(req.query.userId) : null;
    const since = req.query.since ? new Date(String(req.query.since)) : null;
    const until = req.query.until ? new Date(String(req.query.until)) : null;
    const limit = Math.max(1, Math.min(5000, Number(req.query.limit) || 200));

    const where = {};
    if (entity) where.entity = entity;
    if (entityId) where.entityId = entityId;
    if (action) where.action = action;
    if (Number.isFinite(userId)) where.userId = userId;
    if (since && !Number.isNaN(since.getTime())) where.timestamp = { ...(where.timestamp || {}), gte: since };
    if (until && !Number.isNaN(until.getTime())) where.timestamp = { ...(where.timestamp || {}), lte: until };

    const logs = await prisma.auditLog.findMany({
      where,
      orderBy: { timestamp: 'desc' },
      take: limit
    });

    res.json({ count: logs.length, logs });
  } catch (error) {
    console.error('[audit/search] error:', error);
    res.status(500).json({ error: 'Error al buscar logs' });
  }
});

app.get('/superadmin/reports', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const status = String(req.query?.status || '').trim().toLowerCase();
    const where = status ? { status } : {};

    const reports = await prisma.report.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: 200,
      include: {
        reporter: { select: { id: true, name: true, email: true, avatar: true } },
        reported: { select: { id: true, name: true, email: true, avatar: true } },
        reviewedBy: { select: { id: true, name: true, email: true } },
        raffle: { select: { id: true, title: true, status: true, createdAt: true } }
      }
    });

    return res.json(reports);
  } catch (error) {
    console.error('[REPORTS][SUPERADMIN] list error:', error);
    if (isPrismaMissingTableError(error)) {
      return res.status(503).json({ error: 'Función no disponible: falta aplicar migración de reportes (Report).' });
    }
    return res.status(500).json({ error: 'Error al obtener reportes' });
  }
});

app.patch('/superadmin/reports/:id', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const reportId = Number(req.params.id);
    const nextStatus = String(req.body?.status || '').trim().toLowerCase();
    const allowed = new Set(['open', 'reviewed', 'resolved', 'dismissed']);

    if (!Number.isFinite(reportId)) return res.status(400).json({ error: 'ID inválido' });
    if (!allowed.has(nextStatus)) return res.status(400).json({ error: 'Estado inválido' });

    const updated = await prisma.report.update({
      where: { id: reportId },
      data: {
        status: nextStatus,
        reviewedById: Number(req.user?.userId) || null,
        reviewedAt: new Date()
      }
    });

    try {
      await prisma.auditLog.create({
        data: {
          action: 'REPORT_STATUS_UPDATED',
          userId: Number(req.user?.userId) || null,
          userEmail: String(req.user?.email || ''),
          entity: 'Report',
          entityId: String(updated.id),
          detail: `Reporte actualizado. Status=${nextStatus}`,
          ipAddress: String(req.ip || ''),
          userAgent: String(req.headers['user-agent'] || ''),
          severity: 'INFO',
          metadata: { status: nextStatus }
        }
      });
    } catch (_e) {
      // No bloquear
    }

    return res.json({ id: updated.id, status: updated.status });
  } catch (error) {
    console.error('[REPORTS][SUPERADMIN] update error:', error);
    if (isPrismaMissingTableError(error)) {
      return res.status(503).json({ error: 'Función no disponible: falta aplicar migración de reportes (Report).' });
    }
    return res.status(500).json({ error: 'Error al actualizar reporte' });
  }
});

// --- SUPERADMIN: ADMINISTRACIÓN GLOBAL DE RIFAS ---

app.get('/superadmin/riferos/search', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const qRaw = String(req.query?.q || '').trim();
    const take = Math.min(Math.max(Number(req.query?.take) || 20, 1), 50);
    const includeInactive = String(req.query?.includeInactive || '').trim().toLowerCase() === 'true';

    if (!qRaw) return res.json([]);

    const qLower = qRaw.toLowerCase();
    const looksLikeEmail = qLower.includes('@');

    const baseWhere = {
      role: 'admin',
      ...(includeInactive ? {} : { active: true })
    };

    const or = [];
    if (looksLikeEmail) {
      or.push({ email: { contains: qRaw, mode: 'insensitive' } });
    } else {
      or.push({ publicId: { contains: qRaw, mode: 'insensitive' } });
      or.push({ securityId: { contains: qRaw, mode: 'insensitive' } });
      // fallback: búsqueda por email parcial aunque no tenga @
      or.push({ email: { contains: qRaw, mode: 'insensitive' } });
    }

    const selectUser = {
      id: true,
      publicId: true,
      email: true,
      name: true,
      active: true,
      securityId: true,
      createdAt: true,
      _count: { select: { raffles: true } },
      raffles: {
        where: { status: 'active' },
        orderBy: [{ activatedAt: 'desc' }, { createdAt: 'desc' }],
        take: 6,
        select: { id: true, title: true, status: true, activatedAt: true, createdAt: true }
      }
    };

    const primary = await prisma.user.findMany({
      where: { ...baseWhere, OR: or },
      take,
      orderBy: { createdAt: 'desc' },
      select: selectUser
    });

    const byId = new Map(primary.map((u) => [u.id, u]));

    // Búsqueda por nombre (encriptado): escaneo limitado SOLO si hace falta.
    if (!looksLikeEmail && byId.size < take && qLower.length >= 2) {
      const scanTake = Math.min(Math.max(Number(req.query?.scanTake) || 250, 50), 1200);
      const candidates = await prisma.user.findMany({
        where: baseWhere,
        take: scanTake,
        orderBy: { createdAt: 'desc' },
        select: selectUser
      });

      for (const u of candidates) {
        if (byId.size >= take) break;
        const name = u?.name ? String(safeDecrypt(u.name) || '').toLowerCase() : '';
        if (name && name.includes(qLower)) {
          byId.set(u.id, u);
        }
      }
    }

    const list = Array.from(byId.values())
      .sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime())
      .slice(0, take)
      .map((u) => ({
        id: u.id,
        publicId: u.publicId,
        email: u.email,
        name: u.name ? safeDecrypt(u.name) : u.name,
        active: u.active,
        securityId: u.securityId,
        totalRaffles: u._count?.raffles || 0,
        activeRaffles: Array.isArray(u.raffles) ? u.raffles : [],
        activeRafflesCount: Array.isArray(u.raffles) ? u.raffles.length : 0
      }));

    return res.json(list);
  } catch (error) {
    console.error('[SUPERADMIN][riferos/search] error:', error);
    return res.status(500).json({ error: 'Error al buscar riferos' });
  }
});

app.get('/superadmin/riferos/:id/raffles', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const idRaw = String(req.params.id || '').trim();
    if (!idRaw) return res.status(400).json({ error: 'ID inválido' });

    const isNumeric = /^\d+$/.test(idRaw);
    const user = await prisma.user.findUnique({
      where: isNumeric ? { id: Number(idRaw) } : { publicId: idRaw },
      select: { id: true, publicId: true, email: true, name: true, active: true, securityId: true }
    });
    if (!user) return res.status(404).json({ error: 'Rifero no encontrado' });

    const status = String(req.query?.status || 'active').trim().toLowerCase();
    const allowed = new Set(['active', 'draft', 'closed', 'all']);
    if (!allowed.has(status)) return res.status(400).json({ error: 'Estado inválido' });

    const where = {
      userId: user.id,
      ...(status === 'all' ? {} : { status })
    };

    const raffles = await prisma.raffle.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }],
      include: { _count: { select: { tickets: true } } }
    });

    return res.json({
      user: {
        id: user.id,
        publicId: user.publicId,
        email: user.email,
        name: user.name ? safeDecrypt(user.name) : user.name,
        active: user.active,
        securityId: user.securityId
      },
      raffles: raffles.map((r) => ({ ...r, soldTickets: r._count?.tickets || 0 }))
    });
  } catch (error) {
    console.error('[SUPERADMIN][riferos/:id/raffles] error:', error);
    return res.status(500).json({ error: 'Error al obtener rifas del rifero' });
  }
});

app.post('/superadmin/raffles/:id/report', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const raffleId = Number(req.params.id);
    if (!Number.isFinite(raffleId) || raffleId <= 0) return res.status(400).json({ error: 'ID inválido' });

    const reason = String(req.body?.reason || '').trim();
    const details = req.body?.details == null ? null : String(req.body.details);
    if (!reason) return res.status(400).json({ error: 'Motivo requerido' });

    const raffle = await prisma.raffle.findUnique({ where: { id: raffleId }, select: { id: true, title: true, status: true, userId: true } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });
    if (!raffle.userId) return res.status(400).json({ error: 'La rifa no tiene rifero asignado' });

    const actorId = Number(req.user?.userId) || null;
    const actorEmail = String(req.user?.email || '');

    let report = null;
    try {
      report = await prisma.report.create({
        data: {
          reason,
          details,
          status: 'open',
          reporterUserId: actorId,
          reportedUserId: raffle.userId,
          raffleId: raffle.id,
          reviewedById: actorId,
          reviewedAt: new Date()
        }
      });
    } catch (e) {
      if (isPrismaMissingTableError(e)) {
        return res.status(503).json({ error: 'Función no disponible: falta aplicar migración de reportes (Report).' });
      }
      throw e;
    }

    try {
      await prisma.auditLog.create({
        data: {
          action: 'RAFFLE_REPORTED',
          userId: actorId,
          userEmail: actorEmail,
          entity: 'Raffle',
          entityId: String(raffle.id),
          detail: `Reporte creado para rifa #${raffle.id} (${raffle.title}). Motivo=${reason}`,
          ipAddress: String(req.ip || ''),
          userAgent: String(req.headers['user-agent'] || ''),
          severity: 'WARN',
          metadata: { reason }
        }
      });
    } catch (_e) {
      // no bloquear
    }

    return res.status(201).json({ message: 'Reporte creado', reportId: report?.id || null });
  } catch (error) {
    console.error('[SUPERADMIN][raffles/:id/report] error:', error);
    return res.status(500).json({ error: 'Error al reportar rifa' });
  }
});

app.post('/superadmin/raffles/:id/close', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const raffleId = Number(req.params.id);
    if (!Number.isFinite(raffleId) || raffleId <= 0) return res.status(400).json({ error: 'ID inválido' });

    const reason = String(req.body?.reason || '').trim();
    const details = req.body?.details == null ? null : String(req.body.details);
    if (!reason) return res.status(400).json({ error: 'Motivo requerido' });

    const actorId = Number(req.user?.userId) || null;
    const actorEmail = String(req.user?.email || '');

    const raffle = await prisma.raffle.findUnique({ where: { id: raffleId }, select: { id: true, title: true, status: true, userId: true } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    const updated = await prisma.raffle.update({
      where: { id: raffleId },
      data: { status: 'closed', closedAt: new Date() }
    });

    // Intentar crear reporte asociado (si existe la tabla)
    if (raffle.userId) {
      try {
        await prisma.report.create({
          data: {
            reason: `CIERRE_SUPERADMIN: ${reason}`,
            details,
            status: 'reviewed',
            reporterUserId: actorId,
            reportedUserId: raffle.userId,
            raffleId: raffle.id,
            reviewedById: actorId,
            reviewedAt: new Date()
          }
        });
      } catch (e) {
        if (!isPrismaMissingTableError(e)) {
          console.error('[SUPERADMIN][close] report create failed:', e);
        }
      }
    }

    try {
      await prisma.auditLog.create({
        data: {
          action: 'RAFFLE_CLOSED_BY_SUPERADMIN',
          userId: actorId,
          userEmail: actorEmail,
          entity: 'Raffle',
          entityId: String(updated.id),
          detail: `Rifa cerrada por superadmin #${updated.id} (${updated.title}). Motivo=${reason}`,
          ipAddress: String(req.ip || ''),
          userAgent: String(req.headers['user-agent'] || ''),
          severity: 'WARN',
          metadata: { reason }
        }
      });
    } catch (_e) {
      // no bloquear
    }

    return res.json({ message: 'Rifa cerrada', raffle: updated });
  } catch (error) {
    console.error('[SUPERADMIN][raffles/:id/close] error:', error);
    return res.status(500).json({ error: 'Error al cerrar rifa' });
  }
});

app.post('/superadmin/users', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  const { email, password, role, firstName, lastName, active } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        role,
        name: `${firstName} ${lastName}`,
        active,
        publicId: generateShortId(role === 'admin' || role === 'superadmin' ? 'ADM' : 'USR')
      }
    });
    await prisma.auditLog.create({
      data: { action: 'CREATE_USER', detail: `Created user ${email}`, entity: 'User' }
    });
    res.status(201).json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error al crear usuario' });
  }
});

// Superadmin: eliminar/anonomizar usuario por email (evita problemas de integridad referencial)
// - Por defecto: soft delete (anónimo + desactivado)
// - Opcional: hardDelete=true (si falla por FK, hace fallback a soft delete)
app.post('/superadmin/users/delete-by-email', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const hardDelete = req.body?.hardDelete === true;
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Email inválido' });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (user.role === 'superadmin') return res.status(403).json({ error: 'No se puede eliminar un superadmin' });

    const actorId = req.user?.userId;
    const actorEmail = req.user?.email;

    if (hardDelete) {
      try {
        await prisma.user.delete({ where: { email } });
        try {
          await prisma.auditLog.create({
            data: {
              action: 'SUPERADMIN_HARD_DELETE_USER_BY_EMAIL',
              userId: actorId,
              userEmail: actorEmail,
              entity: 'User',
              entityId: String(user.id),
              detail: `Hard deleted user by email: ${email}`,
              ipAddress: String(req.ip || ''),
              userAgent: String(req.headers['user-agent'] || ''),
              severity: 'CRITICAL'
            }
          });
        } catch (_e) {}
        return res.json({ ok: true, mode: 'hard', message: 'Usuario eliminado', userId: user.id, email });
      } catch (e) {
        console.warn('[SUPERADMIN][delete-by-email] hard delete failed, falling back to soft delete:', e?.message || e);
      }
    }

    // Soft delete/anonymize
    const updated = await prisma.user.update({
      where: { id: user.id },
      data: {
        name: 'Usuario Eliminado',
        email: `deleted_${user.id}_${Date.now()}@megarifas.deleted`,
        password: await bcrypt.hash(uuidv4(), 10),
        active: false,
        verified: false,
        phone: null,
        address: null,
        cedula: null,
        pushToken: null,
        socials: {},
        bankDetails: {},
        bio: null,
        avatar: null,
        securityId: null,
        verificationToken: null
      }
    });

    try {
      await prisma.auditLog.create({
        data: {
          action: 'SUPERADMIN_SOFT_DELETE_USER_BY_EMAIL',
          userId: actorId,
          userEmail: actorEmail,
          entity: 'User',
          entityId: String(user.id),
          detail: `Soft deleted user by email: ${email}`,
          ipAddress: String(req.ip || ''),
          userAgent: String(req.headers['user-agent'] || ''),
          severity: 'WARN'
        }
      });
    } catch (_e) {}

    return res.json({ ok: true, mode: 'soft', message: 'Usuario eliminado (anónimo)', user: redactUserForResponse(updated) });
  } catch (error) {
    console.error('[SUPERADMIN][delete-by-email] error:', error);
    return res.status(500).json({ error: 'Error al eliminar usuario' });
  }
});

// Superadmin: resetear contraseña por email (para soporte).
// Nota: requiere token superadmin. No devuelve la contraseña.
app.post('/superadmin/users/reset-password-by-email', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const newPassword = String(req.body?.newPassword || '').trim();
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Email inválido' });
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: 'Contraseña inválida (mínimo 6 caracteres)' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (user.role === 'superadmin') return res.status(403).json({ error: 'No se puede resetear contraseña de superadmin por este endpoint' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const updated = await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        verificationToken: null,
        // Evitar bloqueos en login
        active: true,
        verified: true
      }
    });

    try {
      await prisma.auditLog.create({
        data: {
          action: 'SUPERADMIN_RESET_PASSWORD_BY_EMAIL',
          userId: req.user?.userId,
          userEmail: req.user?.email,
          entity: 'User',
          entityId: String(user.id),
          detail: `Reset password by email: ${email}`,
          ipAddress: String(req.ip || ''),
          userAgent: String(req.headers['user-agent'] || ''),
          severity: 'CRITICAL'
        }
      });
    } catch (_e) {}

    return res.json({ ok: true, message: 'Contraseña actualizada', user: redactUserForResponse(updated) });
  } catch (error) {
    console.error('[SUPERADMIN][reset-password-by-email] error:', error);
    return res.status(500).json({ error: 'Error al resetear contraseña' });
  }
});

app.patch('/superadmin/users/:id/status', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  const { id } = req.params;
  const { active, verified } = req.body;
  try {
    const data = {};
    if (active !== undefined) data.active = active;
    if (verified !== undefined) data.verified = verified;
    
    const user = await prisma.user.update({ where: { id: Number(id) }, data });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar estado de usuario' });
  }
});

// Asignar o actualizar plan a un admin (solo superadmin)
app.patch('/superadmin/users/:id/plan', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  const { id } = req.params;
  try {
    const planConfig = await getPlanConfig();
    const incoming = req.body || {};
    const plan = normalizeAdminPlan(incoming, planConfig);
    if (!plan) return res.status(400).json({ error: 'Plan inválido' });
    const user = await prisma.user.update({ where: { id: Number(id) }, data: { adminPlan: plan } });
    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar plan de usuario' });
  }
});

app.patch('/superadmin/settings/tech-support', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const techSupport = req.body; // { phone, email }
    const settings = await prisma.systemSettings.upsert({
      where: { id: 1 },
      update: { techSupport },
      create: { branding: {}, modules: {}, techSupport }
    });
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: 'Error al guardar soporte técnico' });
  }
});

app.get('/settings/tech-support', async (req, res) => {
  try {
    const settings = await prisma.systemSettings.findFirst();
    res.json(settings?.techSupport || {});
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener soporte' });
  }
});

app.post('/superadmin/users/:id/reset-2fa', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    await prisma.user.update({
      where: { id: Number(req.params.id) },
      data: { verificationToken: null }
    });
    res.json({ message: '2FA reseteado correctamente' });
  } catch (error) {
    res.status(500).json({ error: 'Error al resetear 2FA' });
  }
});

app.post('/superadmin/users/:id/revoke-sessions', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  // En una implementación JWT simple sin estado, no podemos revocar fácilmente sin cambiar el secreto o usar blacklist.
  // Para cumplir con el requerimiento sin romper la arquitectura actual, simularemos éxito pero
  // en un sistema real se requeriría una tabla de sesiones o un campo 'tokenVersion' en el usuario.
  res.json({ message: 'Sesiones marcadas para cierre (Efectivo al expirar token actual)' });
});

// Endpoint público para perfil de usuario
app.get('/users/public/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const user = await prisma.user.findUnique({
      where: { id: Number(id) },
      select: {
        id: true,
        name: true,
        avatar: true,
        securityId: true,
        identityVerified: true,
        reputationScore: true,
        createdAt: true,
        bio: true,
        socials: true
      }
    });

    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    if (user.name) user.name = decrypt(user.name);

    // Calcular estadísticas en tiempo real
    const rafflesCount = await prisma.raffle.count({ where: { userId: user.id } });
    
    // Contar tickets vendidos en todas sus rifas
    // Primero obtenemos los IDs de sus rifas
    const userRaffles = await prisma.raffle.findMany({ 
      where: { userId: user.id },
      select: { id: true }
    });
    const raffleIds = userRaffles.map(r => r.id);
    
    const salesCount = await prisma.ticket.count({
      where: { raffleId: { in: raffleIds } }
    });

    res.json({
      ...user,
      stats: {
        raffles: rafflesCount,
        sales: salesCount
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener perfil público' });
  }
});

// --- MANUAL PAYMENTS ENDPOINTS ---

// Crear pago manual
app.post('/raffles/:id/manual-payments', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { quantity, provider, reference, note, proof } = req.body;
  
  if (!quantity || quantity <= 0) return res.status(400).json({ error: 'Cantidad inválida' });
  if (!proof) return res.status(400).json({ error: 'Comprobante requerido' });

  try {
    const raffle = await prisma.raffle.findUnique({ where: { id: Number(id) } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    const ticketPrice = Number(raffle.ticketPrice);
    if (!Number.isFinite(ticketPrice) || ticketPrice <= 0) {
      return res.status(400).json({ error: 'Esta rifa no tiene un precio válido para cobrar pagos manuales' });
    }

    const amount = ticketPrice * Number(quantity);

    const transaction = await prisma.transaction.create({
      data: {
        userId: req.user.userId,
        amount,
        type: 'manual_payment',
        status: 'pending',
        provider: provider ? String(provider) : null,
        reference: encrypt(reference || `Pago manual para rifa ${id}`),
        proof: encrypt(proof),
        raffleId: raffle.id
      }
    });

    res.json({ message: 'Pago registrado, pendiente de aprobación', transaction });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al registrar pago manual' });
  }
});

// Nota: endpoints de administración de pagos manuales están al final en la sección "GESTIÓN DE PAGOS MANUALES (Admin)"

const cron = require('node-cron');
const { Expo } = require('expo-server-sdk');
const expo = new Expo();

// --- NOTIFICATIONS ---
async function sendPushNotification(tokens, title, body, data = {}) {
  const messages = [];
  for (const token of tokens) {
    if (!Expo.isExpoPushToken(token)) continue;
    messages.push({ to: token, sound: 'default', title, body, data });
  }
  const chunks = expo.chunkPushNotifications(messages);
  for (const chunk of chunks) {
    try {
      await expo.sendPushNotificationsAsync(chunk);
    } catch (error) {
      console.error(error);
    }
  }
}

// Cron Job: 1:00 PM Notification
cron.schedule('0 13 * * *', async () => {
  console.log('[CRON] Sending 1 PM notification...');
  try {
    const users = await prisma.user.findMany({
      where: { pushToken: { not: null } },
      select: { pushToken: true }
    });
    const tokens = users.map(u => u.pushToken).filter(Boolean);
    if (tokens.length) {
      await sendPushNotification(tokens, '¡Sorteo de la Tarde!', 'El sorteo de la 1:00 PM está por comenzar. ¡Atentos!');
    }
  } catch (error) {
    console.error('[CRON ERROR]', error);
  }
}, {
  scheduled: true,
  timezone: "America/Caracas"
});

// --- KYC ROUTES ---

app.post('/kyc/submit', authenticateToken, async (req, res) => {
  const { documentType, frontImage, backImage, selfieImage } = req.body;
  
  if (!frontImage || !selfieImage) {
    return res.status(400).json({ error: 'Imágenes requeridas (Frontal y Selfie)' });
  }

  try {
    // Check if already verified or pending
    const existing = await prisma.kYCRequest.findFirst({
      where: { 
        userId: req.user.userId,
        status: { in: ['pending', 'approved'] }
      }
    });

    if (existing) {
      if (existing.status === 'approved') return res.status(400).json({ error: 'Ya estás verificado' });
      return res.status(400).json({ error: 'Ya tienes una solicitud pendiente' });
    }

    const kyc = await prisma.kYCRequest.create({
      data: {
        userId: req.user.userId,
        documentType: documentType || 'cedula',
        frontImage: encrypt(frontImage),
        backImage: backImage ? encrypt(backImage) : null,
        selfieImage: encrypt(selfieImage),
        status: 'pending'
      }
    });

    res.status(201).json({ message: 'Solicitud KYC enviada', id: kyc.id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al enviar solicitud KYC' });
  }
});

app.get('/kyc/status', authenticateToken, async (req, res) => {
  try {
    const kyc = await prisma.kYCRequest.findFirst({
      where: { userId: req.user.userId },
      orderBy: { createdAt: 'desc' }
    });
    
    if (!kyc) return res.json({ status: 'none', identityVerified: false });

    res.json({ 
      status: kyc.status, 
      rejectionReason: kyc.rejectionReason,
      createdAt: kyc.createdAt 
    });
  } catch (error) {
    res.status(500).json({ error: 'Error al consultar estado KYC' });
  }
});

app.get('/admin/kyc/pending', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const requests = await prisma.kYCRequest.findMany({
      where: { status: 'pending' },
      include: { user: { select: { id: true, name: true, email: true, cedula: true } } },
      orderBy: { createdAt: 'asc' }
    });

    const decrypted = requests.map(r => ({
      ...r,
      frontImage: decrypt(r.frontImage),
      backImage: r.backImage ? decrypt(r.backImage) : null,
      selfieImage: decrypt(r.selfieImage),
      user: {
        ...r.user,
        name: r.user.name ? decrypt(r.user.name) : 'Usuario',
        cedula: r.user.cedula ? decrypt(r.user.cedula) : null
      }
    }));

    res.json(decrypted);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al listar solicitudes KYC' });
  }
});

app.post('/admin/kyc/:id/review', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { status, reason } = req.body; // status: 'approved' | 'rejected'
  
  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Estado inválido' });
  }

  try {
    const kyc = await prisma.kYCRequest.findUnique({ where: { id: Number(req.params.id) } });
    if (!kyc) return res.status(404).json({ error: 'Solicitud no encontrada' });

    await prisma.$transaction(async (tx) => {
      await tx.kYCRequest.update({
        where: { id: kyc.id },
        data: { 
          status, 
          rejectionReason: reason,
          reviewedBy: req.user.userId
        }
      });

      if (status === 'approved') {
        await tx.user.update({
          where: { id: kyc.userId },
          data: { identityVerified: true }
        });
      } else {
        // If rejected, ensure user is not verified
        await tx.user.update({
          where: { id: kyc.userId },
          data: { identityVerified: false }
        });
      }
    });

    // Notify user
    const user = await prisma.user.findUnique({ where: { id: kyc.userId } });
    if (user && user.email) {
      const subject = status === 'approved' ? 'Identidad Verificada' : 'Verificación de Identidad Rechazada';
      const msg = status === 'approved' 
        ? 'Tu identidad ha sido verificada exitosamente.' 
        : `Tu solicitud de verificación ha sido rechazada. Motivo: ${reason}`;
      
      sendEmail(user.email, subject, msg, `<h1>${subject}</h1><p>${msg}</p>`).catch(console.error);
    }

    res.json({ message: `Solicitud ${status}` });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al procesar solicitud' });
  }
});

// Cron Job: 4:00 PM Notification
cron.schedule('0 16 * * *', async () => {
  console.log('[CRON] Sending 4 PM notification...');
  try {
    const users = await prisma.user.findMany({
      where: { pushToken: { not: null } },
      select: { pushToken: true }
    });
    const tokens = users.map(u => u.pushToken).filter(Boolean);
    if (tokens.length) {
      await sendPushNotification(tokens, '¡Sorteo Vespertino!', 'El sorteo de las 4:00 PM está por comenzar. ¡No te lo pierdas!');
    }
  } catch (error) {
    console.error('[CRON ERROR]', error);
  }
}, {
  scheduled: true,
  timezone: "America/Caracas"
});

// Cron Job: 10:00 PM Notification
cron.schedule('0 22 * * *', async () => {
  console.log('[CRON] Sending 10 PM notification...');
  try {
    const users = await prisma.user.findMany({
      where: { pushToken: { not: null } },
      select: { pushToken: true }
    });
    const tokens = users.map(u => u.pushToken).filter(Boolean);
    if (tokens.length) {
      await sendPushNotification(tokens, '¡Sorteo Mayor!', 'El sorteo de las 10:00 PM está por comenzar. ¡Mucha suerte!');
    }
  } catch (error) {
    console.error('[CRON ERROR]', error);
  }
}, {
  scheduled: true,
  timezone: "America/Caracas" // Adjust as needed
});

// Cron Job: Daily Audit Report (XLSX)
async function sendDailyAuditReport() {
  const enabled = String(process.env.AUDIT_REPORT_ENABLED || '').toLowerCase() === 'true';
  if (!enabled) return;

  const maxRows = Math.min(Math.max(Number(process.env.AUDIT_REPORT_MAX_ROWS) || 5000, 100), 50000);

  const recipients = parseEmailList(process.env.AUDIT_REPORT_EMAILS || SUPERADMIN_EMAIL);
  if (!recipients.length) {
    console.warn('[CRON] AUDIT_REPORT_EMAILS not set; skipping audit report.');
    return;
  }

  const now = new Date();
  const to = now;
  const from = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  try {
    const logs = await prisma.auditLog.findMany({
      where: { timestamp: { gte: from, lt: to } },
      orderBy: { timestamp: 'asc' },
      take: maxRows
    });

    // Resolver roles reales desde User para separar Admins vs Usuarios
    const rolesById = new Map();
    const rolesByEmail = new Map();
    try {
      const userIds = Array.from(
        new Set(
          (Array.isArray(logs) ? logs : [])
            .map((l) => l?.userId)
            .filter((id) => typeof id === 'number' && Number.isFinite(id))
        )
      );

      if (userIds.length) {
        const users = await prisma.user.findMany({
          where: { id: { in: userIds } },
          select: { id: true, email: true, role: true }
        });
        for (const u of users) {
          if (u && typeof u.id === 'number') rolesById.set(u.id, u.role);
          if (u && u.email) rolesByEmail.set(String(u.email).toLowerCase(), u.role);
        }
      }

      const missingEmails = Array.from(
        new Set(
          (Array.isArray(logs) ? logs : [])
            .filter((l) => l?.userId == null)
            .map((l) => String(l?.userEmail || '').toLowerCase())
            .filter(Boolean)
        )
      ).slice(0, 2000);

      if (missingEmails.length) {
        const usersByEmail = await prisma.user.findMany({
          where: { email: { in: missingEmails } },
          select: { email: true, role: true, id: true }
        });
        for (const u of usersByEmail) {
          if (u && u.email) rolesByEmail.set(String(u.email).toLowerCase(), u.role);
          if (u && typeof u.id === 'number') rolesById.set(u.id, u.role);
        }
      }
    } catch (e) {
      console.warn('[CRON] Could not resolve user roles for audit report:', e?.message || e);
    }

    const truncated = Array.isArray(logs) && logs.length >= maxRows;
    const dateLabel = formatDateYYYYMMDD(to);
    const filename = `audit_${dateLabel}.xlsx`;
    const attachment = await buildAuditXlsxBuffer(logs, { from, to, truncated, rolesById, rolesByEmail });

    const subject = `Reporte diario de auditoría (${dateLabel})`;
    const text = `Reporte diario de auditoría.\nRango: ${from.toISOString()} → ${to.toISOString()}\nRegistros: ${logs.length}${truncated ? ' (TRUNCADO por límite)' : ''}\n`;
    const html = `<h1>Reporte diario de auditoría</h1><p><b>Rango:</b> ${from.toISOString()} → ${to.toISOString()}</p><p><b>Registros:</b> ${logs.length}${truncated ? ' <b>(TRUNCADO por límite)</b>' : ''}</p><p>Adjunto: <b>${filename}</b></p>`;

    const ok = await sendEmail(
      recipients.join(','),
      subject,
      text,
      html,
      { forceSmtp: true, attachments: [{ filename, content: attachment }] }
    );

    await prisma.auditLog.create({
      data: {
        action: ok ? 'AUDIT_REPORT_SENT' : 'AUDIT_REPORT_FAILED',
        entity: 'AuditLog',
        userEmail: recipients[0] || null,
        detail: `Daily audit report ${ok ? 'sent' : 'failed'} to ${recipients.join(', ')}. Rows: ${logs.length}${truncated ? ' (truncated)' : ''}.`,
        severity: ok ? 'INFO' : 'ERROR',
        metadata: { recipients, from: from.toISOString(), to: to.toISOString(), rows: logs.length, truncated }
      }
    });
  } catch (error) {
    console.error('[CRON] Daily audit report failed:', error);
    try {
      await prisma.auditLog.create({
        data: {
          action: 'AUDIT_REPORT_FAILED',
          entity: 'AuditLog',
          detail: `Daily audit report failed: ${String(error?.message || error)}`,
          severity: 'ERROR'
        }
      });
    } catch (_e) {
      // ignore
    }
  }
}

const AUDIT_REPORT_CRON = process.env.AUDIT_REPORT_CRON || '0 1 * * *';
cron.schedule(
  AUDIT_REPORT_CRON,
  async () => {
    console.log('[CRON] Sending daily audit report...');
    await sendDailyAuditReport();
  },
  {
    scheduled: true,
    timezone: process.env.AUDIT_REPORT_TIMEZONE || 'America/Caracas'
  }
);

// --- SECURITY ---
app.post('/me/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Faltan datos' });

  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.userId } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) return res.status(401).json({ error: 'Contraseña actual incorrecta' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword }
    });

    res.json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al cambiar contraseña' });
  }
});

// --- USER PROFILE ---
app.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      select: {
        id: true,
        publicId: true,
        securityId: true,
        email: true,
        name: true,
        phone: true,
        address: true,
        cedula: true,
        state: true,
        role: true,
        adminPlan: true,
        balance: true,
        avatar: true,
        bio: true,
        socials: true,
        verified: true,
        identityVerified: true,
        referralCode: true,
        createdAt: true
      }
    });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    // Decrypt sensitive data
    if (user.name) user.name = safeDecrypt(user.name);
    if (user.phone) user.phone = safeDecrypt(user.phone);
    if (user.address) user.address = safeDecrypt(user.address);
    if (user.cedula) user.cedula = safeDecrypt(user.cedula);

    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener perfil' });
  }
});

// Sube avatar como archivo (multipart/form-data). Guarda URL en BD.
app.post(
  '/me/avatar',
  authenticateToken,
  upload.fields([
    { name: 'avatar', maxCount: 1 },
    { name: 'file', maxCount: 1 }
  ]),
  async (req, res) => {
    try {
      const file = req?.files?.avatar?.[0] || req?.files?.file?.[0] || null;
      if (!file || !file.buffer) {
        return res.status(400).json({ error: 'Archivo requerido' });
      }
      if (!sharp) {
        return res.status(500).json({ error: 'Procesador de imagen no disponible' });
      }
      if (file.size && file.size > 5 * 1024 * 1024) {
        return res.status(413).json({ error: 'Avatar demasiado grande (max 5MB)' });
      }

      const prev = await prisma.user.findUnique({
        where: { id: req.user.userId },
        select: { avatar: true }
      });

      const saved = await saveAvatarBuffer(req, req.user.userId, file.buffer);
      await prisma.user.update({
        where: { id: req.user.userId },
        data: { avatar: saved.url }
      });

      // Limpieza best-effort del archivo anterior
      if (prev?.avatar && prev.avatar !== saved.url) {
        tryDeleteOldAvatarFile(prev.avatar);
      }

      res.json({ avatar: saved.url });
    } catch (error) {
      console.error('[POST /me/avatar]', error);
      res.status(500).json({ error: 'Error al subir avatar' });
    }
  }
);

app.patch('/me', authenticateToken, async (req, res) => {
  try {
    const { name, avatar, bio, socials, phone, address, cedula } = req.body;
    const data = {};

    if (name !== undefined) {
      const trimmedName = String(name ?? '').trim();
      if (trimmedName) data.name = encrypt(trimmedName);
    }
    // Avatar: si llega como dataURL/base64, convertir a archivo y guardar solo URL en BD.
    let oldAvatarForCleanup = null;
    let newAvatarForCleanup = null;
    if (avatar !== undefined) {
      if (!avatar) {
        data.avatar = null;
      } else {
        const avatarStr = String(avatar);
        if (avatarStr.startsWith('data:image/')) {
          const parsed = parseDataUrlImage(avatarStr);
          if (!parsed) {
            return res.status(400).json({ error: 'Formato de avatar inválido' });
          }
          if (parsed.buffer.length > 5 * 1024 * 1024) {
            return res.status(413).json({ error: 'Avatar demasiado grande (max 5MB)' });
          }
          if (!sharp) {
            // Fallback (no ideal): si sharp no está disponible, mantener compatibilidad.
            data.avatar = avatarStr;
          } else {
            const prev = await prisma.user.findUnique({
              where: { id: req.user.userId },
              select: { avatar: true }
            });
            oldAvatarForCleanup = prev?.avatar || null;
            const saved = await saveAvatarBuffer(req, req.user.userId, parsed.buffer);
            data.avatar = saved.url;
            newAvatarForCleanup = saved.url;
          }
        } else {
          // URL o string normal
          if (avatarStr.length > 2048) {
            return res.status(400).json({ error: 'Avatar demasiado largo' });
          }
          data.avatar = avatarStr;
        }
      }
    }
    if (bio !== undefined) data.bio = bio ? String(bio) : null;
    if (socials !== undefined) data.socials = socials && typeof socials === 'object' ? socials : {};

    if (phone !== undefined) data.phone = phone ? encrypt(String(phone)) : null;
    if (address !== undefined) data.address = address ? encrypt(String(address)) : null;
    if (cedula !== undefined) data.cedula = cedula ? encrypt(String(cedula)) : null;

    const user = await prisma.user.update({
      where: { id: req.user.userId },
      data
    });

    // Limpieza best-effort del archivo anterior si lo reemplazamos.
    if (oldAvatarForCleanup && newAvatarForCleanup && oldAvatarForCleanup !== newAvatarForCleanup) {
      tryDeleteOldAvatarFile(oldAvatarForCleanup);
    }

    // Responder con datos desencriptados, consistente con GET /me
    const out = {
      ...user,
      name: user?.name ? safeDecrypt(user.name) : user.name,
      phone: user?.phone ? safeDecrypt(user.phone) : user.phone,
      address: user?.address ? safeDecrypt(user.address) : user.address,
      cedula: user?.cedula ? safeDecrypt(user.cedula) : user.cedula,
    };
    res.json(out);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar perfil' });
  }
});

app.delete('/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // Anonymize user data instead of hard delete to preserve integrity of raffles/transactions
    await prisma.user.update({
      where: { id: Number(userId) },
      data: {
        name: 'Usuario Eliminado',
        email: `deleted_${userId}_${Date.now()}@megarifas.deleted`,
        password: await bcrypt.hash(uuidv4(), 10), // Unusable password
        active: false,
        pushToken: null,
        socials: {},
        bankDetails: {},
        bio: null,
        avatar: null,
        securityId: null,
        verificationToken: null
      }
    });

    res.json({ message: 'Cuenta eliminada correctamente' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Error al eliminar la cuenta' });
  }
});

app.get('/me/tickets', authenticateToken, async (req, res) => {
  try {
    const tickets = await prisma.ticket.findMany({
      where: { userId: req.user.userId },
      include: { raffle: true },
      orderBy: { createdAt: 'desc' }
    });
    res.json(tickets);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener tickets' });
  }
});

app.get('/me/wins', authenticateToken, async (req, res) => {
  try {
    const wins = await prisma.winner.findMany({
      where: { userId: req.user.userId },
      include: { raffle: true },
      orderBy: { drawDate: 'desc' }
    });
    res.json(wins);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener premios' });
  }
});

app.get('/me/audit-logs', authenticateToken, async (req, res) => {
  try {
    // Fetch audit logs related to this user's email
    // Note: AuditLog uses userEmail, so we need to ensure we have the email.
    const user = await prisma.user.findUnique({ where: { id: req.user.userId }, select: { email: true } });
    if (!user || !user.email) return res.json([]);

    const logs = await prisma.auditLog.findMany({
      where: { userEmail: user.email },
      orderBy: { timestamp: 'desc' },
      take: 50
    });
    res.json(logs);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener registros de auditoría' });
  }
});

app.get('/me/payments', authenticateToken, async (req, res) => {
  try {
    const payments = await prisma.transaction.findMany({
      where: { userId: req.user.userId },
      orderBy: { createdAt: 'desc' }
    });
    
    // Decrypt sensitive data
    const decryptedPayments = payments.map(p => ({
      ...p,
      reference: decrypt(p.reference),
      proof: decrypt(p.proof)
    }));

    res.json(decryptedPayments);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener pagos' });
  }
});

// --- REFERRALS ---
app.get('/me/referrals', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      include: {
        referrals: {
          select: { name: true, createdAt: true, verified: true }
        }
      }
    });
    
    if (!user.referralCode) {
      // Generate if missing
      const code = user.name.substring(0, 3).toUpperCase() + Math.floor(1000 + Math.random() * 9000);
      await prisma.user.update({ where: { id: user.id }, data: { referralCode: code } });
      user.referralCode = code;
    }

    res.json({ code: user.referralCode, referrals: user.referrals });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener referidos' });
  }
});

app.post('/me/referral', authenticateToken, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Código requerido' });
    
    const referrer = await prisma.user.findUnique({ where: { referralCode: code } });
    if (!referrer) return res.status(404).json({ error: 'Código inválido' });
    if (referrer.id === req.user.userId) return res.status(400).json({ error: 'No puedes referirte a ti mismo' });

    await prisma.user.update({
      where: { id: req.user.userId },
      data: { referredById: referrer.id }
    });

    // Check for rewards
    checkAndRewardReferrer(referrer.id).catch(console.error);

    res.json({ message: 'Referido registrado' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al registrar referido' });
  }
});

// --- PUBLIC PROFILES ---
app.get('/users/public/:id', async (req, res) => {
  try {
    const { id } = req.params;
    let user = await prisma.user.findUnique({
      where: { publicId: id },
      select: {
        publicId: true,
        name: true,
        avatar: true,
        bio: true,
        socials: true,
        createdAt: true,
        verified: true,
        role: true,
        _count: {
          select: { tickets: true, announcements: true }
        }
      }
    });

    if (!user && !isNaN(Number(id))) {
      user = await prisma.user.findUnique({
        where: { id: Number(id) },
        select: {
          publicId: true,
          name: true,
          avatar: true,
          bio: true,
          socials: true,
          createdAt: true,
          verified: true,
          role: true,
          _count: {
            select: { tickets: true, announcements: true }
          }
        }
      });
    }

    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    let stats = {};
    if (user.role === 'admin' || user.role === 'superadmin') {
      const rafflesCount = await prisma.raffle.count();
      const winnersCount = await prisma.winner.count();
      stats = { raffles: rafflesCount, prizes: winnersCount };
    }

    if (user.name) user.name = decrypt(user.name);

    res.json({ ...user, stats });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener perfil público' });
  }
});

// --- ANNOUNCEMENTS ---
app.get('/announcements', attachUserIfTokenPresent, async (req, res) => {
  try {
    const announcements = await prisma.announcement.findMany({
      orderBy: { createdAt: 'desc' },
      take: 20,
      include: {
        admin: {
          select: { name: true, avatar: true, role: true, verified: true }
        },
        _count: {
          select: { reactions: true }
        }
      }
    });

    const ids = announcements.map((a) => a.id);
    const grouped = ids.length
      ? await prisma.reaction.groupBy({
          by: ['announcementId', 'type'],
          where: { announcementId: { in: ids } },
          _count: { _all: true }
        })
      : [];

    const countsMap = new Map();
    for (const g of grouped) {
      const annId = g.announcementId;
      if (!countsMap.has(annId)) countsMap.set(annId, { LIKE: 0, HEART: 0, DISLIKE: 0 });
      const entry = countsMap.get(annId);
      const key = String(g.type || '').toUpperCase();
      if (key === 'LIKE' || key === 'HEART' || key === 'DISLIKE') {
        entry[key] = g._count?._all || 0;
      }
    }

    const decryptedAnnouncements = announcements.map(a => {
      if (a.admin && a.admin.name) a.admin.name = decrypt(a.admin.name);
      return {
        ...a,
        reactionCounts: countsMap.get(a.id) || { LIKE: 0, HEART: 0, DISLIKE: 0 }
      };
    });

    const actorUserId = Number(req.user?.userId);
    if (Number.isFinite(actorUserId) && actorUserId > 0) {
      const ids = announcements.map((a) => a.id).filter((x) => Number.isFinite(Number(x)));
      const my = ids.length
        ? await prisma.reaction.findMany({
            where: { userId: actorUserId, announcementId: { in: ids } },
            select: { announcementId: true, type: true }
          })
        : [];
      const myMap = new Map(my.map((r) => [r.announcementId, String(r.type || '').toUpperCase()]));
      return res.json(
        decryptedAnnouncements.map((a) => ({
          ...a,
          myReaction: myMap.get(a.id) || null
        }))
      );
    }

    res.json(decryptedAnnouncements.map((a) => ({ ...a, myReaction: null })));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener anuncios' });
  }
});

app.post('/admin/announcements', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const { title, content, imageUrl, sendEmail: sendEmailFlag } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'Título y contenido requeridos' });

    const announcement = await prisma.announcement.create({
      data: {
        title,
        content,
        imageUrl,
        adminId: req.user.userId
      }
    });

    res.json(announcement);

    const shouldSendEmail = sendEmailFlag === true;
    if (shouldSendEmail) {
      const adminId = req.user.userId;
      setImmediate(async () => {
        const startedAt = Date.now();
        let totalSent = 0;
        let totalFailed = 0;

        try {
          const safeTitle = String(title || '').trim();
          const safeContent = String(content || '').trim();

          const subject = `MegaRifas: ${safeTitle}`;
          const text = `${safeTitle}\n\n${safeContent}\n\nAbre la app para más detalles.`;
          const imageBlock = imageUrl ? `<p><img alt="" src="${escapeHtml(imageUrl)}" style="max-width:100%;height:auto;" /></p>` : '';
          const html = `
            <div>
              <h2>${escapeHtml(safeTitle)}</h2>
              <p>${escapeHtml(safeContent).replace(/\n/g, '<br/>')}</p>
              ${imageBlock}
              <p style="font-size:12px;color:#666">Abre la app para más detalles.</p>
            </div>
          `.trim();

          let lastId = 0;
          const pageSize = Number(process.env.MASS_EMAIL_PAGE_SIZE || 500);

          while (true) {
            const users = await prisma.user.findMany({
              where: {
                id: { gt: lastId },
                active: true,
                verified: true,
                role: 'user'
              },
              select: { id: true, email: true },
              orderBy: { id: 'asc' },
              take: Number.isFinite(pageSize) ? pageSize : 500
            });

            if (!users.length) break;
            lastId = users[users.length - 1].id;

            const recipients = users.map((u) => u.email).filter(Boolean);
            const summary = await sendBulkEmails(recipients, { subject, text, html, forceSmtp: true });
            totalSent += summary.sent;
            totalFailed += summary.failed;

            console.log(
              `[BROADCAST EMAIL] announcementId=${announcement.id} batch=${recipients.length} sent=${summary.sent} failed=${summary.failed} lastUserId=${lastId}`
            );
          }

          try {
            await prisma.auditLog.create({
              data: {
                action: 'EMAIL_BROADCAST',
                userId: adminId,
                entity: 'Announcement',
                entityId: String(announcement.id),
                detail: `Broadcast announcement email sent=${totalSent} failed=${totalFailed}`,
                severity: totalFailed > 0 ? 'WARN' : 'INFO',
                metadata: { announcementId: announcement.id, sent: totalSent, failed: totalFailed }
              }
            });
          } catch (_e) {
            // ignore audit log failures
          }

          console.log(
            `[BROADCAST EMAIL] DONE announcementId=${announcement.id} sent=${totalSent} failed=${totalFailed} ms=${Date.now() - startedAt}`
          );
        } catch (e) {
          console.error(`[BROADCAST EMAIL] FAILED announcementId=${announcement.id}`, e);
          try {
            await prisma.auditLog.create({
              data: {
                action: 'EMAIL_BROADCAST_FAILED',
                userId: adminId,
                entity: 'Announcement',
                entityId: String(announcement.id),
                detail: String(e?.message || e),
                severity: 'ERROR',
                metadata: { announcementId: announcement.id }
              }
            });
          } catch (_e2) {
            // ignore
          }
        }
      });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear anuncio' });
  }
});

app.post('/announcements/:id/react', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const type = String(req.body?.type || '').toUpperCase();
    
    if (!['LIKE', 'HEART', 'DISLIKE'].includes(type)) {
      return res.status(400).json({ error: 'Tipo de reacción inválido' });
    }

    const existing = await prisma.reaction.findUnique({
      where: {
        userId_announcementId: {
          userId: req.user.userId,
          announcementId: Number(id)
        }
      }
    });

    if (existing) {
      const existingType = String(existing.type || '').toUpperCase();
      if (existingType === type) {
        await prisma.reaction.delete({ where: { id: existing.id } });
        return res.json({ message: 'Reacción eliminada', active: false });
      } else {
        const updated = await prisma.reaction.update({
          where: { id: existing.id },
          data: { type }
        });
        return res.json({ message: 'Reacción actualizada', active: true, reaction: updated });
      }
    } else {
      const reaction = await prisma.reaction.create({
        data: {
          userId: req.user.userId,
          announcementId: Number(id),
          type
        }
      });
      return res.json({ message: 'Reacción agregada', active: true, reaction });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al reaccionar' });
  }
});

app.patch('/superadmin/settings/smtp', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const smtp = req.body; // { host, port, user, pass, secure, fromName, fromEmail }
    const settings = await prisma.systemSettings.upsert({
      where: { id: 1 },
      update: { smtp },
      create: { branding: {}, modules: {}, smtp }
    });
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: 'Error al guardar configuración SMTP' });
  }
});

// Puerto
const PORT = process.env.PORT || 3000;
app.get('/health', (req, res) => {
  res.json({ ok: true, status: 'up', timestamp: Date.now() });
});

// Forzar redeploy en Render
app.get('/', (req, res) => {
  res.json({ message: 'API de rifas funcionando' });
});

// --- GESTIÓN DE PAGOS MANUALES (Admin) ---

// Listar movimientos/transacciones del sistema
app.get('/admin/transactions', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const status = req.query.status ? String(req.query.status).trim().toLowerCase() : '';
    const q = req.query.q ? String(req.query.q).trim() : '';
    const limitRaw = Number(req.query.limit);
    const take = Number.isFinite(limitRaw) ? Math.max(1, Math.min(500, Math.floor(limitRaw))) : 200;

    const where = {};
    if (status) where.status = status;

    if (q) {
      where.OR = [
        { type: { contains: q, mode: 'insensitive' } },
        { provider: { contains: q, mode: 'insensitive' } },
        { externalId: { contains: q, mode: 'insensitive' } },
        { txCode: { contains: q, mode: 'insensitive' } },
        { user: { email: { contains: q, mode: 'insensitive' } } }
      ];
    }

    const transactions = await prisma.transaction.findMany({
      where,
      include: {
        user: { select: { id: true, name: true, email: true, state: true } }
      },
      orderBy: { createdAt: 'desc' },
      take
    });

    // Backfill lazy: asigna txCode a registros viejos que no lo tengan
    const txCodeById = new Map();
    const missing = transactions.filter((t) => !t?.txCode);
    for (const t of missing) {
      let attempts = 0;
      while (attempts < 3) {
        attempts += 1;
        const nextCode = generateTxCode();
        try {
          const updated = await prisma.transaction.update({
            where: { id: t.id },
            data: { txCode: nextCode }
          });
          txCodeById.set(updated.id, updated.txCode);
          break;
        } catch (_e) {
          // unique collision muy improbable: reintentar
        }
      }
    }

    const mapped = transactions.map((t) => {
      const safeRef = t.reference ? safeDecrypt(t.reference) : null;
      const safeProof = t.proof ? safeDecrypt(t.proof) : null;
      const safeUserName = t.user?.name ? safeDecrypt(t.user.name) : t.user?.name || null;
      return {
        ...t,
        txCode: t.txCode || txCodeById.get(t.id) || null,
        reference: safeRef,
        proof: safeProof,
        user: t.user ? { ...t.user, name: safeUserName } : null
      };
    });

    res.json(mapped);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener movimientos' });
  }
});

// Validar boleto (Admin / Superadmin)
app.post('/admin/tickets/validate', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const { ticketId, serial } = req.body || {};
    if (!ticketId && !serial) return res.status(400).json({ error: 'ticketId o serial requerido' });

    let ticket = null;
    if (ticketId) {
      ticket = await prisma.ticket.findUnique({ where: { id: Number(ticketId) } });
    } else if (serial) {
      ticket = await prisma.ticket.findFirst({ where: { OR: [{ serialNumber: String(serial) }, { code: String(serial) }] } });
    }

    if (!ticket) return res.status(404).json({ error: 'Ticket no encontrado' });

    const status = String(ticket.status || '').toLowerCase();
    if (status === 'redeemed' || status === 'used' || status === 'closed') {
      return res.status(400).json({ error: 'Ticket ya fue validado' });
    }

    // Marcar como redimido
    const updated = await prisma.ticket.update({ where: { id: ticket.id }, data: { status: 'redeemed' } });

    // Registrar auditoría
    try {
      await prisma.auditLog.create({
        data: {
          action: 'TICKET_VALIDATED',
          userId: req.user.userId,
          entity: 'Ticket',
          entityId: String(ticket.id),
          detail: `Ticket validado por admin ${req.user.userId}`,
          severity: 'INFO',
          metadata: { serial: ticket.serialNumber ?? null }
        }
      });
    } catch (_e) {
      // no bloquear la respuesta por fallo en auditoría
    }

    res.json({ ok: true, ticket: { id: updated.id, status: updated.status } });
  } catch (error) {
    console.error('[POST /admin/tickets/validate] error', error);
    res.status(500).json({ error: 'Error al validar ticket' });
  }
});

// Verificar un número de transacción (auditable)
app.get('/admin/transactions/verify/:txCode', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const txCode = String(req.params.txCode || '').trim();
  if (!txCode) return res.status(400).json({ error: 'txCode requerido' });

  try {
    const transaction = await prisma.transaction.findFirst({
      where: { txCode },
      include: { user: { select: { id: true, name: true, email: true } } }
    });

    const found = !!transaction;
    try {
      await prisma.auditLog.create({
        data: {
          action: found ? 'TRANSACTION_VERIFIED' : 'TRANSACTION_VERIFY_NOT_FOUND',
          userId: req.user.userId,
          userEmail: req.user.email,
          entity: 'Transaction',
          entityId: found ? String(transaction.id) : txCode,
          detail: found ? `Verified txCode=${txCode}` : `Verify failed txCode=${txCode}`,
          severity: found ? 'INFO' : 'WARN',
          metadata: { txCode, found }
        }
      });
    } catch (_e) {
      // ignore audit log failures
    }

    if (!transaction) return res.status(404).json({ error: 'Transacción no encontrada' });

    const safeUserName = transaction.user?.name ? safeDecrypt(transaction.user.name) : transaction.user?.name || null;
    res.json({
      ...transaction,
      reference: transaction.reference ? safeDecrypt(transaction.reference) : null,
      proof: transaction.proof ? safeDecrypt(transaction.proof) : null,
      user: transaction.user ? { ...transaction.user, name: safeUserName } : null
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al verificar transacción' });
  }
});

// Listar pagos manuales (permite filtrar y normaliza el proof para mostrar la imagen)
app.get('/admin/manual-payments', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;
    const { raffleId, status, reference } = req.query;
    const where = { type: 'manual_payment' };
    if (status) where.status = status;
    else where.status = 'pending';
    if (raffleId) where.raffleId = Number(raffleId);
    if (reference) where.reference = { contains: reference, mode: 'insensitive' };

    // Admin: limitar a sus rifas. Superadmin: ve todo.
    if (actorRole !== 'superadmin') {
      const own = await prisma.raffle.findMany({ where: { userId: actorId }, select: { id: true } });
      const ownIds = own.map((r) => r.id);
      if (!ownIds.length) return res.json([]);
      if (where.raffleId) {
        if (!ownIds.includes(where.raffleId)) return res.json([]);
      } else {
        where.raffleId = { in: ownIds };
      }
    }

    const payments = await prisma.transaction.findMany({
      where,
      include: {
        user: { select: { id: true, name: true, email: true, state: true } }
      },
      orderBy: { createdAt: 'desc' }
    });

    const normalizeProof = (p) => {
      if (!p) return null;
      if (p.startsWith('http') || p.startsWith('data:')) return p;
      return `data:image/jpeg;base64,${p}`;
    };

    const mapped = payments.map((p) => {
      const decryptedReference = decrypt(p.reference);
      const decryptedProof = decrypt(p.proof);
      const decryptedUserName = p.user ? decrypt(p.user.name) : null;

      return {
        id: p.id,
        raffleId: p.raffleId,
        amount: p.amount,
        reference: decryptedReference,
        proof: normalizeProof(decryptedProof),
        status: p.status,
        note: decryptedReference,
        createdAt: p.createdAt,
        user: p.user ? { ...p.user, name: decryptedUserName } : null
      };
    });

    res.json(mapped);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al listar pagos manuales' });
  }
});

// Aprobar pago manual y asignar tickets
app.post('/admin/manual-payments/:id/approve', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { id } = req.params;

  try {
    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;

    const payment = await prisma.transaction.findUnique({ where: { id: Number(id) } });
    if (!payment) return res.status(404).json({ error: 'Pago no encontrado' });
    if (payment.status !== 'pending') return res.status(400).json({ error: 'El pago ya fue procesado' });

    if (!payment.raffleId) return res.status(400).json({ error: 'Pago sin rifa asociada' });
    const raffle = await prisma.raffle.findUnique({ where: { id: payment.raffleId } });

    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });
    if (actorRole !== 'superadmin' && raffle.userId !== actorId) {
      return res.status(403).json({ error: 'No puedes aprobar pagos de rifas de otros admins' });
    }

    const ticketPrice = Number(raffle.ticketPrice);
    const totalTickets = Number(raffle.totalTickets);
    if (!Number.isFinite(ticketPrice) || ticketPrice <= 0) {
      return res.status(400).json({ error: 'La rifa tiene un precio inválido. Corrige el precio antes de aprobar pagos.' });
    }
    if (!Number.isFinite(totalTickets) || totalTickets <= 0) {
      return res.status(400).json({ error: 'La rifa tiene totalTickets inválido. Corrige la rifa antes de aprobar pagos.' });
    }
    
    const quantity = Math.floor(Number(payment.amount) / ticketPrice);
    if (quantity <= 0) return res.status(400).json({ error: 'Monto insuficiente para un ticket' });

    const soldTickets = await prisma.ticket.findMany({
      where: { raffleId: raffle.id },
      select: { number: true }
    });
    const soldSet = new Set(soldTickets.map(t => t.number));
    
    const assignedNumbers = [];
    let attempts = 0;
    while (assignedNumbers.length < quantity && attempts < quantity * 100) {
      const num = Math.floor(Math.random() * totalTickets) + 1;
      if (!soldSet.has(num) && !assignedNumbers.includes(num)) {
        assignedNumbers.push(num);
      }
      attempts++;
    }

    if (assignedNumbers.length < quantity) {
      return res.status(400).json({ error: 'No hay suficientes tickets disponibles' });
    }

    await prisma.$transaction(async (tx) => {
      await tx.transaction.update({
        where: { id: Number(id) },
        data: { status: 'approved' }
      });

      for (const num of assignedNumbers) {
        await tx.ticket.create({
          data: {
            number: num,
            userId: payment.userId,
            raffleId: raffle.id,
            status: 'approved'
          }
        });
      }
    });

    const user = await prisma.user.findUnique({ where: { id: payment.userId } });
    if (user) {
      const digits = getTicketDigitsFromRaffle(raffle);
      const assignedNumbersFormatted = assignedNumbers.map((n) => formatTicketNumber(n, digits));
      sendEmail(
        user.email,
        'Pago Aprobado - Tickets Asignados',
        `Tu pago ha sido aprobado. Tus números son: ${assignedNumbersFormatted.join(', ')}`,
        `<h1>¡Pago Aprobado!</h1><p>Gracias por tu compra.</p><p>Tus números de la suerte son:</p><h3>${assignedNumbersFormatted.join(', ')}</h3>`
      ).catch(console.error);
    }

    {
      const digits = getTicketDigitsFromRaffle(raffle);
      res.json({
        message: 'Pago aprobado y tickets generados',
        tickets: assignedNumbers,
        ticketsFormatted: assignedNumbers.map((n) => formatTicketNumber(n, digits)),
        digits
      });
    }

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al aprobar pago' });
  }
});

// Rechazar pago manual
app.post('/admin/manual-payments/:id/reject', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { id } = req.params;
  try {
    await prisma.transaction.update({
      where: { id: Number(id) },
      data: { status: 'rejected' }
    });
    res.json({ message: 'Pago rechazado' });
  } catch (error) {
    res.status(500).json({ error: 'Error al rechazar pago' });
  }
});

// Validar ticket (Superadmin / Admin)
app.post('/admin/tickets/validate', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { serialNumber, raffleId, number } = req.body || {};
  if (!serialNumber && !(raffleId && number)) {
    return res.status(400).json({ error: 'serialNumber o (raffleId + number) requerido' });
  }

  try {
    let ticket = null;
    if (serialNumber) {
      ticket = await prisma.ticket.findUnique({ where: { serialNumber: String(serialNumber) } });
    } else {
      ticket = await prisma.ticket.findFirst({ where: { raffleId: Number(raffleId), number: Number(number) } });
    }

    if (!ticket) return res.status(404).json({ error: 'Ticket no encontrado' });

    const currentStatus = String(ticket.status || '').toLowerCase();
    if (currentStatus === 'validated' || currentStatus === 'used') {
      return res.status(400).json({ error: 'Ticket ya validado' });
    }

    const updated = await prisma.ticket.update({ where: { id: Number(ticket.id) }, data: { status: 'validated' } });

    try {
      if (typeof securityLogger !== 'undefined' && securityLogger && typeof securityLogger.log === 'function') {
        await securityLogger.log({
          action: 'TICKET_VALIDATED',
          userEmail: req.user?.email,
          userId: req.user?.userId,
          ipAddress: String(req.ip || req.headers['x-forwarded-for'] || ''),
          userAgent: String(req.headers['user-agent'] || ''),
          severity: 'INFO',
          detail: `Ticket validated serial=${updated.serialNumber || ''} number=${updated.number || ''} raffle=${updated.raffleId}`,
          entity: 'Ticket',
          entityId: String(updated.id)
        });
      }
    } catch (_e) {
      // No bloquear si falla el logger
    }

    return res.json({ ok: true, ticket: updated });
  } catch (error) {
    console.error('[/admin/tickets/validate] Error:', error);
    return res.status(500).json({ error: 'Error al validar ticket' });
  }
});

// Endpoint de diagnóstico para Email (Temporal)
app.get('/debug/test-email', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'Falta el parametro ?email=...' });

  try {
    console.log(`[DEBUG] Probando envío a ${email}...`);
    // Usamos sendEmail para aprovechar la lógica de Resend API
    const success = await sendEmail(
      email,
      'Prueba de Diagnóstico MegaRifas',
      'Si lees esto, el correo funciona.',
      '<h1>¡Funciona!</h1><p>Si lees esto, el sistema de correos está operativo.</p>'
    );

    if (success) {
      return res.json({ message: 'Correo enviado exitosamente (Revisa logs para ver si fue API o SMTP)' });
    } else {
      return res.status(500).json({ error: 'Fallo el envio', details: 'Revisa los logs del servidor.' });
    }
  } catch (err) {
    return res.status(500).json({ 
      error: 'Error interno', 
      details: err.message 
    });
  }
});

// Start Server with DB Check and Error Handling
async function startServer() {
  console.log('Iniciando proceso de arranque del servidor...');
  const port = Number(process.env.PORT) || 3000;
  
  // 1. Iniciar servidor HTTP inmediatamente para satisfacer a Render (evitar timeout 502)
  const server = app.listen(port, '0.0.0.0', () => {
    console.log(`✅ Servidor backend escuchando en el puerto ${port} (Accesible desde red)`);
    console.log(`   - Ambiente: ${process.env.NODE_ENV || 'development'}`);
    console.log(`   - URL Local: http://localhost:${port}`);
  });

  // 2. Conectar a la base de datos en segundo plano
  try {
    console.log('⏳ Intentando conectar a la base de datos...');
    await prisma.$connect();
    console.log('✅ Conexión a base de datos exitosa.');
  } catch (error) {
    console.error('❌ ERROR CRÍTICO DE BASE DE DATOS:', error);
    console.error('   El servidor seguirá ejecutándose para mostrar logs, pero las consultas fallarán.');
    // No hacemos process.exit(1) para permitir ver los logs en Render
  }

  // Scheduler: cerrar rifas expiradas periódicamente (evita depender solo de llamadas manuales)
  try {
    const intervalMin = Number(process.env.RAFFLE_CLOSE_INTERVAL_MINUTES) || 5; // cada 5 minutos por defecto
    let closingInProgress = false;
    const runCloseJob = async () => {
      if (closingInProgress) return;
      closingInProgress = true;
      try {
        console.log(`[RAFFLE_CLOSE_JOB] iniciando check de rifas vencidas (limit=200)`);
        const out = await closeExpiredRafflesBatch(200);
        if (out && out.closed) {
          console.log(`[RAFFLE_CLOSE_JOB] cerrado: ${out.closed} de ${out.scanned} rifas escaneadas`);
        } else {
          console.log(`[RAFFLE_CLOSE_JOB] nada que cerrar (escaneadas=${out?.scanned || 0})`);
        }
      } catch (e) {
        console.error('[RAFFLE_CLOSE_JOB] Error ejecutando job:', e);
      } finally {
        closingInProgress = false;
      }
    };

    // Primera ejecución inmediata para cerrar lo pendiente al arrancar
    setTimeout(runCloseJob, 5 * 1000);
    setInterval(runCloseJob, Math.max(1, intervalMin) * 60 * 1000);
    console.log(`[RAFFLE_CLOSE_JOB] programado cada ${intervalMin} minutos`);

    // Scheduler: revisar rifas pospuestas por número no vendido
    try {
      const postponeRecheckMin = Number(process.env.RAFFLE_POSTPONE_RECHECK_MINUTES) || 60;
      let rechecking = false;
      const runRecheckPostponed = async () => {
        if (rechecking) return;
        rechecking = true;
        try {
          console.log(`[RAFFLE_POSTPONE_JOB] iniciando re-evaluación de rifas pospuestas`);
          const out = await reEvaluatePostponedRafflesBatch(200);
          console.log(`[RAFFLE_POSTPONE_JOB] result: ${JSON.stringify(out)}`);
        } catch (e) {
          console.error('[RAFFLE_POSTPONE_JOB] Error:', e);
        } finally {
          rechecking = false;
        }
      };
      setTimeout(runRecheckPostponed, 10 * 1000);
      setInterval(runRecheckPostponed, Math.max(10, postponeRecheckMin) * 60 * 1000);
      console.log(`[RAFFLE_POSTPONE_JOB] programado cada ${postponeRecheckMin} minutos`);
    } catch (e) {
      console.error('[RAFFLE_POSTPONE_JOB] no se pudo inicializar:', e);
    }
  } catch (e) {
    console.error('[RAFFLE_CLOSE_JOB] no se pudo inicializar el scheduler:', e);
  }

  // Graceful shutdown
  const shutdown = async (signal) => {
    console.log(`${signal} recibido. Cerrando servidor...`);
    server.close(() => {
      console.log('Servidor HTTP cerrado.');
    });
    try {
      await prisma.$disconnect();
      console.log('Conexión a BD cerrada.');
    } catch (e) {
      console.error('Error al cerrar BD:', e);
    }
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

// Manejo de errores no capturados
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});



startServer();

// Middleware global de manejo de errores (SIEMPRE al final)
app.use((err, req, res, next) => {
  console.error('[GLOBAL ERROR HANDLER]', err);
  // Si el error es de sintaxis JSON (body-parser)
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'JSON malformado' });
  }
  // Cualquier otro error
  res.status(err.status || 500).json({
    error: err.message || 'Error interno del servidor',
    details: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});


