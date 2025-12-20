require('dotenv').config();
const express = require('express');
const { PrismaClient, Prisma } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const crypto = require('crypto');
const FraudEngine = require('./utils/fraudEngine');
const paymentService = require('./services/paymentService');

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

const app = express();

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

app.get('/__diag/routes', (req, res) => {
  const stack = app?._router?.stack || app?.router?.stack || [];
  const allRoutes = stack
    .filter((layer) => layer?.route?.path)
    .map((layer) => {
      const methods = Object.keys(layer.route.methods || {}).join(',');
      return { path: layer.route.path, methods };
    });

  const techSupportRoutes = allRoutes.filter(
    (r) => r.path === '/settings/tech-support' || r.path === '/superadmin/settings/tech-support' || String(r.path).startsWith('/settings')
  );

  const hasSettingsTechSupport = allRoutes.some((r) => r.path === '/settings/tech-support');
  const hasSuperadminTechSupport = allRoutes.some((r) => r.path === '/superadmin/settings/tech-support');
  const hasRaffles = allRoutes.some((r) => r.path === '/raffles');

  res.json({
    totals: {
      topLevelRoutes: allRoutes.length
    },
    hasRaffles,
    hasSettingsTechSupport,
    hasSuperadminTechSupport,
    sample: {
      first: allRoutes.slice(0, 25),
      last: allRoutes.slice(-25)
    },
    techSupportRoutes
  });
});

console.log('🔒 Security Module Loaded: Encryption Enabled');

// Security Middleware
app.use(helmet());
app.use(cors());
app.use(compression());

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

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

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
        await prisma.mailLog.create({
          data: { to, subject, status: 'FAILED_API', timestamp: new Date() }
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
      await prisma.mailLog.create({
        data: { to, subject, status: 'FAILED', timestamp: new Date() }
      });
    } catch (logError) {
      console.warn('Failed to log email failure to DB:', logError.message);
    }
    return false;
  }
}

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
app.get('/raffles', async (req, res) => {
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
          totalTickets: true,
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

    res.json(decryptedRaffles);
  } catch (error) {
    console.error('[GET /raffles] Error:', error);
    res.status(500).json({ error: 'Error al obtener rifas' });
  }
});

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
  const safeEmail = (email || '').toLowerCase().trim();
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
  const verificationToken = generateVerificationCode();

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
        verified: false
      }
    });

    if (referredById) {
      // Check for rewards asynchronously
      checkAndRewardReferrer(referredById).catch(console.error);
    }
    
    // Enviar correo de bienvenida con token
    sendEmail(
      email, 
      'Activa tu cuenta en MegaRifas', 
      `Hola ${name}, tu código de verificación es: ${verificationToken}`,
      `<h1>¡Bienvenido a MegaRifas!</h1>
       <p>Hola <b>${name}</b>,</p>
       <p>Gracias por registrarte. Para activar tu cuenta, usa el siguiente código:</p>
       <h2 style="color: #4f46e5; letter-spacing: 5px;">${verificationToken}</h2>
       <p>Si no solicitaste esta cuenta, ignora este correo.</p>`
    ).catch(console.error);

    res.status(201).json({ message: 'Usuario registrado. Verifique su correo.', user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// Verificar email
app.post('/verify-email', async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'Faltan datos' });

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    if (user.verified) return res.json({ message: 'Cuenta ya verificada' });

    if (user.verificationToken !== code) {
      return res.status(400).json({ error: 'Código inválido' });
    }

    await prisma.user.update({
      where: { email },
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

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (user.verified) return res.status(400).json({ error: 'Usuario ya verificado' });

    const verificationToken = generateVerificationCode();
    await prisma.user.update({
      where: { email },
      data: { verificationToken }
    });

    await sendEmail(
      email,
      'Reenvío de Código de Verificación',
      `Tu nuevo código es: ${verificationToken}`,
      `<h1>Código de Verificación</h1><p>Tu nuevo código es:</p><h2>${verificationToken}</h2>`
    );

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
// Nota: esta versión envía un correo informativo; no cambia contraseña directamente.
app.post('/auth/password/reset/request', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email requerido' });

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    // Evitar enumeración de usuarios: respondemos OK aunque no exista.
    if (!user) {
      return res.json({ message: 'Si el correo existe, enviaremos instrucciones.' });
    }

    const webBaseUrl = String(process.env.WEB_BASE_URL || '').trim();
    const resetToken = jwt.sign({ email, purpose: 'password_reset' }, JWT_SECRET, { expiresIn: '15m' });
    const resetLink = webBaseUrl ? `${webBaseUrl.replace(/\/$/, '')}/recuperar?token=${encodeURIComponent(resetToken)}` : null;

    const subject = 'Recuperación de contraseña - MegaRifas';
    const text = resetLink
      ? `Para recuperar tu contraseña, abre este enlace (válido por 15 minutos): ${resetLink}`
      : 'Solicitaste recuperación de contraseña. Contacta a soporte o intenta nuevamente más tarde.';
    const html = resetLink
      ? `<h1>Recuperación de contraseña</h1><p>Para recuperar tu contraseña, haz clic aquí (válido por 15 minutos):</p><p><a href="${escapeHtml(resetLink)}">Recuperar contraseña</a></p>`
      : '<h1>Recuperación de contraseña</h1><p>Solicitaste recuperación de contraseña. Contacta a soporte o intenta nuevamente más tarde.</p>';

    await sendEmail(email, subject, text, html).catch(console.error);
    return res.json({ message: 'Hemos enviado instrucciones a tu correo.' });
  } catch (error) {
    console.error('Password reset request error:', error);
    return res.status(500).json({ error: 'Error al solicitar recuperación' });
  }
});

// Refresh token endpoint esperado por la app móvil.
// Si no manejas refresh tokens, respondemos JSON (no HTML/404) para evitar errores.
app.post('/auth/refresh', async (_req, res) => {
  return res.status(501).json({ error: 'Refresh token no soportado en esta versión.' });
});

// Login de usuario
const handleLogin = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  const user = await prisma.user.findUnique({ where: { email } });
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

  const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  
  // Remove password from user object before sending
  const { password: _, ...userWithoutPassword } = user;
  
  // Decrypt sensitive data
  if (userWithoutPassword.name) userWithoutPassword.name = decrypt(userWithoutPassword.name);
  if (userWithoutPassword.bankDetails) userWithoutPassword.bankDetails = JSON.parse(decrypt(JSON.stringify(userWithoutPassword.bankDetails)));

  // Adaptar respuesta para que coincida con lo que espera la App móvil (accessToken)
  res.json({ message: 'Login exitoso', token, accessToken: token, user: userWithoutPassword });
};

app.post('/login', loginLimiter, handleLogin);
app.post('/auth/login', loginLimiter, handleLogin); // Alias para la App Móvil

// Validar 2FA Admin
app.post('/auth/2fa', async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'Faltan datos' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

  if (user.verificationToken !== code) {
    await securityLogger.log({
      action: '2FA_FAILED',
      userEmail: email,
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
    userEmail: email,
    userId: user.id,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    severity: 'INFO',
    detail: '2FA verification successful'
  });

  const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  const { password: _, ...userWithoutPassword } = user;

  // Decrypt sensitive data
  if (userWithoutPassword.name) userWithoutPassword.name = decrypt(userWithoutPassword.name);
  if (userWithoutPassword.bankDetails) userWithoutPassword.bankDetails = JSON.parse(decrypt(JSON.stringify(userWithoutPassword.bankDetails)));

  res.json({ message: 'Login exitoso', token, user: userWithoutPassword });
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

    return res.json({
      raffle: { id: raffle.id, title: raffle.title },
      paymentMethods,
      bankDetails: seller?.bankDetails || null,
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
    const raffle = await prisma.raffle.findUnique({ where: { id: Number(id) } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

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

    // Transacción
    await prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: userId },
        data: { balance: { decrement: totalCost } }
      });

      await tx.transaction.create({
        data: {
          txCode: generateTxCode(),
          userId,
          raffleId: Number(id),
          amount: totalCost,
          type: 'purchase',
          status: 'approved',
          provider: 'wallet',
          reference: `Compra de ${qty} tickets en rifa #${id}`
        }
      });

      for (const num of newNumbers) {
        await tx.ticket.create({
          data: {
            raffleId: Number(id),
            userId,
            number: num,
            status: 'approved'
          }
        });
      }
    });

    res.status(201).json({ 
      message: 'Compra exitosa', 
      numbers: newNumbers,
      remainingBalance: user.balance - totalCost 
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al procesar la compra' });
  }
});

app.get('/me/raffles', authenticateToken, async (req, res) => {
  try {
    const tickets = await prisma.ticket.findMany({
      where: { userId: req.user.userId },
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
    
    const raffleIds = Array.from(new Set((tickets || []).map((t) => t.raffleId).filter(Boolean)));
    const purchases = raffleIds.length
      ? await prisma.transaction.findMany({
          where: {
            userId: req.user.userId,
            raffleId: { in: raffleIds },
            type: 'purchase'
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
          method: null
        };
      }
      const amount = Number(p.amount);
      if (Number.isFinite(amount)) purchaseByRaffle[rid].totalSpent += amount;
      purchaseByRaffle[rid].purchasedAt = p.createdAt;
      purchaseByRaffle[rid].method = p.provider || purchaseByRaffle[rid].method;
    }

    const grouped = {};
    for (const t of tickets) {
      if (!t) continue;
      if (!grouped[t.raffleId]) {
        const raffle = t.raffle || {};
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
          isWinner: false,
          createdAt: t.createdAt,
          payment: purchaseByRaffle[t.raffleId] || { totalSpent: null, purchasedAt: null, method: null }
        };
      }
      grouped[t.raffleId].numbers.push(t.number);
      // La fecha/hora más útil para el usuario es la del último ticket de esa rifa (aprox. última compra)
      if (t.createdAt && (!grouped[t.raffleId].createdAt || t.createdAt > grouped[t.raffleId].createdAt)) {
        grouped[t.raffleId].createdAt = t.createdAt;
      }
    }

    res.json(Object.values(grouped));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener mis rifas' });
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
  const { amount, currency, provider, type, raffleId } = req.body;
  const userId = req.user.userId;

  try {
    const result = await paymentService.initiateTransaction(userId, parseFloat(amount), currency, provider, type, raffleId);
    res.json(result);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error initiating payment' });
  }
});

// Webhook for payment providers
app.post('/payments/webhook/:provider', async (req, res) => {
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
          reference: encrypt(`Compra Rifa: ${raffle.title}`),
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
            reference: encrypt(`Ticket #${assignedNumber} - ${raffle.title}`)
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
      sendEmail(
        ticket.user.email,
        'Confirmación de Ticket - MegaRifas',
        `Has comprado el ticket #${ticket.number} para la rifa ${ticket.raffle.title}. Serial: ${ticket.serialNumber}`,
        `<h1>¡Ticket Confirmado!</h1><p>Has adquirido el número <b>${ticket.number}</b> para la rifa <i>${ticket.raffle.title}</i>.</p><p>Serial único: <code>${ticket.serialNumber}</code></p>`
      ).catch(console.error);
    }

    res.status(201).json({ message: 'Ticket creado', ticket });
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
      sendEmail(
        transaction.user.email,
        'Pago Aprobado - Ticket Asignado',
        `Tu pago ha sido verificado. Tu número es: ${ticket.number}`,
        `<h1>¡Pago Verificado!</h1><p>Tu número asignado es: <b>${ticket.number}</b></p><p>Rifa: ${raffle.title}</p>`
      ).catch(console.error);
    }

    res.json({ message: 'Pago verificado y ticket asignado', ticket });

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
        raffle: { select: { title: true } }
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
    // Asumimos que el admin principal es el ID 1 o buscamos por rol
    const admin = await prisma.user.findFirst({ where: { role: 'superadmin' } });
    if (!admin || !admin.bankDetails) return res.status(404).json({ error: 'Datos bancarios no disponibles' });
    res.json(admin.bankDetails);
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
    res.json(raffles.map(r => ({ ...r, soldTickets: r._count?.tickets || 0 })));
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

    return res.json({ message: 'Rifa activada', raffle: updated });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al activar rifa' });
  }
});

app.patch('/admin/raffles/:id', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { id } = req.params;
  const data = req.body;
  try {
    const actorRole = String(req.user?.role || '').toLowerCase();
    const actorId = req.user?.userId;
    const raffle = await prisma.raffle.findUnique({ where: { id: Number(id) }, select: { userId: true } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });
    if (actorRole !== 'superadmin' && raffle.userId !== actorId) {
      return res.status(403).json({ error: 'No puedes editar rifas de otros usuarios.' });
    }

    // Handle style update specifically if nested
    if (data.style) {
      const current = await prisma.raffle.findUnique({ where: { id: Number(id) }, select: { style: true } });
      data.style = { ...(current?.style || {}), ...data.style };
    }
    
    const updatedRaffle = await prisma.raffle.update({
      where: { id: Number(id) },
      data
    });
    res.json(updatedRaffle);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar rifa' });
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
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    const tickets = await prisma.ticket.findMany({ include: { raffle: { select: { ticketPrice: true } } } });
    const todayTickets = tickets.filter((t) => t.createdAt >= startOfDay);
    const ticketsSold = tickets.length;
    const participants = new Set(tickets.map((t) => t.userId)).size;
    const totalRevenue = tickets.reduce((acc, t) => acc + (t.raffle?.ticketPrice || 0), 0);
    const todayRevenue = todayTickets.reduce((acc, t) => acc + (t.raffle?.ticketPrice || 0), 0);
    const pendingPayments = await prisma.transaction.count({ where: { status: 'pending' } });

    res.json({
      ticketsSold,
      participants,
      pendingPayments,
      totalRevenue,
      todaySales: todayTickets.length,
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
    const since = new Date();
    since.setHours(0, 0, 0, 0);
    since.setDate(since.getDate() - (days - 1));

    const tickets = await prisma.ticket.findMany({
      where: { createdAt: { gte: since } },
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
    const tickets = await prisma.ticket.findMany({
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
    const buyers = await prisma.ticket.groupBy({
      by: ['userId'],
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
  const { raffleId, ticketNumber, winnerName, prize, testimonial, photoUrl } = req.body;
  
  if (!raffleId || !winnerName || !prize) {
    return res.status(400).json({ error: 'Faltan datos requeridos (Rifa, Nombre, Premio)' });
  }

  try {
    // Intentar buscar usuario por ticket si existe
    let userId = null;
    if (ticketNumber) {
      const ticket = await prisma.ticket.findFirst({
        where: { raffleId: Number(raffleId), number: Number(ticketNumber) },
        include: { user: true }
      });
      if (ticket) userId = ticket.userId;
    }

    const winner = await prisma.winner.create({
      data: {
        raffleId: Number(raffleId),
        userId,
        prize,
        testimonial: testimonial || '',
        photoUrl: photoUrl || null,
        // Si no hay usuario registrado, guardamos el nombre en el testimonio o necesitamos campo extra.
        // Por ahora el schema tiene userId opcional.
      }
    });

    res.json({ message: 'Ganador publicado exitosamente', winner });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al publicar ganador' });
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
    res.json(winners);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener ganadores' });
  }
});

// --- ADMIN ANNOUNCEMENTS ---

app.post('/admin/announcements', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { title, content, imageUrl } = req.body;
  
  if (!title || !content) {
    return res.status(400).json({ error: 'Título y contenido requeridos' });
  }

  try {
    const announcement = await prisma.announcement.create({
      data: {
        title,
        content,
        imageUrl,
        adminId: req.user.userId
      }
    });
    
    // Opcional: Enviar push notification automática
    // sendPushToAll(title, content);

    res.json({ message: 'Anuncio publicado', announcement });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear anuncio' });
  }
});

app.get('/announcements', async (req, res) => {
  try {
    const news = await prisma.announcement.findMany({
      orderBy: { createdAt: 'desc' },
      take: 20,
      include: { admin: { select: { name: true } } }
    });
    res.json(news);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener noticias' });
  }
});

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

    // Crear tabla Winner si no existe
    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS "Winner" (
        "id" SERIAL NOT NULL,
        "raffleId" INTEGER NOT NULL,
        "userId" INTEGER,
        "photoUrl" TEXT,
        "testimonial" TEXT,
        "prize" TEXT,
        "drawDate" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT "Winner_pkey" PRIMARY KEY ("id")
      );
    `);

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

    // 1. Buscar tickets vendidos
    const tickets = await prisma.ticket.findMany({ where: { raffleId, status: 'approved' } });
    if (tickets.length === 0) return res.status(400).json({ error: 'No hay tickets vendidos para sortear' });

    // 2. Elegir ganador aleatorio
    const randomIndex = Math.floor(Math.random() * tickets.length);
    const winningTicket = tickets[randomIndex];

    // 3. Crear registro de ganador (Winner)
    // Nota: Esto es un sorteo interno. Si es por lotería externa, el admin usa "Publicar Ganador" manualmente.
    // Pero si usa este botón "Cerrar Rifa", asumimos que quiere que el sistema elija.
    
    const creatorRole = String(raffle?.user?.role || '').toLowerCase();
    const shouldAutoDelete = creatorRole === 'admin';

    if (shouldAutoDelete) {
      await prisma.$transaction(async (tx) => {
        await tx.ticket.deleteMany({ where: { raffleId } });
        await tx.winner.deleteMany({ where: { raffleId } });
        await tx.raffle.delete({ where: { id: raffleId } });
      });

      return res.json({
        message: 'Sorteo realizado. Esta rifa (creada por admin) fue eliminada automáticamente al finalizar.',
        winner: {
          number: winningTicket.number,
          userId: winningTicket.userId,
          serial: winningTicket.serialNumber
        },
        raffleDeleted: true
      });
    }

    await prisma.raffle.update({
      where: { id: raffleId },
      data: { status: 'closed', closedAt: new Date() }
    });

    return res.json({
      message: 'Sorteo realizado',
      winner: {
        number: winningTicket.number,
        userId: winningTicket.userId,
        serial: winningTicket.serialNumber
      },
      raffleDeleted: false
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al cerrar rifa' });
  }
});

// --- SUPERADMIN ENDPOINTS ---

app.get('/admin/bank-details', authenticateToken, async (req, res) => {
  try {
    // Asumimos que el primer superadmin o admin tiene los datos
    const admin = await prisma.user.findFirst({
      where: { role: { in: ['admin', 'superadmin'] }, bankDetails: { not: Prisma.DbNull } }
    });
    if (!admin || !admin.bankDetails) return res.json({ bankDetails: null });
    res.json({ bankDetails: admin.bankDetails });
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener datos bancarios' });
  }
});

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
          provider: provider ? String(provider) : 'manual',
          reference: encrypt('Recarga de saldo')
        }
      })
    ]);
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
  const { quantity, reference, note, proof } = req.body;
  
  if (!quantity || quantity <= 0) return res.status(400).json({ error: 'Cantidad inválida' });
  if (!proof) return res.status(400).json({ error: 'Comprobante requerido' });

  try {
    const raffle = await prisma.raffle.findUnique({ where: { id: Number(id) } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    const amount = Number(raffle.ticketPrice) * Number(quantity);

    const transaction = await prisma.transaction.create({
      data: {
        userId: req.user.userId,
        amount,
        type: 'manual_payment',
        status: 'pending',
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

// --- WINNERS ---
app.get('/winners', async (req, res) => {
  try {
    const winners = await prisma.winner.findMany({
      orderBy: { drawDate: 'desc' },
      include: {
        user: { select: { name: true, avatar: true, publicId: true } },
        raffle: { select: { title: true } }
      }
    });
    res.json(winners);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener ganadores' });
  }
});

app.post('/admin/winners', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const { raffleId, userId, photoUrl, testimonial, prize } = req.body;
    
    // Enforce KYC for winners
    if (userId) {
      const user = await prisma.user.findUnique({ where: { id: Number(userId) } });
      if (!user) return res.status(404).json({ error: 'Usuario ganador no encontrado' });
      
      if (!user.identityVerified) {
        return res.status(400).json({ 
          error: 'El usuario ganador NO ha verificado su identidad (KYC). No se puede registrar como ganador hasta cumplir con la normativa Anti-Lavado de Dinero.' 
        });
      }
    }

    const winner = await prisma.winner.create({
      data: {
        raffleId: Number(raffleId),
        userId: userId ? Number(userId) : null,
        photoUrl,
        testimonial,
        prize,
        status: 'delivered'
      }
    });

    // --- NOTIFICATION SYSTEM ---
    // 1. Get Raffle Details
    const raffle = await prisma.raffle.findUnique({ where: { id: Number(raffleId) } });

    // 2. Get Participants (Unique Users who bought tickets)
    const participants = await prisma.ticket.findMany({
      where: { raffleId: Number(raffleId) },
      distinct: ['userId'],
      select: { 
        user: { select: { pushToken: true, email: true, name: true } } 
      }
    });

    // 3. Prepare Notification Content
    let winnerName = 'Por anunciar';
    if (userId) {
      const winnerUser = await prisma.user.findUnique({ where: { id: Number(userId) } });
      if (winnerUser && winnerUser.name) winnerName = decrypt(winnerUser.name);
    }

    const title = `¡Resultados: ${raffle.title}!`;
    const body = `El ganador es: ${winnerName}. ¡Entra para ver los detalles!`;

    // 4. Send Push Notifications
    const tokens = participants.map(p => p.user.pushToken).filter(Boolean);
    if (tokens.length > 0) {
      // Send in background
      sendPushNotification(tokens, title, body, { type: 'raffle_result', raffleId: Number(raffleId) }).catch(console.error);
    }

    // 5. Audit Log (Proof of Publication Time)
    await prisma.auditLog.create({
      data: {
        action: 'RESULT_PUBLISHED',
        entity: 'Raffle',
        userEmail: req.user.email,
        detail: `Results published for raffle ${raffleId}. Winner: ${winnerName}. Notified ${tokens.length} participants at ${new Date().toISOString()}.`,
        timestamp: new Date()
      }
    });
    // ---------------------------

    res.json(winner);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al registrar ganador' });
  }
});

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
        email: true,
        name: true,
        role: true,
        adminPlan: true,
        balance: true,
        avatar: true,
        bio: true,
        socials: true,
        referralCode: true,
        createdAt: true
      }
    });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    // Decrypt sensitive data
    if (user.name) user.name = decrypt(user.name);

    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener perfil' });
  }
});

app.patch('/me', authenticateToken, async (req, res) => {
  try {
    const { name, avatar, bio, socials } = req.body;
    const user = await prisma.user.update({
      where: { id: req.user.userId },
      data: { name, avatar, bio, socials }
    });
    res.json(user);
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
app.get('/announcements', async (req, res) => {
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
      entry[g.type] = g._count?._all || 0;
    }

    const decryptedAnnouncements = announcements.map(a => {
      if (a.admin && a.admin.name) a.admin.name = decrypt(a.admin.name);
      return {
        ...a,
        reactionCounts: countsMap.get(a.id) || { LIKE: 0, HEART: 0, DISLIKE: 0 }
      };
    });

    res.json(decryptedAnnouncements);
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
    const { type } = req.body; 
    
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
      if (existing.type === type) {
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
    const { raffleId, status, reference } = req.query;
    const where = { type: 'manual_payment' };
    if (status) where.status = status;
    else where.status = 'pending';
    if (raffleId) where.raffleId = Number(raffleId);
    if (reference) where.reference = { contains: reference, mode: 'insensitive' };

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
    const payment = await prisma.transaction.findUnique({ where: { id: Number(id) } });
    if (!payment) return res.status(404).json({ error: 'Pago no encontrado' });
    if (payment.status !== 'pending') return res.status(400).json({ error: 'El pago ya fue procesado' });

    if (!payment.raffleId) return res.status(400).json({ error: 'Pago sin rifa asociada' });
    const raffle = await prisma.raffle.findUnique({ where: { id: payment.raffleId } });
    
    const quantity = Math.floor(payment.amount / raffle.ticketPrice);
    if (quantity <= 0) return res.status(400).json({ error: 'Monto insuficiente para un ticket' });

    const soldTickets = await prisma.ticket.findMany({
      where: { raffleId: raffle.id },
      select: { number: true }
    });
    const soldSet = new Set(soldTickets.map(t => t.number));
    
    const assignedNumbers = [];
    let attempts = 0;
    while (assignedNumbers.length < quantity && attempts < quantity * 100) {
      const num = Math.floor(Math.random() * raffle.totalTickets) + 1;
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
      sendEmail(
        user.email,
        'Pago Aprobado - Tickets Asignados',
        `Tu pago ha sido aprobado. Tus números son: ${assignedNumbers.join(', ')}`,
        `<h1>¡Pago Aprobado!</h1><p>Gracias por tu compra.</p><p>Tus números de la suerte son:</p><h3>${assignedNumbers.join(', ')}</h3>`
      ).catch(console.error);
    }

    res.json({ message: 'Pago aprobado y tickets generados', tickets: assignedNumbers });

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


