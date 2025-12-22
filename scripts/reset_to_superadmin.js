// scripts/reset_to_superadmin.js
// PELIGRO: borra datos. Deja solo el superadmin en la BD.
// Uso:
//   node scripts/reset_to_superadmin.js --yes
//   node scripts/reset_to_superadmin.js "postgresql://..." --yes
// Alternativa:
//   $env:RESET_TO_SUPERADMIN_YES="true"; node scripts/reset_to_superadmin.js

require('dotenv').config();
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const SUPERADMIN_EMAIL = process.env.SUPERADMIN_EMAIL || 'rifa@megarifasapp.com';
const SUPERADMIN_PASSWORD = process.env.SUPERADMIN_PASSWORD || 'rifasadmin123';
const SUPERADMIN_ROLE = process.env.SUPERADMIN_ROLE || 'superadmin';

function hasYesFlag(argv) {
  return argv.includes('--yes') || argv.includes('-y');
}

function looksLikeDbUrl(value) {
  return typeof value === 'string' && value.includes('://') && value.toLowerCase().startsWith('postgres');
}

function generateSecurityId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let result = 'MR-';
  for (let i = 0; i < 4; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
  result += '-';
  result += chars.charAt(Math.floor(Math.random() * chars.length));
  return result;
}

async function generateUniqueSecurityId(prisma, maxAttempts = 25) {
  for (let i = 0; i < maxAttempts; i++) {
    const securityId = generateSecurityId();
    const exists = await prisma.user.findUnique({ where: { securityId } });
    if (!exists) return securityId;
  }
  for (let i = 0; i < maxAttempts; i++) {
    const securityId = `MR-${Math.random().toString(36).slice(2, 10).toUpperCase()}`;
    const exists = await prisma.user.findUnique({ where: { securityId } });
    if (!exists) return securityId;
  }
  throw new Error('No se pudo generar un securityId único');
}

async function ensureSuperadmin(prisma) {
  const existing = await prisma.user.findUnique({ where: { email: SUPERADMIN_EMAIL } });
  if (!existing) {
    const hashed = await bcrypt.hash(SUPERADMIN_PASSWORD, 10);
    const securityId = await generateUniqueSecurityId(prisma);
    await prisma.user.create({
      data: {
        email: SUPERADMIN_EMAIL,
        name: 'Super Admin',
        password: hashed,
        role: SUPERADMIN_ROLE,
        active: true,
        verified: true,
        referredById: null,
        securityId
      }
    });
    return;
  }

  const data = {};
  if (existing.role !== SUPERADMIN_ROLE) data.role = SUPERADMIN_ROLE;
  if (!existing.active) data.active = true;
  if (!existing.verified) data.verified = true;
  if (existing.referredById) data.referredById = null;
  if (!existing.securityId) data.securityId = await generateUniqueSecurityId(prisma);

  if (Object.keys(data).length) {
    await prisma.user.update({ where: { email: SUPERADMIN_EMAIL }, data });
  }
}

async function safeDeleteMany(prisma, modelKey, args = {}) {
  const client = prisma?.[modelKey];
  if (!client || typeof client.deleteMany !== 'function') {
    console.warn(`[RESET] Modelo Prisma no encontrado: ${modelKey} (omitido)`);
    return { count: 0, skipped: true };
  }
  return client.deleteMany(args);
}

async function safeDeleteManyAny(prisma, modelKeys, args = {}) {
  for (const key of Array.isArray(modelKeys) ? modelKeys : []) {
    const client = prisma?.[key];
    if (client && typeof client.deleteMany === 'function') {
      return safeDeleteMany(prisma, key, args);
    }
  }
  console.warn(`[RESET] Ningún modelo Prisma válido encontrado para: ${modelKeys.join(', ')} (omitido)`);
  return { count: 0, skipped: true };
}

async function resetToSuperadmin() {
  const argv = process.argv.slice(2);
  const firstArg = argv[0];
  if (looksLikeDbUrl(firstArg)) process.env.DATABASE_URL = firstArg;

  const confirmed = hasYesFlag(argv) || String(process.env.RESET_TO_SUPERADMIN_YES || '').toLowerCase() === 'true';
  if (!confirmed) {
    console.error('ABORTADO: operación destructiva sin confirmación.');
    console.error('Ejecuta con: node scripts/reset_to_superadmin.js --yes');
    console.error('O usa: $env:RESET_TO_SUPERADMIN_YES="true"');
    process.exit(1);
  }

  if (!process.env.DATABASE_URL) {
    console.error('ERROR: No se encontró DATABASE_URL. Exporta la variable o pásala como argumento.');
    process.exit(1);
  }

  const prisma = new PrismaClient();

  try {
    console.log('Conectando a la base de datos...');
    await prisma.$queryRaw`SELECT 1`;

    console.log('Asegurando superadmin...');
    await ensureSuperadmin(prisma);

    console.log('Limpiando referencias de referidos (User.referredById)...');
    await prisma.user.updateMany({ data: { referredById: null } });

    console.log('Borrando datos (excepto superadmin)...');

    // Orden importante por llaves foráneas
    // Reacciones y módulos que dependen de usuarios/entidades
    await safeDeleteMany(prisma, 'reaction');
    await safeDeleteMany(prisma, 'raffleReaction');
    await safeDeleteMany(prisma, 'raffleRating');
    await safeDeleteMany(prisma, 'report');
    await safeDeleteMany(prisma, 'userBoost');

    await safeDeleteMany(prisma, 'announcement');

    await safeDeleteMany(prisma, 'ticket');
    await safeDeleteMany(prisma, 'winner');
    await safeDeleteMany(prisma, 'transaction');

    // Prisma client usa lowerCamelCase basado en el nombre del modelo.
    // Para KYCRequest típicamente es `kYCRequest`.
    await safeDeleteManyAny(prisma, ['kYCRequest', 'kycRequest']);
    await safeDeleteMany(prisma, 'suspiciousActivity');

    await safeDeleteMany(prisma, 'raffle');

    await safeDeleteMany(prisma, 'auditLog');
    await safeDeleteMany(prisma, 'mailLog');
    await safeDeleteMany(prisma, 'blacklist');

    // Asegurar que exista SystemSettings (id=1). No forzamos null en Json porque Prisma usa JsonNull/DbNull.
    try {
      await prisma.systemSettings.upsert({
        where: { id: 1 },
        update: {},
        create: { id: 1 }
      });
    } catch (e) {
      console.warn('[RESET] No se pudo asegurar SystemSettings:', e?.message || e);
    }

    const deletedUsers = await prisma.user.deleteMany({
      where: {
        NOT: { email: SUPERADMIN_EMAIL }
      }
    });

    const remaining = await prisma.user.findMany({ select: { id: true, email: true, role: true, securityId: true } });

    console.log('OK: reset completado.');
    console.log('Usuarios eliminados:', deletedUsers.count);
    console.log('Usuarios restantes:', remaining);
  } finally {
    await prisma.$disconnect();
  }
}

resetToSuperadmin().catch((err) => {
  console.error('Error en reset_to_superadmin:', err);
  process.exit(1);
});
