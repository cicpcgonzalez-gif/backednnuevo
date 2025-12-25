require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { PrismaClient } = require('@prisma/client');

let sharp;
try {
  sharp = require('sharp');
} catch (_e) {
  sharp = null;
}

const prisma = new PrismaClient();

const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || process.env.BASE_URL || null;
const UPLOADS_DIR = path.join(__dirname, '..', 'uploads');
const AVATARS_DIR = path.join(UPLOADS_DIR, 'avatars');

function ensureDirs() {
  fs.mkdirSync(AVATARS_DIR, { recursive: true });
}

function parseDataUrlImage(dataUrl) {
  const str = String(dataUrl || '');
  const m = str.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/);
  if (!m) return null;
  const buffer = Buffer.from(m[2], 'base64');
  return { mime: m[1], buffer };
}

async function main() {
  if (!sharp) {
    console.error('sharp no está disponible. Instala dependencias y reintenta.');
    process.exitCode = 1;
    return;
  }
  if (!PUBLIC_BASE_URL) {
    console.error('Falta PUBLIC_BASE_URL (ej: https://tu-backend.onrender.com).');
    process.exitCode = 1;
    return;
  }

  ensureDirs();

  const pageSize = 200;
  let processed = 0;
  let migrated = 0;
  let skipped = 0;

  while (true) {
    const users = await prisma.user.findMany({
      where: { avatar: { startsWith: 'data:image/' } },
      select: { id: true, avatar: true },
      take: pageSize
    });
    if (!users.length) break;

    for (const u of users) {
      processed++;
      const parsed = parseDataUrlImage(u.avatar);
      if (!parsed) {
        skipped++;
        continue;
      }
      if (parsed.buffer.length > 5 * 1024 * 1024) {
        skipped++;
        continue;
      }

      const filename = `avatar_${u.id}_${Date.now()}.webp`;
      const relPath = `/uploads/avatars/${filename}`;
      const fullPath = path.join(AVATARS_DIR, filename);

      await sharp(parsed.buffer)
        .resize(256, 256, { fit: 'cover' })
        .webp({ quality: 80 })
        .toFile(fullPath);

      const url = String(PUBLIC_BASE_URL).replace(/\/$/, '') + relPath;

      await prisma.user.update({
        where: { id: u.id },
        data: { avatar: url }
      });
      migrated++;
    }

    console.log(`[migrate_avatars] processed=${processed} migrated=${migrated} skipped=${skipped}`);
  }

  console.log(`[migrate_avatars] DONE processed=${processed} migrated=${migrated} skipped=${skipped}`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
