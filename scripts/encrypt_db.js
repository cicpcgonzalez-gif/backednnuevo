require('dotenv').config();
const { PrismaClient } = require('@prisma/client');
const crypto = require('crypto');

const prisma = new PrismaClient();

// Encryption Configuration
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

function isEncrypted(text) {
  if (!text || typeof text !== 'string') return false;
  // Check for 32 hex chars (IV) + : + hex chars
  return /^[0-9a-fA-F]{32}:[0-9a-fA-F]+$/.test(text);
}

async function main() {
  console.log('🔒 Starting database encryption...');

  // 1. Encrypt Users
  const users = await prisma.user.findMany();
  console.log(`Found ${users.length} users.`);

  for (const user of users) {
    const updates = {};
    let needsUpdate = false;

    // Name
    if (user.name && !isEncrypted(user.name)) {
      updates.name = encrypt(user.name);
      needsUpdate = true;
    }

    // Phone
    if (user.phone && !isEncrypted(user.phone)) {
      updates.phone = encrypt(user.phone);
      needsUpdate = true;
    }

    // Address
    if (user.address && !isEncrypted(user.address)) {
      updates.address = encrypt(user.address);
      needsUpdate = true;
    }

    // Cedula
    if (user.cedula && !isEncrypted(user.cedula)) {
      updates.cedula = encrypt(user.cedula);
      needsUpdate = true;
    }

    // Bank Details
    if (user.bankDetails) {
      const strDetails = JSON.stringify(user.bankDetails);
      // If it's already a string that looks encrypted, skip. 
      // But bankDetails is Json type in Prisma, so it comes as object.
      // We need to store it as an encrypted string. 
      // Wait, the schema says `bankDetails Json?`. 
      // If I store a string in a Json field, it will be a JSON string "iv:content".
      // My code in index.js expects `JSON.parse(decrypt(user.bankDetails))`.
      // If user.bankDetails is a JSON object, I should stringify -> encrypt -> store as string (which is valid JSON).
      
      // Check if it's already an encrypted string
      if (typeof user.bankDetails === 'string' && isEncrypted(user.bankDetails)) {
        // Already encrypted
      } else {
        // It's likely an object or a plain string
        const payload = typeof user.bankDetails === 'string' ? user.bankDetails : JSON.stringify(user.bankDetails);
        // Double check we aren't re-encrypting
        if (!isEncrypted(payload)) {
           updates.bankDetails = encrypt(payload);
           needsUpdate = true;
        }
      }
    }

    if (needsUpdate) {
      await prisma.user.update({
        where: { id: user.id },
        data: updates
      });
      console.log(`  User ${user.id} encrypted.`);
    }
  }

  // 2. Encrypt Transactions
  const transactions = await prisma.transaction.findMany();
  console.log(`Found ${transactions.length} transactions.`);

  for (const tx of transactions) {
    const updates = {};
    let needsUpdate = false;

    if (tx.reference && !isEncrypted(tx.reference)) {
      updates.reference = encrypt(tx.reference);
      needsUpdate = true;
    }

    if (tx.proof && !isEncrypted(tx.proof)) {
      updates.proof = encrypt(tx.proof);
      needsUpdate = true;
    }

    if (needsUpdate) {
      await prisma.transaction.update({
        where: { id: tx.id },
        data: updates
      });
      console.log(`  Transaction ${tx.id} encrypted.`);
    }
  }

  console.log('✅ Database encryption complete.');
}

main()
  .catch(e => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
