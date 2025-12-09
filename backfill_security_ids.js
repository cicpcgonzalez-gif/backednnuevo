require('dotenv').config();
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

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

async function main() {
  console.log('Starting backfill of Security IDs...');
  
  // Find users where securityId is null
  // Note: If the field doesn't exist yet in DB, this might fail until migration runs.
  const users = await prisma.user.findMany({
    where: { 
      OR: [
        { securityId: null },
        { securityId: { equals: undefined } } // Just in case
      ]
    }
  });

  console.log(`Found ${users.length} users without Security ID.`);

  for (const user of users) {
    let securityId = generateSecurityId();
    // Check collision
    let exists = await prisma.user.findUnique({ where: { securityId } });
    while (exists) {
      securityId = generateSecurityId();
      exists = await prisma.user.findUnique({ where: { securityId } });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { 
        securityId,
        reputationScore: 5.0,
        identityVerified: false
      }
    });
    console.log(`Updated user ${user.email} with ID: ${securityId}`);
  }

  console.log('Backfill complete.');
}

main()
  .catch(e => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
