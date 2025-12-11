const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  console.log('⚠️  STARTING PRODUCTION CLEANUP ⚠️');
  console.log('This will delete ALL data except the Superadmin account.');
  
  // Find Superadmin
  const superadmin = await prisma.user.findFirst({
    where: { role: 'superadmin' }
  });

  if (!superadmin) {
    console.error('❌ No Superadmin found! Aborting to prevent total lockout.');
    process.exit(1);
  }

  console.log(`✅ Preserving Superadmin: ${superadmin.email} (ID: ${superadmin.id})`);

  // Delete dependent data first
  console.log('🗑️  Deleting Reactions...');
  await prisma.reaction.deleteMany({});

  console.log('🗑️  Deleting Announcements...');
  await prisma.announcement.deleteMany({});

  console.log('🗑️  Deleting Winners...');
  await prisma.winner.deleteMany({});

  console.log('🗑️  Deleting Tickets...');
  await prisma.ticket.deleteMany({});

  console.log('🗑️  Deleting Transactions...');
  await prisma.transaction.deleteMany({});

  console.log('🗑️  Deleting Suspicious Activities...');
  await prisma.suspiciousActivity.deleteMany({});

  console.log('🗑️  Deleting KYC Requests...');
  await prisma.kYCRequest.deleteMany({});

  console.log('🗑️  Deleting Raffles...');
  await prisma.raffle.deleteMany({});

  // Delete all users except Superadmin
  console.log('🗑️  Deleting Users (except Superadmin)...');
  const deletedUsers = await prisma.user.deleteMany({
    where: {
      id: {
        not: superadmin.id
      }
    }
  });

  console.log(`✅ Deleted ${deletedUsers.count} users.`);
  console.log('✨ Cleanup Complete. Database is ready for production.');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
