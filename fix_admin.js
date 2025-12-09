const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  const email = 'rifa@megarifasapp.com';
  try {
    const user = await prisma.user.update({
      where: { email },
      data: { verified: true },
    });
    console.log(`User ${email} verified successfully:`, user);
  } catch (e) {
    console.error(`Error verifying user ${email}:`, e);
  } finally {
    await prisma.$disconnect();
  }
}

main();
