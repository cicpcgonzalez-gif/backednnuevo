const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const prisma = new PrismaClient();

const adminUsers = [
  { email: 'neririfas.com', password: 'rifasneri123', role: 'admin' },
  { email: 'gatorifas.com', password: 'rifasgato123', role: 'admin' },
  { email: 'adrianrifas.com', password: 'rifasadrian123', role: 'admin' },
  { email: 'sergiorifas.com', password: 'rifassergio123', role: 'admin' },
  { email: 'jesusrifas.com', password: 'rifasjesus123', role: 'admin' },
  { email: 'pruebaadmin', password: 'rifas123', role: 'admin' }
];

const normalUsers = [
  { email: 'youbarrios', password: 'barrio123', role: 'user' },
  { email: 'amiguita.com', password: 'yuvanelafresa', role: 'user' },
  { email: 'maholismanao', password: 'macario123', role: 'user' },
  { email: 'pruebauser', password: 'claverifas123', role: 'user' }
];

const toDelete = ['gonzalezcicpc@gmail.com', 'cicpcgonzalez@gmail.com'];

function toName(email) {
  return String(email).split('@')[0] || String(email);
}

async function upsertUser({ email, password, role }) {
  const hashed = await bcrypt.hash(password, 10);
  const name = toName(email);

  const data = {
    email,
    name,
    password: hashed,
    role,
    active: true,
    verified: true
  };

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    const updated = await prisma.user.update({ where: { email }, data });
    console.log(`Updated ${role}: ${email}`);
    return updated;
  }

  const created = await prisma.user.create({ data });
  console.log(`Created ${role}: ${email}`);
  return created;
}

async function main() {
  try {
    // Delete requested users if they exist
    for (const email of toDelete) {
      try {
        await prisma.user.delete({ where: { email } });
        console.log(`Deleted user: ${email}`);
      } catch (err) {
        if (err.code !== 'P2025') console.warn(`Could not delete ${email}:`, err.message || err);
      }
    }

    for (const user of [...adminUsers, ...normalUsers]) {
      await upsertUser(user);
    }
    console.log('Seed complete');
  } catch (e) {
    console.error('Error seeding users:', e);
  } finally {
    await prisma.$disconnect();
  }
}

main();
