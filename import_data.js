const { PrismaClient } = require('@prisma/client');
const fs = require('fs');
const path = require('path');
const prisma = new PrismaClient();

async function importUsers() {
  // Aquí deberías tener un archivo users.json exportado del backend anterior
  const usersPath = path.join(__dirname, 'rifas', 'users.json');
  if (!fs.existsSync(usersPath)) {
    console.log('No se encontró users.json. Exporta los usuarios del backend anterior en formato JSON.');
    return;
  }
  const users = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
  for (const user of users) {
    await prisma.user.create({
      data: {
        email: user.email,
        name: user.firstName + ' ' + user.lastName,
        password: user.password,
        createdAt: user.createdAt ? new Date(user.createdAt) : undefined,
      },
    });
  }
  console.log('Usuarios importados correctamente.');
}

async function importRaffles() {
  // Aquí deberías tener un archivo raffles.json exportado del backend anterior
  const rafflesPath = path.join(__dirname, 'rifas', 'raffles.json');
  if (!fs.existsSync(rafflesPath)) {
    console.log('No se encontró raffles.json. Exporta las rifas del backend anterior en formato JSON.');
    return;
  }
  const raffles = JSON.parse(fs.readFileSync(rafflesPath, 'utf8'));
  for (const raffle of raffles) {
    await prisma.raffle.create({
      data: {
        title: raffle.title,
        prize: raffle.description,
        createdAt: raffle.createdAt ? new Date(raffle.createdAt) : undefined,
      },
    });
  }
  console.log('Rifas importadas correctamente.');
}

async function main() {
  await importUsers();
  await importRaffles();
  await prisma.$disconnect();
}

main();
