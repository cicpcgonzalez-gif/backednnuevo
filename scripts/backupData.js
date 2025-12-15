const { PrismaClient } = require('@prisma/client');
const fs = require('fs');
const path = require('path');

const prisma = new PrismaClient();

async function backupDatabase() {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupDir = path.join(__dirname, '../backups');
  const backupFile = path.join(backupDir, `backup_${timestamp}.json`);

  console.log('📦 Iniciando respaldo de base de datos...');

  try {
    // Crear carpeta si no existe
    if (!fs.existsSync(backupDir)) {
      fs.mkdirSync(backupDir);
    }

    // Leer todas las tablas críticas
    // Nota: En una DB gigante esto se haría con streams o pg_dump, 
    // pero para este tamaño, JSON es perfecto y portable.
    const data = {
      metadata: {
        timestamp: new Date(),
        version: '1.0'
      },
      users: await prisma.user.findMany(),
      raffles: await prisma.raffle.findMany(),
      tickets: await prisma.ticket.findMany(),
      transactions: await prisma.transaction.findMany(),
      winners: await prisma.winner.findMany(),
      auditLogs: await prisma.auditLog.findMany(),
      suspiciousActivity: await prisma.suspiciousActivity.findMany(),
      blacklist: await prisma.blacklist.findMany()
    };

    // Escribir archivo
    fs.writeFileSync(backupFile, JSON.stringify(data, null, 2));
    
    console.log(`✅ Respaldo completado exitosamente.`);
    console.log(`📂 Archivo guardado en: ${backupFile}`);
    console.log(`📊 Estadísticas:`);
    console.log(`   - Usuarios: ${data.users.length}`);
    console.log(`   - Rifas: ${data.raffles.length}`);
    console.log(`   - Tickets: ${data.tickets.length}`);
    console.log(`   - Transacciones: ${data.transactions.length}`);

  } catch (error) {
    console.error('❌ Error durante el respaldo:', error);
  } finally {
    await prisma.$disconnect();
  }
}

backupDatabase();
