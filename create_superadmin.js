// create_superadmin.js
// Uso: DATABASE_URL en env o pasar la URL completa como primer argumento
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

(async () => {
  try {
    const dbUrlArg = process.argv[2];
    if (dbUrlArg) process.env.DATABASE_URL = dbUrlArg;
    if (!process.env.DATABASE_URL) {
      console.error('ERROR: No se encontró DATABASE_URL. Exporta la variable o pásala como argumento.');
      console.error('Ejemplo (Linux/macOS): export DATABASE_URL="postgresql://user:pass@host:5432/db"');
      console.error('Ejemplo (PowerShell): $env:DATABASE_URL = "postgresql://user:pass@host:5432/db"');
      process.exit(1);
    }

    const prisma = new PrismaClient();
    const email = 'rifa@megarifasapp.com';
    const passwordPlain = 'rifasadmin123';
    const specialSecurityId = 'MR-SADM-1';

    console.log('Comprobando existencia de superadmin...');
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      console.log('Superadmin ya existe:', existing.email);
      if (!existing.securityId) {
        try {
          await prisma.user.update({ where: { email }, data: { securityId: specialSecurityId } });
          console.log('SecurityId especial asignado al superadmin:', specialSecurityId);
        } catch (e) {
          console.warn('No se pudo asignar securityId especial (posible colisión):', e.message || e);
        }
      }
    } else {
      const hashed = await bcrypt.hash(passwordPlain, 10);
      // Intentamos crear con campo `role` si existe en el esquema; si falla, intentamos sin role.
      try {
        await prisma.user.create({ data: { email, name: 'Super Admin', password: hashed, role: 'superadmin', securityId: specialSecurityId } });
        console.log('Superadmin creado correctamente (with role)');
      } catch (err) {
        console.warn('No se pudo crear con campo role (posible esquema sin role), intentando sin role:', err.message || err);
        await prisma.user.create({ data: { email, name: 'Super Admin', password: hashed, securityId: specialSecurityId } });
        console.log('Superadmin creado correctamente (without role)');
      }
    }

    await prisma.$disconnect();
  } catch (err) {
    console.error('Error creando superadmin:', err);
    process.exit(1);
  }
})();
