const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const FraudEngine = require('../utils/fraudEngine');
const bcrypt = require('bcryptjs');

async function simulateFraudScenarios() {
  console.log('🕵️  Iniciando Simulación de Escenarios de Fraude...');
  
  try {
    // 1. Crear usuario de prueba "Atacante"
    const email = `attacker_${Date.now()}@test.com`;
    const password = await bcrypt.hash('123456', 10);
    
    let user = await prisma.user.create({
      data: {
        email,
        password,
        name: 'Simulated Attacker',
        role: 'user'
      }
    });
    console.log(`✅ Usuario de prueba creado: ${user.email}`);

    // ---------------------------------------------------------
    // ESCENARIO A: Fuerza Bruta (Login Fails)
    // ---------------------------------------------------------
    console.log('\n[ESCENARIO A] Simulando intentos fallidos de login...');
    
    // Simulamos 5 intentos fallidos
    for (let i = 0; i < 5; i++) {
      await FraudEngine.logActivity(user.id, 'LOGIN_FAIL', 'Invalid password', 'LOW', '192.168.1.50');
    }

    // Verificar si se registró la actividad
    const fails = await prisma.suspiciousActivity.count({
      where: { userId: user.id, action: 'LOGIN_FAIL' }
    });
    
    console.log(`   -> Intentos registrados: ${fails}/5`);
    
    // Verificar si el usuario fue marcado (Risk Score debería haber subido)
    const updatedUserA = await prisma.user.findUnique({ where: { id: user.id } });
    console.log(`   -> Risk Score del usuario: ${updatedUserA.riskScore} (Esperado: > 0)`);

    // ---------------------------------------------------------
    // ESCENARIO B: Velocidad de Compra (High Velocity)
    // ---------------------------------------------------------
    console.log('\n[ESCENARIO B] Simulando compras a velocidad sobrehumana...');
    
    // Simulamos compras muy rápidas (menos de 2 segundos entre ellas)
    // Nota: checkPurchaseVelocity lanza error si detecta fraude
    
    // Crear una rifa dummy para la prueba
    const raffle = await prisma.raffle.create({
      data: {
        title: 'Fraud Test Raffle',
        prize: 'Test Prize',
        ticketPrice: 10,
        totalTickets: 1000,
        lottery: 'Test',
        style: {}
      }
    });
    const raffleId = raffle.id;
    let blocked = false;

    try {
      // Para simular velocidad, necesitamos crear tickets reales en la DB
      // ya que checkPurchaseVelocity cuenta tickets en la DB.
      
      // Compra 1
      await prisma.ticket.create({ data: { number: 1001, userId: user.id, raffleId, serialNumber: 'TEST1', status: 'approved' } });
      await FraudEngine.checkPurchaseVelocity(user.id, raffleId);
      
      // Compra 2 (Inmediata)
      await prisma.ticket.create({ data: { number: 1002, userId: user.id, raffleId, serialNumber: 'TEST2', status: 'approved' } });
      await FraudEngine.checkPurchaseVelocity(user.id, raffleId);
      
      // Compra 3 (Inmediata - Debería disparar la alerta)
      await prisma.ticket.create({ data: { number: 1003, userId: user.id, raffleId, serialNumber: 'TEST3', status: 'approved' } });
      await FraudEngine.checkPurchaseVelocity(user.id, raffleId);
      
    } catch (error) {
      if (error.message.includes('velocidad') || error.message.includes('suspicious')) {
        blocked = true;
        console.log('   -> ✅ Sistema BLOQUEÓ la compra por velocidad sospechosa.');
      } else {
        console.log('   -> ❌ Error inesperado:', error.message);
      }
    }

    if (!blocked) {
      console.log('   -> ⚠️ ALERTA: El sistema NO bloqueó la velocidad de compra.');
    }

    // Verificar logs de fraude
    const velocityLogs = await prisma.suspiciousActivity.count({
      where: { userId: user.id, action: 'HIGH_VELOCITY_PURCHASE' }
    });
    console.log(`   -> Alertas de velocidad registradas en DB: ${velocityLogs}`);

    // ---------------------------------------------------------
    // LIMPIEZA
    // ---------------------------------------------------------
    console.log('\n🧹 Limpiando datos de prueba...');
    await prisma.suspiciousActivity.deleteMany({ where: { userId: user.id } });
    await prisma.ticket.deleteMany({ where: { userId: user.id } });
    await prisma.user.delete({ where: { id: user.id } });
    await prisma.raffle.delete({ where: { id: raffleId } });
    console.log('✅ Limpieza completada.');

  } catch (error) {
    console.error('❌ Error en la simulación:', error);
  } finally {
    await prisma.$disconnect();
  }
}

simulateFraudScenarios();
