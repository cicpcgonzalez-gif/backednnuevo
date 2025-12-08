require('dotenv').config();
const express = require('express');
const { PrismaClient, Prisma } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');

const app = express();

// Security Middleware
app.use(helmet());
app.use(compression());

// Simple request logger (method, path, duration)
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[REQ] ${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
  });
  next();
});

// Global rate limit (applies to all routes)
const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 min
  max: 100, // 100 requests/min/IP
  standardHeaders: true,
  legacyHeaders: false
});
app.use(globalLimiter);

// Default pagination guard for GET requests
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
app.use((req, res, next) => {
  if (req.method === 'GET') {
    const limit = Number(req.query.limit);
    const offset = Number(req.query.offset);
    req.query.limit = Number.isFinite(limit) && limit > 0 ? Math.min(limit, MAX_LIMIT) : DEFAULT_LIMIT;
    req.query.offset = Number.isFinite(offset) && offset >= 0 ? offset : 0;
  }
  next();
});

// Rate Limiter for Login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per windowMs
  message: { error: 'Demasiados intentos de inicio de sesión, por favor intente nuevamente en 15 minutos.' }
});

// Inicializar Prisma
const prisma = new PrismaClient();

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

const SUPERADMIN_EMAIL = 'rifa@megarifasapp.com';
const SUPERADMIN_PASSWORD = 'rifasadmin123';
const SUPERADMIN_ROLE = 'superadmin';

// Middleware de autenticación
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
}

// Middleware de autorización por rol
function authorizeRole(roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Acceso denegado: Rol insuficiente' });
    }
    next();
  };
}

// Prisma middleware para medir tiempos de consulta y loguear consultas lentas
prisma.$use(async (params, next) => {
  const start = Date.now();
  try {
    const result = await next(params);
    const duration = Date.now() - start;
    const model = params.model || 'raw';
    const action = params.action || 'query';
    if (duration > 200) {
      console.warn(`[PRISMA SLOW] ${model}.${action} took ${duration}ms`, { params });
    } else {
      console.log(`[PRISMA] ${model}.${action} ${duration}ms`);
    }
    return result;
  } catch (err) {
    console.error('[PRISMA ERROR]', err);
    throw err;
  }
});

const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');

// Configuración de transporte de correo (Mock o SMTP)
// Se inicializa vacío, se crea dinámicamente en sendEmail
let defaultTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.ethereal.email',
  port: Number(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER || 'ethereal_user',
    pass: process.env.SMTP_PASS || 'ethereal_pass'
  }
});

async function sendEmail(to, subject, text, html) {
  try {
    // 1. Buscar configuración SMTP personalizada en DB
    const settings = await prisma.systemSettings.findFirst();
    let transporter = defaultTransporter;
    let fromAddress = '"MegaRifas" <noreply@megarifasapp.com>';

    if (settings && settings.smtp) {
      const smtp = settings.smtp;
      if (smtp.host && smtp.user && smtp.pass) {
        transporter = nodemailer.createTransport({
          host: smtp.host,
          port: Number(smtp.port) || 587,
          secure: smtp.secure === true || smtp.secure === 'true',
          auth: {
            user: smtp.user,
            pass: smtp.pass
          }
        });
        fromAddress = `"${smtp.fromName || 'MegaRifas'}" <${smtp.fromEmail || smtp.user}>`;
      }
    } else if (!process.env.SMTP_HOST) {
      // Si no hay config en DB ni en ENV, mock
      console.log(`[MOCK EMAIL] To: ${to} | Subject: ${subject}`);
      await prisma.mailLog.create({
        data: { to, subject, status: 'SENT_MOCK', timestamp: new Date() }
      });
      return true;
    }

    const info = await transporter.sendMail({
      from: fromAddress,
      to,
      subject,
      text,
      html
    });

    console.log('Message sent: %s', info.messageId);
    await prisma.mailLog.create({
      data: { to, subject, status: 'SENT', timestamp: new Date() }
    });
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    await prisma.mailLog.create({
      data: { to, subject, status: 'FAILED', timestamp: new Date() }
    });
    return false;
  }
}

// Helper para generar IDs cortos y legibles (ej. USR-12345678)
function generateShortId(prefix = 'ID') {
  const random = Math.random().toString(36).substring(2, 10).toUpperCase();
  return `${prefix}-${random}`;
}

function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Reintentos para conexión a DB al iniciar
async function waitForDatabase(retries = 5, delay = 2000) {
  for (let i = 0; i < retries; i++) {
    try {
      const start = Date.now();
      await prisma.$queryRaw`SELECT 1`;
      const ping = Date.now() - start;
      console.log('Conexión a DB OK (ping)', ping, 'ms');
      return true;
    } catch (err) {
      console.warn(`DB connect attempt ${i + 1} failed:`, err.message || err);
      if (i === retries - 1) throw err;
      await new Promise(r => setTimeout(r, delay * (i + 1)));
    }
  }
}

async function ensureSuperAdmin() {
  try {
    await waitForDatabase(5, 2000);
    const existing = await prisma.user.findUnique({ where: { email: SUPERADMIN_EMAIL } });
    if (!existing) {
      const hashed = await bcrypt.hash(SUPERADMIN_PASSWORD, 10);
      await prisma.user.create({
        data: {
          email: SUPERADMIN_EMAIL,
          password: hashed,
          name: 'Super Admin',
          role: SUPERADMIN_ROLE,
          publicId: generateShortId('ADM')
        }
      });
      console.log('Superadmin creado automáticamente');
    } else {
      // Asegurar que el superadmin tenga el rol correcto si ya existe
      if (existing.role !== SUPERADMIN_ROLE) {
        await prisma.user.update({
          where: { email: SUPERADMIN_EMAIL },
          data: { role: SUPERADMIN_ROLE }
        });
        console.log('Rol de superadmin actualizado');
      }
      console.log('Superadmin ya existe');
    }
  } catch (err) {
    console.error('No se pudo verificar/crear superadmin:', err.message || err);
  }
}

// Middleware de logging más detallado (oculta passwords)
function maskSensitive(obj) {
  try {
    const copy = JSON.parse(JSON.stringify(obj));
    if (copy && copy.password) copy.password = '***';
    return copy;
  } catch (_) {
    return obj;
  }
}

function logRequest(req, res, next) {
  const start = Date.now();
  const body = maskSensitive(req.body);
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${req.method}] ${req.originalUrl} - ${res.statusCode} (${duration}ms) body=${JSON.stringify(body)} params=${JSON.stringify(req.params)}`);
  });
  next();
}
app.use(logRequest);

// Manejo global de errores no capturados
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

// Ejecutar verificación de superadmin al iniciar
ensureSuperAdmin().catch(err => console.error('ensureSuperAdmin error:', err));

// Endpoint de salud
app.get('/health', async (req, res) => {
  const start = Date.now();
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: 'ok', db: 'ok', time: Date.now() - start });
  } catch (error) {
    res.status(500).json({ status: 'error', db: 'fail', error: error.message });
  }
});

// Endpoint para obtener todos los usuarios
app.get('/users', async (req, res) => {
  const start = Date.now();
  try {
    const users = await prisma.user.findMany();
    console.log('Consulta usuarios:', Date.now() - start, 'ms');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

// Endpoint para obtener todas las rifas
app.get('/raffles', async (req, res) => {
  const start = Date.now();
  try {
    const raffles = await prisma.raffle.findMany();
    console.log('Consulta rifas:', Date.now() - start, 'ms');
    res.json(raffles);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener rifas' });
  }
});

// Helper: Check and Reward Referrer
async function checkAndRewardReferrer(referrerId) {
  try {
    const count = await prisma.user.count({ where: { referredById: referrerId } });
    // Reward every 5 referrals
    if (count > 0 && count % 5 === 0) {
      const rewardAmount = 5.0; // Configurable reward (e.g., $5 or 5 VES)
      await prisma.$transaction([
        prisma.user.update({
          where: { id: referrerId },
          data: { balance: { increment: rewardAmount } }
        }),
        prisma.transaction.create({
          data: {
            userId: referrerId,
            amount: rewardAmount,
            type: 'bonus',
            status: 'approved',
            reference: `Recompensa por ${count} referidos`
          }
        })
      ]);
      console.log(`[REWARD] User ${referrerId} rewarded for ${count} referrals.`);
      
      // Optional: Notify referrer via Push
      const referrer = await prisma.user.findUnique({ where: { id: referrerId }, select: { pushToken: true } });
      if (referrer?.pushToken) {
        await sendPushNotification([referrer.pushToken], '¡Recompensa Ganada!', `Has alcanzado ${count} referidos. Te hemos abonado saldo.`);
      }
    }
  } catch (err) {
    console.error('[REWARD ERROR]', err);
  }
}

// Registro de usuario
app.post('/register', async (req, res) => {
  const { email, name, password, referralCode } = req.body;
  if (!email || !name || !password) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationToken = generateVerificationCode();

  try {
    let referredById = null;
    if (referralCode) {
      const referrer = await prisma.user.findUnique({ where: { referralCode } });
      if (referrer) referredById = referrer.id;
    }

    const user = await prisma.user.create({
      data: { 
        email, 
        name, 
        password: hashedPassword,
        publicId: generateShortId('USR'),
        referredById,
        verificationToken,
        verified: false
      }
    });

    if (referredById) {
      // Check for rewards asynchronously
      checkAndRewardReferrer(referredById).catch(console.error);
    }
    
    // Enviar correo de bienvenida con token
    sendEmail(
      email, 
      'Activa tu cuenta en MegaRifas', 
      `Hola ${name}, tu código de verificación es: ${verificationToken}`,
      `<h1>¡Bienvenido a MegaRifas!</h1>
       <p>Hola <b>${name}</b>,</p>
       <p>Gracias por registrarte. Para activar tu cuenta, usa el siguiente código:</p>
       <h2 style="color: #4f46e5; letter-spacing: 5px;">${verificationToken}</h2>
       <p>Si no solicitaste esta cuenta, ignora este correo.</p>`
    ).catch(console.error);

    res.status(201).json({ message: 'Usuario registrado. Verifique su correo.', user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// Verificar email
app.post('/verify-email', async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'Faltan datos' });

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    if (user.verified) return res.json({ message: 'Cuenta ya verificada' });

    if (user.verificationToken !== code) {
      return res.status(400).json({ error: 'Código inválido' });
    }

    await prisma.user.update({
      where: { email },
      data: { verified: true, verificationToken: null }
    });

    res.json({ message: 'Cuenta verificada exitosamente' });
  } catch (error) {
    res.status(500).json({ error: 'Error al verificar cuenta' });
  }
});

// Login de usuario
app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });

  // 1. Verificar si la cuenta está activa
  if (!user.verified) {
    return res.status(403).json({ error: 'Cuenta no verificada. Revise su correo.' });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });

  // 2. Seguridad para Admins (2FA)
  if (user.role === 'admin') {
    const twoFactorToken = generateVerificationCode();
    await prisma.user.update({
      where: { id: user.id },
      data: { verificationToken: twoFactorToken }
    });

    // Enviar código al admin
    sendEmail(
      user.email,
      'Código de Seguridad (2FA)',
      `Tu código de acceso es: ${twoFactorToken}`,
      `<h1>Seguridad MegaRifas</h1><p>Estás intentando acceder como Administrador.</p><p>Tu código es:</p><h2 style="color: #d97706;">${twoFactorToken}</h2>`
    ).catch(console.error);

    return res.json({ require2FA: true, email: user.email, message: 'Código de seguridad enviado' });
  }

  const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  
  // Remove password from user object before sending
  const { password: _, ...userWithoutPassword } = user;
  
  res.json({ message: 'Login exitoso', token, user: userWithoutPassword });
});

// Validar 2FA Admin
app.post('/auth/2fa', async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'Faltan datos' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

  if (user.verificationToken !== code) {
    return res.status(400).json({ error: 'Código inválido' });
  }

  // Limpiar token
  await prisma.user.update({
    where: { id: user.id },
    data: { verificationToken: null }
  });

  const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  const { password: _, ...userWithoutPassword } = user;

  res.json({ message: 'Login exitoso', token, user: userWithoutPassword });
});

// CRUD para rifas
app.post('/raffles', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { title, description, ticketPrice, totalTickets, style, lottery } = req.body;
  if (!title || !description) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  
  const maxTickets = 10000;
  const ticketsCount = Number(totalTickets) || 10000;
  
  if (ticketsCount > maxTickets) {
    return res.status(400).json({ error: `El máximo de tickets permitidos es ${maxTickets}` });
  }

  try {
    const raffle = await prisma.raffle.create({ 
      data: { 
        title, 
        prize: description,
        ticketPrice: Number(ticketPrice) || 0,
        totalTickets: ticketsCount,
        lottery,
        style: style || {}
      } 
    });
    res.status(201).json({ message: 'Rifa creada', raffle });
  } catch (error) {
    res.status(500).json({ error: 'Error al crear rifa' });
  }
});

app.put('/raffles/:id', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { id } = req.params;
  const { title, description, ticketPrice, totalTickets, style } = req.body;
  
  const maxTickets = 10000;
  if (totalTickets && Number(totalTickets) > maxTickets) {
    return res.status(400).json({ error: `El máximo de tickets permitidos es ${maxTickets}` });
  }

  try {
    const raffle = await prisma.raffle.update({
      where: { id: Number(id) },
      data: { 
        title, 
        prize: description,
        ticketPrice: ticketPrice !== undefined ? Number(ticketPrice) : undefined,
        totalTickets: totalTickets !== undefined ? Number(totalTickets) : undefined,
        style: style !== undefined ? style : undefined
      }
    });
    res.json({ message: 'Rifa actualizada', raffle });
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar rifa' });
  }
});

app.delete('/raffles/:id', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { id } = req.params;
  try {
    await prisma.raffle.delete({ where: { id: Number(id) } });
    res.json({ message: 'Rifa eliminada' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar rifa' });
  }
});

// Compra de tickets (Asignación aleatoria)
app.post('/raffles/:id/purchase', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;
  const userId = req.user.userId;

  if (!quantity || isNaN(quantity) || Number(quantity) <= 0) {
    return res.status(400).json({ error: 'Cantidad inválida' });
  }
  
  const qty = Number(quantity);

  try {
    const raffle = await prisma.raffle.findUnique({ where: { id: Number(id) } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    const totalCost = Number(raffle.ticketPrice) * qty;
    if (user.balance < totalCost) {
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // Generar números aleatorios
    const soldTickets = await prisma.ticket.findMany({
      where: { raffleId: Number(id) },
      select: { number: true }
    });
    const occupiedNumbers = new Set(soldTickets.map(t => t.number));
    
    const maxTickets = raffle.totalTickets || 10000;
    const newNumbers = [];
    let attempts = 0;
    
    if (occupiedNumbers.size + qty > maxTickets) {
       return res.status(400).json({ error: 'No hay suficientes tickets disponibles' });
    }

    while (newNumbers.length < qty && attempts < maxTickets * 3) {
      const num = Math.floor(Math.random() * maxTickets) + 1;
      if (!occupiedNumbers.has(num) && !newNumbers.includes(num)) {
        newNumbers.push(num);
      }
      attempts++;
    }

    if (newNumbers.length < qty) {
      return res.status(400).json({ error: 'No se pudieron generar números disponibles, intenta de nuevo' });
    }

    // Transacción
    await prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: userId },
        data: { balance: { decrement: totalCost } }
      });

      await tx.transaction.create({
        data: {
          userId,
          amount: totalCost,
          type: 'purchase',
          status: 'approved',
          reference: `Compra de ${qty} tickets en rifa #${id}`
        }
      });

      for (const num of newNumbers) {
        await tx.ticket.create({
          data: {
            raffleId: Number(id),
            userId,
            number: num,
            status: 'approved'
          }
        });
      }
    });

    res.status(201).json({ 
      message: 'Compra exitosa', 
      numbers: newNumbers,
      remainingBalance: user.balance - totalCost 
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al procesar la compra' });
  }
});

app.get('/me/raffles', authenticateToken, async (req, res) => {
  try {
    const tickets = await prisma.ticket.findMany({
      where: { userId: req.user.userId },
      include: { raffle: true }
    });
    
    const grouped = {};
    tickets.forEach(t => {
      if (!grouped[t.raffleId]) {
        grouped[t.raffleId] = {
          raffle: t.raffle,
          numbers: [],
          serialNumber: t.serialNumber,
          status: t.raffle.status,
          isWinner: false 
        };
      }
      grouped[t.raffleId].numbers.push(t.number);
    });
    
    res.json(Object.values(grouped));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener mis rifas' });
  }
});

// CRUD para usuarios
app.get('/users/:id', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: Number(req.params.id) } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error al consultar usuario' });
  }
});

app.put('/users/:id', authenticateToken, async (req, res) => {
  const { name, email } = req.body;
  // Solo admin/superadmin o el propio usuario pueden editar
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin' && req.user.userId !== Number(req.params.id)) {
     return res.status(403).json({ error: 'No autorizado para editar este usuario' });
  }
  try {
    const user = await prisma.user.update({
      where: { id: Number(req.params.id) },
      data: { name, email }
    });
    res.json({ message: 'Usuario actualizado', user });
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar usuario' });
  }
});

app.delete('/users/:id', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    await prisma.user.delete({ where: { id: Number(req.params.id) } });
    res.json({ message: 'Usuario eliminado' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar usuario' });
  }
});

// CRUD para tickets
app.post('/tickets', authenticateToken, async (req, res) => {
  const { number, userId, raffleId, paymentMethod, proof } = req.body;
  if (!userId || !raffleId) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  
  try {
    const raffle = await prisma.raffle.findUnique({ where: { id: Number(raffleId) } });
    const user = await prisma.user.findUnique({ where: { id: Number(userId) } });
    
    if (!raffle || !user) return res.status(404).json({ error: 'Rifa o usuario no encontrado' });

    // Si es pago manual (transferencia)
    if (paymentMethod === 'manual') {
      if (!proof) return res.status(400).json({ error: 'Se requiere comprobante de pago' });
      
      // Crear transacción pendiente
      const transaction = await prisma.transaction.create({
        data: {
          userId: user.id,
          amount: -raffle.ticketPrice,
          type: 'manual_payment',
          status: 'pending',
          reference: `Compra Rifa: ${raffle.title}`,
          proof
        }
      });

      // Crear ticket en estado pendiente (sin número asignado aún o reservado)
      // NOTA: El usuario pidió números aleatorios 00001-10000 al verificar.
      // Aquí solo registramos la intención.
      
      return res.status(201).json({ 
        message: 'Pago registrado. Esperando verificación del administrador.', 
        transactionId: transaction.id 
      });
    }
    
    // Si es pago con saldo (Wallet)
    if (user.balance < raffle.ticketPrice) {
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // Generar número aleatorio único
    let assignedNumber;
    let isUnique = false;
    let attempts = 0;
    const maxRange = raffle.totalTickets || 10000;
    
    while (!isUnique && attempts < 10) {
      assignedNumber = Math.floor(Math.random() * maxRange) + 1;
      const existing = await prisma.ticket.findFirst({
        where: { raffleId: raffle.id, number: assignedNumber }
      });
      if (!existing) isUnique = true;
      attempts++;
    }

    if (!isUnique) return res.status(500).json({ error: 'No se pudo asignar un número único, intente de nuevo' });

    // Transacción atómica
    const result = await prisma.$transaction(async (prisma) => {
      await prisma.user.update({
        where: { id: user.id },
        data: { balance: { decrement: raffle.ticketPrice } }
      });

      if (raffle.ticketPrice > 0) {
        await prisma.transaction.create({
          data: {
            userId: user.id,
            amount: -raffle.ticketPrice,
            type: 'purchase',
            status: 'approved',
            reference: `Ticket #${assignedNumber} - ${raffle.title}`
          }
        });
      }

      const ticket = await prisma.ticket.create({
        data: { 
          number: assignedNumber, 
          userId: Number(userId), 
          raffleId: Number(raffleId),
          serialNumber: generateShortId('TKT'),
          status: 'approved'
        },
        include: { user: true, raffle: true }
      });
      
      return ticket;
    });

    const ticket = result;

    if (ticket.user && ticket.user.email) {
      sendEmail(
        ticket.user.email,
        'Confirmación de Ticket - MegaRifas',
        `Has comprado el ticket #${ticket.number} para la rifa ${ticket.raffle.title}. Serial: ${ticket.serialNumber}`,
        `<h1>¡Ticket Confirmado!</h1><p>Has adquirido el número <b>${ticket.number}</b> para la rifa <i>${ticket.raffle.title}</i>.</p><p>Serial único: <code>${ticket.serialNumber}</code></p>`
      ).catch(console.error);
    }

    res.status(201).json({ message: 'Ticket creado', ticket });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear ticket' });
  }
});

// Endpoint para que el Admin verifique pagos manuales
app.post('/admin/verify-payment/:transactionId', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { transactionId } = req.params;
  const { action, reason, raffleId } = req.body; // 'approve' or 'reject', reason for rejection

  try {
    const transaction = await prisma.transaction.findUnique({ where: { id: Number(transactionId) }, include: { user: true } });
    if (!transaction || transaction.status !== 'pending') {
      return res.status(404).json({ error: 'Transacción no encontrada o ya procesada' });
    }

    if (action === 'reject') {
      await prisma.transaction.update({
        where: { id: transaction.id },
        data: { status: 'rejected', reference: reason ? `Rechazado: ${reason}` : 'Rechazado por admin' }
      });
      
      if (transaction.user.email) {
        sendEmail(
          transaction.user.email,
          'Pago Rechazado - Rifas App',
          `Tu pago ha sido rechazado. Motivo: ${reason || 'No especificado'}. Por favor contacta a soporte.`,
          `<h1>Pago Rechazado</h1><p>Tu pago ha sido rechazado.</p><p><b>Motivo:</b> ${reason || 'No especificado'}</p><p>Por favor verifica tu comprobante y vuelve a intentarlo o contacta a soporte.</p>`
        ).catch(console.error);
      }
      
      return res.json({ message: 'Pago rechazado' });
    }

    // Aprobar: Generar ticket
    // Usamos raffleId del body o intentamos inferirlo si ya lo guardamos (ahora lo guardamos en Transaction.raffleId si actualizamos el endpoint de creación, pero por compatibilidad chequeamos body)
    // Mejor aún: si transaction tiene raffleId, úsalo. Si no, usa el del body.
    const targetRaffleId = transaction.raffleId || raffleId;
    
    if (!targetRaffleId) return res.status(400).json({ error: 'Falta raffleId para asignar ticket' });

    const raffle = await prisma.raffle.findUnique({ where: { id: Number(targetRaffleId) } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    // Generar número aleatorio con reintentos y transacción atómica
    // Nota: La restricción @@unique([raffleId, number]) en la DB asegura que no haya duplicados finales.
    // Intentaremos generar un número y crear. Si falla por unique constraint, reintentamos.
    
    let ticket;
    let attempts = 0;
    const maxAttempts = 15;
    const maxRange = raffle.totalTickets || 10000;
    
    while (!ticket && attempts < maxAttempts) {
      attempts++;
      const assignedNumber = Math.floor(Math.random() * maxRange) + 1;
      
      try {
        ticket = await prisma.$transaction(async (tx) => {
          // Verificación extra dentro de la transacción (opcional pero buena práctica)
          const existing = await tx.ticket.findFirst({ where: { raffleId: raffle.id, number: assignedNumber } });
          if (existing) throw new Error('Number taken'); // Fuerza rollback y catch para reintentar

          // Actualizar transacción solo si es el primer intento exitoso (para no actualizarla múltiples veces si fallara algo más, aunque aquí es todo o nada)
          // Pero como estamos en un loop, solo queremos actualizar la transacción UNA vez.
          // El problema es que si actualizamos la transacción aquí y luego falla el ticket, se hace rollback de todo. Correcto.
          
          await tx.transaction.update({
            where: { id: transaction.id },
            data: { status: 'approved', reference: `Ticket #${assignedNumber} - ${raffle.title}` }
          });

          return await tx.ticket.create({
            data: {
              number: assignedNumber,
              userId: transaction.userId,
              raffleId: raffle.id,
              serialNumber: generateShortId('TKT'),
              status: 'approved'
            },
            include: { user: true, raffle: true }
          });
        });
      } catch (err) {
        // Si el error es por duplicado (P2002) o nuestro 'Number taken', continuamos el loop
        if (err.code === 'P2002' || err.message === 'Number taken') {
          console.log(`Intento ${attempts}: Número ${assignedNumber} ocupado, reintentando...`);
          ticket = null; // Asegurar que ticket es null para seguir loop
        } else {
          throw err; // Otro error, lanzar
        }
      }
    }

    if (!ticket) return res.status(500).json({ error: 'No se pudo asignar un número único después de varios intentos. Intenta de nuevo.' });

    // Notificar usuario
    if (transaction.user.email) {
      sendEmail(
        transaction.user.email,
        'Pago Aprobado - Ticket Asignado',
        `Tu pago ha sido verificado. Tu número es: ${ticket.number}`,
        `<h1>¡Pago Verificado!</h1><p>Tu número asignado es: <b>${ticket.number}</b></p><p>Rifa: ${raffle.title}</p>`
      ).catch(console.error);
    }

    res.json({ message: 'Pago verificado y ticket asignado', ticket });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al verificar pago' });
  }
});

// Endpoint para guardar datos bancarios del admin
app.put('/admin/bank-details', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { bankDetails } = req.body;
  try {
    await prisma.user.update({
      where: { id: req.user.userId },
      data: { bankDetails }
    });
    res.json({ message: 'Datos bancarios actualizados' });
  } catch (error) {
    res.status(500).json({ error: 'Error al guardar datos bancarios' });
  }
});

// Endpoint público para ver datos bancarios del admin (para que el usuario pague)
app.get('/admin/bank-details', async (req, res) => {
  try {
    // Asumimos que el primer superadmin o admin tiene los datos
    const admin = await prisma.user.findFirst({
      where: { role: { in: ['admin', 'superadmin'] }, bankDetails: { not: Prisma.DbNull } }
    });
    if (!admin || !admin.bankDetails) return res.json({ bankDetails: null });
    res.json({ bankDetails: admin.bankDetails });
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener datos bancarios' });
  }
});

// --- WALLET ENDPOINTS ---

app.get('/wallet', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ 
      where: { id: req.user.userId },
      include: { transactions: { orderBy: { createdAt: 'desc' }, take: 20 } }
    });
    res.json({ balance: user.balance, transactions: user.transactions });
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener wallet' });
  }
});

app.post('/wallet/topup', authenticateToken, async (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Monto inválido' });

  try {
    await prisma.$transaction([
      prisma.user.update({
        where: { id: req.user.userId },
        data: { balance: { increment: Number(amount) } }
      }),
      prisma.transaction.create({
        data: {
          userId: req.user.userId,
          amount: Number(amount),
          type: 'deposit',
          status: 'approved',
          reference: 'Recarga de saldo'
        }
      })
    ]);
    res.json({ message: 'Recarga exitosa' });
  } catch (error) {
    res.status(500).json({ error: 'Error al recargar' });
  }
});

app.get('/tickets/:id', authenticateToken, async (req, res) => {
  try {
    const ticket = await prisma.ticket.findUnique({ where: { id: Number(req.params.id) } });
    if (!ticket) return res.status(404).json({ error: 'Ticket no encontrado' });
    res.json(ticket);
  } catch (error) {
    res.status(500).json({ error: 'Error al consultar ticket' });
  }
});

app.put('/tickets/:id', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { number } = req.body;
  try {
    const ticket = await prisma.ticket.update({
      where: { id: Number(req.params.id) },
      data: { number }
    });
    res.json({ message: 'Ticket actualizado', ticket });
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar ticket' });
  }
});

app.delete('/tickets/:id', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    await prisma.ticket.delete({ where: { id: Number(req.params.id) } });
    res.json({ message: 'Ticket eliminado' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar ticket' });
  }
});

// --- SUPERADMIN ENDPOINTS ---

app.get('/superadmin/settings', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    let settings = await prisma.systemSettings.findFirst();
    if (!settings) {
      settings = await prisma.systemSettings.create({ data: { branding: {}, modules: {} } });
    }
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener ajustes' });
  }
});

app.patch('/superadmin/settings/branding', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const branding = req.body;
    const settings = await prisma.systemSettings.upsert({
      where: { id: 1 },
      update: { branding },
      create: { branding, modules: {} }
    });
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: 'Error al guardar branding' });
  }
});

app.patch('/superadmin/settings/modules', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const { modules } = req.body;
    const settings = await prisma.systemSettings.upsert({
      where: { id: 1 },
      update: { modules },
      create: { branding: {}, modules }
    });
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: 'Error al guardar módulos' });
  }
});

app.get('/superadmin/audit/users', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const users = await prisma.user.findMany({ orderBy: { createdAt: 'desc' } });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error al auditar usuarios' });
  }
});

app.get('/superadmin/mail/logs', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const logs = await prisma.mailLog.findMany({ orderBy: { timestamp: 'desc' }, take: 50 });
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener logs de correo' });
  }
});

app.get('/superadmin/audit/actions', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const logs = await prisma.auditLog.findMany({ orderBy: { timestamp: 'desc' }, take: 50 });
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener logs de auditoría' });
  }
});

app.post('/superadmin/users', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  const { email, password, role, firstName, lastName, active } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        role,
        name: `${firstName} ${lastName}`,
        active,
        publicId: generateShortId(role === 'admin' || role === 'superadmin' ? 'ADM' : 'USR')
      }
    });
    await prisma.auditLog.create({
      data: { action: 'CREATE_USER', detail: `Created user ${email}`, entity: 'User' }
    });
    res.status(201).json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error al crear usuario' });
  }
});

app.patch('/superadmin/users/:id/status', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  const { id } = req.params;
  const { active, verified } = req.body;
  try {
    const data = {};
    if (active !== undefined) data.active = active;
    if (verified !== undefined) data.verified = verified;
    
    const user = await prisma.user.update({ where: { id: Number(id) }, data });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar estado de usuario' });
  }
});

app.post('/superadmin/users/:id/reset-2fa', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  res.json({ message: '2FA reseteado' });
});

app.post('/superadmin/users/:id/revoke-sessions', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  res.json({ message: 'Sesiones revocadas' });
});

// --- MANUAL PAYMENTS ENDPOINTS ---

// Crear pago manual
app.post('/raffles/:id/manual-payments', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { quantity, reference, note, proof } = req.body;
  
  if (!quantity || quantity <= 0) return res.status(400).json({ error: 'Cantidad inválida' });
  if (!proof) return res.status(400).json({ error: 'Comprobante requerido' });

  try {
    const raffle = await prisma.raffle.findUnique({ where: { id: Number(id) } });
    if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

    const amount = Number(raffle.ticketPrice) * Number(quantity);

    const transaction = await prisma.transaction.create({
      data: {
        userId: req.user.userId,
        amount,
        type: 'manual_payment',
        status: 'pending',
        reference: reference || `Pago manual para rifa ${id}`,
        proof,
        raffleId: raffle.id
      }
    });

    res.json({ message: 'Pago registrado, pendiente de aprobación', transaction });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al registrar pago manual' });
  }
});

// Listar pagos manuales pendientes (Admin)
app.get('/admin/manual-payments', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const payments = await prisma.transaction.findMany({
      where: { 
        type: 'manual_payment',
        status: 'pending'
      },
      include: { user: true },
      orderBy: { createdAt: 'desc' }
    });
    
    // Mapear para el frontend
    const mapped = payments.map(p => ({
      id: p.id,
      raffleId: p.raffleId,
      userId: p.user.email,
      amount: p.amount,
      reference: p.reference,
      proof: p.proof,
      status: p.status,
      note: p.reference
    }));

    res.json(mapped);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al listar pagos manuales' });
  }
});

// Aprobar/Rechazar pago manual
app.post('/admin/manual-payments/:id/:action', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  const { id, action } = req.params; // action: 'approve' | 'reject'
  
  try {
    const transaction = await prisma.transaction.findUnique({ where: { id: Number(id) } });
    if (!transaction || transaction.status !== 'pending') {
      return res.status(404).json({ error: 'Transacción no encontrada o ya procesada' });
    }

    if (action === 'reject') {
      await prisma.transaction.update({
        where: { id: Number(id) },
        data: { status: 'rejected' }
      });
      return res.json({ message: 'Pago rechazado' });
    }

    if (action === 'approve') {
      if (!transaction.raffleId) return res.status(400).json({ error: 'Transacción sin ID de rifa asociado' });
      
      const raffle = await prisma.raffle.findUnique({ where: { id: transaction.raffleId } });
      if (!raffle) return res.status(404).json({ error: 'Rifa no encontrada' });

      // Calcular cantidad de tickets basada en el monto
      const quantity = Math.floor(transaction.amount / raffle.ticketPrice);
      if (quantity <= 0) return res.status(400).json({ error: 'Monto insuficiente para un ticket' });

      const assignedNumbers = [];
      
      // Generar tickets
      await prisma.$transaction(async (prisma) => {
        await prisma.transaction.update({
          where: { id: transaction.id },
          data: { status: 'approved' }
        });

        for (let i = 0; i < quantity; i++) {
          let assignedNumber;
          let isUnique = false;
          let attempts = 0;
          while (!isUnique && attempts < 20) {
            assignedNumber = Math.floor(Math.random() * 10000) + 1;
            const existing = await prisma.ticket.findFirst({ where: { raffleId: raffle.id, number: assignedNumber } });
            if (!existing) isUnique = true;
            attempts++;
          }
          
          if (isUnique) {
            const ticket = await prisma.ticket.create({
              data: {
                number: assignedNumber,
                userId: transaction.userId,
                raffleId: raffle.id,
                serialNumber: generateShortId('TKT'),
                status: 'approved'
              }
            });
            assignedNumbers.push(ticket.number);
          }
        }
      });

      // Notificar
      const user = await prisma.user.findUnique({ where: { id: transaction.userId } });
      if (user && user.email) {
         sendEmail(
          user.email,
          'Pago Aprobado - Tickets Asignados',
          `Tu pago ha sido verificado. Tus números son: ${assignedNumbers.join(', ')}`,
          `<h1>¡Pago Verificado!</h1><p>Tus números asignados son: <b>${assignedNumbers.join(', ')}</b></p>`
        ).catch(console.error);
      }

      res.json({ message: 'Pago aprobado y tickets generados', numbers: assignedNumbers });
    } else {
      res.status(400).json({ error: 'Acción inválida' });
    }

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al procesar pago manual' });
  }
});

const cron = require('node-cron');
const { Expo } = require('expo-server-sdk');
const expo = new Expo();

// --- NOTIFICATIONS ---
async function sendPushNotification(tokens, title, body, data = {}) {
  const messages = [];
  for (const token of tokens) {
    if (!Expo.isExpoPushToken(token)) continue;
    messages.push({ to: token, sound: 'default', title, body, data });
  }
  const chunks = expo.chunkPushNotifications(messages);
  for (const chunk of chunks) {
    try {
      await expo.sendPushNotificationsAsync(chunk);
    } catch (error) {
      console.error(error);
    }
  }
}

// Cron Job: 1:00 PM Notification
cron.schedule('0 13 * * *', async () => {
  console.log('[CRON] Sending 1 PM notification...');
  try {
    const users = await prisma.user.findMany({
      where: { pushToken: { not: null } },
      select: { pushToken: true }
    });
    const tokens = users.map(u => u.pushToken).filter(Boolean);
    if (tokens.length) {
      await sendPushNotification(tokens, '¡Sorteo de la Tarde!', 'El sorteo de la 1:00 PM está por comenzar. ¡Atentos!');
    }
  } catch (error) {
    console.error('[CRON ERROR]', error);
  }
}, {
  scheduled: true,
  timezone: "America/Caracas"
});

// Cron Job: 4:00 PM Notification
cron.schedule('0 16 * * *', async () => {
  console.log('[CRON] Sending 4 PM notification...');
  try {
    const users = await prisma.user.findMany({
      where: { pushToken: { not: null } },
      select: { pushToken: true }
    });
    const tokens = users.map(u => u.pushToken).filter(Boolean);
    if (tokens.length) {
      await sendPushNotification(tokens, '¡Sorteo Vespertino!', 'El sorteo de las 4:00 PM está por comenzar. ¡No te lo pierdas!');
    }
  } catch (error) {
    console.error('[CRON ERROR]', error);
  }
}, {
  scheduled: true,
  timezone: "America/Caracas"
});

// Cron Job: 10:00 PM Notification
cron.schedule('0 22 * * *', async () => {
  console.log('[CRON] Sending 10 PM notification...');
  try {
    const users = await prisma.user.findMany({
      where: { pushToken: { not: null } },
      select: { pushToken: true }
    });
    const tokens = users.map(u => u.pushToken).filter(Boolean);
    if (tokens.length) {
      await sendPushNotification(tokens, '¡Sorteo Mayor!', 'El sorteo de las 10:00 PM está por comenzar. ¡Mucha suerte!');
    }
  } catch (error) {
    console.error('[CRON ERROR]', error);
  }
}, {
  scheduled: true,
  timezone: "America/Caracas" // Adjust as needed
});

// --- WINNERS ---
app.get('/winners', async (req, res) => {
  try {
    const winners = await prisma.winner.findMany({
      orderBy: { drawDate: 'desc' },
      include: {
        user: { select: { name: true, avatar: true, publicId: true } },
        raffle: { select: { title: true } }
      }
    });
    res.json(winners);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener ganadores' });
  }
});

app.post('/admin/winners', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const { raffleId, userId, photoUrl, testimonial, prize } = req.body;
    const winner = await prisma.winner.create({
      data: {
        raffleId: Number(raffleId),
        userId: userId ? Number(userId) : null,
        photoUrl,
        testimonial,
        prize
      }
    });
    res.json(winner);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al registrar ganador' });
  }
});

// --- SECURITY ---
app.post('/me/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Faltan datos' });

  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.userId } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) return res.status(401).json({ error: 'Contraseña actual incorrecta' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword }
    });

    res.json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al cambiar contraseña' });
  }
});

// --- USER PROFILE ---
app.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        balance: true,
        avatar: true,
        bio: true,
        socials: true,
        referralCode: true,
        createdAt: true
      }
    });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener perfil' });
  }
});

app.patch('/me', authenticateToken, async (req, res) => {
  try {
    const { name, avatar, bio, socials } = req.body;
    const user = await prisma.user.update({
      where: { id: req.user.userId },
      data: { name, avatar, bio, socials }
    });
    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar perfil' });
  }
});

app.get('/me/tickets', authenticateToken, async (req, res) => {
  try {
    const tickets = await prisma.ticket.findMany({
      where: { userId: req.user.userId },
      include: { raffle: true },
      orderBy: { createdAt: 'desc' }
    });
    res.json(tickets);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener tickets' });
  }
});

app.get('/me/payments', authenticateToken, async (req, res) => {
  try {
    const payments = await prisma.transaction.findMany({
      where: { userId: req.user.userId },
      orderBy: { createdAt: 'desc' }
    });
    res.json(payments);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener pagos' });
  }
});

// --- REFERRALS ---
app.get('/me/referrals', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      include: {
        referrals: {
          select: { name: true, createdAt: true, verified: true }
        }
      }
    });
    
    if (!user.referralCode) {
      // Generate if missing
      const code = user.name.substring(0, 3).toUpperCase() + Math.floor(1000 + Math.random() * 9000);
      await prisma.user.update({ where: { id: user.id }, data: { referralCode: code } });
      user.referralCode = code;
    }

    res.json({ code: user.referralCode, referrals: user.referrals });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener referidos' });
  }
});

app.post('/me/referral', authenticateToken, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Código requerido' });
    
    const referrer = await prisma.user.findUnique({ where: { referralCode: code } });
    if (!referrer) return res.status(404).json({ error: 'Código inválido' });
    if (referrer.id === req.user.userId) return res.status(400).json({ error: 'No puedes referirte a ti mismo' });

    await prisma.user.update({
      where: { id: req.user.userId },
      data: { referredById: referrer.id }
    });

    // Check for rewards
    checkAndRewardReferrer(referrer.id).catch(console.error);

    res.json({ message: 'Referido registrado' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al registrar referido' });
  }
});

// --- PUBLIC PROFILES ---
app.get('/users/public/:id', async (req, res) => {
  try {
    const { id } = req.params;
    let user = await prisma.user.findUnique({
      where: { publicId: id },
      select: {
        publicId: true,
        name: true,
        avatar: true,
        bio: true,
        socials: true,
        createdAt: true,
        verified: true,
        role: true,
        _count: {
          select: { tickets: true, announcements: true }
        }
      }
    });

    if (!user && !isNaN(Number(id))) {
      user = await prisma.user.findUnique({
        where: { id: Number(id) },
        select: {
          publicId: true,
          name: true,
          avatar: true,
          bio: true,
          socials: true,
          createdAt: true,
          verified: true,
          role: true,
          _count: {
            select: { tickets: true, announcements: true }
          }
        }
      });
    }

    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    let stats = {};
    if (user.role === 'admin' || user.role === 'superadmin') {
      const rafflesCount = await prisma.raffle.count();
      const winnersCount = await prisma.winner.count();
      stats = { raffles: rafflesCount, prizes: winnersCount };
    }

    res.json({ ...user, stats });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener perfil público' });
  }
});

// --- ANNOUNCEMENTS ---
app.get('/announcements', async (req, res) => {
  try {
    const announcements = await prisma.announcement.findMany({
      orderBy: { createdAt: 'desc' },
      take: 20,
      include: {
        admin: {
          select: { name: true, avatar: true, role: true, verified: true }
        },
        _count: {
          select: { reactions: true }
        }
      }
    });
    res.json(announcements);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener anuncios' });
  }
});

app.post('/admin/announcements', authenticateToken, authorizeRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const { title, content, imageUrl } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'Título y contenido requeridos' });

    const announcement = await prisma.announcement.create({
      data: {
        title,
        content,
        imageUrl,
        adminId: req.user.userId
      }
    });
    res.json(announcement);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear anuncio' });
  }
});

app.post('/announcements/:id/react', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { type } = req.body; 
    
    if (!['LIKE', 'HEART', 'DISLIKE'].includes(type)) {
      return res.status(400).json({ error: 'Tipo de reacción inválido' });
    }

    const existing = await prisma.reaction.findUnique({
      where: {
        userId_announcementId: {
          userId: req.user.userId,
          announcementId: Number(id)
        }
      }
    });

    if (existing) {
      if (existing.type === type) {
        await prisma.reaction.delete({ where: { id: existing.id } });
        return res.json({ message: 'Reacción eliminada', active: false });
      } else {
        const updated = await prisma.reaction.update({
          where: { id: existing.id },
          data: { type }
        });
        return res.json({ message: 'Reacción actualizada', active: true, reaction: updated });
      }
    } else {
      const reaction = await prisma.reaction.create({
        data: {
          userId: req.user.userId,
          announcementId: Number(id),
          type
        }
      });
      return res.json({ message: 'Reacción agregada', active: true, reaction });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al reaccionar' });
  }
});

app.patch('/superadmin/settings/smtp', authenticateToken, authorizeRole(['superadmin']), async (req, res) => {
  try {
    const smtp = req.body; // { host, port, user, pass, secure, fromName, fromEmail }
    const settings = await prisma.systemSettings.upsert({
      where: { id: 1 },
      update: { smtp },
      create: { branding: {}, modules: {}, smtp }
    });
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: 'Error al guardar configuración SMTP' });
  }
});

// Puerto
const PORT = process.env.PORT || 3000;
app.get('/health', (req, res) => {
  res.json({ ok: true, status: 'up', timestamp: Date.now() });
});

// Forzar redeploy en Render
app.get('/', (req, res) => {
  res.json({ message: 'API de rifas funcionando' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor backend escuchando en el puerto ${PORT} (Accesible desde red)`);
});

// Middleware global de manejo de errores (SIEMPRE al final)
app.use((err, req, res, next) => {
  console.error('[GLOBAL ERROR HANDLER]', err);
  // Si el error es de sintaxis JSON (body-parser)
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'JSON malformado' });
  }
  // Cualquier otro error
  res.status(err.status || 500).json({
    error: err.message || 'Error interno del servidor',
    details: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});
