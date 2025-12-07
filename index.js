const express = require('express');
const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
// Inicializar Prisma
const prisma = new PrismaClient();

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

const SUPERADMIN_EMAIL = 'rifa@megarifasapp.com';
const SUPERADMIN_PASSWORD = 'rifasadmin123';
const SUPERADMIN_ROLE = 'superadmin';

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
          role: SUPERADMIN_ROLE,
          name: 'Super Admin',
        }
      });
      console.log('Superadmin creado automáticamente');
    } else {
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

// Registro de usuario
app.post('/register', async (req, res) => {
  const { email, name, password } = req.body;
  if (!email || !name || !password) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = await prisma.user.create({
      data: { email, name, password: hashedPassword }
    });
    res.status(201).json({ message: 'Usuario registrado', user });
  } catch (error) {
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// Login de usuario
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });
  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ message: 'Login exitoso', token });
});

// CRUD para rifas
app.post('/raffles', async (req, res) => {
  const { title, description } = req.body;
  if (!title || !description) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  try {
    const raffle = await prisma.raffle.create({ data: { title, prize: description } });
    res.status(201).json({ message: 'Rifa creada', raffle });
  } catch (error) {
    res.status(500).json({ error: 'Error al crear rifa' });
  }
});

app.put('/raffles/:id', async (req, res) => {
  const { id } = req.params;
  const { title, description } = req.body;
  try {
    const raffle = await prisma.raffle.update({
      where: { id: Number(id) },
      data: { title, prize: description }
    });
    res.json({ message: 'Rifa actualizada', raffle });
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar rifa' });
  }
});

app.delete('/raffles/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await prisma.raffle.delete({ where: { id: Number(id) } });
    res.json({ message: 'Rifa eliminada' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar rifa' });
  }
});

// CRUD para usuarios
app.get('/users/:id', async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: Number(req.params.id) } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error al consultar usuario' });
  }
});

app.put('/users/:id', async (req, res) => {
  const { name, email } = req.body;
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

app.delete('/users/:id', async (req, res) => {
  try {
    await prisma.user.delete({ where: { id: Number(req.params.id) } });
    res.json({ message: 'Usuario eliminado' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar usuario' });
  }
});

// CRUD para tickets
app.post('/tickets', async (req, res) => {
  const { number, userId, raffleId } = req.body;
  if (!number || !userId || !raffleId) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  try {
    const ticket = await prisma.ticket.create({
      data: { number, userId: Number(userId), raffleId: Number(raffleId) }
    });
    res.status(201).json({ message: 'Ticket creado', ticket });
  } catch (error) {
    res.status(500).json({ error: 'Error al crear ticket' });
  }
});

app.get('/tickets/:id', async (req, res) => {
  try {
    const ticket = await prisma.ticket.findUnique({ where: { id: Number(req.params.id) } });
    if (!ticket) return res.status(404).json({ error: 'Ticket no encontrado' });
    res.json(ticket);
  } catch (error) {
    res.status(500).json({ error: 'Error al consultar ticket' });
  }
});

app.put('/tickets/:id', async (req, res) => {
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

app.delete('/tickets/:id', async (req, res) => {
  try {
    await prisma.ticket.delete({ where: { id: Number(req.params.id) } });
    res.json({ message: 'Ticket eliminado' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar ticket' });
  }
});

// Puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor backend escuchando en el puerto ${PORT}`);
});

// Forzar redeploy en Render
app.get('/', (req, res) => {
  res.json({ message: 'API de rifas funcionando' });
});
