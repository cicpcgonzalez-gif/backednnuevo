# MegaRifas Backend API

Backend de la aplicación de rifas MegaRifas construido con Node.js, Express y Prisma.

## 🚀 Características

- API RESTful completa para gestión de rifas, usuarios, tickets y transacciones
- Autenticación JWT con roles (user, admin, superadmin)
- Sistema de verificación por email
- 2FA para administradores
- Sistema de referidos
- Gestión de anuncios y reacciones
- Rate limiting y seguridad con Helmet
- Logging de auditoría y correos
- Sistema de notificaciones push
- CORS habilitado para conexión con frontend

## 📋 Requisitos Previos

- Node.js 14+ 
- PostgreSQL 12+
- npm o yarn

## 🔧 Configuración

### 1. Clonar el repositorio

```bash
git clone https://github.com/cicpcgonzalez-gif/backednnuevo.git
cd backednnuevo
```

### 2. Instalar dependencias

```bash
npm install
```

### 3. Configurar variables de entorno

Copiar el archivo de ejemplo y configurar las variables:

```bash
cp .env.example .env
```

Editar `.env` con tus valores:

```env
DATABASE_URL="postgresql://usuario:password@host:5432/nombre_db"
JWT_SECRET="tu_secret_jwt_seguro_aqui"
PORT=3000

# Opcional: Configuración SMTP (se puede configurar también desde la API)
SMTP_HOST="smtp.gmail.com"
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER="tu_email@gmail.com"
SMTP_PASS="tu_password_app"
```

### 4. Ejecutar migraciones de base de datos

```bash
npx prisma migrate deploy
# O si necesitas crear migraciones:
npx prisma migrate dev
```

### 5. Generar cliente de Prisma

```bash
npx prisma generate
```

### 6. Crear superadmin inicial (opcional)

```bash
npm run seed:superadmin
```

Esto creará un superadmin con las credenciales:
- Email: `rifa@megarifasapp.com`
- Password: `rifasadmin123`

**⚠️ IMPORTANTE: Cambiar estas credenciales en producción**

## 🏃 Ejecución

### Desarrollo

```bash
npm start
```

El servidor iniciará en `http://localhost:3000` (o el puerto configurado en PORT)

### Producción

```bash
NODE_ENV=production npm start
```

## 🔌 Conexión con Frontend

### CORS

El backend tiene CORS habilitado para todas las origins. En producción, se recomienda configurar origins específicos editando el middleware CORS en `index.js`:

```javascript
app.use(cors({
  origin: ['https://tu-frontend.com', 'http://localhost:19006'],
  credentials: true
}));
```

### URL Base API

El frontend debe apuntar a la URL del backend:

**Desarrollo local:**
```
http://localhost:3000
```

**Producción (ejemplo Render):**
```
https://tu-app.onrender.com
```

### Configuración en Frontend

En tu aplicación frontend (React Native/Expo), configura la URL base:

```javascript
// config.js o similar
const API_BASE_URL = __DEV__ 
  ? 'http://localhost:3000' 
  : 'https://tu-backend.onrender.com';

export default API_BASE_URL;
```

## 📡 Endpoints Principales

### Autenticación

- `POST /register` - Registro de usuario
- `POST /login` - Inicio de sesión
- `POST /verify` - Verificar email con código
- `POST /resend-code` - Reenviar código de verificación
- `POST /auth/2fa` - Verificación 2FA para admins

### Usuarios

- `GET /me` - Obtener perfil del usuario autenticado
- `PATCH /me` - Actualizar perfil
- `GET /users/public/:id` - Obtener perfil público

### Rifas

- `GET /raffles` - Listar rifas
- `GET /raffles/:id` - Obtener detalle de rifa
- `POST /admin/raffles` - Crear rifa (admin)
- `PATCH /admin/raffles/:id` - Actualizar rifa (admin)

### Tickets

- `POST /tickets` - Comprar tickets
- `GET /my-tickets` - Mis tickets

### Transacciones

- `POST /deposit` - Depositar fondos (sube comprobante)
- `POST /withdraw` - Solicitar retiro
- `GET /my-transactions` - Mis transacciones

### Administración

- `GET /admin/users` - Listar usuarios (admin)
- `PATCH /admin/users/:id` - Actualizar usuario (admin)
- `POST /admin/announcements` - Crear anuncio (admin)
- `PATCH /superadmin/settings/smtp` - Configurar SMTP (superadmin)

Ver `index.js` para la lista completa de endpoints.

## 🔐 Seguridad

- Autenticación JWT
- Rate limiting global (100 req/min/IP)
- Rate limiting en login (5 intentos/15min)
- Helmet para headers de seguridad
- Validación de entrada en todos los endpoints
- Passwords hasheados con bcrypt
- 2FA opcional para admins

## 📧 Configuración de Email

Ver [EMAIL_SETUP.md](EMAIL_SETUP.md) para instrucciones detalladas sobre cómo configurar el envío de correos electrónicos.

## 🗄️ Base de Datos

El proyecto usa Prisma ORM con PostgreSQL. El esquema se encuentra en `prisma/schema.prisma`.

### Modelos principales:

- **User** - Usuarios del sistema
- **Raffle** - Rifas
- **Ticket** - Tickets de rifas
- **Transaction** - Transacciones de wallet
- **Winner** - Ganadores de rifas
- **Announcement** - Anuncios
- **SystemSettings** - Configuración del sistema
- **AuditLog** - Logs de auditoría
- **MailLog** - Logs de emails

## 🚀 Despliegue

### Render.com (Recomendado)

1. Crear cuenta en Render.com
2. Crear PostgreSQL database
3. Crear Web Service
4. Conectar repositorio de GitHub
5. Configurar variables de entorno:
   - `DATABASE_URL` - External Database URL de Render
   - `JWT_SECRET` - Secret seguro
6. Build Command: `npm install && npx prisma generate`
7. Start Command: `npm start`

### Otras plataformas

El backend es compatible con:
- Heroku
- Railway
- DigitalOcean App Platform
- AWS (EC2, Elastic Beanstalk)
- Google Cloud Run

## 📝 Scripts Útiles

- `npm start` - Iniciar servidor
- `npm run migrate` - Ejecutar migraciones
- `npm run seed:superadmin` - Crear superadmin
- `node backfill_security_ids.js` - Migrar security IDs
- `node fix_admin.js` - Reparar admin

## 🐛 Solución de Problemas

### El servidor no inicia

- Verificar que DATABASE_URL esté correctamente configurada
- Verificar que PostgreSQL esté corriendo
- Ejecutar `npm install` de nuevo
- Verificar logs de error

### Error de conexión a base de datos

- Verificar credenciales en DATABASE_URL
- Verificar que la base de datos exista
- Ejecutar `npx prisma migrate deploy`

### CORS errors desde frontend

- Verificar que CORS esté habilitado
- Verificar la URL del backend en el frontend
- Verificar que el backend esté corriendo

## 📄 Licencia

MIT License - Ver [LICENSE](LICENSE)

## 👥 Soporte

Para soporte técnico, contactar al equipo de desarrollo.

## 📚 Documentación Adicional

- [Configuración de Email](EMAIL_SETUP.md)
- [Prisma Schema](prisma/schema.prisma)
- Documentación API completa: Próximamente (Swagger/OpenAPI)
