# 🚀 Guía Rápida - MegaRifas Backend

Guía de inicio rápido para desarrolladores. ¡Pon el backend funcionando en 5 minutos!

## ⚡ Inicio Rápido

### 1. Clonar e Instalar

```bash
# Clonar el repositorio
git clone https://github.com/cicpcgonzalez-gif/backednnuevo.git
cd backednnuevo

# Instalar dependencias
npm install
```

### 2. Configurar Base de Datos

**Opción A: PostgreSQL Local**

```bash
# Instalar PostgreSQL (si no lo tienes)
# macOS: brew install postgresql
# Ubuntu: sudo apt-get install postgresql
# Windows: Descargar desde postgresql.org

# Crear base de datos
createdb rifas_db

# O usando psql:
psql postgres
CREATE DATABASE rifas_db;
\q
```

**Opción B: PostgreSQL en la Nube (Recomendado para producción)**

1. Ir a [Render.com](https://render.com)
2. Crear cuenta gratis
3. Crear "PostgreSQL" database
4. Copiar la "External Database URL"

### 3. Configurar Variables de Entorno

```bash
# Copiar el archivo de ejemplo
cp .env.example .env

# Editar .env con tus valores
nano .env
# o
code .env
```

Configuración mínima en `.env`:

```env
# Para desarrollo local:
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/rifas_db"
JWT_SECRET="dev_secret_12345"
PORT=3000
```

### 4. Ejecutar Migraciones

```bash
# Generar cliente de Prisma
npx prisma generate

# Ejecutar migraciones
npx prisma migrate deploy

# O crear nueva migración (si modificaste schema):
npx prisma migrate dev --name init
```

### 5. Crear Superadmin (Opcional)

```bash
npm run seed:superadmin
```

Credenciales por defecto:
- Email: `rifa@megarifasapp.com`
- Password: `rifasadmin123`

**⚠️ Cambiar en producción!**

### 6. Iniciar Servidor

```bash
npm start
```

Deberías ver:
```
Servidor backend escuchando en el puerto 3000 (Accesible desde red)
```

### 7. Verificar Funcionamiento

En otra terminal:

```bash
# Health check
curl http://localhost:3000/health

# Respuesta esperada:
# {"ok":true,"status":"up","timestamp":1234567890}

# Listar rifas (vacío si es la primera vez)
curl http://localhost:3000/raffles

# Respuesta esperada:
# {"raffles":[],"pagination":{"total":0,"limit":50,"offset":0}}
```

## ✅ ¡Listo!

Tu backend está funcionando. Ahora puedes:

### Conectar el Frontend

Ver: [FRONTEND_CONNECTION.md](FRONTEND_CONNECTION.md)

### Probar la API

```bash
# Registrar usuario
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "name": "Test User"
  }'

# Login
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

### Explorar Base de Datos

```bash
# Abrir Prisma Studio (GUI visual)
npx prisma studio

# Se abrirá en http://localhost:5555
```

## 📚 Siguientes Pasos

### Para Desarrollo:

1. **Leer la documentación:**
   - [README.md](README.md) - Documentación general
   - [API_DOCUMENTATION.md](API_DOCUMENTATION.md) - Referencia completa de API
   - [EMAIL_SETUP.md](EMAIL_SETUP.md) - Configurar envío de emails

2. **Desarrollar el Frontend:**
   - [FRONTEND_CONNECTION.md](FRONTEND_CONNECTION.md) - Guía de integración

### Para Producción:

1. **Desplegar el Backend:**
   - [DEPLOYMENT.md](DEPLOYMENT.md) - Guía de despliegue en Render, Heroku, etc.

2. **Configurar Seguridad:**
   - Cambiar JWT_SECRET por valor seguro
   - Configurar CORS con origins específicos
   - Configurar SMTP para emails reales

## 🐛 Problemas Comunes

### Error: "Cannot find module '@prisma/client'"

```bash
npx prisma generate
npm install
```

### Error: "Can't reach database server"

- Verificar que PostgreSQL esté corriendo
- Verificar DATABASE_URL en .env
- Verificar credenciales y nombre de base de datos

```bash
# Ver logs de PostgreSQL (macOS):
tail -f /usr/local/var/log/postgres.log

# Ubuntu:
sudo journalctl -u postgresql
```

### Error: "Port 3000 already in use"

```bash
# Encontrar proceso:
lsof -i :3000

# Matar proceso:
kill -9 <PID>

# O cambiar puerto en .env:
PORT=3001
```

### Base de datos vacía

```bash
# Verificar migraciones:
npx prisma migrate status

# Aplicar migraciones:
npx prisma migrate deploy

# O resetear (CUIDADO: borra todo):
npx prisma migrate reset
```

## 🔧 Comandos Útiles

```bash
# Ver estructura de BD
npx prisma studio

# Formatear schema
npx prisma format

# Validar schema
npx prisma validate

# Ver logs en tiempo real
npm start | grep -i error

# Seed superadmin
npm run seed:superadmin

# Ver migraciones aplicadas
npx prisma migrate status
```

## 📊 Estructura del Proyecto

```
backednnuevo/
├── index.js              # Servidor Express principal
├── package.json          # Dependencias
├── prisma/
│   └── schema.prisma    # Esquema de base de datos
├── .env                 # Variables de entorno (no subir a git)
├── .env.example         # Ejemplo de configuración
├── README.md            # Documentación general
├── API_DOCUMENTATION.md # Referencia completa de API
├── DEPLOYMENT.md        # Guía de despliegue
├── FRONTEND_CONNECTION.md # Integración con frontend
├── EMAIL_SETUP.md       # Configuración de emails
└── QUICKSTART.md        # Esta guía
```

## 🎯 Endpoints Clave

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/register` | POST | Registrar usuario |
| `/login` | POST | Iniciar sesión |
| `/verify` | POST | Verificar email |
| `/raffles` | GET | Listar rifas |
| `/raffles/:id` | GET | Detalle de rifa |
| `/tickets` | POST | Comprar tickets |
| `/my-tickets` | GET | Mis tickets |
| `/my-wallet` | GET | Mi wallet |
| `/deposit` | POST | Depositar fondos |
| `/announcements` | GET | Listar anuncios |

Ver lista completa en [API_DOCUMENTATION.md](API_DOCUMENTATION.md)

## 🌐 Variables de Entorno

| Variable | Requerida | Descripción | Ejemplo |
|----------|-----------|-------------|---------|
| `DATABASE_URL` | ✅ Sí | URL de PostgreSQL | `postgresql://user:pass@localhost:5432/db` |
| `JWT_SECRET` | ✅ Sí | Secret para JWT | `mi_secret_super_seguro` |
| `PORT` | ❌ No | Puerto del servidor | `3000` (default) |
| `NODE_ENV` | ❌ No | Modo de entorno | `development` o `production` |
| `SMTP_HOST` | ❌ No | Servidor SMTP | `smtp.gmail.com` |
| `SMTP_PORT` | ❌ No | Puerto SMTP | `587` |
| `SMTP_USER` | ❌ No | Usuario SMTP | `tu@email.com` |
| `SMTP_PASS` | ❌ No | Password SMTP | `tu_password` |

## 🔒 Seguridad

El backend incluye:

- ✅ Autenticación JWT
- ✅ Passwords hasheados con bcrypt
- ✅ Rate limiting (100 req/min)
- ✅ Helmet.js para headers de seguridad
- ✅ CORS configurado
- ✅ Validación de entrada
- ✅ 2FA para admins

## 📞 ¿Necesitas Ayuda?

1. **Revisa la documentación:**
   - README.md para overview general
   - API_DOCUMENTATION.md para detalles de endpoints
   - DEPLOYMENT.md para despliegue

2. **Revisa los logs:**
   ```bash
   npm start
   # Los logs muestran cada petición y tiempo de respuesta
   ```

3. **Usa Prisma Studio:**
   ```bash
   npx prisma studio
   # GUI para ver/editar datos
   ```

4. **Contacta al equipo:**
   - Abre un issue en GitHub
   - Revisa la documentación de Prisma
   - Revisa la documentación de Express

## 🎉 ¡Eso es Todo!

Ya tienes el backend funcionando. Siguiente paso:

→ [Conectar el Frontend](FRONTEND_CONNECTION.md)

→ [Desplegar a Producción](DEPLOYMENT.md)

---

**Happy Coding! 🚀**
