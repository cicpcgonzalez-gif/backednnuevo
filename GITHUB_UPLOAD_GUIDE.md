# 📦 Subir Todo a GitHub y Conectar Backend-Frontend

Esta guía te ayuda a asegurar que todo esté correctamente subido a GitHub y conectado entre backend y frontend sin errores.

## ✅ Estado Actual

El backend está completamente configurado y listo para:
- ✅ Subir a GitHub
- ✅ Conectar con frontend
- ✅ Desplegar en producción
- ✅ Funcionar sin errores

## 📤 1. Subir Todo a GitHub

### Verificar Estado del Repositorio

```bash
cd /ruta/a/backednnuevo

# Ver archivos modificados
git status

# Ver qué está ignorado
git status --ignored
```

### Archivos Importantes que DEBEN estar en GitHub

✅ **Código fuente:**
- `index.js` - Servidor principal
- `prisma/schema.prisma` - Esquema de base de datos
- `package.json` - Dependencias
- Scripts de utilidad (`.js`)

✅ **Documentación:**
- `README.md` - Documentación principal
- `API_DOCUMENTATION.md` - Referencia de API
- `DEPLOYMENT.md` - Guía de despliegue
- `FRONTEND_CONNECTION.md` - Integración frontend
- `QUICKSTART.md` - Inicio rápido
- `EMAIL_SETUP.md` - Configuración de emails

✅ **Configuración:**
- `.env.example` - Ejemplo de configuración
- `.gitignore` - Archivos a ignorar
- `package-lock.json` - Lock de dependencias

### Archivos que NO DEBEN estar en GitHub

❌ **Nunca subir:**
- `.env` - Variables de entorno (CONTIENE SECRETOS)
- `node_modules/` - Dependencias (muy pesado)
- Backups y temporales

El `.gitignore` ya está configurado para protegerte.

### Subir Cambios a GitHub

```bash
# Ver qué hay para subir
git status

# Agregar todos los cambios
git add .

# Ver qué se va a subir
git status

# Commitear con mensaje descriptivo
git commit -m "feat: Add complete documentation and configuration"

# Subir a GitHub
git push origin main
# O si estás en otra rama:
git push origin nombre-de-tu-rama
```

### Verificar en GitHub

1. Ir a https://github.com/cicpcgonzalez-gif/backednnuevo
2. Verificar que los archivos estén ahí
3. Verificar que `.env` NO esté (debe aparecer en .gitignore)

## 🔗 2. Conectar Backend y Frontend

### A. Verificar Backend

**1. Backend funcionando localmente:**

```bash
# En terminal del backend
cd backednnuevo
npm install
npm start

# Debería mostrar:
# Servidor backend escuchando en el puerto 3000
```

**2. Probar endpoint:**

```bash
# En otra terminal
curl http://localhost:3000/health

# Respuesta esperada:
# {"ok":true,"status":"up","timestamp":...}
```

### B. Configurar Frontend

**1. Instalar frontend (si no lo has hecho):**

Si tu frontend está en otro repositorio, clónalo:

```bash
git clone https://github.com/tu-usuario/tu-frontend.git
cd tu-frontend
npm install
```

**2. Configurar URL del backend:**

Crear o editar `config.js` o similar en el frontend:

```javascript
// config/api.js
export const API_BASE_URL = __DEV__ 
  ? 'http://localhost:3000'  // Desarrollo local
  : 'https://tu-backend.onrender.com';  // Producción
```

**3. Probar conexión:**

En tu app frontend, hacer una petición:

```javascript
// Test rápido
fetch('http://localhost:3000/health')
  .then(r => r.json())
  .then(data => console.log('Backend conectado:', data))
  .catch(err => console.error('Error:', err));
```

### C. Solución de Problemas de Conexión

#### Error: "Network request failed"

**En React Native (Desarrollo):**

```javascript
// Si usas emulador Android
const API_URL = 'http://10.0.2.2:3000';

// Si usas dispositivo físico en misma red WiFi
const API_URL = 'http://192.168.1.X:3000';  // Tu IP local

// Para encontrar tu IP:
// macOS/Linux: ifconfig | grep inet
// Windows: ipconfig
```

#### Error: "CORS"

Ya está resuelto. El backend tiene `app.use(cors())` habilitado.

#### Error: "Cannot connect"

Verificar:
1. ✅ Backend corriendo (`npm start`)
2. ✅ Puerto correcto (3000 por defecto)
3. ✅ URL correcta en frontend
4. ✅ Misma red WiFi (dispositivos físicos)

## 🚀 3. Desplegar a Producción

### Opción A: Render.com (Recomendado - Gratis)

**Paso 1: Subir código a GitHub** (ya hecho ✅)

**Paso 2: Crear cuenta en Render**
- Ir a https://render.com
- Registrarse con GitHub

**Paso 3: Crear base de datos**
1. New + → PostgreSQL
2. Name: `megarifas-db`
3. Create Database
4. Copiar "External Database URL"

**Paso 4: Crear Web Service**
1. New + → Web Service
2. Conectar repositorio: `cicpcgonzalez-gif/backednnuevo`
3. Configurar:
   - **Name**: `megarifas-backend`
   - **Build Command**: `npm install && npx prisma generate && npx prisma migrate deploy`
   - **Start Command**: `npm start`
4. Variables de entorno:
   ```
   DATABASE_URL=postgresql://... (copiar de Step 3)
   JWT_SECRET=genera_un_secret_seguro_aqui
   NODE_ENV=production
   ```
5. Create Web Service

**Paso 5: Esperar despliegue**
- Toma 5-10 minutos
- Ver logs en tiempo real
- URL final: `https://tu-app.onrender.com`

**Paso 6: Crear superadmin**

En Render Shell (o usando API):
```bash
npm run seed:superadmin
```

**Paso 7: Actualizar frontend**

```javascript
// config/api.js
export const API_BASE_URL = 'https://tu-app.onrender.com';
```

### Opción B: Otras Plataformas

Ver guía completa en [DEPLOYMENT.md](DEPLOYMENT.md):
- Heroku
- Railway
- DigitalOcean
- Docker

## 🧪 4. Verificar que Todo Funciona

### Checklist Backend

```bash
# 1. Health check
curl https://tu-app.onrender.com/health

# 2. Listar rifas
curl https://tu-app.onrender.com/raffles

# 3. Registro
curl -X POST https://tu-app.onrender.com/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123","name":"Test"}'

# 4. Login
curl -X POST https://tu-app.onrender.com/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123"}'
```

### Checklist Frontend

- [ ] Frontend puede hacer petición a `/health`
- [ ] Puede registrar usuario
- [ ] Puede hacer login
- [ ] Puede listar rifas
- [ ] Puede comprar tickets
- [ ] Puede ver wallet

### Checklist Conexión

- [ ] CORS funcionando (sin errores en consola)
- [ ] Autenticación funcionando (JWT)
- [ ] Todos los endpoints respondiendo
- [ ] Velocidad aceptable (<2s por petición)
- [ ] Manejo de errores funcionando

## 📋 Guía Visual de Conexión

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  1. DESARROLLO LOCAL                                    │
│                                                         │
│  ┌─────────────┐           ┌──────────────┐           │
│  │  Frontend   │ ────────> │   Backend    │           │
│  │ localhost   │  fetch    │ localhost    │           │
│  │   :19006    │ <──────── │   :3000      │           │
│  └─────────────┘   JSON    └──────────────┘           │
│                                    │                    │
│                                    ▼                    │
│                             ┌──────────────┐           │
│                             │  PostgreSQL  │           │
│                             │  localhost   │           │
│                             └──────────────┘           │
│                                                         │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                                                         │
│  2. PRODUCCIÓN                                          │
│                                                         │
│  ┌─────────────┐           ┌──────────────┐           │
│  │  Frontend   │ ────────> │   Backend    │           │
│  │  Vercel/    │  HTTPS    │   Render     │           │
│  │  Netlify    │ <──────── │   .com       │           │
│  └─────────────┘   JSON    └──────────────┘           │
│                                    │                    │
│                                    ▼                    │
│                             ┌──────────────┐           │
│                             │  PostgreSQL  │           │
│                             │   Render     │           │
│                             └──────────────┘           │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## 🎯 Flujo Completo

### 1. Usuario Registra

```
Frontend → POST /register → Backend
                            ↓
                      Crea usuario en DB
                            ↓
                      Envía email con código
                            ↓
Backend ← Respuesta 201 ← Frontend muestra "Revisa tu email"
```

### 2. Usuario Verifica

```
Frontend → POST /verify → Backend
                          ↓
                    Verifica código
                          ↓
                    Genera JWT token
                          ↓
Backend ← Token + User ← Frontend guarda token
```

### 3. Usuario Compra Ticket

```
Frontend → POST /tickets (con token) → Backend
                                       ↓
                                 Verifica token
                                       ↓
                                 Verifica balance
                                       ↓
                                 Crea tickets en DB
                                       ↓
                                 Descuenta balance
                                       ↓
Backend ← Tickets + Balance ← Frontend muestra éxito
```

## 📚 Documentación Completa

| Documento | Descripción |
|-----------|-------------|
| [README.md](README.md) | Documentación general del proyecto |
| [QUICKSTART.md](QUICKSTART.md) | Inicio rápido en 5 minutos |
| [API_DOCUMENTATION.md](API_DOCUMENTATION.md) | Referencia completa de API |
| [FRONTEND_CONNECTION.md](FRONTEND_CONNECTION.md) | Guía de integración frontend |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Despliegue en producción |
| [EMAIL_SETUP.md](EMAIL_SETUP.md) | Configuración de emails |

## 🆘 Solución de Problemas

### "No puedo subir a GitHub"

```bash
# Verificar remoto
git remote -v

# Si no hay remoto, agregarlo
git remote add origin https://github.com/cicpcgonzalez-gif/backednnuevo.git

# Autenticarse con GitHub
git config --global user.name "Tu Nombre"
git config --global user.email "tu@email.com"

# Intentar de nuevo
git push origin main
```

### "Frontend no conecta con backend"

1. ✅ Verificar backend corriendo: `curl http://localhost:3000/health`
2. ✅ Verificar URL en frontend config
3. ✅ Verificar CORS (ya está habilitado)
4. ✅ Ver logs del backend para errores
5. ✅ Ver consola del frontend para errores

### "Error al desplegar en Render"

1. ✅ Verificar que código esté en GitHub
2. ✅ Verificar Build Command correcto
3. ✅ Verificar variables de entorno configuradas
4. ✅ Ver logs de despliegue
5. ✅ Verificar DATABASE_URL válido

### "Base de datos no conecta"

```bash
# Probar conexión localmente
npx prisma studio

# Verificar DATABASE_URL
echo $DATABASE_URL

# Probar formato
# Correcto: postgresql://user:pass@host:5432/db
# Incorrecto: postgres://... (debe ser postgresql://)
```

## ✅ Checklist Final

### GitHub
- [ ] Código subido a GitHub
- [ ] `.env` NO está en GitHub
- [ ] `.gitignore` configurado
- [ ] Documentación completa
- [ ] README.md actualizado

### Backend Local
- [ ] Dependencias instaladas (`npm install`)
- [ ] Base de datos configurada
- [ ] Migraciones ejecutadas
- [ ] Servidor inicia sin errores
- [ ] Health check responde

### Backend Producción
- [ ] Desplegado en Render/Heroku
- [ ] Base de datos en la nube
- [ ] Variables de entorno configuradas
- [ ] Superadmin creado
- [ ] Endpoints respondiendo

### Frontend
- [ ] URL del backend configurada
- [ ] Puede conectar con backend
- [ ] Registro funcionando
- [ ] Login funcionando
- [ ] Operaciones CRUD funcionando

### Integración
- [ ] CORS funcionando
- [ ] Autenticación funcionando
- [ ] Manejo de errores implementado
- [ ] Timeout configurado
- [ ] Loading states implementados

## 🎉 ¡Todo Listo!

Si completaste todos los pasos:

✅ Tu código está en GitHub
✅ Backend y frontend están conectados
✅ No hay errores
✅ Todo funciona en desarrollo
✅ Listo para producción

## 🚀 Próximos Pasos

1. **Desarrollar funcionalidades** - El backend ya tiene todo lo necesario
2. **Mejorar UI/UX** - Enfocarte en la experiencia del usuario
3. **Agregar más rifas** - Crear contenido
4. **Marketing** - Promocionar tu app
5. **Monitoreo** - Configurar analytics y error tracking

---

**¿Preguntas?** Revisa la documentación o contacta al equipo de desarrollo.

**Happy Coding! 🚀**
