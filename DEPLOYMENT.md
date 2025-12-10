# Guía de Despliegue - MegaRifas Backend

Esta guía describe cómo desplegar el backend de MegaRifas en diferentes plataformas.

## 📦 Pre-requisitos

- Código del backend subido a GitHub
- Base de datos PostgreSQL (puede ser proporcionada por la plataforma de hosting)
- Variables de entorno configuradas

## 🚀 Despliegue en Render.com (Recomendado)

Render.com ofrece hosting gratuito para proyectos pequeños y es muy fácil de configurar.

### Paso 1: Crear cuenta en Render

1. Ir a [https://render.com](https://render.com)
2. Registrarse con GitHub
3. Autorizar acceso a tu repositorio

### Paso 2: Crear base de datos PostgreSQL

1. En el dashboard de Render, hacer clic en "New +"
2. Seleccionar "PostgreSQL"
3. Configurar:
   - **Name**: `megarifas-db` (o el nombre que prefieras)
   - **Database**: `megarifas`
   - **User**: (auto-generado)
   - **Region**: Elegir la más cercana (ej: Ohio, Frankfurt)
   - **Plan**: Free (o el que necesites)
4. Hacer clic en "Create Database"
5. **IMPORTANTE**: Copiar la "External Database URL" (la necesitarás después)
   - Formato: `postgresql://usuario:password@host:5432/database`

### Paso 3: Crear Web Service

1. En el dashboard, hacer clic en "New +"
2. Seleccionar "Web Service"
3. Conectar el repositorio de GitHub `cicpcgonzalez-gif/backednnuevo`
4. Configurar el servicio:
   - **Name**: `megarifas-backend`
   - **Region**: Misma que la base de datos
   - **Branch**: `main` (o la rama que uses)
   - **Root Directory**: (dejar vacío)
   - **Environment**: `Node`
   - **Build Command**: 
     ```bash
     npm install && npx prisma generate && npx prisma migrate deploy
     ```
   - **Start Command**: 
     ```bash
     npm start
     ```
   - **Plan**: Free (o el que necesites)

### Paso 4: Configurar Variables de Entorno

En la sección "Environment" del Web Service, agregar:

```
DATABASE_URL=postgresql://usuario:password@host:5432/database
JWT_SECRET=tu_secret_jwt_muy_seguro_y_aleatorio_aqui
NODE_ENV=production
PORT=3000
```

**Para generar un JWT_SECRET seguro:**
```bash
# En tu terminal local:
openssl rand -base64 64
```

**Opcional - Configuración SMTP:**
```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=tu_email@gmail.com
SMTP_PASS=tu_app_password
```

### Paso 5: Desplegar

1. Hacer clic en "Create Web Service"
2. Render comenzará a desplegar automáticamente
3. Esperar a que el despliegue complete (puede tomar 5-10 minutos)
4. Una vez completado, tu API estará disponible en: `https://tu-app.onrender.com`

### Paso 6: Crear Superadmin

Una vez desplegado, crear el superadmin:

1. En el dashboard de Render, ir a tu servicio
2. En la pestaña "Shell", ejecutar:
   ```bash
   npm run seed:superadmin
   ```

O usar el endpoint de verificación de salud:
```bash
curl https://tu-app.onrender.com/health
```

### Paso 7: Verificar Funcionamiento

Probar endpoints básicos:

```bash
# Health check
curl https://tu-app.onrender.com/health

# Listar rifas (público)
curl https://tu-app.onrender.com/raffles

# Root endpoint
curl https://tu-app.onrender.com/
```

### Configuración de Auto-Deploy

Render detecta automáticamente cambios en GitHub:
- Cada push a la rama configurada desplegará automáticamente
- Los logs están disponibles en el dashboard
- Los deploys fallidos no afectan la versión en producción

## 🎯 Despliegue en Heroku

### Paso 1: Instalar Heroku CLI

```bash
npm install -g heroku
heroku login
```

### Paso 2: Crear aplicación

```bash
cd /ruta/a/tu/proyecto
heroku create megarifas-backend
```

### Paso 3: Agregar PostgreSQL

```bash
heroku addons:create heroku-postgresql:mini
```

### Paso 4: Configurar variables

```bash
heroku config:set JWT_SECRET="tu_secret_seguro"
heroku config:set NODE_ENV=production
```

### Paso 5: Desplegar

```bash
git push heroku main
```

### Paso 6: Ejecutar migraciones

```bash
heroku run npx prisma migrate deploy
heroku run npm run seed:superadmin
```

## 🌊 Despliegue en Railway

### Paso 1: Crear cuenta

1. Ir a [https://railway.app](https://railway.app)
2. Registrarse con GitHub

### Paso 2: Nuevo proyecto

1. Click en "New Project"
2. Seleccionar "Deploy from GitHub repo"
3. Elegir `backednnuevo`

### Paso 3: Agregar PostgreSQL

1. Click en "+ New"
2. Seleccionar "Database" → "PostgreSQL"
3. Railway creará la base de datos automáticamente

### Paso 4: Configurar variables

En el servicio backend, agregar variables:
```
JWT_SECRET=tu_secret_seguro
NODE_ENV=production
```

Railway conectará automáticamente DATABASE_URL.

### Paso 5: Configurar Build

En Settings:
- **Build Command**: `npm install && npx prisma generate && npx prisma migrate deploy`
- **Start Command**: `npm start`

## ☁️ Despliegue en DigitalOcean App Platform

### Paso 1: Crear cuenta

1. Ir a [https://cloud.digitalocean.com](https://cloud.digitalocean.com)
2. Crear cuenta

### Paso 2: Crear App

1. Click en "Create" → "Apps"
2. Conectar GitHub
3. Seleccionar repositorio

### Paso 3: Configurar

- **Build Command**: `npm install && npx prisma generate`
- **Run Command**: `npm start`
- **Port**: 3000

### Paso 4: Agregar Database

1. Agregar "Database" component
2. Seleccionar PostgreSQL
3. La URL se auto-configura

### Paso 5: Variables de entorno

Agregar en App Settings:
```
JWT_SECRET=tu_secret_seguro
NODE_ENV=production
```

## 🐳 Despliegue con Docker (Opcional)

Crear `Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
COPY prisma ./prisma/

RUN npm ci
RUN npx prisma generate

COPY . .

EXPOSE 3000

CMD ["npm", "start"]
```

Crear `docker-compose.yml`:

```yaml
version: '3.8'

services:
  db:
    image: postgres:15
    environment:
      POSTGRES_USER: megarifas
      POSTGRES_PASSWORD: password
      POSTGRES_DB: megarifas
    ports:
      - "5432:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data

  backend:
    build: .
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: postgresql://megarifas:password@db:5432/megarifas
      JWT_SECRET: dev_secret_change_in_production
      NODE_ENV: production
    depends_on:
      - db
    command: >
      sh -c "npx prisma migrate deploy && npm start"

volumes:
  postgres-data:
```

Ejecutar:
```bash
docker-compose up -d
```

## 🔧 Configuración Post-Despliegue

### 1. Configurar SMTP

Usar el endpoint del superadmin:

```bash
curl -X PATCH https://tu-app.onrender.com/superadmin/settings/smtp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TU_TOKEN_SUPERADMIN" \
  -d '{
    "host": "smtp.gmail.com",
    "port": 587,
    "secure": false,
    "user": "tu_email@gmail.com",
    "pass": "tu_app_password",
    "fromName": "MegaRifas",
    "fromEmail": "noreply@tudominio.com"
  }'
```

### 2. Conectar Frontend

Actualizar la URL del backend en tu frontend:

```javascript
// config.js en tu app frontend
const API_URL = 'https://tu-app.onrender.com';
```

### 3. Probar Conexión

Desde el frontend, probar:
- Registro de usuario
- Login
- Listar rifas
- Comprar tickets

## 📊 Monitoreo

### Render
- Ver logs en tiempo real en el dashboard
- Configurar alertas de uptime
- Métricas de CPU y memoria

### Heroku
```bash
heroku logs --tail
heroku ps
```

### Logs personalizados

El backend ya incluye logging:
- Peticiones HTTP con duración
- Consultas lentas a la base de datos (>200ms)
- Errores globales

## 🔒 Seguridad en Producción

1. **JWT_SECRET**: Usar valores únicos y seguros
2. **CORS**: Configurar origins específicos en `index.js`:
   ```javascript
   app.use(cors({
     origin: ['https://tu-frontend.com'],
     credentials: true
   }));
   ```
3. **Rate Limiting**: Ya configurado (100 req/min)
4. **HTTPS**: Todas las plataformas lo proveen automáticamente
5. **Variables de entorno**: Nunca commitear `.env`

## 🆘 Solución de Problemas

### Error: "Cannot find module @prisma/client"

```bash
# En Render, asegurar que Build Command incluye:
npm install && npx prisma generate
```

### Error: Database connection failed

- Verificar DATABASE_URL
- Verificar que la base de datos esté corriendo
- Verificar firewall/network rules

### Error: Application failed to start

- Revisar logs
- Verificar que todas las variables de entorno estén configuradas
- Probar localmente primero

### App se duerme (Free tier)

Render Free tier duerme después de 15 min de inactividad:
- Usar un cron job para hacer ping cada 10 minutos
- O usar UptimeRobot para mantenerla activa

## 📱 Configurar Frontend

Una vez desplegado el backend, actualizar frontend:

### React Native / Expo

```javascript
// config.js
export const API_BASE_URL = 'https://tu-app.onrender.com';
```

### Web

```javascript
// .env.production
REACT_APP_API_URL=https://tu-app.onrender.com
```

## ✅ Checklist Final

- [ ] Backend desplegado y respondiendo
- [ ] Base de datos creada y conectada
- [ ] Migraciones ejecutadas
- [ ] Superadmin creado
- [ ] SMTP configurado (opcional)
- [ ] Frontend apuntando a la URL correcta
- [ ] Health check funcionando
- [ ] Registro y login probados
- [ ] CORS configurado correctamente
- [ ] Variables de entorno seguras
- [ ] Monitoreo configurado

## 📞 Soporte

Para problemas de despliegue, revisar:
- Logs del servicio
- Documentación de la plataforma
- [Documentación de Prisma](https://www.prisma.io/docs)
- Issues del repositorio en GitHub

---

**¡Listo!** Tu backend está desplegado y listo para conectar con el frontend.
