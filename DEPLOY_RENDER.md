# Deploy del Backend en Render (sin APK)

Este documento sube **solo el backend** (API Express + Prisma) a la nube usando **Render**.

## 1) Requisitos

- Tener el backend en un repo (GitHub o GitLab).
- Tener una base de datos Postgres (Render Postgres, Neon, Supabase, etc.).

## 2) Variables de entorno necesarias

En Render → tu servicio → **Environment** agrega:

- `DATABASE_URL` (Postgres)
- `JWT_SECRET` (string largo)

Opcional (recomendado):

- `ENCRYPTION_KEY` (hex de 32 bytes / 64 chars). Si no lo pones, el backend deriva una clave desde `JWT_SECRET`.

## 3) Render Blueprint (render.yaml)

El proyecto ya incluye configuración en render.yaml para:

- Instalar dependencias
- Generar Prisma Client
- Ejecutar migraciones en el arranque (`prisma migrate deploy`)
- Iniciar el servidor

Archivo: render.yaml

## 4) Pasos en Render

1. Render → **New +** → **Blueprint**.
2. Conecta el repo del backend.
3. Render detecta `render.yaml` y crea el servicio.
4. En **Environment**, configura `DATABASE_URL` y `JWT_SECRET`.
5. Haz deploy.

Si el deploy falla por DB, normalmente es porque `DATABASE_URL` no es válida o la DB no permite conexiones externas.

## 5) Crear Superadmin (una vez)

El backend incluye un script:

- `npm run seed:superadmin`

Puedes correrlo desde:

- Render → tu servicio → **Shell**

Y ejecutar:

- `npm run seed:superadmin`

## 6) Verificación rápida

- Healthcheck: `GET /health`

## 7) Nota sobre la App móvil

Este despliegue NO genera APK ni publica nada en stores. Solo deja la API corriendo en la nube.
