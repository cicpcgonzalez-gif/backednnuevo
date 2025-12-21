# Despliegue SANDBOX en Render (recomendado)

Objetivo: tener un backend **separado** para pruebas/demos/cumplimiento, sin mezclar datos con producción.

## Opción recomendada (dos servicios)
Crea **2 Web Services** en Render apuntando al mismo repo:
- **Producción**: `backednnuevo-prod`
- **Sandbox**: `backednnuevo-sandbox`

Cada uno con su propia base de datos Postgres (idealmente **dos DBs distintas**):
- `DATABASE_URL` prod
- `DATABASE_URL` sandbox

## Variables de entorno (Sandbox)
Configura estas env vars en el servicio `backednnuevo-sandbox`:
- `NODE_VERSION=20` (o la versión 20.x que estés usando)
- `NODE_ENV=production`
- `JWT_SECRET=<un secreto distinto al de prod>`
- `DATABASE_URL=<url de la DB sandbox>`
- `SANDBOX_MODE=true`

Opcional:
- `SANDBOX_ALLOW_EMAIL=false` (default) para que no envíe correos reales.
  - Si necesitas pruebas de correo controladas: `SANDBOX_ALLOW_EMAIL=true`.

## Verificación rápida
1) Abre:
- `GET https://<tu-sandbox>.onrender.com/__version`
- `GET https://<tu-sandbox>.onrender.com/sandbox/status`

2) Esperado:
- `sandbox: true`
- `payments.webhooksEnabled: false`

## Nota importante
Aunque el backend simule pagos, **separar DB** es lo que evita riesgos y mezclas de datos.
