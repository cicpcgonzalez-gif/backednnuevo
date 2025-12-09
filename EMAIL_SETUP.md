# Configurar SMTP para envíos de correo

Este backend ya envía correos en:
- Registro (`/register`) y reenvío de código (`/resend-code`).
- 2FA de admins (`/login` cuando role=admin y `/auth/2fa`).
- Compras de tickets: wallet (`/tickets`) y aprobación de pagos manuales (`/admin/verify-payment/:transactionId`).

El flujo de prioridad es:
1) `SystemSettings.smtp` en la base de datos (se puede guardar vía API).
2) Variables de entorno `SMTP_*` (Render u host donde corra el backend).
3) Si no hay nada, usa Ethereal (mock) y no entrega correos reales.

## Opción A: Guardar SMTP en DB (recomendada)
Usa el superadmin y llama:
```
PATCH /superadmin/settings/smtp
Authorization: Bearer <token superadmin>
Content-Type: application/json
{
  "host": "smtp.tudominio.com",
  "port": 465,
  "secure": true,
  "user": "usuario_smtp",
  "pass": "clave_smtp",
  "fromName": "MegaRifas",
  "fromEmail": "noreply@tudominio.com"
}
```
Se guarda en `SystemSettings.smtp` y se usa en caliente sin reiniciar.

## Opción B: Variables de entorno (Render u host)
Define estas env vars antes de arrancar el backend:
- `SMTP_HOST`
- `SMTP_PORT` (ej. 465 o 587)
- `SMTP_SECURE` (`true` para 465/SSL, `false` para 587/TLS start)
- `SMTP_USER`
- `SMTP_PASS`
- (Opcional) `SMTP_FROM_NAME`, `SMTP_FROM_EMAIL` si quieres cambiar el remitente por defecto

## Prueba rápida
1) Configura SMTP (DB o env vars).
2) Haz un registro o `POST /resend-code` a tu correo.
3) Verifica en la tabla `MailLog` el estado (`SENT` o `FAILED`).

## Notas
- El remitente por defecto si no se define es `"MegaRifas" <noreply@megarifasapp.com>`.
- Si no se configura nada, los envíos se marcan como `SENT_MOCK` en `MailLog` y no se entregan.
- Usa SMTP con dominio propio y SPF/DKIM para evitar spam.
