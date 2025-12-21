# Expediente de cumplimiento (Venezuela) — Rifas (Plataforma/puente)

Este documento describe cómo generar evidencia reproducible de pruebas end‑to‑end (rifa de prueba → compras → cierre por tiempo → ganador → auditoría) para presentar en procesos de permisos/licencias.

## Concepto clave
- La plataforma actúa como **puente tecnológico**.
- Los *riferos* son quienes crean y ejecutan rifas.
- El sistema debe mantener **trazabilidad/auditoría** y **respaldo** de acciones para defensa ante disputas.

## Componentes del expediente
1. Evidencia de ejecución del flujo (smoke test): archivo JSON con pasos y respuestas relevantes.
2. Evidencia de cierre por tiempo (`endDate`) y estado final de la rifa.
3. Evidencia de ganador (`Winner`) cuando existan tickets.
4. Evidencia de auditoría (`AuditLog`) de acciones críticas.

## Requisitos
- Backend en Render accesible (ej: `https://backednnuevo.onrender.com`).
- (Recomendado para pruebas sin riesgo) Backend en **SANDBOX MODE**.
- Credenciales de superadmin (se crean/aseguran al iniciar):
  - Email: `rifa@megarifasapp.com`
  - Password: `rifasadmin123`

## SANDBOX MODE (simulación total)
Para que la plataforma “funcione como real” pero sin riesgo de pagos/dinero real:
- Define `SANDBOX_MODE=true`.
- Verifica el estado con:
  - `GET /sandbox/status`

Comportamiento en SANDBOX:
- `POST /payments/webhook/*` se bloquea (403).
- `POST /payments/initiate` fuerza `providerUsed=sandbox`.
- Las transacciones (recarga/compra) quedan marcadas con `provider=sandbox` y referencias con `[SIMULADO]`.
- Se ocultan datos bancarios en:
  - `GET /admin/bank-details`
  - `GET /raffles/:id/payment-details`
- Emails se suprimen por defecto (se registran como `SENT_SANDBOX_SUPPRESSED`).
  - Si necesitas enviar correos en pruebas controladas: `SANDBOX_ALLOW_EMAIL=true`.

## Generación de evidencia (automática)
### A) Smoke test (crea todo y cierra por tiempo)
Ejecuta desde la carpeta del backend:

- `BASE_URL=https://backednnuevo.onrender.com node scripts/complianceSmokeTest.js`

Resultado:
- Se crea un rifero (admin) y un comprador (user) de prueba.
- Se crea una rifa con `endDate` cercano y se activa.
- El comprador recarga wallet y compra tickets.
- Se ejecuta job de cierre por tiempo.
- Se valida ganador.

Evidencia:
- Se guarda en `artifacts/compliance-smoke-*.json`.

### B) Paquete de evidencia para una rifa específica
- `BASE_URL=https://backednnuevo.onrender.com node scripts/complianceEvidencePack.js --raffleId <ID>`

Incluye:
- `GET /raffles/:id`
- `GET /winners` (filtrado por raffleId)
- `GET /superadmin/audit/search?...`

Evidencia:
- Se guarda en `artifacts/compliance-pack-raffle-<ID>-*.json`.

## Endpoints relevantes
- Estado sandbox:
  - `GET /sandbox/status`
- Cierre por tiempo (manual/job):
  - `POST /admin/jobs/close-expired-raffles` (requiere superadmin)
- Auditoría:
  - `GET /superadmin/audit/actions` (últimos 50)
  - `GET /superadmin/audit/search` (filtros por `entity`, `entityId`, `action`, `userId`, `since`, `until`)
- Estado y resultado:
  - `GET /raffles/:id`
  - `GET /winners`

## Qué revisar en el expediente
- La rifa pasa de `draft` → `active` y luego a `closed` por `endDate`.
- Compras bloqueadas luego del cierre.
- Ganador registrado cuando hay tickets.
- AuditLog registra (mínimo):
  - `RAFFLE_CREATED`, `RAFFLE_ACTIVATED`, `TICKETS_PURCHASED`, `WALLET_TOPUP`, `RAFFLE_CLOSED`, `RAFFLES_AUTO_CLOSED_JOB`.

## Notas de seguridad
- La evidencia redacta tokens (`[REDACTED]`) para poder compartirse sin exponer credenciales.
