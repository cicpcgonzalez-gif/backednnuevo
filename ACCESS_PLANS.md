# Planes de acceso (Admin) – propuesta

Objetivo: definir **niveles de acceso** para personal/admins (operación, pagos, soporte, auditoría) sin mezclarlo con el rol de usuario final.

## Conceptos

- **Rol**: identifica el tipo de cuenta (ej: `superadmin`, `admin`). Hoy el backend usa `authorizeRole([...])`.
- **Módulos (feature flags)**: el sistema ya tiene `SystemSettings.modules` para activar/desactivar secciones completas (admin/superadmin).
- **Nivel** (propuesto): un “paquete” de permisos dentro de admin para separar funciones (pago vs verificación vs gestión). Esto hoy NO está modelado por usuario; se puede implementar con:
  - (Recomendado) `User.scopes` como arreglo de strings (permisos finos), o
  - (Más simple) nuevos roles (`admin_payments`, `admin_support`, etc.).

## Niveles recomendados

### Nivel 4 — Superadmin
Para dueños del sistema.

- Configuración global: branding, módulos, SMTP, soporte técnico, empresa.
- Gestión de usuarios admin: crear/bloquear/cambiar roles.
- Auditoría: ver logs críticos y mail logs.
- Operación completa: rifas, pagos, tickets, anuncios, ganadores.
- Acceso a PII (cédula/teléfono) desencriptado cuando sea necesario.

### Nivel 3 — Admin Operaciones (Manager)
Para operar rifas de punta a punta.

- Rifas: crear/editar/cerrar, estilo, galería, términos.
- Pagos: validar (aprobar/rechazar) + ver comprobantes.
- Tickets: verificador por serial y por número.
- Novedades: crear anuncios.
- Ganadores: publicar/actualizar.
- Reportes básicos/metrics.

No debe poder:
- Cambiar módulos/branding/SMTP.
- Administrar usuarios/roles.
- Acceder a auditoría crítica completa (opcional: solo lectura “baja”).

### Nivel 2 — Admin Pagos (Finanzas)
Para un equipo financiero.

- Pagos: aprobar/rechazar, ver comprobantes, ver referencias.
- Tickets: verificador (solo lectura) para soporte al pago.
- Reportes: exportar lista de pagos/tickets (si se añade export).

No debe poder:
- Crear/editar rifas.
- Publicar anuncios.
- Cambiar configuración del sistema.

### Nivel 1 — Verificador / Soporte
Para personal en punto de venta / eventos.

- Verificador de tickets: buscar por serial/# y confirmar estado.
- Opcional: ver **solo datos mínimos** del comprador (ej: nombre enmascarado y últimos 3–4 dígitos del teléfono).

No debe poder:
- Aprobar pagos.
- Editar rifas.
- Acceder a PII completa.

### Nivel 0 — Auditor (solo lectura)
Para control interno.

- Ver métricas/reportes.
- Ver auditoría (solo lectura).

No debe poder:
- Aprobar pagos.
- Crear/editar rifas.
- Cambiar settings.

## Matriz (resumen rápido)

Acción / Nivel | 1 Soporte | 2 Pagos | 3 Operaciones | 4 Superadmin
---|---:|---:|---:|---:
Verificar ticket | ✅ | ✅ | ✅ | ✅
Ver PII completa (tel/ced) | ❌ (enmascarado) | ⚠️ parcial | ✅ | ✅
Aprobar/rechazar pagos | ❌ | ✅ | ✅ | ✅
Crear/editar rifas | ❌ | ❌ | ✅ | ✅
Cerrar rifa / acciones críticas | ❌ | ❌ | ⚠️ opcional | ✅
Publicar anuncios | ❌ | ❌ | ✅ | ✅
Branding / módulos / SMTP | ❌ | ❌ | ❌ | ✅
Usuarios / roles | ❌ | ❌ | ❌ | ✅
Auditoría completa | ❌ | ❌ | ⚠️ opcional | ✅

## Módulos extra que vale la pena anexar

1) **Exportaciones** (CSV/Excel) para pagos, tickets, ganadores.
2) **Reembolsos** y reversos (con bitácora obligatoria).
3) **KYC** (ya existe modelo `KYCRequest`): panel para aprobar/rechazar documentos.
4) **Gestión de retiros** (wallet withdrawals) con aprobación por finanzas.
5) **Alertas de fraude** (ya existe `SuspiciousActivity`): panel operativo + acciones.
6) **Roles/Scoping** por usuario (scopes), para separar Pagos vs Soporte sin crear mil roles.
7) **API Keys/Webhooks** (si integras pasarelas): llaves por ambiente y rotación.

## Recomendación de implementación (siguiente paso)

Para que estos niveles funcionen “de verdad” (no solo UI), lo ideal es:

- Agregar `User.scopes` (Json o String[]) en Prisma.
- Validar permisos en backend por endpoint (no solo por rol).
- En la app, ocultar o deshabilitar secciones según `scopes`.

Si quieres, te lo implemento con estos scopes iniciales:

- `tickets:verify`
- `payments:review`
- `raffles:write`
- `announcements:write`
- `users:admin`
- `settings:write`
- `audit:read`
- `pii:read`
