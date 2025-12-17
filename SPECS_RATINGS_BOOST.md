# Especificación (MVP) — Calificaciones (1–10) + Boost/Promoción (24h)

Fecha: 16-dic-2025

## 1) Alcance

### Incluye (MVP)
- Calificación por rifa: solo **estrellas 1–10** (sin comentario).
- Solo se puede calificar cuando la rifa esté **cerrada**.
- Solo pueden calificar usuarios que **compraron ticket** en esa rifa.
- 1 calificación por usuario por rifa.
- Encuesta simple (no pública): “¿Te gustaría poder dejar comentario?” Sí/No.
- Boost/promoción del rifero: **24h**.
- Boost con **cupos globales simultáneos** (máximo **15** rifero(s) boosteados al mismo tiempo).
- Regla semanal (para no colapsar el apartado de rifas): cada rifero puede tener **máximo 1 boost por semana** (cooldown de 7 días entre activaciones).
- Restricción adicional: un rifero no puede tener **más de 2 boosts activos** simultáneamente (safety adicional).

### No incluye (por ahora)
- Comentarios en calificación.
- Responder reviews, likes, reportes.
- Sistema de niveles automático (esto queda para otra especificación).

## 2) Definiciones
- **Rifero**: usuario creador de rifas.
- **Comprador**: usuario con al menos 1 ticket en la rifa.
- **Boost activo**: ventana de promoción vigente (now entre startAt y endAt).

## 3) Reglas de Calificación

### 3.1 Quién puede calificar
- Requisito: el usuario autenticado debe tener al menos un `Ticket` asociado a esa `Raffle`.
- Requisito: la `Raffle` debe estar `status = 'closed'`.
- Unicidad: 1 calificación por (raffleId, userId).

Regla clave (anti-fraude): el usuario tiene **una sola oportunidad** de calificar una rifa específica. No puede “acomodar” o cambiar la calificación después. En rifas futuras sí puede calificar nuevamente (siempre que haya participado comprando ticket en esa rifa).

### 3.2 Qué se guarda
- `score`: entero 1..10.
- `likedCommentsFeature`: boolean (encuesta Sí/No).
- Metadatos anti-fraude mínimos: `createdAt`, `ipHash` (opcional), `deviceHash` (opcional), `securityRiskScore` (opcional si ya existe motor).

### 3.3 Qué se muestra
- En perfil público del rifero (y/o detalle de rifa):
  - Promedio de calificación (1–10) y cantidad de votos.
  - No se muestra encuesta.

## 4) Boost/Promoción (24h)

### 4.1 Objetivo
- Dar visibilidad extra al rifero durante 24h mediante:
  - A) Badge “PROMOCIONADO”
  - B) Prioridad de orden en listados
  - C) Ambas (seleccionado)

### 4.2 Cupos globales (slots)
- Regla: máximo **15 rifero(s)** pueden estar boosteados simultáneamente.
- Cuando se intenta activar un boost y los slots están llenos:
  - Se rechaza (mensaje “No hay cupos disponibles, intenta más tarde”).
  - Alternativa futura (no MVP): cola/turnos.

### 4.3 Regla semanal (cooldown)
- Regla: un rifero solo puede **activar** boost si han pasado **7 días** desde su última activación.
- Fórmula: `now >= lastBoostStartAt + 7d`.
- Si no cumple, se rechaza con mensaje “Ya usaste tu boost esta semana; inténtalo más adelante”.

### 4.4 Límite por rifero
- Un rifero no puede tener más de **2 boosts activos** simultáneamente.

**Interpretación cerrada:** no hay “stacking” de prioridad; el efecto es binario (boost activo = sí/no).

### 4.5 Duración y ventana
- Duración fija: 24 horas.
- `startAt = now`, `endAt = now + 24h`.

### 4.6 Efecto en listados
- En endpoints de listado de rifas (`GET /raffles` y/o listados web/admin) se agrega info del usuario:
  - `user.isBoosted` (true si el rifero tiene boost activo)
  - `user.boostEndsAt` (para UI)
- Orden sugerido (MVP):
  1) Rifas activas, no vencidas
  2) Dentro de activas: riferos boosteados primero
  3) Luego por `createdAt` desc (o la regla actual)

## 5) Antifraude / Límites

### Para calificaciones
- Solo compradores.
- Solo rifa cerrada.
- Unicidad por usuario+rifa.

### Para boost
- Activación solo por el rifero dueño.
- Enforce de slots globales 15.
- Enforce de 1 boost por semana por rifero (cooldown 7 días).
- Enforce de máximo 2 boosts activos por rifero.

(Extra opcional): registrar auditoría de activaciones.

## 6) API propuesta (contrato)

> Nota: no se implementa hasta aprobación.

### 6.1 Calificar rifa
`POST /raffles/:id/rating`
Body:
- `score`: number (1..10)
- `likedCommentsFeature`: boolean

Respuestas:
- 200: rating creado
- 400: score inválido
- 403: no compró ticket / rifa no cerrada
- 409: ya calificó

**Decisión cerrada:** en MVP, **no permitir editar**. Aquí “editar” significa que el mismo usuario pueda cambiar la puntuación después de haberla enviado (ej. hoy puso 10 y mañana la cambia a 1). Se bloquea para reducir manipulación/fraude.

### 6.2 Resumen de rating de rifero
`GET /users/public/:id/rating-summary`
Respuesta:
- `avgScore` (float)
- `count` (int)

### 6.3 Activar boost
`POST /boosts/activate`
Body:
- (vacío)

Reglas:
- valida slots globales 15
- valida cooldown 7 días (1 boost por semana)
- valida max 2 boosts activos por rifero

Respuesta:
- `startAt`, `endAt`

### 6.4 Estado de boost
`GET /boosts/me`
Respuesta:
- `activeBoosts`: array [{startAt,endAt}]
- `isBoosted`: boolean
- `nextEligibleAt`: datetime (cuándo puede volver a activar por regla semanal)

## 7) Modelo de datos (Prisma) — propuesta

### Rating
- `RaffleRating`
  - `id`
  - `raffleId`
  - `raterUserId`
  - `riferoUserId`
  - `score` (int 1..10)
  - `likedCommentsFeature` (boolean)
  - `createdAt`
  - Unique: `(raffleId, raterUserId)`

### Boost
- `UserBoost`
  - `id`
  - `userId`
  - `startAt`
  - `endAt`
  - `createdAt`

Índices:
- `UserBoost(userId, endAt)`
- (opcional) índice para contar activos por tiempo.

## 8) Controles de Admin
- Superadmin puede:
  - ver lista de calificaciones (si hiciera falta moderación futura)
  - ver boosts activos
  - (opcional) invalidar boost / eliminar rating por fraude (no MVP si no lo piden)

## 9) Preguntas para cerrar antes de implementar
1) ¿Se permite **editar** una calificación (sí/no)? Decisión: **no**.

## 10) Nota de producto (pendiente, relacionada): Crear rifas — mínimo de números por compra

Aunque este documento es de calificaciones/boost, queda definido este criterio para “Crear rifa”:

- El rifero debe poder configurar, al crear la rifa, **desde cuántos números/tickets mínimos** se permite comprar en una sola compra.
  - Ejemplos: mínimo 1 ("1 en adelante"), mínimo 2 ("2 en adelante"), etc.
- Valor por defecto: **1** (si el rifero no configura nada).
- Ese valor es potestad del rifero por rifa y se debe **enforzar en dos lados**:
  - Backend: en el endpoint de compra, rechazar si `quantity < minTicketsPerPurchase`.
  - App/Web: en la UI de compra, no permitir seleccionar menos del mínimo y **preseleccionar automáticamente** el mínimo configurado por el rifero al abrir la compra.

Nombre sugerido del campo (para cuando se implemente): `minTicketsPerPurchase` (int >= 1).

## 11) Estado de implementación (backend)

- Endpoints implementados:
  - `POST /raffles/:id/rating`
  - `GET /users/public/:id/rating-summary`
  - `POST /boosts/activate`
  - `GET /boosts/me`
  - `GET /raffles` prioriza `user.isBoosted` (boost global) en el orden
- Requiere migración Prisma (tablas nuevas): `RaffleRating` y `UserBoost`.
