# Documentación API para Integración Frontend

Esta guía detalla cómo conectar el frontend con el backend de MegaRifas.

## 🔗 Configuración de Conexión

### URLs Base

**Desarrollo:**
```javascript
const API_URL = 'http://localhost:3000';
```

**Producción (Render):**
```javascript
const API_URL = 'https://tu-app.onrender.com';
```

**Detección Automática:**
```javascript
const API_URL = process.env.NODE_ENV === 'development' 
  ? 'http://localhost:3000' 
  : 'https://tu-backend-production.onrender.com';
```

### Headers Requeridos

Todas las peticiones deben incluir:
```javascript
{
  'Content-Type': 'application/json'
}
```

Para endpoints autenticados, agregar:
```javascript
{
  'Authorization': 'Bearer ' + token
}
```

## 🔐 Autenticación

### 1. Registro de Usuario

```javascript
POST /register
Content-Type: application/json

{
  "email": "usuario@example.com",
  "password": "password123",
  "name": "Nombre Usuario"
}

// Respuesta exitosa (201)
{
  "message": "Usuario creado. Revisa tu correo para el código de verificación",
  "userId": 123
}
```

### 2. Verificar Email

```javascript
POST /verify
Content-Type: application/json

{
  "email": "usuario@example.com",
  "code": "123456"
}

// Respuesta exitosa (200)
{
  "message": "Email verificado correctamente",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 123,
    "email": "usuario@example.com",
    "name": "Nombre Usuario",
    "role": "user",
    "verified": true,
    "balance": 0
  }
}
```

### 3. Login

```javascript
POST /login
Content-Type: application/json

{
  "email": "usuario@example.com",
  "password": "password123"
}

// Respuesta exitosa para usuarios normales (200)
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 123,
    "email": "usuario@example.com",
    "name": "Nombre Usuario",
    "role": "user",
    "balance": 100.50
  }
}

// Para admins, requiere 2FA (202)
{
  "message": "Código 2FA enviado al correo",
  "requires2FA": true,
  "tempToken": "temp_token_here"
}
```

### 4. 2FA (Solo para Admins)

```javascript
POST /auth/2fa
Content-Type: application/json

{
  "email": "admin@example.com",
  "code": "123456"
}

// Respuesta exitosa (200)
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "email": "admin@example.com",
    "role": "admin"
  }
}
```

### 5. Reenviar Código de Verificación

```javascript
POST /resend-code
Content-Type: application/json

{
  "email": "usuario@example.com"
}

// Respuesta exitosa (200)
{
  "message": "Código reenviado"
}
```

## 👤 Gestión de Usuario

### Obtener Mi Perfil

```javascript
GET /me
Authorization: Bearer {token}

// Respuesta (200)
{
  "id": 123,
  "publicId": "uuid-123-456",
  "email": "usuario@example.com",
  "name": "Nombre Usuario",
  "role": "user",
  "balance": 100.50,
  "avatar": "https://...",
  "bio": "Mi bio",
  "verified": true,
  "referralCode": "REF-ABC123",
  "securityId": "SEC-XYZ789"
}
```

### Actualizar Perfil

```javascript
PATCH /me
Authorization: Bearer {token}
Content-Type: application/json

{
  "name": "Nuevo Nombre",
  "avatar": "https://...",
  "bio": "Nueva bio",
  "socials": {
    "instagram": "@usuario",
    "twitter": "@usuario"
  },
  "bankDetails": {
    "bank": "Banco Nacional",
    "account": "01020123456789",
    "type": "corriente",
    "cedula": "V-12345678"
  }
}

// Respuesta (200)
{
  "message": "Perfil actualizado",
  "user": { ... }
}
```

### Obtener Mi Wallet

```javascript
GET /my-wallet
Authorization: Bearer {token}

// Respuesta (200)
{
  "balance": 100.50,
  "transactions": [
    {
      "id": 1,
      "amount": 50,
      "type": "deposit",
      "status": "approved",
      "createdAt": "2024-01-01T00:00:00.000Z"
    }
  ]
}
```

## 🎲 Rifas

### Listar Rifas

```javascript
GET /raffles?limit=20&offset=0

// Respuesta (200)
{
  "raffles": [
    {
      "id": 1,
      "title": "iPhone 15 Pro",
      "prize": "iPhone 15 Pro 256GB",
      "ticketPrice": 5.00,
      "totalTickets": 10000,
      "soldTickets": 4532,
      "lottery": "Zulia",
      "style": {
        "bannerImage": "https://...",
        "themeColor": "#007AFF"
      },
      "createdAt": "2024-01-01T00:00:00.000Z"
    }
  ],
  "pagination": {
    "total": 50,
    "limit": 20,
    "offset": 0
  }
}
```

### Obtener Detalle de Rifa

```javascript
GET /raffles/:id

// Respuesta (200)
{
  "id": 1,
  "title": "iPhone 15 Pro",
  "prize": "iPhone 15 Pro 256GB",
  "terms": "Términos y condiciones...",
  "ticketPrice": 5.00,
  "totalTickets": 10000,
  "soldTickets": 4532,
  "availableTickets": 5468,
  "lottery": "Zulia",
  "style": {
    "bannerImage": "https://...",
    "themeColor": "#007AFF",
    "whatsapp": "+58412345678",
    "instagram": "@megarifas"
  },
  "winners": [
    {
      "id": 1,
      "user": { "name": "Juan Pérez" },
      "prize": "iPhone 15 Pro",
      "drawDate": "2024-01-01T00:00:00.000Z"
    }
  ]
}
```

### Números Disponibles

```javascript
GET /raffles/:id/available?limit=100

// Respuesta (200)
{
  "available": [1, 2, 5, 7, 10, ...],
  "total": 5468
}
```

## 🎟️ Tickets

### Comprar Tickets (Wallet)

```javascript
POST /tickets
Authorization: Bearer {token}
Content-Type: application/json

{
  "raffleId": 1,
  "numbers": [1, 2, 3, 4, 5]
}

// Respuesta exitosa (201)
{
  "message": "Tickets comprados exitosamente",
  "tickets": [
    {
      "id": 1,
      "serialNumber": "uuid-...",
      "number": 1,
      "status": "approved"
    }
  ],
  "newBalance": 75.50
}
```

### Mis Tickets

```javascript
GET /my-tickets?limit=20&offset=0
Authorization: Bearer {token}

// Respuesta (200)
{
  "tickets": [
    {
      "id": 1,
      "serialNumber": "uuid-...",
      "number": 1234,
      "status": "approved",
      "raffle": {
        "id": 1,
        "title": "iPhone 15 Pro",
        "prize": "iPhone 15 Pro 256GB"
      },
      "createdAt": "2024-01-01T00:00:00.000Z"
    }
  ],
  "pagination": {
    "total": 15,
    "limit": 20,
    "offset": 0
  }
}
```

## 💰 Transacciones

### Depositar Fondos

```javascript
POST /deposit
Authorization: Bearer {token}
Content-Type: application/json

{
  "amount": 50,
  "reference": "REF-123456",
  "proof": "data:image/jpeg;base64,..." // Imagen en base64
}

// Respuesta (201)
{
  "message": "Depósito registrado. Pendiente de aprobación",
  "transaction": {
    "id": 1,
    "amount": 50,
    "status": "pending",
    "reference": "REF-123456"
  }
}
```

### Solicitar Retiro

```javascript
POST /withdraw
Authorization: Bearer {token}
Content-Type: application/json

{
  "amount": 25
}

// Respuesta (201)
{
  "message": "Retiro solicitado. Será procesado en 24-48h",
  "transaction": {
    "id": 2,
    "amount": 25,
    "status": "pending",
    "type": "withdrawal"
  }
}
```

### Mis Transacciones

```javascript
GET /my-transactions?limit=20&offset=0
Authorization: Bearer {token}

// Respuesta (200)
[
  {
    "id": 1,
    "amount": 50,
    "type": "deposit",
    "status": "approved",
    "reference": "REF-123456",
    "createdAt": "2024-01-01T00:00:00.000Z"
  }
]
```

## 📢 Anuncios

### Listar Anuncios

```javascript
GET /announcements

// Respuesta (200)
[
  {
    "id": 1,
    "title": "¡Nueva rifa disponible!",
    "content": "Participa en nuestra nueva rifa de iPhone 15 Pro",
    "imageUrl": "https://...",
    "admin": {
      "name": "Admin",
      "avatar": "https://...",
      "role": "admin"
    },
    "_count": {
      "reactions": 45
    },
    "createdAt": "2024-01-01T00:00:00.000Z"
  }
]
```

### Reaccionar a Anuncio

```javascript
POST /announcements/:id/react
Authorization: Bearer {token}
Content-Type: application/json

{
  "type": "LIKE" // o "HEART", "DISLIKE"
}

// Respuesta (200)
{
  "message": "Reacción registrada"
}
```

## 🎁 Referidos

### Mi Código de Referido

```javascript
GET /me/referrals
Authorization: Bearer {token}

// Respuesta (200)
{
  "code": "REF-ABC123",
  "referrals": [
    {
      "id": 456,
      "name": "Usuario Referido",
      "createdAt": "2024-01-01T00:00:00.000Z"
    }
  ]
}
```

### Aplicar Código de Referido

```javascript
POST /me/referral
Authorization: Bearer {token}
Content-Type: application/json

{
  "code": "REF-ABC123"
}

// Respuesta (200)
{
  "message": "Referido registrado"
}
```

## 👥 Perfiles Públicos

```javascript
GET /users/public/:publicId

// Respuesta (200)
{
  "publicId": "uuid-...",
  "name": "Usuario",
  "avatar": "https://...",
  "bio": "Mi bio",
  "socials": { ... },
  "verified": true,
  "role": "user",
  "_count": {
    "tickets": 50,
    "announcements": 0
  }
}
```

## 🏥 Health Check

```javascript
GET /health

// Respuesta (200)
{
  "ok": true,
  "status": "up",
  "timestamp": 1234567890
}
```

## 🔴 Manejo de Errores

Todos los errores devuelven formato consistente:

```javascript
{
  "error": "Mensaje descriptivo del error"
}
```

### Códigos de Estado HTTP

- `200` - Éxito
- `201` - Creado exitosamente
- `400` - Petición inválida
- `401` - No autenticado (token faltante/inválido)
- `403` - No autorizado (permisos insuficientes)
- `404` - Recurso no encontrado
- `429` - Demasiadas peticiones (rate limit)
- `500` - Error interno del servidor

## 📱 Ejemplo de Implementación en React Native

```javascript
// api.js
import AsyncStorage from '@react-native-async-storage/async-storage';

const API_URL = 'https://tu-backend.onrender.com';

export const api = {
  async request(endpoint, options = {}) {
    const token = await AsyncStorage.getItem('token');
    
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };
    
    if (token && !options.skipAuth) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    
    const response = await fetch(`${API_URL}${endpoint}`, {
      ...options,
      headers,
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Error en la petición');
    }
    
    return data;
  },
  
  // Autenticación
  register: (email, password, name) => 
    api.request('/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, name }),
      skipAuth: true,
    }),
  
  login: (email, password) =>
    api.request('/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
      skipAuth: true,
    }),
  
  verify: (email, code) =>
    api.request('/verify', {
      method: 'POST',
      body: JSON.stringify({ email, code }),
      skipAuth: true,
    }),
  
  // Perfil
  getMe: () => api.request('/me'),
  
  updateProfile: (data) =>
    api.request('/me', {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  
  // Rifas
  getRaffles: (limit = 20, offset = 0) =>
    api.request(`/raffles?limit=${limit}&offset=${offset}`, { skipAuth: true }),
  
  getRaffle: (id) =>
    api.request(`/raffles/${id}`, { skipAuth: true }),
  
  // Tickets
  buyTickets: (raffleId, numbers) =>
    api.request('/tickets', {
      method: 'POST',
      body: JSON.stringify({ raffleId, numbers }),
    }),
  
  getMyTickets: (limit = 20, offset = 0) =>
    api.request(`/my-tickets?limit=${limit}&offset=${offset}`),
  
  // Wallet
  getWallet: () => api.request('/my-wallet'),
  
  deposit: (amount, reference, proof) =>
    api.request('/deposit', {
      method: 'POST',
      body: JSON.stringify({ amount, reference, proof }),
    }),
};
```

## 🚀 Notas de Producción

1. **Rate Limiting**: Máximo 100 peticiones por minuto por IP
2. **Login Rate Limit**: Máximo 5 intentos de login por 15 minutos
3. **Paginación**: Por defecto 50 items, máximo 100
4. **CORS**: Habilitado para todas las origins (configurar en producción)
5. **Seguridad**: Todos los passwords hasheados con bcrypt
6. **Tokens JWT**: Incluir en header Authorization como Bearer token

## 📞 Soporte

Para dudas o problemas de integración, contactar al equipo de desarrollo.
