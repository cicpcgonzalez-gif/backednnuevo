# Guía de Conexión Frontend-Backend

Esta guía explica cómo conectar tu aplicación frontend (React Native, Expo, React Web) con el backend de MegaRifas.

## 🔗 Configuración Rápida

### 1. URL del Backend

El backend debe estar desplegado y accesible. Puedes obtener la URL de:

**Desarrollo Local:**
```
http://localhost:3000
```

**Producción (Render):**
```
https://tu-app.onrender.com
```

### 2. Verificar que el Backend está funcionando

Antes de conectar el frontend, verificar:

```bash
# Health check
curl https://tu-app.onrender.com/health

# Respuesta esperada:
# {"ok":true,"status":"up","timestamp":1234567890}
```

### 3. Verificar CORS

El backend tiene CORS habilitado por defecto. Si tienes problemas, verifica en `index.js`:

```javascript
app.use(cors()); // Permite todos los orígenes

// Para producción, es mejor especificar:
app.use(cors({
  origin: [
    'http://localhost:19006',  // Expo local
    'https://tu-frontend.vercel.app'  // Tu frontend en producción
  ],
  credentials: true
}));
```

## 📱 Configuración en React Native / Expo

### Paso 1: Crear archivo de configuración

Crear `src/config/api.js` o `config/api.js`:

```javascript
const API_CONFIG = {
  // Cambia esta URL por la de tu backend desplegado
  BASE_URL: __DEV__ 
    ? 'http://localhost:3000'  // Desarrollo
    : 'https://tu-app.onrender.com',  // Producción
  
  TIMEOUT: 30000, // 30 segundos
};

export default API_CONFIG;
```

### Paso 2: Crear servicio API

Crear `src/services/api.js`:

```javascript
import AsyncStorage from '@react-native-async-storage/async-storage';
import API_CONFIG from '../config/api';

class ApiService {
  constructor() {
    this.baseURL = API_CONFIG.BASE_URL;
    this.timeout = API_CONFIG.TIMEOUT;
  }

  async getToken() {
    return await AsyncStorage.getItem('authToken');
  }

  async setToken(token) {
    await AsyncStorage.setItem('authToken', token);
  }

  async clearToken() {
    await AsyncStorage.removeItem('authToken');
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const token = options.skipAuth ? null : await this.getToken();

    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const config = {
      ...options,
      headers,
    };

    if (options.body && typeof options.body === 'object') {
      config.body = JSON.stringify(options.body);
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      const response = await fetch(url, {
        ...config,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || `Error ${response.status}`);
      }

      return data;
    } catch (error) {
      if (error.name === 'AbortError') {
        throw new Error('La petición tardó demasiado');
      }
      throw error;
    }
  }

  // Métodos de autenticación
  async register(email, password, name) {
    return this.request('/register', {
      method: 'POST',
      body: { email, password, name },
      skipAuth: true,
    });
  }

  async login(email, password) {
    const data = await this.request('/login', {
      method: 'POST',
      body: { email, password },
      skipAuth: true,
    });

    if (data.token) {
      await this.setToken(data.token);
    }

    return data;
  }

  async verify(email, code) {
    const data = await this.request('/verify', {
      method: 'POST',
      body: { email, code },
      skipAuth: true,
    });

    if (data.token) {
      await this.setToken(data.token);
    }

    return data;
  }

  async resendCode(email) {
    return this.request('/resend-code', {
      method: 'POST',
      body: { email },
      skipAuth: true,
    });
  }

  async logout() {
    await this.clearToken();
  }

  // Métodos de usuario
  async getMe() {
    return this.request('/me');
  }

  async updateProfile(data) {
    return this.request('/me', {
      method: 'PATCH',
      body: data,
    });
  }

  // Métodos de rifas
  async getRaffles(limit = 20, offset = 0) {
    return this.request(`/raffles?limit=${limit}&offset=${offset}`, {
      skipAuth: true,
    });
  }

  async getRaffle(id) {
    return this.request(`/raffles/${id}`, {
      skipAuth: true,
    });
  }

  async getAvailableNumbers(raffleId, limit = 100) {
    return this.request(`/raffles/${raffleId}/available?limit=${limit}`, {
      skipAuth: true,
    });
  }

  // Métodos de tickets
  async buyTickets(raffleId, numbers) {
    return this.request('/tickets', {
      method: 'POST',
      body: { raffleId, numbers },
    });
  }

  async getMyTickets(limit = 20, offset = 0) {
    return this.request(`/my-tickets?limit=${limit}&offset=${offset}`);
  }

  // Métodos de wallet
  async getWallet() {
    return this.request('/my-wallet');
  }

  async deposit(amount, reference, proof) {
    return this.request('/deposit', {
      method: 'POST',
      body: { amount, reference, proof },
    });
  }

  async withdraw(amount) {
    return this.request('/withdraw', {
      method: 'POST',
      body: { amount },
    });
  }

  async getTransactions(limit = 20, offset = 0) {
    return this.request(`/my-transactions?limit=${limit}&offset=${offset}`);
  }

  // Métodos de anuncios
  async getAnnouncements() {
    return this.request('/announcements', {
      skipAuth: true,
    });
  }

  async reactToAnnouncement(id, type) {
    return this.request(`/announcements/${id}/react`, {
      method: 'POST',
      body: { type },
    });
  }

  // Métodos de referidos
  async getReferrals() {
    return this.request('/me/referrals');
  }

  async applyReferralCode(code) {
    return this.request('/me/referral', {
      method: 'POST',
      body: { code },
    });
  }
}

export default new ApiService();
```

### Paso 3: Usar en componentes

```javascript
import React, { useEffect, useState } from 'react';
import { View, Text, FlatList } from 'react-native';
import api from '../services/api';

export default function RafflesScreen() {
  const [raffles, setRaffles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadRaffles();
  }, []);

  const loadRaffles = async () => {
    try {
      setLoading(true);
      const data = await api.getRaffles(20, 0);
      setRaffles(data.raffles);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <Text>Cargando...</Text>;
  if (error) return <Text>Error: {error}</Text>;

  return (
    <FlatList
      data={raffles}
      keyExtractor={(item) => item.id.toString()}
      renderItem={({ item }) => (
        <View>
          <Text>{item.title}</Text>
          <Text>{item.prize}</Text>
          <Text>${item.ticketPrice}</Text>
        </View>
      )}
    />
  );
}
```

## 🌐 Configuración en React Web

### Paso 1: Crear archivo .env

```bash
# .env.development
REACT_APP_API_URL=http://localhost:3000

# .env.production
REACT_APP_API_URL=https://tu-app.onrender.com
```

### Paso 2: Crear servicio API

```javascript
// src/services/api.js
const API_URL = process.env.REACT_APP_API_URL;

class ApiService {
  async getToken() {
    return localStorage.getItem('authToken');
  }

  async setToken(token) {
    localStorage.setItem('authToken', token);
  }

  async clearToken() {
    localStorage.removeItem('authToken');
  }

  async request(endpoint, options = {}) {
    const url = `${API_URL}${endpoint}`;
    const token = options.skipAuth ? null : await this.getToken();

    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(url, {
      ...options,
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Error en la petición');
    }

    return data;
  }

  // ... mismos métodos que en React Native
}

export default new ApiService();
```

## 🧪 Probar la Conexión

### Test 1: Health Check

```javascript
import api from './services/api';

async function testConnection() {
  try {
    const response = await fetch(api.baseURL + '/health');
    const data = await response.json();
    console.log('Backend conectado:', data);
    return true;
  } catch (error) {
    console.error('Error de conexión:', error);
    return false;
  }
}
```

### Test 2: Registro de Usuario

```javascript
async function testRegister() {
  try {
    const result = await api.register(
      'test@example.com',
      'password123',
      'Test User'
    );
    console.log('Registro exitoso:', result);
  } catch (error) {
    console.error('Error en registro:', error);
  }
}
```

### Test 3: Listar Rifas

```javascript
async function testRaffles() {
  try {
    const data = await api.getRaffles();
    console.log('Rifas:', data);
  } catch (error) {
    console.error('Error al listar rifas:', error);
  }
}
```

## 🐛 Solución de Problemas

### Error: Network request failed

**Causa:** El backend no está accesible.

**Solución:**
1. Verificar que el backend esté corriendo
2. Verificar la URL en la configuración
3. En iOS simulator, usar la IP de tu computadora en lugar de localhost
4. En Android emulator, usar `10.0.2.2` en lugar de localhost

```javascript
// Para desarrollo en dispositivos físicos
const BASE_URL = __DEV__
  ? 'http://192.168.1.100:3000'  // Tu IP local
  : 'https://tu-app.onrender.com';
```

### Error: CORS

**Causa:** CORS no está configurado correctamente.

**Solución:** Verificar que el backend tenga:
```javascript
app.use(cors());
```

### Error: Token inválido

**Causa:** El token expiró o no es válido.

**Solución:** Implementar refresh de token o logout automático:

```javascript
async request(endpoint, options = {}) {
  try {
    return await this._request(endpoint, options);
  } catch (error) {
    if (error.message.includes('Token inválido')) {
      await this.logout();
      // Redirigir a login
    }
    throw error;
  }
}
```

### Error: Timeout

**Causa:** La petición tardó mucho.

**Solución:** Aumentar el timeout o optimizar el backend:

```javascript
const TIMEOUT = 60000; // 60 segundos para operaciones pesadas
```

## 📊 Estado de Conexión

Crear un hook para monitorear el estado:

```javascript
// useConnectionStatus.js
import { useState, useEffect } from 'react';
import api from '../services/api';

export function useConnectionStatus() {
  const [isConnected, setIsConnected] = useState(false);
  const [isChecking, setIsChecking] = useState(true);

  useEffect(() => {
    checkConnection();
    const interval = setInterval(checkConnection, 30000); // Cada 30s
    return () => clearInterval(interval);
  }, []);

  const checkConnection = async () => {
    try {
      await fetch(api.baseURL + '/health');
      setIsConnected(true);
    } catch {
      setIsConnected(false);
    } finally {
      setIsChecking(false);
    }
  };

  return { isConnected, isChecking };
}
```

Usar en componente:

```javascript
function App() {
  const { isConnected, isChecking } = useConnectionStatus();

  if (isChecking) {
    return <Text>Verificando conexión...</Text>;
  }

  if (!isConnected) {
    return <Text>Sin conexión al servidor</Text>;
  }

  return <MainApp />;
}
```

## ✅ Checklist de Integración

- [ ] Backend desplegado y accesible
- [ ] URL del backend configurada en frontend
- [ ] Health check funcionando
- [ ] CORS configurado
- [ ] AsyncStorage/localStorage configurado
- [ ] Servicio API implementado
- [ ] Manejo de errores implementado
- [ ] Manejo de tokens implementado
- [ ] Registro funcionando
- [ ] Login funcionando
- [ ] Listar rifas funcionando
- [ ] Comprar tickets funcionando
- [ ] Wallet funcionando

## 📚 Recursos Adicionales

- [Documentación API completa](API_DOCUMENTATION.md)
- [Guía de despliegue](DEPLOYMENT.md)
- [Configuración de email](EMAIL_SETUP.md)

## 🎉 ¡Listo!

Tu frontend ya está conectado con el backend. Ahora puedes:
- Registrar usuarios
- Autenticar
- Listar y comprar rifas
- Gestionar wallet
- Y más...

Para más detalles sobre endpoints específicos, ver [API_DOCUMENTATION.md](API_DOCUMENTATION.md).
