const axios = require('axios');
const { performance } = require('perf_hooks');

// Configuration
const BASE_URL = 'http://localhost:3000'; // Adjust if running on a different port or URL
const CONCURRENT_USERS = 50; // Number of simulated users
const REQUESTS_PER_USER = 20; // Requests per user

async function simulateUser(id) {
  const email = `stress_test_${id}_${Date.now()}@example.com`;
  const password = 'password123';
  const name = `Stress User ${id}`;
  
  const results = {
    register: 0,
    login: 0,
    getRaffles: 0,
    errors: 0
  };

  try {
    // 1. Register
    const startReg = performance.now();
    await axios.post(`${BASE_URL}/register`, {
      email,
      password,
      name,
      state: 'Miranda',
      firstName: 'Stress',
      lastName: `User ${id}`
    });
    results.register = performance.now() - startReg;

    // 2. Login
    const startLogin = performance.now();
    const loginRes = await axios.post(`${BASE_URL}/login`, {
      email,
      password
    });
    const token = loginRes.data.token;
    results.login = performance.now() - startLogin;

    // 3. Get Raffles (Multiple times)
    const startRaffles = performance.now();
    for (let i = 0; i < REQUESTS_PER_USER; i++) {
      await axios.get(`${BASE_URL}/raffles`, {
        headers: { Authorization: `Bearer ${token}` }
      });
    }
    results.getRaffles = (performance.now() - startRaffles) / REQUESTS_PER_USER; // Average

  } catch (error) {
    // console.error(`User ${id} failed:`, error.message);
    results.errors++;
  }

  return results;
}

async function runStressTest() {
  console.log(`Starting Stress Test: ${CONCURRENT_USERS} users, ${REQUESTS_PER_USER} requests each.`);
  console.log('------------------------------------------------');

  const promises = [];
  for (let i = 0; i < CONCURRENT_USERS; i++) {
    promises.push(simulateUser(i));
  }

  const startTotal = performance.now();
  const allResults = await Promise.all(promises);
  const endTotal = performance.now();

  // Aggregate Results
  let totalRegisterTime = 0;
  let totalLoginTime = 0;
  let totalRafflesTime = 0;
  let totalErrors = 0;

  allResults.forEach(r => {
    totalRegisterTime += r.register;
    totalLoginTime += r.login;
    totalRafflesTime += r.getRaffles;
    totalErrors += r.errors;
  });

  const avgRegister = totalRegisterTime / CONCURRENT_USERS;
  const avgLogin = totalLoginTime / CONCURRENT_USERS;
  const avgRaffles = totalRafflesTime / CONCURRENT_USERS;
  const totalTimeSec = (endTotal - startTotal) / 1000;
  const totalRequests = CONCURRENT_USERS * (2 + REQUESTS_PER_USER); // Reg + Login + Raffles
  const rps = totalRequests / totalTimeSec;

  console.log('------------------------------------------------');
  console.log('Stress Test Completed');
  console.log(`Total Time: ${totalTimeSec.toFixed(2)} seconds`);
  console.log(`Total Requests: ${totalRequests}`);
  console.log(`Requests Per Second (RPS): ${rps.toFixed(2)}`);
  console.log(`Total Errors: ${totalErrors}`);
  console.log('------------------------------------------------');
  console.log('Average Response Times:');
  console.log(`Register: ${avgRegister.toFixed(2)} ms`);
  console.log(`Login:    ${avgLogin.toFixed(2)} ms`);
  console.log(`Get Raffles: ${avgRaffles.toFixed(2)} ms`);
  console.log('------------------------------------------------');
}

runStressTest();
