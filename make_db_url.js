// make_db_url.js
// Uso: node make_db_url.js <DB_USER> <DB_PASSWORD> <DB_HOST> <DB_PORT> <DB_NAME>
// Ejemplo:
// node make_db_url.js myuser "P@ss:word#1" db.example.com 5432 rifasdb

function encode(s) {
  return encodeURIComponent(s);
}

const args = process.argv.slice(2);
if (args.length < 5) {
  console.error('Uso: node make_db_url.js <DB_USER> <DB_PASSWORD> <DB_HOST> <DB_PORT> <DB_NAME>');
  process.exit(1);
}

const [user, pass, host, port, db] = args;
if (!/^[0-9]+$/.test(port)) {
  console.error('ERROR: el puerto debe ser un número. Puerto recibido:', port);
  process.exit(1);
}

const encodedPass = encode(pass);
const url = `postgresql://${user}:${encodedPass}@${host}:${port}/${db}`;
console.log(url);
