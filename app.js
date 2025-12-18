// Passenger/cPanel default entrypoint for Node apps.
// Keep this file tiny, but log early using only built-in modules.

const fs = require('fs');
const path = require('path');

function safeAppend(fileName, message) {
	try {
		const dir = path.join(__dirname, 'tmp');
		try {
			fs.mkdirSync(dir, { recursive: true });
		} catch (_e) {
			// ignore
		}
		const file = path.join(dir, fileName);
		fs.appendFileSync(file, `${new Date().toISOString()} ${message}\n`);
	} catch (_e) {
		// ignore
	}
}

safeAppend(
	'passenger_boot.log',
	`BOOT pid=${process.pid} node=${process.version} cwd=${process.cwd()} env.PORT=${process.env.PORT || ''} NODE_ENV=${process.env.NODE_ENV || ''}`
);

try {
	require('./index');
	safeAppend('passenger_boot.log', 'REQUIRE index.js OK');
} catch (err) {
	safeAppend('passenger_boot.log', `REQUIRE index.js FAILED: ${(err && (err.stack || err.message)) || String(err)}`);
	throw err;
}
