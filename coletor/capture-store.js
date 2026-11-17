const fs = require('fs');
const path = require('path');

const LOG_PATH = process.env.LOG_PATH || path.join(__dirname, 'data', 'cookies.log');
fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });

// Carrega capturas anteriores (persistência entre reinícios do container).
const captured = [];
try {
  const prev = fs.readFileSync(LOG_PATH, 'utf8').trim();
  if (prev) for (const line of prev.split('\n')) captured.push(JSON.parse(line));
} catch (_) {
  /* arquivo ainda não existe */
}

function addCapture(entry) {
  captured.push(entry);
  fs.appendFileSync(LOG_PATH, JSON.stringify(entry) + '\n');
}

function getCaptures() {
  return captured;
}

module.exports = { addCapture, getCaptures };
