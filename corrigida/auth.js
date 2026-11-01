/*
 * Utilitários de autenticação. As senhas são guardadas com hash (scrypt + salt),
 * tanto na versão vulnerável quanto na corrigida — o foco do laboratório é XSS e
 * roubo de sessão, não armazenamento de senha. Usa apenas o módulo `crypto` do Node.
 */
const crypto = require('crypto');

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(pw), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(pw, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const calc = crypto.scryptSync(String(pw), salt, 64).toString('hex');
  const a = Buffer.from(calc);
  const b = Buffer.from(hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Identificador de sessão imprevisível (256 bits). O ataque do laboratório
// rouba o cookie — não tenta adivinhá-lo.
function newSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = { hashPassword, verifyPassword, newSessionId };
