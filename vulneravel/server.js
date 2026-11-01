/*
 * ============================================================================
 *  MURAL DE RECADOS — VERSÃO VULNERÁVEL  (NÃO USAR EM PRODUÇÃO)
 * ============================================================================
 *  Aplicação propositalmente insegura para o estudo de XSS Armazenado
 *  (Stored Cross-Site Scripting) e Roubo de Sessão.
 *  Disciplina: Segurança e Auditoria de Sistemas (Feevale).
 *  Dupla: João Oliveira e Mateus Wolke.
 *
 *  VULNERABILIDADES PLANTADAS (procure por [VULN] no código):
 *    [VULN-XSS]    O conteúdo e o autor dos recados são renderizados SEM escape
 *                  de saída (EJS `<%- %>`) -> XSS Armazenado (CWE-79).
 *    [VULN-COOKIE] O cookie de sessão é definido SEM os atributos HttpOnly,
 *                  SameSite e Secure -> o JavaScript injetado lê document.cookie
 *                  e envia a sessão ao atacante (CWE-1004 / CWE-614).
 *    [VULN-CSP]    Nenhum cabeçalho Content-Security-Policy é enviado -> scripts
 *                  inline injetados executam livremente (CWE-693).
 *    [VULN-VALID]  Não há validação nem limite de tamanho da entrada.
 *
 *  A versão corrigida (../corrigida) mantém EXATAMENTE a mesma funcionalidade,
 *  com todas essas falhas mitigadas. Compare com `diff -ru vulneravel/ corrigida/`.
 * ============================================================================
 */
const express = require('express');
const path = require('path');
const db = require('./db');
const { hashPassword, verifyPassword, newSessionId } = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// --- Leitura simples de cookies (sem dependência externa) -------------------
function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

// --- Middleware de sessão: identifica o usuário a partir do cookie `sid` -----
app.use((req, res, next) => {
  req.cookies = parseCookies(req);
  req.user = null;
  const sid = req.cookies.sid;
  if (sid) {
    const row = db
      .prepare(
        'SELECT u.id AS id, u.username AS username FROM sessions s ' +
          'JOIN users u ON u.id = s.user_id WHERE s.sid = ?'
      )
      .get(sid);
    if (row) req.user = row;
  }
  next();
});

// --- Rotas ------------------------------------------------------------------
app.get('/', (req, res) => {
  if (!req.user) return res.redirect('/login');
  const messages = db
    .prepare('SELECT author, content, created_at FROM messages ORDER BY id DESC')
    .all();
  res.render('mural', { user: req.user, messages });
});

app.get('/register', (req, res) => {
  if (req.user) return res.redirect('/');
  res.render('register', { erro: null });
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  // [VULN-VALID] validação mínima: só checa se vieram preenchidos.
  if (!username || !password) {
    return res.status(400).render('register', { erro: 'Preencha usuário e senha.' });
  }
  try {
    db.prepare('INSERT INTO users (username, pass_hash) VALUES (?, ?)').run(
      username,
      hashPassword(password)
    );
  } catch (e) {
    return res.status(409).render('register', { erro: 'Usuário já existe.' });
  }
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  if (req.user) return res.redirect('/');
  res.render('login', { erro: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username || '');
  if (!u || !verifyPassword(password || '', u.pass_hash)) {
    return res.status(401).render('login', { erro: 'Credenciais inválidas.' });
  }
  const sid = newSessionId();
  db.prepare('INSERT INTO sessions (sid, user_id) VALUES (?, ?)').run(sid, u.id);

  // [VULN-COOKIE] Cookie de sessão SEM HttpOnly, SEM SameSite e SEM Secure.
  // Resultado: document.cookie fica acessível ao JavaScript injetado (XSS),
  // permitindo o roubo da sessão.
  res.cookie('sid', sid, { path: '/' });

  res.redirect('/');
});

app.post('/mural', (req, res) => {
  if (!req.user) return res.redirect('/login');
  // [VULN-VALID] conteúdo gravado como veio, sem sanitização nem limite.
  const content = req.body.content || '';
  db.prepare('INSERT INTO messages (author, content) VALUES (?, ?)').run(
    req.user.username,
    content
  );
  res.redirect('/');
});

app.get('/perfil', (req, res) => {
  if (!req.user) return res.redirect('/login');
  res.render('perfil', { user: req.user });
});

app.post('/logout', (req, res) => {
  if (req.cookies.sid) {
    db.prepare('DELETE FROM sessions WHERE sid = ?').run(req.cookies.sid);
  }
  res.clearCookie('sid', { path: '/' });
  res.redirect('/login');
});

app.listen(PORT, () => {
  console.log(`[VULNERÁVEL] Mural ouvindo na porta ${PORT}`);
});
