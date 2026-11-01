/*
 * ============================================================================
 *  MURAL DE RECADOS — VERSÃO CORRIGIDA
 * ============================================================================
 *  Mesma funcionalidade da versão vulnerável (../vulneravel), com as falhas de
 *  XSS Armazenado e Roubo de Sessão mitigadas. Disciplina: Segurança e Auditoria
 *  de Sistemas (Feevale). Dupla: João Oliveira e Mateus Wolke.
 *
 *  MITIGAÇÕES APLICADAS (procure por [FIX] no código):
 *    [FIX-XSS]    Output encoding: autor e conteúdo são renderizados com escape
 *                 de saída (EJS `<%= %>`). O payload aparece como TEXTO, não
 *                 executa. É a correção da causa-raiz do CWE-79.
 *    [FIX-COOKIE] Cookie de sessão com HttpOnly + SameSite=Strict + Secure.
 *                 Mesmo que houvesse XSS, o JavaScript não consegue ler o cookie
 *                 (HttpOnly), e ele não vaza em requisições de outros sites (SameSite).
 *    [FIX-CSP]    Content-Security-Policy restritiva + cabeçalhos de segurança.
 *                 Camada extra: bloqueia script inline e recursos de outras origens.
 *    [FIX-VALID]  Validação de entrada (formato de usuário, tamanho do recado).
 *
 *  Defesa em profundidade: a correção da causa-raiz é o output encoding [FIX-XSS];
 *  CSP e cookie HttpOnly são camadas adicionais que limitam o impacto.
 * ============================================================================
 */
const express = require('express');
const path = require('path');
const db = require('./db');
const { hashPassword, verifyPassword, newSessionId } = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

// No acesso via http://localhost o navegador considera a origem segura, então o
// cookie Secure funciona. Em outros hosts HTTP de teste, defina COOKIE_SECURE=false.
const COOKIE_SECURE = process.env.COOKIE_SECURE !== 'false';

// Regras de validação de entrada [FIX-VALID]
const USERNAME_RE = /^[A-Za-z0-9_.-]{3,30}$/;
const MAX_MSG = 500;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// [FIX-CSP] Cabeçalhos de segurança em todas as respostas.
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'", // sem 'unsafe-inline' => script inline injetado não executa
      "style-src 'self'",
      "img-src 'self'", // bloqueia o <img> que tentaria vazar o cookie para o coletor
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
    ].join('; ')
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

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
  res.render('mural', { user: req.user, messages, erro: null });
});

app.get('/register', (req, res) => {
  if (req.user) return res.redirect('/');
  res.render('register', { erro: null });
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  // [FIX-VALID] formato de usuário e tamanho de senha.
  if (!USERNAME_RE.test(username || '')) {
    return res.status(400).render('register', {
      erro: 'Usuário inválido: use 3 a 30 caracteres (letras, números, . _ -).',
    });
  }
  if (!password || String(password).length < 6 || String(password).length > 200) {
    return res.status(400).render('register', { erro: 'A senha deve ter entre 6 e 200 caracteres.' });
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

  // [FIX-COOKIE] HttpOnly (invisível ao JS) + SameSite=Strict + Secure.
  res.cookie('sid', sid, {
    httpOnly: true,
    sameSite: 'strict',
    secure: COOKIE_SECURE,
    path: '/',
  });

  res.redirect('/');
});

app.post('/mural', (req, res) => {
  if (!req.user) return res.redirect('/login');
  // [FIX-VALID] normaliza e limita o tamanho. O conteúdo é guardado como texto;
  // a neutralização do HTML acontece na SAÍDA (output encoding na view).
  const content = String(req.body.content || '').trim();
  if (!content || content.length > MAX_MSG) {
    const messages = db
      .prepare('SELECT author, content, created_at FROM messages ORDER BY id DESC')
      .all();
    return res.status(400).render('mural', {
      user: req.user,
      messages,
      erro: `O recado deve ter entre 1 e ${MAX_MSG} caracteres.`,
    });
  }
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
  console.log(`[CORRIGIDA] Mural ouvindo na porta ${PORT}`);
});
