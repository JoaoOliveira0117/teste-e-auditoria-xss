# O coletor usa apenas módulos nativos do Node (http, fs, url) — sem dependências.
FROM node:22-bookworm-slim

WORKDIR /app
COPY . .
RUN mkdir -p /app/data

EXPOSE 3009

CMD ["node", "server.js"]
