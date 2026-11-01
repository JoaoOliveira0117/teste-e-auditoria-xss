# Node 22: inclui o módulo nativo `node:sqlite` (sem dependência nativa para compilar).
FROM node:22-bookworm-slim

WORKDIR /app

# Instala apenas as dependências de produção (express + ejs, JavaScript puro).
COPY package.json ./
RUN npm install --omit=dev

# Copia o código da aplicação.
COPY . .

# Diretório de dados (banco SQLite). Montado como volume no docker-compose.
RUN mkdir -p /app/data

EXPOSE 3000

# --experimental-sqlite habilita o módulo node:sqlite (emite um aviso, é esperado).
CMD ["node", "--experimental-sqlite", "server.js"]
