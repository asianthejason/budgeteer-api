# Dockerfile (at repo root)
FROM node:20-alpine

WORKDIR /app

# 1) Copy package manifests + prisma BEFORE npm ci (postinstall runs prisma generate)
COPY package*.json ./
COPY prisma ./prisma

# 2) Install deps (runs postinstall -> prisma generate successfully)
RUN npm ci

# 3) Copy the rest of the source and build
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

ENV NODE_ENV=production
EXPOSE 4000

# Run DB migrations and start the server
CMD ["npm", "run", "start:prod"]
