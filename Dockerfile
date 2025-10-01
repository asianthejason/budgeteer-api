# Dockerfile
FROM node:20-bookworm-slim

# Install system deps Prisma expects
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests + prisma first so postinstall (prisma generate) can run
COPY package*.json ./
COPY prisma ./prisma

# Install dependencies (will run postinstall -> prisma generate)
RUN npm ci

# Copy the rest & build
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

ENV NODE_ENV=production
EXPOSE 4000

# Run DB migrations then start server
CMD ["sh", "-c", "npx prisma migrate deploy && node dist/index.js"]

