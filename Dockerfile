# budgeteer-api/Dockerfile

# ---- Build stage: install ALL deps, generate Prisma, compile TS ----
FROM node:20-alpine AS builder
WORKDIR /app

# Prisma on Alpine needs these
RUN apk add --no-cache openssl libc6-compat

# Install deps (uses package-lock.json)
COPY package*.json ./
RUN npm ci

# Generate Prisma client with dev deps available
COPY prisma ./prisma
RUN npx prisma generate

# Copy the rest and build TypeScript
COPY . .
RUN npm run build

# Drop dev deps for runtime
RUN npm prune --omit=dev

# ---- Runtime stage: copy only what's needed ----
FROM node:20-alpine
WORKDIR /app
RUN apk add --no-cache openssl libc6-compat

# Copy production node_modules, built JS, and package files
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json ./

EXPOSE 4000
# Runs `prisma migrate deploy` then starts the server (per your package.json)
CMD ["npm", "run", "start:prod"]
