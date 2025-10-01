# budgeteer-api/Dockerfile

# ---- Build stage ----
FROM node:20-alpine AS builder
WORKDIR /app

# Needed by Prisma on Alpine
RUN apk add --no-cache openssl libc6-compat

# Install deps without running postinstall
COPY package*.json ./
RUN npm ci --ignore-scripts

# Now copy prisma and generate client
COPY prisma ./prisma
RUN npx prisma generate

# Copy the rest, then build TS
COPY . .
RUN npm run build

# Prune dev deps for runtime
RUN npm prune --omit=dev

# ---- Runtime stage ----
FROM node:20-alpine
WORKDIR /app
RUN apk add --no-cache openssl libc6-compat

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json ./

EXPOSE 4000
CMD ["npm", "run", "start:prod"]
# Use a single-stage build so Prisma CLI & generator are available at runtime
FROM node:20-alpine

WORKDIR /app

# Install deps (includes dev deps so Prisma CLI exists)
COPY package*.json ./
RUN npm ci

# Copy source + Prisma schema/migrations
COPY tsconfig.json ./
COPY src ./src
COPY prisma ./prisma

# Generate Prisma client and build TS
RUN npx prisma generate
RUN npm run build

# Runtime
ENV NODE_ENV=production
EXPOSE 4000

# Run migrations then start the server
CMD ["npm", "run", "start:prod"]
