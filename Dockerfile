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
