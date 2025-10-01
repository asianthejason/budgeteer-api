# budgeteer-api/Dockerfile
FROM node:20-alpine
WORKDIR /app

# Install only what's needed with a deterministic lockfile
COPY package*.json ./
RUN npm ci --omit=dev

# Prisma: generate client at build time
COPY prisma ./prisma
RUN npx prisma generate

# Copy source and build
COPY . .
RUN npm run build

# Expose port & start (runs migrate deploy then start)
EXPOSE 4000
CMD ["npm", "run", "start:prod"]
