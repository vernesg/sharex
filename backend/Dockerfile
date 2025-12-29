# backend/Dockerfile
# Multi-stage build for Node TypeScript backend

# ---------- Build stage ----------
FROM node:20-alpine AS builder
WORKDIR /app

# Install utilities required for some native deps (if needed)
RUN apk add --no-cache python3 make g++ git

# Copy package files and install ALL deps for build (dev + prod)
COPY package.json package-lock.json* ./
RUN npm ci

# Copy source and build
COPY . .
RUN npm run build

# ---------- Production stage ----------
FROM node:20-alpine AS runner
WORKDIR /app

# Create non-root user (optional but recommended)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Copy only production dependencies
COPY --chown=appuser:appgroup package.json package-lock.json* ./
RUN npm ci --production

# Copy built files from builder
COPY --chown=appuser:appgroup --from=builder /app/dist ./dist
# If you rely on any runtime files (e.g. data folder) create it
RUN mkdir -p /home/appuser/data
VOLUME ["/home/appuser/data"]

ENV NODE_ENV=production
EXPOSE 4000

# Use node to run the compiled JS entry
CMD ["node", "dist/index.js"]