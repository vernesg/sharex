# frontend/Dockerfile
# Build the Vite React app and serve with nginx

# ---------- Build stage ----------
FROM node:20-alpine AS build
WORKDIR /app

# Install build deps
COPY package.json package-lock.json* ./
RUN npm ci

COPY . .
RUN npm run build

# ---------- Production stage ----------
FROM nginx:stable-alpine AS runner
# Remove default nginx content and copy built site
RUN rm -rf /usr/share/nginx/html/*
COPY --from=build /app/dist /usr/share/nginx/html

# Optional: copy custom nginx.conf if you need rewrites (SPA fallback)
# COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]