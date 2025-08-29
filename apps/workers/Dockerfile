# --- Builder ---
FROM node:20-bullseye AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY tsconfig.json ./
COPY . ./
RUN npm run build

# --- Runtime ---
FROM gcr.io/distroless/nodejs20-debian12
WORKDIR /app
ENV NODE_ENV=production
# Prefer IPv4 during validation to avoid AAAA connect stalls
ENV NODE_OPTIONS=--dns-result-order=ipv4first
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./
EXPOSE 8080
CMD ["dist/server.js"]