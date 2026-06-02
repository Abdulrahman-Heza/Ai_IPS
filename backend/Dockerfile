# Multi-stage build for Node.js Backend

FROM node:18-alpine

WORKDIR /app

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Copy package files
COPY package.json ./

# Install dependencies (both prod and dev)
RUN npm install

# Copy application source code
COPY . .

# Build TypeScript
RUN npx tsc

# Remove devDependencies after build
RUN npm install --production

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app

USER nodejs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:5000/health', (r) => { if (r.statusCode !== 200) throw new Error(r.statusCode) })"

# Expose port
EXPOSE 5000

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start compiled application
CMD ["node", "dist/index.js"]
