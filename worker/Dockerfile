# Trust Layer — Isolated Browser Worker Image
# Non-root user, Chromium sandbox enabled, read-only rootfs compatible

FROM mcr.microsoft.com/playwright:v1.64.1-noble

# Security: Run as unprivileged non-root user
USER pwuser
WORKDIR /home/pwuser/app

# Install the exact Playwright release bundled with this image's Chromium.
COPY --chown=pwuser:pwuser worker/package.json ./worker/package.json
COPY --chown=pwuser:pwuser worker/package-lock.json ./worker/package-lock.json
RUN npm ci --prefix ./worker --omit=dev --ignore-scripts --no-audit --no-fund

# Copy worker application
COPY --chown=pwuser:pwuser worker/ ./worker/
COPY --chown=pwuser:pwuser core/ ./core/

ENV NODE_ENV=production
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

ENTRYPOINT ["node", "worker/browser_worker.js"]
