# Trust Layer — Isolated Browser Worker Image
# Non-root user, Chromium sandbox enabled, read-only rootfs compatible

FROM mcr.microsoft.com/playwright:v1.49.0-noble

# Security: Run as unprivileged non-root user
USER pwuser
WORKDIR /home/pwuser/app

# Copy worker application
COPY --chown=pwuser:pwuser package.json ./
COPY --chown=pwuser:pwuser worker/ ./worker/
COPY --chown=pwuser:pwuser core/ ./core/

ENV NODE_ENV=production
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

ENTRYPOINT ["node", "worker/browser_worker.js"]
