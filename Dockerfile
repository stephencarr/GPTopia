# Official Node/Python Debian bookworm images; no downloaded shell installers.
# Image digests must be captured/reviewed from the actual Railway build.
FROM node:24-bookworm-slim AS node-deps
WORKDIR /build
COPY mcp_adapter/package.json mcp_adapter/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    NODE_ENV=production NODE_OPTIONS=--max-old-space-size=96 \
    GPTOPIA_MCP_BIND=0.0.0.0 GPTOPIA_DB=/data/world.sqlite3 PORT=8080
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home app && mkdir /data && chown app:app /data
COPY --from=node-deps /usr/local/bin/node /usr/local/bin/node
WORKDIR /app
COPY requirements-production.txt ./
RUN pip install --no-cache-dir -r requirements-production.txt
COPY identity.py kernel.py production.py onboarding.py adapter-contract.json container_entrypoint.py ./
COPY mcp_adapter/server.mjs mcp_adapter/worker.py ./mcp_adapter/
COPY --from=node-deps /build/node_modules ./mcp_adapter/node_modules
USER 10001:10001
EXPOSE 8080
CMD ["/usr/local/bin/python", "-I", "/app/container_entrypoint.py"]
