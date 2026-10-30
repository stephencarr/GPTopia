FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements-production.txt .
RUN pip install --no-cache-dir -r requirements-production.txt && useradd --uid 10001 --create-home app && mkdir /data && chown app:app /data
COPY identity.py kernel.py production.py ./
USER 10001:10001
EXPOSE 8080
CMD ["sh", "-c", "exec uvicorn production:from_env --factory --host 0.0.0.0 --port ${PORT:-8080} --workers 1 --limit-concurrency 16 --backlog 32 --timeout-keep-alive 2 --no-access-log --no-proxy-headers --no-server-header"]
