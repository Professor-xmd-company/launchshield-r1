FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080 LAUNCHSHIELD_DATA_DIR=/data/launchshield
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home appuser && mkdir -p /data/launchshield && chown -R appuser:appuser /data
COPY --chown=appuser:appuser app.py ./
COPY --chown=appuser:appuser shield ./shield
COPY --chown=appuser:appuser static ./static
USER appuser
EXPOSE 8080
CMD ["sh", "-c", "exec uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1 --proxy-headers --forwarded-allow-ips 127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"]
