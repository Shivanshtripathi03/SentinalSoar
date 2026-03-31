FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sentinelsoar/ ./sentinelsoar/
COPY dashboard/ ./dashboard/
COPY config/ ./config/
COPY data/ ./data/
COPY app.py .
ENV LOG_DIR=/logs
ENV CONFIG_PATH=/app/config/rules.yaml
ENV DATA_DIR=/app/data
# Optional: AI & Notification (set via docker-compose or env)
ENV GEMINI_API_KEY=""
ENV ABUSEIPDB_API_KEY=""
ENV VIRUSTOTAL_API_KEY=""
ENV WEBHOOK_URL=""
EXPOSE 5000
CMD ["python", "app.py"]
