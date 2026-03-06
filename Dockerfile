FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY siem/ ./siem/
COPY dashboard/ ./dashboard/
COPY app.py .
ENV LOG_DIR=/logs
ENV CONFIG_PATH=/app/config/rules.yaml
ENV DATA_DIR=/app/data
EXPOSE 5000
CMD ["python", "app.py"]
