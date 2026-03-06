FROM python:3.11-slim
RUN pip install --no-cache-dir flask
WORKDIR /app
COPY app.py .
ENV LOG_PATH=/logs/db.log
ENV SERVICE_PORT=3306
EXPOSE 3306
CMD ["python", "app.py"]
