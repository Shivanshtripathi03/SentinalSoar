FROM python:3.11-slim
RUN pip install --no-cache-dir flask
WORKDIR /app
COPY app.py .
ENV LOG_PATH=/logs/web.log
ENV SERVICE_PORT=80
EXPOSE 80
CMD ["python", "app.py"]
