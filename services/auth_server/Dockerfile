FROM python:3.11-slim
RUN pip install --no-cache-dir flask
WORKDIR /app
COPY app.py .
ENV LOG_PATH=/logs/auth.log
ENV SERVICE_PORT=22
EXPOSE 22
CMD ["python", "app.py"]
