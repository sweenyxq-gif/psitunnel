FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default ports: 9001 (OBFS), 9002 (TLS), 9003 (WS), 10000 (Render), 7860 (Spaces)
EXPOSE 9001 9002 9003 10000 7860

ENV PYTHONUNBUFFERED=1

CMD ["sh", "-c", "python cli.py server --host 0.0.0.0 --ws-port ${PORT:-9003} --psk ${PSK:-my-super-secret-key-123}"]
