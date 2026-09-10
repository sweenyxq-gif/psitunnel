FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default ports: 9001 (OBFS), 9002 (TLS), 9003 (WS) or 7860 for HuggingFace Spaces
EXPOSE 9001 9002 9003 7860

ENV WS_PORT=9003

CMD ["python", "cli.py", "server", "--host", "0.0.0.0"]
