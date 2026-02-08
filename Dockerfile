FROM python:3.11-slim

# Install system deps needed for native Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create directories the app needs
RUN mkdir -p uploads instance

EXPOSE 8080

CMD exec gunicorn "app:create_app('default')" --bind 0.0.0.0:${PORT:-8080} --workers 2 --timeout 120
