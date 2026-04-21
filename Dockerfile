FROM python:3.9-slim

# Install system dependencies for network monitoring
RUN apt-get update && apt-get install -y \
    tcpdump \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user but give network capabilities
RUN useradd -m netshield && \
    chown -R netshield:netshield /app

# Expose port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Run as root for network monitoring capabilities
USER root

CMD ["python", "app.py"]