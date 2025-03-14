FROM python:3.11-slim

WORKDIR /app

# Install required system packages
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the honeypot script
COPY ssh_honeypot.py .

# Create a volume for logs
VOLUME ["/app/logs"]

# Expose SSH port
EXPOSE 22

# Run the honeypot
CMD ["python", "ssh_honeypot.py"] 