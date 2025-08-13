FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    libpcap-dev \
    tcpdump \
    iptables \
    iproute2 \
    net-tools \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .

# Use environment variable instead of --break-system-packages flag
ENV PIP_BREAK_SYSTEM_PACKAGES=1
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs data

# Set permissions
RUN chmod +x main.py path_monitor/path_monitor.py ddos_defense/ddos_defense.py 2>/dev/null || true

# Set default entry point
ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
