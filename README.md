# Graypot

A ready-to-deploy SSH honeypot with seamless Graylog integration. Capture and analyze SSH attacks with minimal setup effort.

## Quick Start
```bash
git clone https://github.com/yourusername/graypot.git
cd graypot
cp example.env .env
# Edit .env with your Graylog server details
docker compose up -d
```
That's it! Your SSH honeypot is now running and sending logs to Graylog.

## Features

- **Zero-Configuration Deployment**: Running in minutes with just Docker
- **Seamless Graylog Integration**: Native GELF protocol support for rich log analysis
- **Comprehensive Attack Logging**:
  - Source IP and port
  - Username and password attempts
  - Timestamp
  - SSH client version
- **Reliable Data Collection**:
  - Real-time forwarding to Graylog
  - Local JSON backup logging
  - Structured data format for easy analysis
- **Docker-Based**: Simple deployment and isolation
- **Environment-Based Configuration**: Easy to customize and maintain

## Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/graypot.git
cd graypot
```

2. Copy the example environment file:
```bash
cp example.env .env
```

3. Edit the `.env` file with your configuration:
```bash
GRAYLOG_HOST=your-graylog-server
GRAYLOG_PORT=12201
SSH_PORT=2222
```

4. Start Graypot:
```bash
docker compose up -d
```

## Configuration

Simple environment variable configuration:

- `GRAYLOG_HOST`: Your Graylog server hostname or IP
- `GRAYLOG_PORT`: Graylog GELF UDP input port (default: 12201)
- `SSH_PORT`: Port to expose the honeypot (default: 2222)

## Graylog Setup

1. Create a new GELF UDP Input in Graylog:
   - System > Inputs
   - Select "GELF UDP"
   - Click "Launch new input"
   - Set port to 12201 (or your custom port)
   - Save

You'll immediately start receiving structured data from your honeypot.

## Logs

Graypot maintains logs in two locations:
- **Graylog**: Primary logging destination with full search and analysis capabilities
- **Local JSON**: Backup logs at `./logs/connection_attempts.json`

## Security Considerations

- Deploy in a controlled environment
- Regular monitoring of system resources
- Periodic log review
- Keep Docker and dependencies updated

## Why Graypot?

Graypot combines the simplicity of a Docker-based honeypot with the power of Graylog's analysis capabilities. It's designed for:
- Security researchers collecting attack data
- System administrators monitoring SSH attack patterns
- Organizations wanting to understand their SSH threat landscape

Perfect for both quick deployments and long-term monitoring solutions. 