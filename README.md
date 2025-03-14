# SSH Honeypot

A simple SSH honeypot that logs connection attempts and forwards them to Graylog using GELF protocol.

## Features

- Simulates SSH server to capture login attempts
- Logs all connection attempts with details:
  - Source IP and port
  - Username and password attempts
  - Timestamp
  - SSH client version
- Forwards all events to Graylog using GELF protocol
- Local JSON logging for backup
- Docker containerized for easy deployment
- Configurable through environment variables

## Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ssh-honeypot.git
cd ssh-honeypot
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

4. Start the honeypot:
```bash
docker compose up -d
```

## Configuration

The following environment variables can be configured:

- `GRAYLOG_HOST`: Graylog server hostname or IP
- `GRAYLOG_PORT`: Graylog GELF UDP input port (default: 12201)
- `SSH_PORT`: Port to expose the SSH honeypot (default: 2222)

## Graylog Setup

1. Create a new GELF UDP Input in Graylog:
   - System > Inputs
   - Select "GELF UDP"
   - Click "Launch new input"
   - Set port to 12201 (or your custom port)
   - Save

## Logs

Logs are stored in two locations:
- JSON logs: `./logs/connection_attempts.json`
- Graylog: All events are forwarded to your Graylog server

## Security Considerations

- Always run in a controlled environment
- Monitor system resources
- Regularly review logs
- Keep Docker and dependencies updated 