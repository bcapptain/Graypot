# Graypot

A ready-to-deploy SSH honeypot with seamless Graylog integration. Capture and analyze SSH attacks with minimal setup effort.

![Graylog Dashboard](Screenshots/GraylogDashboard.png)
*Thats just an example Dashboard you can build with the data from Graypot - This dashboard can be imported using the provided Content Pack - see [Graylog Content Pack](#graylog-content-pack) section.*

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
cp example.env.dist .env
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

## Screenshots

### Graylog Dashboard
![Graylog Dashboard](Screenshots/GraylogDashboard.png)
*Example dashboard showing attack statistics, geographic distribution of attackers, and common usernames used in SSH login attempts. This dashboard can be imported using the provided Content Pack - see [Graylog Content Pack](#graylog-content-pack) section.*

### Search Results
![Search Interface](Screenshots/GraylogSearch.png)
*Detailed view of individual SSH login attempts with full metadata including source IPs, usernames, and client details. Configure your field names as described in the [Graylog Content Pack](#graylog-content-pack) section for optimal visualization.*

## Why Graypot?

Graypot combines the simplicity of a Docker-based honeypot with the power of Graylog's analysis capabilities. It's designed for:
- Security researchers collecting attack data
- System administrators monitoring SSH attack patterns
- Organizations wanting to understand their SSH threat landscape

Perfect for both quick deployments and long-term monitoring solutions.

## Graylog Content Pack

A Graylog Content Pack is provided to help visualize the honeypot data. The pack includes:
- Preconfigured dashboard
- Stream configuration
- Search queries

### Field Name Requirements

To use the Content Pack, your Graylog Geo IP Location field names must match:
- `source_ip_country_code`
- `source_ip_city_name`
- `source_ip_geolocation`

If your Graylog instance uses different field names, you'll need to either:
- Rename your fields to match these names, or
- Manually adjust the field names in the Dashboard widgets 