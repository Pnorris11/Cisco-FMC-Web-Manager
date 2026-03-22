# FMC FQDN Manager - Docker Web Application

A containerized web application for managing objects across multiple Cisco FMC (Firepower Management Center) systems.

## Features

- **Web Interface**: User-friendly web interface for FQDN management
- **Multi-FMC Support**: Simultaneously manage FQDNs across multiple FMC systems
- **Real-time Progress**: Live status updates with detailed progress tracking
- **Containerized**: Easy deployment with Docker and Docker Compose
- **Configuration Management**: Environment-based configuration with .env file
- **Background Processing**: Non-blocking FQDN processing with job status tracking

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Access to your Cisco FMC systems
- Network connectivity to your FMC instances

### 1. Configure Environment

Make sure your `.env` file is properly configured with your FMC credentials:

```bash
# Global Configuration
DOMAIN_UUID=**********************************

# FMC Instances
FMC_NAME=FMC 
FMC_URL=https://your-fmc.domain.com
FMC_USERNAME=your_username
FMC_PASSWORD=your_password

# ... repeat for FRA, DFW, JFK instances
```

### 2. Build and Run with Docker Compose

```bash
# Build and start the container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

### 3. Access the Web Interface

Open your browser and navigate to:
- **Local**: http://localhost:5000
- **Network**: http://your-server-ip:5000

## Manual Docker Commands

If you prefer to use Docker directly:

```bash
# Build the image
docker build -t fmc-web .

# Run the container
docker run -d \
  --name fmc-web \
  --env-file .env \
  -p 5000:5000 \
  fmc-web

# View logs
docker logs -f fmc-web

# Stop and remove
docker stop fmc-web
docker rm fmc-web
```

## Web Interface Usage

### 1. Home Page
- Enter an FQDN (e.g., `example.com`) or IP in the input field
- Click "Process" to start the job
- You'll be redirected to the status page

### 2. Status Page
- View real-time progress across all FMC systems
- See detailed steps for each FMC instance
- Monitor success/failure status for each system
- Auto-refreshes every 5 seconds during processing

### 3. Objects Page
- Create and manage objects
- Add objects to network groups
- Delete objects and manage group memberships

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DOMAIN_UUID` | FMC Domain UUID | `****************************` |
| `NETWORK_GROUP_NAME` | Target network group name | `Emp_Permits` |
| `FLASK_DEBUG` | Enable Flask debug mode | `false` |
| `FLASK_SECRET_KEY` | Flask session secret key | `your-secret-key-change-this` |
| `PORT` | Application port | `5000` |

### FMC Instance Configuration

For each FMC instance (BRU, FRA, DFW, JFK), set:
- `FMC_{INSTANCE}_NAME`: Display name
- `FMC_{INSTANCE}_URL`: FMC management URL
- `FMC_{INSTANCE}_USERNAME`: API username
- `FMC_{INSTANCE}_PASSWORD`: API password

## Process Flow

The application performs the following steps for each FMC:

1. **Authentication**: Connect to FMC using provided credentials
2. **FQDN Creation**: Create FQDN object with the specified domain
3. **Network Group**: Add FQDN to the configured network group
4. **Deployment**: Deploy changes to managed devices

## Security Considerations

- **Credentials**: Never commit `.env` files to version control
- **Network**: Run behind a reverse proxy for production use
- **Access**: Consider implementing authentication for production deployments
- **SSL**: Use HTTPS in production environments

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify FMC credentials in `.env` file
   - Check network connectivity to FMC systems
   - Ensure API access is enabled on FMC

2. **Permission Errors**
   - Verify user has appropriate FMC permissions
   - Check domain UUID matches your FMC domain
   - Ensure network group exists on target FMC

3. **Container Issues**
   - Check Docker logs: `docker-compose logs`
   - Verify `.env` file exists and is readable
   - Ensure ports aren't already in use

### Health Check

The application includes a health check endpoint at `/health` that returns the application status.

## Development

### Running Locally (without Docker)

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export FLASK_DEBUG=true

# Run the application
python app.py
```

### Command Line Usage

The original CLI functionality is still available:

```bash
python fmc_push.py
```

## License

This project is provided as-is for educational and operational purposes.
