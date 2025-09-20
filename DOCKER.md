# apkX Docker Setup

This guide explains how to run apkX using Docker, which is the recommended way to run the application.

## Quick Start

### Option 1: Using the Setup Script (Recommended)

```bash
# Clone the repository
git clone https://github.com/h0tak88r/apkX.git
cd apkX

# Run the setup script
./docker-setup.sh
```

The script will:
- Check for Docker and Docker Compose
- Create necessary directories
- Build the Docker image
- Start the apkX web server
- Verify the installation

### Option 2: Manual Setup

```bash
# Clone the repository
git clone https://github.com/h0tak88r/apkX.git
cd apkX

# Create data directories
mkdir -p web-data/{uploads,reports,downloads}

# Build and start the service
docker-compose up -d

# Check if it's running
curl http://localhost:9090/
```

## What's Included

The Docker image includes all necessary tools:

- **apkX Web Server**: Main application
- **JADX Decompiler**: For APK decompilation
- **apkeep**: For downloading APKs from Google Play
- **ipatool**: For downloading IPAs from App Store
- **apk-mitm**: For MITM proxy patching
- **Java Runtime**: Required for JADX
- **Node.js**: Required for apk-mitm

## Usage

1. **Web Interface**: Open http://localhost:9090 in your browser
2. **Upload Files**: Drag and drop APK/IPA files to analyze
3. **View Reports**: Click on completed analyses to view detailed reports
4. **Download Files**: Access downloaded APKs and generated reports

## Configuration

### Environment Variables

You can customize the setup by modifying `docker-compose.yml`:

```yaml
environment:
  - APKX_ROOT=/app
  - APKX_UPLOAD_DIR=/app/web-data/uploads
  - APKX_REPORTS_DIR=/app/web-data/reports
  - APKX_DOWNLOAD_DIR=/app/web-data/downloads
  - APKX_PATTERNS_PATH=/app/config/regexes.yaml
  - DISCORD_WEBHOOK=your_webhook_url_here  # Optional
```

### Volume Mounts

The setup uses both bind mounts and named volumes:

- **Bind Mount**: `./:/app` - Mounts the entire project directory
- **Named Volumes**: For persistent data storage
  - `apkx-uploads`: Uploaded files
  - `apkx-reports`: Generated reports
  - `apkx-downloads`: Downloaded APKs

## Management Commands

```bash
# View logs
docker-compose logs -f

# Stop the service
docker-compose down

# Restart the service
docker-compose restart

# Update and restart
docker-compose pull
docker-compose up -d

# Rebuild the image
docker-compose build --no-cache
docker-compose up -d

# View container status
docker-compose ps

# Access container shell
docker-compose exec apkx-web bash
```

## Troubleshooting

### Common Issues

1. **Port 9090 already in use**:
   ```bash
   # Change the port in docker-compose.yml
   ports:
     - "8080:9090"  # Use port 8080 instead
   ```

2. **Permission issues**:
   ```bash
   # Fix directory permissions
   sudo chown -R $USER:$USER web-data/
   ```

3. **Container won't start**:
   ```bash
   # Check logs
   docker-compose logs
   
   # Rebuild without cache
   docker-compose build --no-cache
   ```

4. **Out of disk space**:
   ```bash
   # Clean up Docker
   docker system prune -a
   
   # Clean up old reports
   rm -rf web-data/reports/*
   ```

### Health Check

The container includes a health check that verifies the web server is responding:

```bash
# Check container health
docker-compose ps

# Manual health check
curl -f http://localhost:9090/
```

## Advanced Usage

### Custom Configuration

1. **Modify regexes.yaml**: Edit `config/regexes.yaml` to customize pattern matching
2. **Add custom patterns**: Create additional pattern files and mount them
3. **Environment-specific configs**: Use different docker-compose files for different environments

### Development Mode

For development, you can mount the source code and enable live reloading:

```yaml
# docker-compose.dev.yml
version: "3.8"
services:
  apkx-web:
    build:
      context: .
    volumes:
      - .:/app
      - /app/apkx-web  # Exclude binary from mount
    command: ["go", "run", "./cmd/server/main.go", "-addr", ":9090"]
```

## Security Considerations

- The container runs as root by default
- Consider using a non-root user for production
- Review volume mounts for sensitive data
- Use secrets management for API keys and webhooks

## Support

If you encounter issues:

1. Check the logs: `docker-compose logs`
2. Verify Docker and Docker Compose versions
3. Ensure sufficient disk space and memory
4. Check the GitHub issues page for known problems

## Performance Tips

- Use SSD storage for better I/O performance
- Allocate sufficient memory (4GB+ recommended)
- Use named volumes for better performance than bind mounts
- Consider using Docker's build cache for faster rebuilds
