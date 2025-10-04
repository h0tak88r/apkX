# GitLab Deployment Guide for apkX 🦊

This guide explains how to deploy and use apkX with GitLab Container Registry and GitLab Pages.

## Quick Start with GitLab 🚀

### Prerequisites
- GitLab account with Container Registry access
- Docker installed on your system
- SSH key configured with GitLab (see main README)

### 1. Clone and Setup
```bash
# Clone from GitLab
git clone git@gitlab.com:yourusername/apkX.git
cd apkX

# Make deployment script executable
chmod +x deploy-gitlab.sh
```

### 2. Deploy with GitLab Container Registry
```bash
# Deploy using the latest image from GitLab Container Registry
./deploy-gitlab.sh -i registry.gitlab.com/yourusername/apkX

# Deploy specific version
./deploy-gitlab.sh -i registry.gitlab.com/yourusername/apkX -t v3.3.0

# Deploy on custom port
./deploy-gitlab.sh -i registry.gitlab.com/yourusername/apkX -p 8080
```

### 3. Access the Web Interface
Open your browser and go to `http://localhost:9090` (or your custom port)

## GitLab CI/CD Pipeline 🔄

The project includes a comprehensive GitLab CI/CD pipeline (`.gitlab-ci.yml`) that:

### Build Stage
- Builds Go binaries for both CLI and web server
- Creates artifacts for the next stages

### Test Stage
- Runs Go tests
- Validates code quality

### Package Stage
- Builds Docker images (main and slim versions)
- Pushes to GitLab Container Registry
- Tags images with commit SHA and version tags

### Deploy Stage
- Deploys to GitLab Pages
- Creates a static documentation site
- Includes quick start instructions

## GitLab Container Registry 🐳

### Available Images
- `registry.gitlab.com/yourusername/apkX:latest` - Latest stable build
- `registry.gitlab.com/yourusername/apkX:slim` - Slim version for production
- `registry.gitlab.com/yourusername/apkX:v3.3.0` - Tagged releases
- `registry.gitlab.com/yourusername/apkX:abc123` - Commit-specific builds

### Pull and Run
```bash
# Pull latest image
docker pull registry.gitlab.com/yourusername/apkX:latest

# Run with Docker Compose
docker-compose -f docker-compose-gitlab.yml up -d

# Or run directly
docker run --rm -p 9090:9090 \
  -v $(pwd)/web-data:/web-data \
  -v $(pwd)/config:/config \
  -e APKX_UPLOAD_DIR=/web-data/uploads \
  -e APKX_REPORTS_DIR=/web-data/reports \
  -e APKX_DOWNLOAD_DIR=/web-data/downloads \
  -e APKX_PATTERNS_PATH=/config/regexes.yaml \
  registry.gitlab.com/yourusername/apkX:latest
```

## GitLab Pages 🌐

The pipeline automatically deploys documentation to GitLab Pages:

- **URL**: `https://yourusername.gitlab.io/apkX/`
- **Content**: Quick start guide, documentation, and usage examples
- **Updates**: Automatically updated on every push to main branch

## Environment Variables 🔧

### Required for GitLab Deployment
```bash
# GitLab CI/CD Variables (set in GitLab project settings)
CI_REGISTRY_USER=your-gitlab-username
CI_REGISTRY_PASSWORD=your-gitlab-token
CI_REGISTRY=registry.gitlab.com
CI_REGISTRY_IMAGE=registry.gitlab.com/yourusername/apkX
```

### Application Environment Variables
```bash
# Data directories
APKX_UPLOAD_DIR=/web-data/uploads
APKX_REPORTS_DIR=/web-data/reports
APKX_DOWNLOAD_DIR=/web-data/downloads
APKX_PATTERNS_PATH=/config/regexes.yaml

# Optional
DISCORD_WEBHOOK=https://discord.com/api/webhooks/your-webhook
```

## Security Features 🔒

### Container Security
- Multi-stage Docker builds for smaller images
- Non-root user in containers
- Health checks for container monitoring
- Security scanning with Trivy (optional)

### GitLab Security
- Private container registry
- Access control via GitLab permissions
- CI/CD pipeline security
- Artifact management

## Monitoring and Logs 📊

### Container Logs
```bash
# View logs
docker logs apkx-web

# Follow logs
docker logs -f apkx-web

# View logs with timestamps
docker logs -t apkx-web
```

### Health Checks
```bash
# Check container health
docker inspect apkx-web | grep Health -A 10

# Manual health check
curl http://localhost:9090/health
```

## Troubleshooting 🔧

### Common Issues

#### Container Won't Start
```bash
# Check logs
docker logs apkx-web

# Check if port is in use
netstat -tulpn | grep :9090

# Check Docker daemon
docker info
```

#### Permission Issues
```bash
# Fix data directory permissions
sudo chown -R $USER:$USER web-data/

# Check volume mounts
docker inspect apkx-web | grep Mounts -A 20
```

#### GitLab CI/CD Issues
- Check GitLab CI/CD variables in project settings
- Verify Container Registry access
- Check pipeline logs in GitLab UI

### Getting Help
- Check the main [README.md](README.md) for general usage
- View [DOCKER.md](DOCKER.md) for Docker-specific help
- Check GitLab CI/CD logs for pipeline issues
- Open an issue in the GitLab project

## Advanced Configuration ⚙️

### Custom GitLab Runner
If you want to use your own GitLab Runner:

1. Install GitLab Runner
2. Register with your GitLab instance
3. Configure for Docker executor
4. The pipeline will automatically use your runner

### Custom Registry
To use a different container registry:

1. Update `CI_REGISTRY` variable
2. Update image names in `.gitlab-ci.yml`
3. Update `docker-compose-gitlab.yml`
4. Update deployment scripts

### Scaling
For production deployments:

1. Use GitLab's Auto DevOps
2. Configure Kubernetes deployment
3. Set up monitoring and logging
4. Configure load balancing

## Contributing 🤝

1. Fork the GitLab repository
2. Create a feature branch
3. Make your changes
4. Push to your fork
5. Create a merge request

The CI/CD pipeline will automatically test your changes and build new images.

---

🔧 **Maintained by [h0tak88r](https://gitlab.com/h0tak88r)**  
📖 **Documentation**: [GitLab Pages](https://yourusername.gitlab.io/apkX/)  
🐳 **Container Registry**: [registry.gitlab.com/yourusername/apkX](https://gitlab.com/yourusername/apkX/container_registry)
