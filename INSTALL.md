# apkX Installation Guide

**Complete setup guide for fresh VPS/Ubuntu/Debian systems**

## 🚀 Quick Start (Recommended)

### For Fresh VPS/Ubuntu/Debian Systems

If you have a fresh VPS with Ubuntu/Debian and want to get apkX running quickly:

```bash
# 1. Clone the repository
git clone https://github.com/h0tak88r/apkX.git
cd apkX

# 2. Run the automated setup script
chmod +x docker-setup.sh
./docker-setup.sh
```

**That's it!** The script will:
- ✅ Install Docker and Docker Compose if needed
- ✅ Create necessary directories
- ✅ Build the Docker image
- ✅ Start the web server
- ✅ Verify everything is working

---

## 📋 Manual Installation

If you prefer to install manually or the automated script doesn't work:

### Step 1: Install Docker

#### Ubuntu/Debian:
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your user to docker group (optional, for running without sudo)
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

#### CentOS/RHEL:
```bash
# Install Docker
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install -y docker-ce docker-ce-cli containerd.io

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### Step 2: Clone and Setup apkX

```bash
# Clone the repository
git clone https://github.com/h0tak88r/apkX.git
cd apkX

# Create necessary directories
mkdir -p web-data/uploads web-data/reports web-data/downloads
chmod 755 web-data/uploads web-data/reports web-data/downloads

# Build and start
docker-compose build
docker-compose up -d
```

### Step 3: Verify Installation

```bash
# Check if the service is running
curl http://localhost:9090/

# View logs if needed
docker-compose logs -f
```

---

## 🌐 Access the Web Interface

Once installed, open your browser and go to:

- **Local access**: http://localhost:9090
- **Remote access**: http://YOUR_VPS_IP:9090

**Note**: Make sure to open port 9090 in your firewall if accessing remotely.

---

## 🔧 Configuration

### Environment Variables

You can customize apkX by setting environment variables in `docker-compose.yml`:

```yaml
environment:
  - APKX_ROOT=/app
  - APKX_UPLOAD_DIR=/app/web-data/uploads
  - APKX_REPORTS_DIR=/app/web-data/reports
  - APKX_DOWNLOAD_DIR=/app/web-data/downloads
  - APKX_PATTERNS_PATH=/app/config/regexes.yaml
```

### Port Configuration

To change the port, modify `docker-compose.yml`:

```yaml
ports:
  - "8080:9090"  # Change 8080 to your desired port
```

---

## 📁 Data Persistence

All your data is stored in the `web-data/` directory:

- **`web-data/uploads/`** - Uploaded APK/IPA files
- **`web-data/reports/`** - Generated analysis reports
- **`web-data/downloads/`** - Downloaded APK files

**Important**: These directories persist between container restarts.

---

## 🛠️ Management Commands

### Basic Operations

```bash
# Start the service
docker-compose up -d

# Stop the service
docker-compose down

# Restart the service
docker-compose restart

# View logs
docker-compose logs -f

# Update to latest version
git pull
docker-compose build
docker-compose up -d
```

### Troubleshooting

```bash
# Check container status
docker-compose ps

# View detailed logs
docker-compose logs apkx-web

# Access container shell
docker-compose exec apkx-web bash

# Rebuild from scratch
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

---

## 🔒 Security Considerations

### Firewall Setup

```bash
# Ubuntu/Debian (UFW)
sudo ufw allow 9090/tcp
sudo ufw enable

# CentOS/RHEL (firewalld)
sudo firewall-cmd --permanent --add-port=9090/tcp
sudo firewall-cmd --reload
```

### Reverse Proxy (Optional)

For production use, consider using a reverse proxy like Nginx:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

---

## 📊 System Requirements

### Minimum Requirements
- **CPU**: 1 core
- **RAM**: 2GB
- **Storage**: 10GB free space
- **OS**: Ubuntu 18.04+, Debian 10+, CentOS 7+

### Recommended Requirements
- **CPU**: 2+ cores
- **RAM**: 4GB+
- **Storage**: 50GB+ free space
- **OS**: Ubuntu 20.04+, Debian 11+

---

## 🆘 Troubleshooting

### Common Issues

#### 1. Port Already in Use
```bash
# Check what's using port 9090
sudo netstat -tlnp | grep :9090

# Kill the process or change port in docker-compose.yml
```

#### 2. Permission Denied
```bash
# Fix directory permissions
sudo chown -R $USER:$USER web-data/
chmod -R 755 web-data/
```

#### 3. Docker Not Found
```bash
# Install Docker first
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

#### 4. Out of Disk Space
```bash
# Clean up Docker images
docker system prune -a

# Check disk usage
df -h
```

### Getting Help

- **GitHub Issues**: [Report bugs](https://github.com/h0tak88r/apkX/issues)
- **Documentation**: [Full docs](https://github.com/h0tak88r/apkX/blob/main/README.md)
- **Docker Guide**: [DOCKER.md](https://github.com/h0tak88r/apkX/blob/main/DOCKER.md)

---

## 🎉 You're Ready!

Once everything is running, you can:

1. **Upload APK/IPA files** through the web interface
2. **Download APKs** from Google Play using package names
3. **Download iOS apps** from App Store (requires authentication)
4. **View detailed security reports** with vulnerability analysis
5. **Download reports** in JSON or HTML format

**Happy analyzing! 🔍✨**
