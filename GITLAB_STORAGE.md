# Using GitLab as File Storage for apkX 📦

This guide explains how to use your GitLab repository as storage for uploaded APK files and analysis reports instead of local storage.

## Why Use GitLab as Storage? 🤔

**Benefits:**
- ✅ **Version Control** - All files are tracked with full history
- ✅ **Backup** - Files are safely stored in GitLab's infrastructure
- ✅ **Collaboration** - Team members can access files from anywhere
- ✅ **Free Storage** - GitLab offers 5GB+ free storage per project
- ✅ **Access Control** - Use GitLab's permission system
- ✅ **No Local Storage** - Save disk space on your server

**Considerations:**
- ⚠️ GitLab API rate limits (400 requests/minute for authenticated users)
- ⚠️ File size limit: 100MB per file (can be increased in self-hosted GitLab)
- ⚠️ Best for moderate usage (not high-volume production)

## Setup Instructions 🚀

### Step 1: Create GitLab Personal Access Token

1. Go to GitLab → Settings → Access Tokens
2. Click "Add new token"
3. Name: `apkX Storage`
4. Scopes: Select `api` (full API access)
5. Click "Create personal access token"
6. **Copy the token** - you'll need it later

### Step 2: Build the Sync Tool

```bash
# Build the sync tool
cd /home/sallam/apkX
go build -o sync-to-gitlab cmd/sync-to-gitlab/main.go
```

### Step 3: Sync Existing Files to GitLab

```bash
# Set your GitLab token (replace with your actual token)
export GITLAB_TOKEN="your-gitlab-token-here"

# Dry run first to see what will be uploaded
./sync-to-gitlab -project "e9101230/apkx" -dry-run

# Actually sync the files
./sync-to-gitlab -project "e9101230/apkx"

# Or specify token directly (less secure)
./sync-to-gitlab -project "e9101230/apkx" -token "your-token"

# Sync specific directory
./sync-to-gitlab -project "e9101230/apkx" -dir "web-data/uploads" -remote "uploads"
```

### Step 4: Configure Environment Variables

```bash
# Add to your shell profile (~/.bashrc or ~/.zshrc)
export GITLAB_TOKEN="your-gitlab-token-here"
export GITLAB_PROJECT="e9101230/apkx"
export USE_GITLAB_STORAGE="true"
```

## Usage Examples 📖

### Sync All Web Data

```bash
# Sync everything in web-data/
./sync-to-gitlab -project "e9101230/apkx" -dir "web-data" -remote "web-data"
```

### Sync Only Uploads

```bash
# Sync only uploaded files
./sync-to-gitlab -project "e9101230/apkx" -dir "web-data/uploads" -remote "web-data/uploads"
```

### Sync Only Reports

```bash
# Sync only analysis reports
./sync-to-gitlab -project "e9101230/apkx" -dir "web-data/reports" -remote "web-data/reports"
```

### Automated Sync with Cron

```bash
# Edit crontab
crontab -e

# Add this line to sync every hour
0 * * * * cd /home/sallam/apkX && ./sync-to-gitlab -project "e9101230/apkx" >> /tmp/gitlab-sync.log 2>&1

# Or sync every 6 hours
0 */6 * * * cd /home/sallam/apkX && ./sync-to-gitlab -project "e9101230/apkx" >> /tmp/gitlab-sync.log 2>&1
```

## Accessing Files from GitLab 🌐

### View Files in Browser

Your files will be stored in a separate `storage` branch:

```
https://gitlab.com/e9101230/apkx/-/tree/storage/web-data
```

### Download a File

```bash
# Using GitLab API
curl --header "PRIVATE-TOKEN: your-token" \
  "https://gitlab.com/api/v4/projects/e9101230%2Fapkx/repository/files/web-data%2Fuploads%2Ftest.apk/raw?ref=storage" \
  -o test.apk
```

### List Files

```bash
# List all files in uploads directory
curl --header "PRIVATE-TOKEN: your-token" \
  "https://gitlab.com/api/v4/projects/e9101230%2Fapkx/repository/tree?ref=storage&path=web-data/uploads"
```

## Storage Branch Structure 📁

The storage branch will have this structure:

```
storage (branch)
└── web-data/
    ├── uploads/
    │   ├── test.apk
    │   ├── app.apk
    │   └── DamnVulnerableiOSApp.ipa
    ├── reports/
    │   ├── 20251004-001512/
    │   │   ├── results.json
    │   │   ├── security-report.html
    │   │   └── AndroidManifest.xml
    │   └── 20251004-012709/
    │       └── ...
    └── downloads/
        └── ...
```

## Best Practices 💡

### 1. Use Separate Branch for Storage

The sync tool automatically uses a `storage` branch to keep your code and files separate:
- **main branch**: Code only
- **storage branch**: Files only

### 2. Selective Sync

Don't sync everything - only sync what you need:

```bash
# Good: Sync only important files
./sync-to-gitlab -project "e9101230/apkx" -dir "web-data/reports"

# Avoid: Syncing very large or temporary files
# Skip cache directories and temporary files
```

### 3. Regular Cleanup

Periodically delete old reports and files:

```bash
# Delete files from GitLab using API
curl --request DELETE \
  --header "PRIVATE-TOKEN: your-token" \
  --header "Content-Type: application/json" \
  --data '{"branch": "storage", "commit_message": "Delete old file"}' \
  "https://gitlab.com/api/v4/projects/e9101230%2Fapkx/repository/files/web-data%2Fuploads%2Fold-file.apk"
```

### 4. Monitor Storage Usage

Check your GitLab project storage:
- Go to GitLab → Project → Settings → Usage Quotas
- Monitor storage to stay within limits

## Troubleshooting 🔧

### Error: "401 Unauthorized"

**Problem**: Invalid or expired token

**Solution**:
```bash
# Create a new personal access token
# Make sure it has 'api' scope
export GITLAB_TOKEN="new-token-here"
```

### Error: "404 Not Found"

**Problem**: Project ID is incorrect

**Solution**:
```bash
# Use the correct format: "namespace/project"
# or numeric ID from project settings
./sync-to-gitlab -project "e9101230/apkx"
```

### Error: "413 Payload Too Large"

**Problem**: File exceeds GitLab's size limit (default 100MB)

**Solution**:
```bash
# Skip large files
# Or use Git LFS for large files (see next section)
```

### Slow Upload Speed

**Problem**: Large files or slow connection

**Solution**:
- Upload in batches
- Use during off-peak hours
- Consider using Git LFS for very large files

## Advanced: Using Git LFS 📦

For files larger than 100MB, use Git LFS:

### Install Git LFS

```bash
# Install Git LFS (requires sudo)
curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash
sudo apt-get install git-lfs

# Initialize Git LFS
git lfs install
```

### Setup Git LFS for Large Files

```bash
# Track APK and IPA files with LFS
git lfs track "*.apk"
git lfs track "*.ipa"
git lfs track "*.xapk"

# Add .gitattributes
git add .gitattributes

# Clone the storage branch
git clone -b storage git@gitlab.com:e9101230/apkx.git apkx-storage
cd apkx-storage

# Copy files
cp -r /home/sallam/apkX/web-data/* ./web-data/

# Commit and push
git add .
git commit -m "Add files with LFS"
git push origin storage
```

## Hybrid Approach: Local + GitLab Backup 🔄

Use local storage for speed, with periodic GitLab backups:

### Setup Automated Backup Script

```bash
#!/bin/bash
# /home/sallam/apkX/backup-to-gitlab.sh

set -e

cd /home/sallam/apkX

# Sync to GitLab
echo "Starting backup to GitLab..."
./sync-to-gitlab -project "e9101230/apkx" -dir "web-data/reports"

# Keep only last 30 days locally
find web-data/reports/ -type d -mtime +30 -exec rm -rf {} \; 2>/dev/null || true

echo "Backup completed: $(date)"
```

Make it executable and add to cron:

```bash
chmod +x backup-to-gitlab.sh

# Run daily at 2 AM
echo "0 2 * * * /home/sallam/apkX/backup-to-gitlab.sh >> /tmp/gitlab-backup.log 2>&1" | crontab -
```

## Security Considerations 🔒

### Protect Your Token

```bash
# Never commit tokens to git
echo ".env" >> .gitignore

# Store token in .env file
echo "GITLAB_TOKEN=your-token-here" > .env
chmod 600 .env

# Load in scripts
source .env
./sync-to-gitlab -project "e9101230/apkx"
```

### Use Project Access Tokens

For production, use Project Access Tokens instead of Personal Access Tokens:
1. Go to Project → Settings → Access Tokens
2. Create token with limited scope
3. Set expiration date

## Cost Analysis 💰

### GitLab Free Tier
- **Storage**: 5GB free
- **Transfer**: Unlimited
- **API Calls**: 400/minute

### Estimated Storage Usage
- **APK File**: ~50-100MB average
- **Report**: ~1-5MB per analysis
- **Total**: Depends on usage

**Example**: 
- 50 APKs × 75MB = 3.75GB
- 100 reports × 2MB = 200MB
- **Total**: ~4GB (within free tier)

## Next Steps 🎯

1. ✅ Create GitLab personal access token
2. ✅ Build sync tool: `go build -o sync-to-gitlab cmd/sync-to-gitlab/main.go`
3. ✅ Test with dry run: `./sync-to-gitlab -project "e9101230/apkx" -dry-run`
4. ✅ Sync files: `./sync-to-gitlab -project "e9101230/apkx"`
5. ✅ Setup automated backups (optional)
6. ✅ Monitor storage usage

## Support 🤝

For issues or questions:
- Check GitLab API documentation
- Review sync logs
- Open an issue in the project

---

🔧 **Maintained by [h0tak88r](https://gitlab.com/h0tak88r)**  
📖 **More Info**: See [GITLAB.md](GITLAB.md) for GitLab CI/CD setup

