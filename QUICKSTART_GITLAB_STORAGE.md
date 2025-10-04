# Quick Start: Using GitLab as File Storage 🚀

## TL;DR - 3 Simple Steps

### 1️⃣ Create GitLab Token
Go to: https://gitlab.com/-/profile/personal_access_tokens
- Name: `apkX Storage`
- Scope: Check `api`
- Click "Create personal access token"
- **Copy the token!**

### 2️⃣ Run Setup Script
```bash
cd /home/sallam/apkX

# Set your token
export GITLAB_TOKEN="glpat-your-token-here"

# Run interactive setup
./setup-gitlab-storage.sh
```

### 3️⃣ Done! 
Your files are now backed up to GitLab:
https://gitlab.com/e9101230/apkx/-/tree/storage/web-data

---

## Manual Commands (Alternative)

### One-Time Sync
```bash
# Sync everything
./sync-to-gitlab -project "e9101230/apkx"

# Dry run first (recommended)
./sync-to-gitlab -project "e9101230/apkx" -dry-run

# Sync specific directory
./sync-to-gitlab -project "e9101230/apkx" -dir "web-data/uploads" -remote "web-data/uploads"
```

### Automated Daily Backups
```bash
# Add to crontab
crontab -e

# Add this line (runs daily at 2 AM):
0 2 * * * cd /home/sallam/apkX && ./sync-to-gitlab -project "e9101230/apkx" >> /tmp/gitlab-sync.log 2>&1
```

---

## How It Works 🔧

1. **Separate Branch**: Files are stored in a `storage` branch (keeps code and files separate)
2. **GitLab API**: Uses GitLab's Repository Files API to upload/download
3. **Version Control**: Every upload creates a commit in GitLab
4. **No Local Changes**: Your local `web-data/` directory stays untouched

## Storage Structure

```
Your Repository:
├── main branch (code only)
│   ├── cmd/
│   ├── internal/
│   └── ...
│
└── storage branch (files only)
    └── web-data/
        ├── uploads/
        │   ├── test.apk
        │   └── app.ipa
        ├── reports/
        │   └── 20251004-001512/
        │       ├── results.json
        │       └── security-report.html
        └── downloads/
            └── ...
```

## View Your Files

**In Browser:**
https://gitlab.com/e9101230/apkx/-/tree/storage/web-data

**Download a File:**
```bash
curl --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.com/api/v4/projects/e9101230%2Fapkx/repository/files/web-data%2Fuploads%2Ftest.apk/raw?ref=storage" \
  -o test.apk
```

## Benefits ✅

- ✅ **Free Backup** - 5GB+ free storage
- ✅ **Access Anywhere** - Files accessible from any device
- ✅ **Version History** - Track all changes
- ✅ **Team Access** - Share with collaborators
- ✅ **Save Disk Space** - Offload from local server

## Troubleshooting 🔧

### Error: "401 Unauthorized"
```bash
# Your token expired or is invalid
# Create a new token and update:
export GITLAB_TOKEN="new-token-here"
```

### Error: "404 Not Found"
```bash
# Wrong project ID
# Use format: "namespace/project" or numeric ID
./sync-to-gitlab -project "e9101230/apkx"
```

### Files Not Showing?
```bash
# Make sure you're looking at the 'storage' branch:
https://gitlab.com/e9101230/apkx/-/tree/storage
```

## Need Help? 📚

- **Full Guide**: `cat GITLAB_STORAGE.md`
- **GitLab CI/CD**: `cat GITLAB.md`
- **General Setup**: `cat README.md`

---

**Your GitLab Project**: https://gitlab.com/e9101230/apkx

