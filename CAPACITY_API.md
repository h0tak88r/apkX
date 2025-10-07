# APKX Capacity Check API

## Overview
The APKX server now includes a capacity check endpoint that allows external systems (like n8n workflows) to check if the server can handle new scan requests before submitting them.

## Endpoint

**URL:** `http://194.163.160.166:9090/api/capacity`  
**Method:** `GET`  
**Authentication:** None required

## Response Format

```json
{
    "running_jobs": 0,
    "max_concurrent": 5,
    "available_slots": 5,
    "can_start_new": true,
    "active_jobs": 0,
    "status": "ok"
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `running_jobs` | integer | Number of jobs currently downloading or analyzing |
| `max_concurrent` | integer | Maximum number of concurrent scans allowed (hardcoded to 5) |
| `available_slots` | integer | Number of available slots for new scans |
| `can_start_new` | boolean | Whether a new scan can be started |
| `active_jobs` | integer | Total number of active jobs (including completed/failed) |
| `status` | string | API status (always "ok" if endpoint responds) |

## Usage in n8n Workflow

The updated n8n workflow (`n8n-workflow.json`) now includes capacity checks for **both APK and iOS scans**:

### APK Scan Flow
1. **Check APKX Capacity** node - HTTP GET request to `/api/capacity`
2. **Has Capacity?** node - Conditional check:
   - `can_start_new` equals `true`
   - `running_jobs` is less than `5`
3. **Capacity Warning** node - Discord notification when capacity is full

### iOS Scan Flow
1. **Check APKX Capacity IOS** node - HTTP GET request to `/api/capacity`
2. **Has Capacity IOS?** node - Conditional check (same conditions as APK)
3. **Capacity Warning IOS** node - Discord notification when capacity is full

### Workflow Flows

**APK Scan:**
```
APK Scan? → Check APKX Capacity → Has Capacity?
                                    ├─ YES → APKX APK Scan
                                    └─ NO  → Capacity Warning (Discord)
```

**iOS Scan:**
```
IOS Scan → Check APKX Capacity IOS → Has Capacity IOS?
                                      ├─ YES → APKX IOS Scan
                                      └─ NO  → Capacity Warning IOS (Discord)
```

## Testing

Test the endpoint manually:

```bash
curl http://194.163.160.166:9090/api/capacity
```

Example response when idle:
```json
{
    "active_jobs": 0,
    "available_slots": 5,
    "can_start_new": true,
    "max_concurrent": 5,
    "running_jobs": 0,
    "status": "ok"
}
```

Example response when at capacity:
```json
{
    "active_jobs": 5,
    "available_slots": 0,
    "can_start_new": false,
    "max_concurrent": 5,
    "running_jobs": 5,
    "status": "ok"
}
```

## Configuration

The maximum concurrent scans is currently hardcoded to **5** in `cmd/server/main.go`:

```go
maxConcurrent := 5 // Maximum concurrent scans
```

To change this limit, modify the value and rebuild the Docker container.

## Implementation Details

The endpoint counts jobs with the following statuses as "running":
- `JobDownloading` - APK/IPA is being downloaded
- `JobAnalyzing` - Analysis is in progress

Jobs with other statuses (completed, failed, etc.) are not counted toward the capacity limit.

## Benefits

✅ **Prevents server overload** - Stops new scans when at capacity  
✅ **Better resource management** - Ensures consistent performance  
✅ **Automated workflow control** - n8n can intelligently queue scans  
✅ **Visibility** - Discord notifications when capacity is reached  
✅ **No manual intervention** - Fully automated capacity management
