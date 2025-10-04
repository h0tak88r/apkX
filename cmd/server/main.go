package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/apkX/internal/analyzer"
	"github.com/h0tak88r/apkX/internal/downloader"
	"github.com/h0tak88r/apkX/internal/storage"
)

var (
	uploadDir           string
	reportsRoot         string
	downloadDir         string
	patternsPathDefault string
	
	// Storage backend (GitLab or Local)
	storageBackend storage.StorageBackend
	useGitLabStorage bool
	tempDir string // For temporary processing
)

func init() {
	root := detectProjectRoot()

	// Check if GitLab storage should be used
	useGitLabStorage = false
	
	if os.Getenv("USE_GITLAB_STORAGE") == "true" {
		gitlabProject := os.Getenv("GITLAB_PROJECT")
		gitlabToken := os.Getenv("GITLAB_TOKEN")
		
		if gitlabProject != "" && gitlabToken != "" {
			log.Printf("🔄 Initializing GitLab storage backend (project: %s)", gitlabProject)
			gitlab := storage.NewGitLabStorage(gitlabProject, gitlabToken)
			
			// Ensure storage branch exists
			if err := gitlab.EnsureBranchExists(); err != nil {
				log.Printf("⚠️  Warning: Failed to ensure GitLab branch exists: %v", err)
				log.Printf("⚠️  Falling back to local storage")
			} else {
				storageBackend = gitlab
				useGitLabStorage = true
				log.Printf("✅ GitLab storage active - files will be stored in GitLab")
				
				// Use temp directory for processing
				tempDir = os.Getenv("APKX_TEMP_DIR")
				if tempDir == "" {
					tempDir = "/tmp/apkx"
				}
				uploadDir = filepath.Join(tempDir, "uploads")
				reportsRoot = filepath.Join(tempDir, "reports")
				downloadDir = filepath.Join(tempDir, "downloads")
			}
		} else {
			log.Printf("⚠️  GitLab storage enabled but credentials missing")
		}
	}
	
	// Use local storage if GitLab not enabled or failed
	if !useGitLabStorage {
		log.Printf("📁 Using local filesystem storage")
		storageBackend = storage.NewLocalStorage(filepath.Join(root, "web-data"))
		
		if v := os.Getenv("APKX_UPLOAD_DIR"); v != "" {
			uploadDir = v
		} else {
			uploadDir = filepath.Join(root, "web-data", "uploads")
		}

		if v := os.Getenv("APKX_REPORTS_DIR"); v != "" {
			reportsRoot = v
		} else {
			reportsRoot = filepath.Join(root, "web-data", "reports")
		}

		if v := os.Getenv("APKX_DOWNLOAD_DIR"); v != "" {
			downloadDir = v
		} else {
			downloadDir = filepath.Join(root, "web-data", "downloads")
		}
	}

	if v := os.Getenv("APKX_PATTERNS_PATH"); v != "" {
		patternsPathDefault = v
	} else {
		patternsPathDefault = filepath.Join(root, "config", "regexes.yaml")
	}
}

// Optional global Discord webhook to forward results (JSON + HTML)
var serverDefaultWebhook string

// Global MITM patching flag
var enableMITMPatch bool

// Job management
type JobStatus string

const (
	Version                  = "v3.2.0"
	JobPending     JobStatus = "pending"
	JobDownloading JobStatus = "downloading"
	JobAnalyzing   JobStatus = "analyzing"
	JobCompleted   JobStatus = "completed"
	JobFailed      JobStatus = "failed"
)

type Job struct {
	ID          string     `json:"id"`
	PackageName string     `json:"package_name"`
	Version     string     `json:"version"`
	Source      string     `json:"source"`
	Status      JobStatus  `json:"status"`
	Progress    string     `json:"progress"`
	Error       string     `json:"error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	ReportID    string     `json:"report_id,omitempty"`
}

type JobManager struct {
	jobs  map[string]*Job
	mutex sync.RWMutex
}

var jobManager = &JobManager{
	jobs: make(map[string]*Job),
}

func (jm *JobManager) CreateJob(packageName, version, source string) *Job {
	jm.mutex.Lock()
	defer jm.mutex.Unlock()

	jobID := fmt.Sprintf("job_%d", time.Now().UnixNano())
	job := &Job{
		ID:          jobID,
		PackageName: packageName,
		Version:     version,
		Source:      source,
		Status:      JobPending,
		Progress:    "Job created",
		CreatedAt:   time.Now(),
	}

	jm.jobs[jobID] = job
	return job
}

func (jm *JobManager) UpdateJobStatus(jobID string, status JobStatus, progress string) {
	jm.mutex.Lock()
	defer jm.mutex.Unlock()

	if job, exists := jm.jobs[jobID]; exists {
		job.Status = status
		job.Progress = progress
		if status == JobCompleted || status == JobFailed {
			now := time.Now()
			job.CompletedAt = &now
		}
	}
}

func (jm *JobManager) SetJobError(jobID string, err error) {
	jm.mutex.Lock()
	defer jm.mutex.Unlock()

	if job, exists := jm.jobs[jobID]; exists {
		job.Status = JobFailed
		job.Error = err.Error()
		now := time.Now()
		job.CompletedAt = &now
	}
}

func (jm *JobManager) SetJobReportID(jobID, reportID string) {
	jm.mutex.Lock()
	defer jm.mutex.Unlock()

	if job, exists := jm.jobs[jobID]; exists {
		job.ReportID = reportID
	}
}

func (jm *JobManager) GetJob(jobID string) (*Job, bool) {
	jm.mutex.RLock()
	defer jm.mutex.RUnlock()

	job, exists := jm.jobs[jobID]
	return job, exists
}

func (jm *JobManager) GetAllJobs() []*Job {
	jm.mutex.RLock()
	defer jm.mutex.RUnlock()

	jobs := make([]*Job, 0, len(jm.jobs))
	for _, job := range jm.jobs {
		jobs = append(jobs, job)
	}

	// Sort by creation time (newest first)
	for i, j := 0, len(jobs)-1; i < j; i, j = i+1, j-1 {
		jobs[i], jobs[j] = jobs[j], jobs[i]
	}

	return jobs
}

func (jm *JobManager) GetActiveJobs() []*Job {
	jm.mutex.RLock()
	defer jm.mutex.RUnlock()

	var jobs []*Job
	for _, job := range jm.jobs {
		if job.Status != JobCompleted {
			jobs = append(jobs, job)
		}
	}

	// Sort by creation time (newest first)
	for i, j := 0, len(jobs)-1; i < j; i, j = i+1, j-1 {
		jobs[i], jobs[j] = jobs[j], jobs[i]
	}

	return jobs
}

func (jm *JobManager) DeleteJob(jobID string) bool {
	jm.mutex.Lock()
	defer jm.mutex.Unlock()

	if _, exists := jm.jobs[jobID]; exists {
		delete(jm.jobs, jobID)
		return true
	}
	return false
}

func main() {
	log.Printf("apkX paths: uploadDir=%s, reportsRoot=%s, downloadDir=%s, patterns=%s", uploadDir, reportsRoot, downloadDir, patternsPathDefault)
	must(os.MkdirAll(uploadDir, 0755))
	must(os.MkdirAll(reportsRoot, 0755))
	must(os.MkdirAll(downloadDir, 0755))

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/upload", handleUploadAsync)
	http.HandleFunc("/download", handleDownloadAsync)
	http.HandleFunc("/download-ios", handleDownloadIOSAsync)
	http.HandleFunc("/api/jobs", handleJobsAPI)
	http.HandleFunc("/api/job/", handleJobAPI)
	http.HandleFunc("/api/job/delete/", handleDeleteJob)
	http.HandleFunc("/api/report/delete/", handleDeleteReport)
	http.HandleFunc("/api/install/", handleInstallAPK)
	http.HandleFunc("/api/manifest/", handleDownloadManifest)
	http.HandleFunc("/api/plist/", handleDownloadPlist)

	// Serve reports statically
	fs := http.FileServer(http.Dir(reportsRoot))
	http.Handle("/reports/", http.StripPrefix("/reports/", fs))

	// Serve downloads statically
	downloadFs := http.FileServer(http.Dir(downloadDir))
	http.Handle("/downloads/", http.StripPrefix("/downloads/", downloadFs))

	// Address selection: PORT env or default 9090; can override with -addr
	defaultAddr := ":" + getEnv("PORT", "9090")
	addr := flag.String("addr", defaultAddr, "HTTP listen address, e.g. :9090 or 127.0.0.1:9090")
	webhook := flag.String("webhook", getEnv("DISCORD_WEBHOOK", ""), "Discord webhook URL to send results (JSON + HTML)")
	mitmPatch := flag.Bool("mitm", false, "Enable MITM patching for HTTPS inspection using apk-mitm")
	flag.Parse()

	serverDefaultWebhook = *webhook
	enableMITMPatch = *mitmPatch

	log.Printf("apkX web server listening on %s (set PORT env or -addr to change)", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

var indexTmpl = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>apkX Web v3.2.0</title>
  <style>
    :root {
      --bg-primary: #1a1a1a;
      --bg-secondary: #2d2d2d;
      --bg-tertiary: #3a3a3a;
      --text-primary: #ffffff;
      --text-secondary: #b0b0b0;
      --text-muted: #808080;
      --accent-primary: #00d4ff;
      --accent-secondary: #0099cc;
      --border-color: #404040;
      --shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    }
    
    [data-theme="light"] {
      --bg-primary: #ffffff;
      --bg-secondary: #f8f9fa;
      --bg-tertiary: #e9ecef;
      --text-primary: #212529;
      --text-secondary: #6c757d;
      --text-muted: #adb5bd;
      --accent-primary: #007bff;
      --accent-secondary: #0056b3;
      --border-color: #dee2e6;
      --shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
    }
    
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      line-height: 1.6;
      color: var(--text-primary);
      background: var(--bg-primary);
      min-height: 100vh;
      transition: all 0.3s ease;
    }
    
    .header {
      background: var(--bg-secondary);
      padding: 20px 40px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: var(--shadow);
    }
    
    .header h1 {
      color: var(--accent-primary);
      font-size: 2em;
      font-weight: 700;
    }
    
    .theme-toggle {
      background: var(--accent-primary);
      color: var(--bg-primary);
      border: none;
      padding: 10px 20px;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.3s ease;
    }
    
    .theme-toggle:hover {
      background: var(--accent-secondary);
      transform: translateY(-2px);
    }
    
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 40px;
    }
    
    .card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      padding: 24px;
      border-radius: 12px;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
      transition: all 0.3s ease;
    }
    
    .card:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.2);
    }
    
    .card h2 {
      color: var(--accent-primary);
      margin-bottom: 20px;
      font-size: 1.5em;
      font-weight: 600;
    }
    
    .tab-navigation {
      display: flex;
      margin-bottom: 20px;
      border-bottom: 2px solid var(--border-color);
    }
    
    .tab-btn {
      background: transparent;
      border: none;
      padding: 12px 24px;
      cursor: pointer;
      color: var(--text-secondary);
      font-weight: 500;
      transition: all 0.3s ease;
      border-bottom: 3px solid transparent;
    }
    
    .tab-btn:hover {
      color: var(--text-primary);
      background: var(--bg-tertiary);
    }
    
    .tab-btn.active {
      color: var(--accent-primary);
      border-bottom-color: var(--accent-primary);
    }
    
    .tab-content {
      display: none;
    }
    
    .tab-content.active {
      display: block;
    }
    
    .form-group {
      margin-bottom: 20px;
    }
    
    .form-group label {
      display: block;
      margin-bottom: 8px;
      color: var(--text-primary);
      font-weight: 500;
    }
    
    .form-group input[type="file"] {
      width: 100%;
      padding: 12px;
      border: 2px dashed var(--border-color);
      border-radius: 8px;
      background: var(--bg-tertiary);
      color: var(--text-primary);
      cursor: pointer;
      transition: all 0.3s ease;
    }
    
    .form-group input[type="file"]:hover {
      border-color: var(--accent-primary);
      background: var(--bg-primary);
    }
    
    .form-group input[type="text"] {
      width: 100%;
      padding: 12px 16px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      background: var(--bg-tertiary);
      color: var(--text-primary);
      font-size: 14px;
      transition: all 0.3s ease;
    }
    
    .form-group input[type="text"]:focus {
      outline: none;
      border-color: var(--accent-primary);
      box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.1);
    }
    
    .form-group input[type="text"]::placeholder {
      color: var(--text-muted);
    }
    
    .form-group select {
      width: 100%;
      padding: 12px 16px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      background: var(--bg-tertiary);
      color: var(--text-primary);
      font-size: 14px;
      transition: all 0.3s ease;
    }
    
    .form-group select:focus {
      outline: none;
      border-color: var(--accent-primary);
      box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.1);
    }
    
    .checkbox-group {
      display: flex;
      align-items: center;
      margin-bottom: 15px;
    }
    
    .checkbox-group input[type="checkbox"] {
      margin-right: 10px;
      transform: scale(1.2);
    }
    
    .checkbox-group label {
      margin-bottom: 0;
      cursor: pointer;
      user-select: none;
    }
    
    .btn {
      background: var(--accent-primary);
      color: var(--bg-primary);
      border: none;
      padding: 12px 24px;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
      font-size: 16px;
      transition: all 0.3s ease;
      width: 100%;
    }
    
    .btn:hover {
      background: var(--accent-secondary);
      transform: translateY(-2px);
      box-shadow: 0 4px 15px rgba(0, 212, 255, 0.3);
    }
    
    .btn:active {
      transform: translateY(0);
    }
    
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }
    
    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid var(--border-color);
    }
    
    th {
      background: var(--bg-tertiary);
      color: var(--accent-primary);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.9em;
      letter-spacing: 0.5px;
    }
    
    td {
      color: var(--text-primary);
    }
    
    a {
      color: var(--accent-primary);
      text-decoration: none;
      font-weight: 500;
      transition: color 0.3s ease;
    }
    
    a:hover {
      color: var(--accent-secondary);
      text-decoration: underline;
    }
    
    .webhook-section {
      background: var(--bg-tertiary);
      padding: 16px;
      border-radius: 8px;
      margin-top: 15px;
      border-left: 4px solid var(--accent-primary);
    }
    
    .webhook-section.hidden {
      display: none;
    }
    
    .small-text {
      font-size: 0.85em;
      color: var(--text-muted);
      margin-top: 8px;
    }
    
    .no-reports {
      text-align: center;
      padding: 40px;
      color: var(--text-muted);
      font-style: italic;
    }
    
    .file-type-badge {
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.8em;
      font-weight: 600;
    }
    
    .file-type-badge.APK {
      background: #4CAF50;
      color: white;
    }
    
    .file-type-badge.IPA {
      background: #2196F3;
      color: white;
    }
    
    .file-type-badge.XAPK {
      background: #FF9800;
      color: white;
    }
    
    .info-box {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 20px;
    }
    
    .info-box h3 {
      margin: 0 0 12px 0;
      color: var(--text-primary);
      font-size: 18px;
    }
    
    .info-box p {
      margin: 0 0 12px 0;
      color: var(--text-secondary);
      line-height: 1.5;
    }
    
    .info-box ul {
      margin: 0;
      padding-left: 20px;
      color: var(--text-secondary);
    }
    
    .info-box li {
      margin-bottom: 4px;
    }
    
    .google-play-section {
      background: var(--bg-tertiary);
      padding: 16px;
      border-radius: 8px;
      margin-top: 15px;
      border-left: 4px solid #4285F4;
    }
    
    .google-play-section.hidden {
      display: none;
    }
    
    .status-badge {
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.8em;
      font-weight: 600;
    }
    
    .status-badge.pending {
      background: #ffc107;
      color: #000;
    }
    
    .status-badge.downloading {
      background: #17a2b8;
      color: white;
    }
    
    .status-badge.analyzing {
      background: #6f42c1;
      color: white;
    }
    
    .status-badge.completed {
      background: #28a745;
      color: white;
    }
    
    .status-badge.failed {
      background: #dc3545;
      color: white;
    }
    
    .error-text {
      color: #dc3545;
      font-size: 0.9em;
    }
    
    .muted {
      color: var(--text-muted);
      font-style: italic;
    }
    
    .btn-small {
      padding: 4px 8px;
      font-size: 0.8em;
      border-radius: 4px;
      text-decoration: none;
      border: none;
      cursor: pointer;
      margin-left: 8px;
      display: inline-block;
    }
    
    .btn-small.btn-danger {
      background: #dc3545;
      color: white;
    }
    
    .btn-small.btn-danger:hover {
      background: #c82333;
    }
    
    .btn-small:not(.btn-danger) {
      background: var(--accent-primary);
      color: var(--bg-primary);
    }
    
    .btn-small:not(.btn-danger):hover {
      background: var(--accent-secondary);
    }
    
    .mitm-section {
      background: var(--bg-tertiary);
      padding: 16px;
      border-radius: 8px;
      margin-top: 15px;
      border-left: 4px solid #FF6B35;
    }
    
    .mitm-section.hidden {
      display: none;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🔍 apkX Web Portal v3.2.0</h1>
    <button class="theme-toggle" onclick="toggleTheme()">🌙 Dark Mode</button>
  </div>
  
  <div class="container">
    <div class="card">
      <h2>📱 Analyze Mobile App</h2>
      
      <!-- Tab Navigation -->
      <div class="tab-navigation">
        <button class="tab-btn active" onclick="switchTab('upload')">📁 Upload File</button>
        <button class="tab-btn" onclick="switchTab('download')">⬇️ Download APK</button>
        <button class="tab-btn" onclick="switchTab('download-ios')">🍎 Download iOS App</button>
      </div>
      
      <!-- Upload Tab -->
      <div id="upload-tab" class="tab-content active">
        <form action="/upload" method="post" enctype="multipart/form-data">
          <div class="form-group">
            <label for="apk">Select APK, XAPK or IPA File</label>
            <input type="file" name="apk" id="apk" accept=".apk,.xapk,.ipa" required>
          </div>
          
          <div class="checkbox-group">
            <input type="checkbox" name="html" id="html" checked>
            <label for="html">Generate HTML report</label>
          </div>
          
          <div class="checkbox-group">
            <input type="checkbox" name="mitm_patch" id="mitmPatch" {{if .EnableMITMPatch}}checked{{end}}>
            <label for="mitmPatch">Apply MITM patch for HTTPS inspection</label>
          </div>
          
          <div class="checkbox-group">
            <input type="checkbox" name="send_discord" id="discordCheckbox" onchange="toggleWebhookSection()">
            <label for="discordCheckbox">Send to Discord</label>
          </div>
          
          <div class="webhook-section hidden" id="webhookSection">
            <div class="form-group">
              <label for="webhook">Discord Webhook URL</label>
              <input type="text" name="webhook" id="webhook" placeholder="https://discord.com/api/webhooks/...">
              <div class="small-text">Server default: {{.DefaultWebhookHint}}</div>
            </div>
          </div>
          
          <button class="btn" type="submit">🚀 Analyze File</button>
        </form>
      </div>
      
      <!-- Download Tab -->
      <div id="download-tab" class="tab-content">
        <form action="/download" method="post">
          <div class="form-group">
            <label for="package">Package Name</label>
            <input type="text" name="package" id="package" placeholder="com.instagram.android" required>
            <div class="small-text">Enter the package name (e.g., com.instagram.android)</div>
          </div>
          
          <div class="form-group">
            <label for="version">Version (Optional)</label>
            <input type="text" name="version" id="version" placeholder="1.2.3">
            <div class="small-text">Leave empty for latest version</div>
          </div>
          
          <div class="form-group">
            <label for="source">Download Source</label>
            <select name="source" id="source" onchange="toggleGooglePlaySection()">
              <option value="apk-pure">APKPure (No credentials needed)</option>
              <option value="google-play">Google Play Store</option>
              <option value="f-droid">F-Droid</option>
              <option value="huawei-app-gallery">Huawei AppGallery</option>
            </select>
          </div>
          
          <div class="google-play-section hidden" id="googlePlaySection">
            <h3>🔐 Google Play Store Credentials</h3>
            <div class="form-group">
              <label for="email">Google Email</label>
              <input type="email" name="email" id="email" placeholder="your-email@gmail.com">
            </div>
            <div class="form-group">
              <label for="oauth_token">OAuth Token (Optional)</label>
              <input type="text" name="oauth_token" id="oauth_token" placeholder="OAuth token for AAS token generation">
            </div>
            <div class="form-group">
              <label for="aas_token">AAS Token</label>
              <input type="text" name="aas_token" id="aas_token" placeholder="AAS token from Google Play">
            </div>
            <div class="checkbox-group">
              <input type="checkbox" name="accept_tos" id="accept_tos" checked>
              <label for="accept_tos">Accept Google Play Terms of Service</label>
            </div>
          </div>
          
          <div class="checkbox-group">
            <input type="checkbox" name="html" id="html_download" checked>
            <label for="html_download">Generate HTML report</label>
          </div>
          
          <div class="checkbox-group">
            <input type="checkbox" name="mitm_patch" id="mitmPatchDownload" {{if .EnableMITMPatch}}checked{{end}}>
            <label for="mitmPatchDownload">Apply MITM patch for HTTPS inspection</label>
          </div>
          
          <div class="checkbox-group">
            <input type="checkbox" name="send_discord" id="discordCheckboxDownload" onchange="toggleWebhookSectionDownload()">
            <label for="discordCheckboxDownload">Send to Discord</label>
          </div>
          
          <div class="webhook-section hidden" id="webhookSectionDownload">
            <div class="form-group">
              <label for="webhook_download">Discord Webhook URL</label>
              <input type="text" name="webhook" id="webhook_download" placeholder="https://discord.com/api/webhooks/...">
              <div class="small-text">Server default: {{.DefaultWebhookHint}}</div>
            </div>
          </div>
          
          <button class="btn" type="submit">⬇️ Download & Analyze</button>
        </form>
      </div>
      
      <!-- iOS Download Tab -->
      <div id="download-ios-tab" class="tab-content">
        <div class="info-box">
          <h3>🍎 Enhanced iOS Analysis</h3>
          <p>Now with <strong>regex-based pattern matching</strong> and <strong>concurrent processing</strong> for faster, more accurate analysis!</p>
          <ul>
            <li>✅ 1652+ security patterns</li>
            <li>✅ Mach-O binary analysis</li>
            <li>✅ Plist parsing (XML & binary)</li>
            <li>✅ Concurrent file processing</li>
            <li>✅ Enhanced context extraction</li>
          </ul>
        </div>
        <form action="/download-ios" method="post">
          <div class="form-group">
            <label for="bundle_id">Bundle ID</label>
            <input type="text" name="bundle_id" id="bundle_id" placeholder="com.apple.mobilesafari" required>
            <div class="small-text">Enter the iOS app bundle ID (e.g., com.apple.mobilesafari)</div>
          </div>
          
          <div class="form-group">
            <label for="ios_version">Version (Optional)</label>
            <input type="text" name="ios_version" id="ios_version" placeholder="1.2.3">
            <div class="small-text">Leave empty for latest version</div>
          </div>
          
          <div class="checkbox-group">
            <input type="checkbox" name="html" id="html_ios" checked>
            <label for="html_ios">Generate HTML report</label>
          </div>
          
          <div class="checkbox-group">
            <input type="checkbox" name="send_discord" id="discordCheckboxIOS" onchange="toggleWebhookSectionIOS()">
            <label for="discordCheckboxIOS">Send to Discord</label>
          </div>
          
          <div class="webhook-section hidden" id="webhookSectionIOS">
            <div class="form-group">
              <label for="webhook_ios">Discord Webhook URL</label>
              <input type="text" name="webhook" id="webhook_ios" placeholder="https://discord.com/api/webhooks/...">
              <div class="small-text">Server default: {{.DefaultWebhookHint}}</div>
            </div>
          </div>
          
          <button class="btn" type="submit">🍎 Download & Analyze iOS App</button>
        </form>
      </div>
    </div>
    
    <div class="card">
      <h2>🔄 Active Jobs</h2>
      <div id="jobs-container">
        <div class="no-reports">
          <p>Loading jobs...</p>
        </div>
      </div>
    </div>
    
    <div class="card">
      <h2>📊 Analysis Reports</h2>
      {{if .Rows}}
      <table>
        <thead>
          <tr>
            <th>File</th>
            <th>Type</th>
            <th>Time</th>
            <th>JSON</th>
            <th>HTML</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {{range .Rows}}
          <tr>
            <td>{{.APK}}</td>
            <td><span class="file-type-badge {{.Type}}">{{.Type}}</span></td>
            <td>{{.When}}</td>
            <td>{{if .JSON}}<a href="/reports/{{.ID}}/results.json">📄 results.json</a>{{end}}</td>
            <td>{{if .HTML}}<a href="/reports/{{.ID}}/security-report.html">🌐 security-report.html</a>{{end}}</td>
            <td>
              {{if or (eq .Type "APK") (eq .Type "XAPK")}}
              <a href="/api/install/{{.ID}}" class="btn-small" style="background: #28a745; color: white; text-decoration: none;">📱 Download</a>
              <a href="/api/manifest/{{.ID}}" class="btn-small" style="background: #17a2b8; color: white; text-decoration: none;">📄 Manifest</a>
              {{else if eq .Type "IPA"}}
              <a href="/api/plist/{{.ID}}" class="btn-small" style="background: #17a2b8; color: white; text-decoration: none;">📄 Plist</a>
              {{end}}
              <button onclick="deleteReport('{{.ID}}')" class="btn-small btn-danger">🗑️ Delete</button>
            </td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{else}}
      <div class="no-reports">
        <p>No analysis reports yet. Upload a file or download an APK to get started!</p>
      </div>
      {{end}}
    </div>
  </div>
  
  <script>
    // Theme management
    function toggleTheme() {
      const body = document.body;
      const themeToggle = document.querySelector('.theme-toggle');
      const currentTheme = body.getAttribute('data-theme');
      
      if (currentTheme === 'light') {
        body.setAttribute('data-theme', 'dark');
        themeToggle.textContent = '🌙 Dark Mode';
        localStorage.setItem('theme', 'dark');
      } else {
        body.setAttribute('data-theme', 'light');
        themeToggle.textContent = '☀️ Light Mode';
        localStorage.setItem('theme', 'light');
      }
    }
    
    // Load saved theme
    function loadTheme() {
      const savedTheme = localStorage.getItem('theme') || 'dark';
      const body = document.body;
      const themeToggle = document.querySelector('.theme-toggle');
      
      body.setAttribute('data-theme', savedTheme);
      themeToggle.textContent = savedTheme === 'light' ? '☀️ Light Mode' : '🌙 Dark Mode';
    }
    
    // Tab switching
    function switchTab(tabName) {
      // Hide all tabs
      document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
      });
      
      // Remove active class from all buttons
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
      });
      
      // Show selected tab
      document.getElementById(tabName + '-tab').classList.add('active');
      
      // Add active class to clicked button
      event.target.classList.add('active');
    }
    
    // Webhook section toggle
    function toggleWebhookSection() {
      const checkbox = document.getElementById('discordCheckbox');
      const section = document.getElementById('webhookSection');
      const webhookInput = document.getElementById('webhook');
      
      if (checkbox.checked) {
        section.classList.remove('hidden');
        webhookInput.focus();
      } else {
        section.classList.add('hidden');
        webhookInput.value = '';
      }
    }
    
    function toggleWebhookSectionDownload() {
      const checkbox = document.getElementById('discordCheckboxDownload');
      const section = document.getElementById('webhookSectionDownload');
      const webhookInput = document.getElementById('webhook_download');
      
      if (checkbox.checked) {
        section.classList.remove('hidden');
        webhookInput.focus();
      } else {
        section.classList.add('hidden');
        webhookInput.value = '';
      }
    }
    
    function toggleWebhookSectionIOS() {
      const checkbox = document.getElementById('discordCheckboxIOS');
      const section = document.getElementById('webhookSectionIOS');
      const webhookInput = document.getElementById('webhook_ios');
      
      if (checkbox.checked) {
        section.classList.remove('hidden');
        webhookInput.focus();
      } else {
        section.classList.add('hidden');
        webhookInput.value = '';
      }
    }
    
    // Google Play section toggle
    function toggleGooglePlaySection() {
      const source = document.getElementById('source').value;
      const section = document.getElementById('googlePlaySection');
      
      if (source === 'google-play') {
        section.classList.remove('hidden');
      } else {
        section.classList.add('hidden');
      }
    }
    
    // Job management
    function loadJobs() {
      fetch('/api/jobs')
        .then(response => {
          if (!response.ok) {
            throw new Error('Network response was not ok');
          }
          return response.json();
        })
        .then(jobs => {
          const container = document.getElementById('jobs-container');
          if (!jobs || jobs.length === 0) {
            container.innerHTML = '<div class="no-reports"><p>No active jobs</p></div>';
            return;
          }
          
          let html = '<table><thead><tr><th>Package</th><th>Status</th><th>Progress</th><th>Created</th><th>Actions</th></tr></thead><tbody>';
          jobs.forEach(job => {
            const statusClass = job.status.toLowerCase();
            const statusIcon = getStatusIcon(job.status);
            const createdAt = new Date(job.created_at).toLocaleString();
            
            html += '<tr>' +
              '<td>' + job.package_name + (job.version ? '@' + job.version : '') + '</td>' +
              '<td><span class="status-badge ' + statusClass + '">' + statusIcon + ' ' + job.status + '</span></td>' +
              '<td>' + job.progress + '</td>' +
              '<td>' + createdAt + '</td>' +
              '<td>' + getJobActions(job) + '</td>' +
            '</tr>';
          });
          html += '</tbody></table>';
          container.innerHTML = html;
        })
        .catch(error => {
          console.error('Error loading jobs:', error);
          document.getElementById('jobs-container').innerHTML = '<div class="no-reports"><p>Error loading jobs</p></div>';
        });
    }
    
    function getStatusIcon(status) {
      switch(status) {
        case 'pending': return '⏳';
        case 'downloading': return '⬇️';
        case 'analyzing': return '🔍';
        case 'completed': return '✅';
        case 'failed': return '❌';
        default: return '❓';
      }
    }
    
    function getJobActions(job) {
      if (job.status === 'completed' && job.report_id) {
        return '<a href="/reports/' + job.report_id + '/security-report.html" target="_blank" class="btn-small">View Report</a>';
      } else if (job.status === 'failed') {
        return '<span class="error-text">' + (job.error || 'Unknown error') + '</span> ' +
               '<button onclick="deleteJob(\'' + job.id + '\')" class="btn-small btn-danger">Remove</button>';
      } else {
        return '<span class="muted">Processing...</span>';
      }
    }
    
    function deleteJob(jobId) {
      if (confirm('Are you sure you want to remove this failed job?')) {
        fetch('/api/job/delete/' + jobId, {
          method: 'DELETE'
        })
        .then(response => {
          if (response.ok) {
            loadJobs(); // Refresh the job list
          } else {
            alert('Failed to delete job');
          }
        })
        .catch(error => {
          console.error('Error deleting job:', error);
          alert('Error deleting job');
        });
      }
    }
    
    function deleteReport(reportId) {
      if (confirm('Are you sure you want to delete this report? This action cannot be undone.')) {
        fetch('/api/report/delete/' + reportId, {
          method: 'DELETE'
        })
        .then(response => {
          if (response.ok) {
            location.reload(); // Refresh the page to show updated reports
          } else {
            alert('Failed to delete report');
          }
        })
        .catch(error => {
          console.error('Error deleting report:', error);
          alert('Error deleting report');
        });
      }
    }
    
    
    // Auto-refresh jobs every 2 seconds
    function startJobRefresh() {
      loadJobs();
      setInterval(loadJobs, 2000);
    }
    
    // Initialize on page load
    document.addEventListener('DOMContentLoaded', function() {
      loadTheme();
      startJobRefresh();
      
      // Check if Discord checkbox should be checked (if webhook is provided)
      const webhookInput = document.getElementById('webhook');
      if (webhookInput && webhookInput.value) {
        document.getElementById('discordCheckbox').checked = true;
        toggleWebhookSection();
      }
      
      // Check for upload success message
      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.get('upload') === 'success') {
        const jobId = urlParams.get('job_id');
        alert('✅ File uploaded successfully! Job ID: ' + jobId + '\n\nYou can track the progress in the "Active Jobs" section below.');
        
        // Clean up URL by removing the parameters
        const newUrl = window.location.pathname;
        window.history.replaceState({}, document.title, newUrl);
      }
    });
  </script>
</body>
</html>`))

type reportRow struct {
	ID   string
	APK  string
	Type string
	When string
	JSON bool
	HTML bool
}

type indexData struct {
	Rows               []reportRow
	DefaultWebhookHint string
	EnableMITMPatch    bool
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	rows := listReports()
	data := indexData{Rows: rows, DefaultWebhookHint: "configured", EnableMITMPatch: enableMITMPatch}
	if err := indexTmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func handleDownloadIOSAsync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bundleID := strings.TrimSpace(r.FormValue("bundle_id"))
	if bundleID == "" {
		http.Error(w, "bundle ID is required", http.StatusBadRequest)
		return
	}

	version := strings.TrimSpace(r.FormValue("ios_version"))
	source := "ipatool"

	// Create job
	job := jobManager.CreateJob(bundleID, version, source)

	// Start background processing
	go processIOSDownloadJob(job, r)

	// Return job ID for tracking
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"job_id":  job.ID,
		"status":  "started",
		"message": "iOS download job started",
	})
}

func processIOSDownloadJob(job *Job, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			jobManager.SetJobError(job.ID, fmt.Errorf("panic: %v", r))
		}
	}()

	// Update status to downloading
	jobManager.UpdateJobStatus(job.ID, JobDownloading, "Starting iOS app download...")

	// Create iOS downloader
	iosDownloader := downloader.NewIPAToolDownloader(downloadDir)

	// Download the app
	ipaPath, err := iosDownloader.DownloadApp(job.PackageName, job.Version)
	if err != nil {
		log.Printf("Job %s: iOS download failed: %v", job.ID, err)
		jobManager.SetJobError(job.ID, fmt.Errorf("iOS download failed: %v", err))
		return
	}

	log.Printf("Job %s: iOS app downloaded successfully: %s", job.ID, ipaPath)

	// Update status to analyzing
	jobManager.UpdateJobStatus(job.ID, JobAnalyzing, "Starting iOS analysis...")

	// Create report directory
	runID := time.Now().Format("20060102-150405")
	outDir := filepath.Join(reportsRoot, runID)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		jobManager.SetJobError(job.ID, fmt.Errorf("failed to create report directory: %v", err))
		return
	}

	// Write meta
	metaData := map[string]string{
		"original_ipa": filepath.Base(ipaPath),
		"bundle_id":    job.PackageName,
		"version":      job.Version,
		"source":       "ipatool",
	}
	metaJSON, _ := json.Marshal(metaData)
	_ = os.WriteFile(filepath.Join(outDir, "apk.name"), metaJSON, 0644)

	// Run iOS analyzer
	generateHTML := r.FormValue("html") != ""
	sendDiscord := r.FormValue("send_discord") != ""
	webhookURL := strings.TrimSpace(r.FormValue("webhook"))

	// Use form webhook if provided, otherwise use server default
	if sendDiscord {
		if webhookURL == "" {
			webhookURL = serverDefaultWebhook
		}
	} else {
		webhookURL = ""
	}

	cfg := analyzer.Config{
		APKPath:      ipaPath,
		OutputDir:    outDir,
		PatternsPath: patternsPathDefault,
		Workers:      3,
		HTMLOutput:   generateHTML,
		WebhookURL:   webhookURL,
	}

	iosAnalyzer := analyzer.NewIOSAnalyzer(&cfg)
	if err := iosAnalyzer.AnalyzeIPA(ipaPath); err != nil {
		log.Printf("Job %s: iOS analysis error: %v", job.ID, err)
		jobManager.SetJobError(job.ID, fmt.Errorf("iOS analysis failed: %v", err))
		return
	}

	// Job completed successfully
	jobManager.SetJobReportID(job.ID, runID)
	jobManager.UpdateJobStatus(job.ID, JobCompleted, "iOS analysis completed successfully")
	log.Printf("Job %s: iOS analysis completed successfully", job.ID)
}

func handleDownloadAsync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	packageName := strings.TrimSpace(r.FormValue("package"))
	if packageName == "" {
		http.Error(w, "package name is required", http.StatusBadRequest)
		return
	}

	version := strings.TrimSpace(r.FormValue("version"))
	source := r.FormValue("source")
	if source == "" {
		source = "apk-pure"
	}

	// Create job
	job := jobManager.CreateJob(packageName, version, source)

	// Start background processing
	go processDownloadJob(job, r)

	// Return job ID for tracking
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"job_id":  job.ID,
		"status":  "started",
		"message": "Download job started",
	})
}

func processDownloadJob(job *Job, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			jobManager.SetJobError(job.ID, fmt.Errorf("panic: %v", r))
		}
	}()

	// Update status to downloading
	jobManager.UpdateJobStatus(job.ID, JobDownloading, "Starting download...")

	// Build apkeep command arguments
	args := []string{}

	// Add package name with optional version
	appID := job.PackageName
	if job.Version != "" {
		appID = job.PackageName + "@" + job.Version
	}
	args = append(args, "-a", appID)

	// Add download source
	if job.Source != "" {
		args = append(args, "-d", job.Source)
	}

	// Add Google Play specific options
	if job.Source == "google-play" {
		email := strings.TrimSpace(r.FormValue("email"))
		aasToken := strings.TrimSpace(r.FormValue("aas_token"))
		oauthToken := strings.TrimSpace(r.FormValue("oauth_token"))
		acceptTOS := r.FormValue("accept_tos") != ""

		if email != "" {
			args = append(args, "-e", email)
		}
		if aasToken != "" {
			args = append(args, "-t", aasToken)
		}
		if oauthToken != "" {
			args = append(args, "--oauth-token", oauthToken)
		}
		if acceptTOS {
			args = append(args, "--accept-tos")
		}
	}

	// Add sleep duration and parallel downloads
	args = append(args, "-s", "1000", "-r", "1")
	args = append(args, downloadDir)

	log.Printf("Job %s: Downloading APK: %s from %s", job.ID, job.PackageName, job.Source)

	// Execute apkeep command
	cmd := exec.Command("apkeep", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Job %s: apkeep download failed: %v, output: %s", job.ID, err, string(output))
		jobManager.SetJobError(job.ID, fmt.Errorf("download failed: %v", err))
		return
	}

	// Find the downloaded APK file
	apkPath, err := findDownloadedAPK(job.PackageName)
	if err != nil {
		log.Printf("Job %s: failed to find downloaded APK: %v", job.ID, err)
		jobManager.SetJobError(job.ID, fmt.Errorf("failed to find downloaded APK: %v", err))
		return
	}

	// If XAPK, convert to APK
	if strings.HasSuffix(strings.ToLower(apkPath), ".xapk") {
		jobManager.UpdateJobStatus(job.ID, JobDownloading, "Converting XAPK to APK...")
		apkConverted, err := convertXAPKToAPK(apkPath)
		if err != nil {
			log.Printf("Job %s: XAPK conversion failed: %v", job.ID, err)
			jobManager.SetJobError(job.ID, fmt.Errorf("XAPK conversion failed: %v", err))
			return
		}
		apkPath = apkConverted
	}

	log.Printf("Job %s: APK downloaded successfully: %s", job.ID, apkPath)

	// Update status to analyzing
	jobManager.UpdateJobStatus(job.ID, JobAnalyzing, "Starting analysis...")

	// Check if MITM patching is requested
	applyMITM := r.FormValue("mitm_patch") != ""
	var patchedAPKPath string
	var mitmFailed bool

	if applyMITM {
		jobManager.UpdateJobStatus(job.ID, JobAnalyzing, "Applying MITM patch...")
		patchedPath, err := applyMITMPatch(apkPath)
		if err != nil {
			log.Printf("Job %s: MITM patching failed: %v", job.ID, err)
			// Do not fail the job; continue with analysis of the original APK
			mitmFailed = true
			jobManager.UpdateJobStatus(job.ID, JobAnalyzing, "MITM patch failed, continuing without patch...")
		} else {
			patchedAPKPath = patchedPath
			jobManager.UpdateJobStatus(job.ID, JobAnalyzing, "MITM patch applied, starting analysis...")
		}
	}

	// Now analyze the ORIGINAL APK (not the patched one)
	generateHTML := r.FormValue("html") != ""
	sendDiscord := r.FormValue("send_discord") != ""
	webhookURL := strings.TrimSpace(r.FormValue("webhook"))

	// Use form webhook if provided, otherwise use server default
	if sendDiscord {
		if webhookURL == "" {
			webhookURL = serverDefaultWebhook
		}
	} else {
		webhookURL = ""
	}

	// Create report directory
	runID := time.Now().Format("20060102-150405")
	outDir := filepath.Join(reportsRoot, runID)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		jobManager.SetJobError(job.ID, fmt.Errorf("failed to create report directory: %v", err))
		return
	}

	// Write meta - store both original and patched paths
	metaData := map[string]string{
		"original_apk": filepath.Base(apkPath),
		"mitm_enabled": fmt.Sprintf("%t", applyMITM),
	}
	if applyMITM {
		metaData["patched_apk"] = filepath.Base(patchedAPKPath)
		if mitmFailed {
			metaData["mitm_failed"] = "true"
		}
	}

	metaJSON, _ := json.Marshal(metaData)
	_ = os.WriteFile(filepath.Join(outDir, "apk.name"), metaJSON, 0644)

	// Run analyzer on ORIGINAL APK
	cfg := analyzer.Config{
		APKPath:      apkPath, // Use original APK for analysis
		OutputDir:    outDir,
		PatternsPath: patternsPathDefault,
		Workers:      3,
		HTMLOutput:   generateHTML,
		WebhookURL:   webhookURL,
	}
	scanner := analyzer.NewAPKScanner(&cfg)
	if err := scanner.Run(); err != nil {
		log.Printf("Job %s: analyze error: %v", job.ID, err)
		jobManager.SetJobError(job.ID, fmt.Errorf("analysis failed: %v", err))
		return
	}

	// Job completed successfully
	jobManager.SetJobReportID(job.ID, runID)
	jobManager.UpdateJobStatus(job.ID, JobCompleted, "Analysis completed successfully")
	log.Printf("Job %s: Analysis completed successfully", job.ID)
}

func handleJobsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jobs := jobManager.GetActiveJobs()
	if jobs == nil {
		jobs = []*Job{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jobs)
}

func handleJobAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jobID := strings.TrimPrefix(r.URL.Path, "/api/job/")
	job, exists := jobManager.GetJob(jobID)
	if !exists {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

func handleDeleteJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jobID := strings.TrimPrefix(r.URL.Path, "/api/job/delete/")
	success := jobManager.DeleteJob(jobID)

	if success {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	} else {
		http.NotFound(w, r)
	}
}

func handleDownloadSimple(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	packageName := strings.TrimSpace(r.FormValue("package"))
	if packageName == "" {
		http.Error(w, "package name is required", http.StatusBadRequest)
		return
	}

	version := strings.TrimSpace(r.FormValue("version"))
	source := r.FormValue("source")
	if source == "" {
		source = "apk-pure"
	}

	// Build apkeep command arguments
	args := []string{}

	// Add package name with optional version
	appID := packageName
	if version != "" {
		appID = packageName + "@" + version
	}
	args = append(args, "-a", appID)

	// Add download source
	if source != "" {
		args = append(args, "-d", source)
	}

	// Add Google Play specific options
	if source == "google-play" {
		email := strings.TrimSpace(r.FormValue("email"))
		aasToken := strings.TrimSpace(r.FormValue("aas_token"))
		oauthToken := strings.TrimSpace(r.FormValue("oauth_token"))
		acceptTOS := r.FormValue("accept_tos") != ""

		if email == "" || aasToken == "" {
			http.Error(w, "email and AAS token are required for Google Play", http.StatusBadRequest)
			return
		}

		if email != "" {
			args = append(args, "-e", email)
		}
		if aasToken != "" {
			args = append(args, "-t", aasToken)
		}
		if oauthToken != "" {
			args = append(args, "--oauth-token", oauthToken)
		}
		if acceptTOS {
			args = append(args, "--accept-tos")
		}
	}

	// Add sleep duration
	args = append(args, "-s", "1000")

	// Add parallel downloads
	args = append(args, "-r", "1")

	// Add output directory
	args = append(args, downloadDir)

	log.Printf("Downloading APK: %s from %s", packageName, source)

	// Execute apkeep command
	cmd := exec.Command("apkeep", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("apkeep download failed: %v, output: %s", err, string(output))
		http.Error(w, "download failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Find the downloaded APK file
	apkPath, err := findDownloadedAPK(packageName)
	if err != nil {
		log.Printf("failed to find downloaded APK: %v", err)
		http.Error(w, "failed to find downloaded APK: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("APK downloaded successfully: %s", apkPath)

	// Now analyze the downloaded APK
	generateHTML := r.FormValue("html") != ""
	sendDiscord := r.FormValue("send_discord") != ""
	webhookURL := strings.TrimSpace(r.FormValue("webhook"))

	// Use form webhook if provided, otherwise use server default
	if sendDiscord {
		if webhookURL == "" {
			webhookURL = serverDefaultWebhook
		}
	} else {
		webhookURL = ""
	}

	// Create report directory
	runID := time.Now().Format("20060102-150405")
	outDir := filepath.Join(reportsRoot, runID)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Write meta
	_ = os.WriteFile(filepath.Join(outDir, "apk.name"), []byte(filepath.Base(apkPath)), 0644)

	// Run analyzer
	cfg := analyzer.Config{
		APKPath:      apkPath,
		OutputDir:    outDir,
		PatternsPath: patternsPathDefault,
		Workers:      3,
		HTMLOutput:   generateHTML,
		WebhookURL:   webhookURL,
	}
	scanner := analyzer.NewAPKScanner(&cfg)
	if err := scanner.Run(); err != nil {
		log.Printf("analyze error: %v", err)
		http.Error(w, "analysis failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func findDownloadedAPK(packageName string) (string, error) {
	// Look for APK and XAPK files in the download directory
	entries, err := os.ReadDir(downloadDir)
	if err != nil {
		return "", err
	}

	// Find the most recently created APK or XAPK file
	var latestFile string
	var latestTime time.Time

	for _, entry := range entries {
		if !entry.IsDir() {
			fileName := strings.ToLower(entry.Name())
			// Check for both .apk and .xapk files
			if strings.HasSuffix(fileName, ".apk") || strings.HasSuffix(fileName, ".xapk") {
				// Check if this file is related to our package
				if strings.Contains(entry.Name(), packageName) ||
					strings.Contains(entry.Name(), strings.ReplaceAll(packageName, ".", "_")) {

					info, err := entry.Info()
					if err != nil {
						continue
					}

					if info.ModTime().After(latestTime) {
						latestTime = info.ModTime()
						latestFile = filepath.Join(downloadDir, entry.Name())
					}
				}
			}
		}
	}

	if latestFile == "" {
		return "", fmt.Errorf("no APK or XAPK file found for package %s", packageName)
	}

	return latestFile, nil
}

func listReports() []reportRow {
	entries, err := os.ReadDir(reportsRoot)
	if err != nil {
		return nil
	}
	var rows []reportRow
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		metaPath := filepath.Join(reportsRoot, id, "apk.name")
		metaContent := readString(metaPath)

		// Try to parse as JSON first (new format)
		var metaData map[string]string
		if err := json.Unmarshal([]byte(metaContent), &metaData); err == nil {
			// New JSON format
			apkName := metaData["original_apk"]
			if apkName == "" {
				apkName = metaData["original_ipa"] // For iOS apps
			}
			st, _ := os.Stat(filepath.Join(reportsRoot, id))
			fileType := "Unknown"
			if strings.HasSuffix(strings.ToLower(apkName), ".apk") {
				fileType = "APK"
			} else if strings.HasSuffix(strings.ToLower(apkName), ".xapk") {
				fileType = "XAPK"
			} else if strings.HasSuffix(strings.ToLower(apkName), ".ipa") {
				fileType = "IPA"
			}

			row := reportRow{
				ID:   id,
				APK:  apkName,
				Type: fileType,
				When: st.ModTime().Format("2006-01-02 15:04:05"),
				JSON: fileExists(filepath.Join(reportsRoot, id, "results.json")),
				HTML: fileExists(filepath.Join(reportsRoot, id, "security-report.html")),
			}
			rows = append(rows, row)
		} else {
			// Old format - just filename
			apkName := metaContent
			st, _ := os.Stat(filepath.Join(reportsRoot, id))
			// Determine file type from the name
			fileType := "Unknown"
			if strings.HasSuffix(strings.ToLower(apkName), ".apk") {
				fileType = "APK"
			} else if strings.HasSuffix(strings.ToLower(apkName), ".xapk") {
				fileType = "XAPK"
			} else if strings.HasSuffix(strings.ToLower(apkName), ".ipa") {
				fileType = "IPA"
			}

			row := reportRow{
				ID:   id,
				APK:  apkName,
				Type: fileType,
				When: st.ModTime().Format("2006-01-02 15:04:05"),
				JSON: fileExists(filepath.Join(reportsRoot, id, "results.json")),
				HTML: fileExists(filepath.Join(reportsRoot, id, "security-report.html")),
			}
			rows = append(rows, row)
		}
	}
	// Newest first
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	return rows
}

func handleUploadAsync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	file, header, err := r.FormFile("apk")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".apk" && ext != ".xapk" && ext != ".ipa" {
		http.Error(w, "only .apk, .xapk and .ipa files are allowed", http.StatusBadRequest)
		return
	}

	// Save upload
	savedPath, err := saveUploadedFile(file, header)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create job for uploaded file
	fileName := filepath.Base(savedPath)
	job := jobManager.CreateJob(fileName, "", "upload")

	// Start background processing
	go processUploadJob(job, savedPath, r)

	// Redirect back to main page with success message
	http.Redirect(w, r, "/?upload=success&job_id="+job.ID, http.StatusSeeOther)
}

func processUploadJob(job *Job, filePath string, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			jobManager.SetJobError(job.ID, fmt.Errorf("panic: %v", r))
		}
	}()

	// Detect file type based on extension
	ext := strings.ToLower(filepath.Ext(filePath))

	// Handle iOS IPA files
	if ext == ".ipa" {
		processIOSUploadJob(job, filePath, r)
		return
	}

	// Handle APK and XAPK files
	apkPath := filePath

	// If XAPK uploaded, convert to APK first
	if ext == ".xapk" {
		jobManager.UpdateJobStatus(job.ID, JobAnalyzing, "Converting XAPK to APK...")
		apkConverted, err := convertXAPKToAPK(apkPath)
		if err != nil {
			jobManager.SetJobError(job.ID, fmt.Errorf("XAPK conversion failed: %v", err))
			return
		}
		apkPath = apkConverted
	}

	// Update status to analyzing
	jobManager.UpdateJobStatus(job.ID, JobAnalyzing, "Starting APK analysis...")

	// Create report directory
	runID := time.Now().Format("20060102-150405")
	outDir := filepath.Join(reportsRoot, runID)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		jobManager.SetJobError(job.ID, fmt.Errorf("failed to create report directory: %v", err))
		return
	}

	// Check if MITM patching is requested
	applyMITM := r.FormValue("mitm_patch") != ""
	var patchedAPKPath string
	var mitmFailed bool

	if applyMITM {
		jobManager.UpdateJobStatus(job.ID, JobAnalyzing, "Applying MITM patch...")
		patchedPath, err := applyMITMPatch(apkPath)
		if err != nil {
			log.Printf("Job %s: MITM patching failed: %v", job.ID, err)
			// Do not fail the job; continue with analysis of the original APK
			mitmFailed = true
			jobManager.UpdateJobStatus(job.ID, JobAnalyzing, "MITM patch failed, continuing without patch...")
		} else {
			patchedAPKPath = patchedPath
			jobManager.UpdateJobStatus(job.ID, JobAnalyzing, "MITM patch applied, starting analysis...")
		}
	}

	// Write meta - store both original and patched paths
	metaData := map[string]string{
		"original_apk": filepath.Base(apkPath),
		"mitm_enabled": fmt.Sprintf("%t", applyMITM),
	}
	if applyMITM {
		metaData["patched_apk"] = filepath.Base(patchedAPKPath)
		if mitmFailed {
			metaData["mitm_failed"] = "true"
		}
	}

	metaJSON, _ := json.Marshal(metaData)
	_ = os.WriteFile(filepath.Join(outDir, "apk.name"), metaJSON, 0644)

	// Run analyzer on ORIGINAL APK
	generateHTML := r.FormValue("html") != ""
	sendDiscord := r.FormValue("send_discord") != ""
	webhookURL := strings.TrimSpace(r.FormValue("webhook"))

	// Use form webhook if provided, otherwise use server default
	if sendDiscord {
		if webhookURL == "" {
			webhookURL = serverDefaultWebhook
		}
	} else {
		webhookURL = ""
	}

	cfg := analyzer.Config{
		APKPath:      apkPath, // Use original APK for analysis
		OutputDir:    outDir,
		PatternsPath: patternsPathDefault,
		Workers:      3,
		HTMLOutput:   generateHTML,
		WebhookURL:   webhookURL,
	}
	scanner := analyzer.NewAPKScanner(&cfg)
	if err := scanner.Run(); err != nil {
		log.Printf("Job %s: analyze error: %v", job.ID, err)
		jobManager.SetJobError(job.ID, fmt.Errorf("analysis failed: %v", err))
		return
	}

	// Job completed successfully
	jobManager.SetJobReportID(job.ID, runID)
	jobManager.UpdateJobStatus(job.ID, JobCompleted, "Analysis completed successfully")
	log.Printf("Job %s: Analysis completed successfully", job.ID)
	
	// Upload reports to GitLab if enabled
	if useGitLabStorage {
		go uploadReportToGitLab(outDir, runID)
		// Cleanup temp upload file
		go func() {
			time.Sleep(5 * time.Second)
			os.Remove(filePath)
			log.Printf("🗑️  Cleaned up temp file: %s", filePath)
		}()
	}
}

// processIOSUploadJob handles uploaded iOS IPA files
func processIOSUploadJob(job *Job, ipaPath string, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			jobManager.SetJobError(job.ID, fmt.Errorf("panic: %v", r))
		}
	}()

	// Update status to analyzing
	jobManager.UpdateJobStatus(job.ID, JobAnalyzing, "Starting iOS analysis...")

	// Create report directory
	runID := time.Now().Format("20060102-150405")
	outDir := filepath.Join(reportsRoot, runID)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		jobManager.SetJobError(job.ID, fmt.Errorf("failed to create report directory: %v", err))
		return
	}

	// Write meta for iOS
	metaData := map[string]string{
		"original_ipa": filepath.Base(ipaPath),
		"source":       "upload",
	}
	metaJSON, _ := json.Marshal(metaData)
	_ = os.WriteFile(filepath.Join(outDir, "apk.name"), metaJSON, 0644)

	// Run iOS analyzer
	generateHTML := r.FormValue("html") != ""
	sendDiscord := r.FormValue("send_discord") != ""
	webhookURL := strings.TrimSpace(r.FormValue("webhook"))

	// Use form webhook if provided, otherwise use server default
	if sendDiscord {
		if webhookURL == "" {
			webhookURL = serverDefaultWebhook
		}
	} else {
		webhookURL = ""
	}

	cfg := analyzer.Config{
		APKPath:      ipaPath,
		OutputDir:    outDir,
		PatternsPath: patternsPathDefault,
		Workers:      3,
		HTMLOutput:   generateHTML,
		WebhookURL:   webhookURL,
	}

	iosAnalyzer := analyzer.NewIOSAnalyzer(&cfg)
	if err := iosAnalyzer.AnalyzeIPA(ipaPath); err != nil {
		log.Printf("Job %s: iOS analysis error: %v", job.ID, err)
		jobManager.SetJobError(job.ID, fmt.Errorf("iOS analysis failed: %v", err))
		return
	}

	// Job completed successfully
	jobManager.SetJobReportID(job.ID, runID)
	jobManager.UpdateJobStatus(job.ID, JobCompleted, "iOS analysis completed successfully")
	log.Printf("Job %s: iOS analysis completed successfully", job.ID)
	
	// Upload reports to GitLab if enabled
	if useGitLabStorage {
		go uploadReportToGitLab(outDir, runID)
		// Cleanup temp upload file
		go func() {
			time.Sleep(5 * time.Second)
			os.Remove(ipaPath)
			log.Printf("🗑️  Cleaned up temp file: %s", ipaPath)
		}()
	}
}

func saveUploadedFile(file multipart.File, header *multipart.FileHeader) (string, error) {
	// Check file size before saving
	if header.Size == 0 {
		return "", fmt.Errorf("uploaded file is empty (0 bytes). Please check the file and try again")
	}

	safeFilename := safeName(header.Filename)
	
	if useGitLabStorage {
		// Save to temp directory for processing
		dst := filepath.Join(uploadDir, safeFilename)
		os.MkdirAll(filepath.Dir(dst), 0755)
		
		out, err := os.Create(dst)
		if err != nil {
			return "", err
		}
		
		// Save to temp file and GitLab simultaneously
		tee := io.TeeReader(file, out)
		
		// Upload to GitLab
		storagePath := "uploads/" + safeFilename
		if err := storageBackend.SaveFile(storagePath, tee); err != nil {
			out.Close()
			log.Printf("⚠️  Warning: Failed to upload to GitLab: %v", err)
			// Continue anyway, file is in temp
		} else {
			log.Printf("✅ Uploaded to GitLab: %s", storagePath)
		}
		
		out.Close()
		return dst, nil
	} else {
		// Local storage (original behavior)
		dst := filepath.Join(uploadDir, safeFilename)
		out, err := os.Create(dst)
		if err != nil {
			return "", err
		}
		defer out.Close()

		bytesWritten, err := io.Copy(out, file)
		if err != nil {
			return "", err
		}

		// Double-check the saved file size
		if bytesWritten == 0 {
			return "", fmt.Errorf("saved file is empty (0 bytes). The uploaded file may be corrupted")
		}

		return dst, nil
	}
}

func safeName(name string) string {
	name = filepath.Base(name)
	repl := strings.NewReplacer(" ", "-", "..", ".", "/", "-", "\\", "-")
	name = repl.Replace(name)
	return name
}

func readString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// convertXAPKToAPK extracts the base APK from a .xapk file and returns the new APK path.
func convertXAPKToAPK(xapkPath string) (string, error) {
	// Open the XAPK as a zip archive
	zr, err := zip.OpenReader(xapkPath)
	if err != nil {
		return "", fmt.Errorf("failed to open XAPK: %v", err)
	}
	defer zr.Close()

	// Create a temp folder to extract
	baseName := strings.TrimSuffix(filepath.Base(xapkPath), filepath.Ext(xapkPath))
	extractDir := filepath.Join(os.TempDir(), "apkx-xapk-"+baseName)
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create extract dir: %v", err)
	}

	// Extract all files
	for _, f := range zr.File {
		destPath := filepath.Join(extractDir, f.Name)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return "", fmt.Errorf("failed to create dir: %v", err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return "", fmt.Errorf("failed to create parent dir: %v", err)
		}
		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("failed to open file in zip: %v", err)
		}
		out, err := os.Create(destPath)
		if err != nil {
			rc.Close()
			return "", fmt.Errorf("failed to create dest file: %v", err)
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			return "", fmt.Errorf("failed to copy file: %v", err)
		}
		out.Close()
		rc.Close()
	}

	// Common locations for base APK inside XAPK
	candidatePaths := []string{
		filepath.Join(extractDir, "base.apk"),
		filepath.Join(extractDir, "app.apk"),
		filepath.Join(extractDir, "Android", "obb", "base.apk"),
	}
	// Also scan for any .apk if the above not found
	var found string
	for _, p := range candidatePaths {
		if _, err := os.Stat(p); err == nil {
			found = p
			break
		}
	}
	if found == "" {
		// Walk to find the first .apk
		_ = filepath.WalkDir(extractDir, func(path string, d os.DirEntry, err error) error {
			if found != "" || err != nil {
				return nil
			}
			if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".apk") && !strings.HasSuffix(strings.ToLower(d.Name()), ".idsig") {
				found = path
			}
			return nil
		})
	}
	if found == "" {
		return "", fmt.Errorf("no APK found inside XAPK")
	}

	// Move the APK to downloads with a sane name
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return "", fmt.Errorf("failed to ensure downloads dir: %v", err)
	}
	outName := baseName + ".apk"
	dest := filepath.Join(downloadDir, outName)

	in, err := os.Open(found)
	if err != nil {
		return "", fmt.Errorf("failed to open extracted APK: %v", err)
	}
	defer in.Close()
	out, err := os.Create(dest)
	if err != nil {
		return "", fmt.Errorf("failed to create dest APK: %v", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return "", fmt.Errorf("failed to copy APK: %v", err)
	}
	out.Close()

	return dest, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func handleDeleteReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reportID := strings.TrimPrefix(r.URL.Path, "/api/report/delete/")
	if reportID == "" {
		http.Error(w, "report ID is required", http.StatusBadRequest)
		return
	}

	// Check if report directory exists
	reportDir := filepath.Join(reportsRoot, reportID)
	if _, err := os.Stat(reportDir); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}

	// Delete the report directory and all its contents
	if err := os.RemoveAll(reportDir); err != nil {
		log.Printf("Failed to delete report %s: %v", reportID, err)
		http.Error(w, "failed to delete report", http.StatusInternalServerError)
		return
	}

	log.Printf("Report %s deleted successfully", reportID)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func handleInstallAPK(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reportID := strings.TrimPrefix(r.URL.Path, "/api/install/")
	if reportID == "" {
		http.Error(w, "report ID is required", http.StatusBadRequest)
		return
	}

	// Find the APK file for this report
	reportDir := filepath.Join(reportsRoot, reportID)
	apkNamePath := filepath.Join(reportDir, "apk.name")

	metaContent, err := os.ReadFile(apkNamePath)
	if err != nil {
		http.Error(w, "report not found", http.StatusNotFound)
		return
	}

	// Try to parse as JSON first (new format)
	var metaData map[string]string
	var fileName string
	var apkPath string

	if err := json.Unmarshal(metaContent, &metaData); err == nil {
		// New JSON format - check if MITM was enabled
		mitmEnabled := metaData["mitm_enabled"] == "true"

		if mitmEnabled && metaData["patched_apk"] != "" {
			// MITM was enabled - serve the patched APK
			fileName = metaData["patched_apk"]
			apkPath = filepath.Join(downloadDir, fileName)
		} else {
			// MITM was not enabled - serve the original APK
			fileName = metaData["original_apk"]
			// Look for the original APK in uploads or downloads
			uploadPath := filepath.Join(uploadDir, fileName)
			downloadPath := filepath.Join(downloadDir, fileName)

			if _, err := os.Stat(uploadPath); err == nil {
				apkPath = uploadPath
			} else if _, err := os.Stat(downloadPath); err == nil {
				apkPath = downloadPath
			} else {
				http.Error(w, "APK file not found", http.StatusNotFound)
				return
			}
		}
	} else {
		// Old format - just filename
		fileName = strings.TrimSpace(string(metaContent))
		// Look for the APK file in uploads or downloads
		uploadPath := filepath.Join(uploadDir, fileName)
		downloadPath := filepath.Join(downloadDir, fileName)

		if _, err := os.Stat(uploadPath); err == nil {
			apkPath = uploadPath
		} else if _, err := os.Stat(downloadPath); err == nil {
			apkPath = downloadPath
		} else {
			http.Error(w, "APK file not found", http.StatusNotFound)
			return
		}
	}

	// Verify the file exists
	if _, err := os.Stat(apkPath); err != nil {
		http.Error(w, "APK file not found", http.StatusNotFound)
		return
	}

	// Set headers for file download
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	w.Header().Set("Content-Type", "application/vnd.android.package-archive")

	// Open and serve the file
	file, err := os.Open(apkPath)
	if err != nil {
		http.Error(w, "failed to open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Copy file to response
	_, err = io.Copy(w, file)
	if err != nil {
		log.Printf("Failed to serve APK %s: %v", apkPath, err)
		return
	}

	log.Printf("APK %s downloaded successfully", fileName)
}

func applyMITMPatch(apkPath string) (string, error) {
	// Check if apk-mitm is available
	if _, err := exec.LookPath("apk-mitm"); err != nil {
		return "", fmt.Errorf("apk-mitm not found in PATH: %v", err)
	}

	// Create a temporary directory for the patched APK
	tempDir, err := os.MkdirTemp("", "apkx-mitm-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir) // Clean up at the end

	// Run apk-mitm command with --keep-tmp-dir to prevent cleanup
	cmd := exec.Command("apk-mitm", apkPath, "--tmp-dir", tempDir, "--keep-tmp-dir")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("apk-mitm failed: %v, output: %s", err, string(output))
	}

	// Find the patched APK file in the temp directory
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		return "", fmt.Errorf("failed to read temp directory: %v", err)
	}

	var patchedAPK string
	for _, entry := range entries {
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".apk") || strings.HasSuffix(entry.Name(), ".xapk")) {
			// Skip signature files
			if !strings.HasSuffix(entry.Name(), ".idsig") {
				patchedAPK = filepath.Join(tempDir, entry.Name())
				break
			}
		}
	}

	if patchedAPK == "" {
		return "", fmt.Errorf("no patched APK found in output directory")
	}

	// Copy the patched APK to the downloads directory
	originalName := filepath.Base(apkPath)
	nameWithoutExt := strings.TrimSuffix(originalName, filepath.Ext(originalName))
	ext := filepath.Ext(originalName)
	patchedName := nameWithoutExt + "-mitm-patched" + ext
	patchedPath := filepath.Join(downloadDir, patchedName)

	// Copy file
	src, err := os.Open(patchedAPK)
	if err != nil {
		return "", fmt.Errorf("failed to open patched APK: %v", err)
	}
	defer src.Close()

	dst, err := os.Create(patchedPath)
	if err != nil {
		return "", fmt.Errorf("failed to create patched APK: %v", err)
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	if err != nil {
		return "", fmt.Errorf("failed to copy patched APK: %v", err)
	}

	log.Printf("MITM patch applied successfully: %s", patchedPath)
	return patchedPath, nil
}

func handleDownloadManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reportID := strings.TrimPrefix(r.URL.Path, "/api/manifest/")
	if reportID == "" {
		http.Error(w, "report ID is required", http.StatusBadRequest)
		return
	}

	// Find the AndroidManifest.xml file for this report
	reportDir := filepath.Join(reportsRoot, reportID)

	// Look for AndroidManifest.xml in common decompilation output locations
	manifestPaths := []string{
		filepath.Join(reportDir, "AndroidManifest.xml"),
		filepath.Join(reportDir, "sources", "AndroidManifest.xml"),
		filepath.Join(reportDir, "resources", "AndroidManifest.xml"),
		filepath.Join(reportDir, "res", "AndroidManifest.xml"),
	}

	var manifestPath string
	for _, path := range manifestPaths {
		if _, err := os.Stat(path); err == nil {
			manifestPath = path
			break
		}
	}

	if manifestPath == "" {
		http.Error(w, "AndroidManifest.xml not found", http.StatusNotFound)
		return
	}

	// Set headers for file download
	w.Header().Set("Content-Disposition", "attachment; filename=AndroidManifest.xml")
	w.Header().Set("Content-Type", "application/xml")

	// Open and serve the file
	file, err := os.Open(manifestPath)
	if err != nil {
		http.Error(w, "failed to open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Copy file to response
	_, err = io.Copy(w, file)
	if err != nil {
		log.Printf("Failed to serve AndroidManifest.xml %s: %v", manifestPath, err)
		return
	}

	log.Printf("AndroidManifest.xml %s downloaded successfully", reportID)
}

func handleDownloadPlist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reportID := strings.TrimPrefix(r.URL.Path, "/api/plist/")
	if reportID == "" {
		http.Error(w, "report ID is required", http.StatusBadRequest)
		return
	}

	// Find the Info.plist file for this iOS report
	reportDir := filepath.Join(reportsRoot, reportID)

	// Look for Info.plist in common iOS extraction locations
	plistPaths := []string{
		filepath.Join(reportDir, "Info.plist"),
		filepath.Join(reportDir, "Payload", "Info.plist"),
		filepath.Join(reportDir, "Payload", "*.app", "Info.plist"),
	}

	var plistPath string
	for _, path := range plistPaths {
		if strings.Contains(path, "*") {
			// Handle glob pattern for .app directory
			matches, err := filepath.Glob(path)
			if err == nil && len(matches) > 0 {
				plistPath = matches[0]
				break
			}
		} else {
			if _, err := os.Stat(path); err == nil {
				plistPath = path
				break
			}
		}
	}

	// If not found in common locations, search for any Info.plist file
	if plistPath == "" {
		err := filepath.Walk(reportDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() && strings.HasSuffix(path, "Info.plist") {
				plistPath = path
				return filepath.SkipDir // Stop searching once found
			}
			return nil
		})
		if err != nil {
			http.Error(w, "failed to search for Info.plist", http.StatusInternalServerError)
			return
		}
	}

	if plistPath == "" {
		http.Error(w, "Info.plist not found", http.StatusNotFound)
		return
	}

	// Read the plist file
	plistContent, err := os.ReadFile(plistPath)
	if err != nil {
		http.Error(w, "failed to read file", http.StatusInternalServerError)
		return
	}

	// Convert binary plist to XML if needed
	xmlContent := convertPlistToXML(plistContent)

	// Set headers for file download
	w.Header().Set("Content-Disposition", "attachment; filename=Info.plist")
	w.Header().Set("Content-Type", "application/xml")

	// Serve the converted content
	_, err = w.Write(xmlContent)
	if err != nil {
		log.Printf("Failed to serve Info.plist %s: %v", plistPath, err)
		return
	}

	log.Printf("Info.plist %s downloaded successfully", reportID)
}

// convertPlistToXML converts binary plist to XML format
func convertPlistToXML(plistContent []byte) []byte {
	// Check if it's already XML
	if len(plistContent) > 5 && string(plistContent[:5]) == "<?xml" {
		return plistContent
	}

	// Check if it's a binary plist
	if len(plistContent) > 8 && string(plistContent[:8]) == "bplist00" {
		// Try to convert using plutil command (macOS/Linux)
		cmd := exec.Command("plutil", "-convert", "xml1", "-o", "-", "-")
		cmd.Stdin = strings.NewReader(string(plistContent))
		output, err := cmd.Output()
		if err == nil {
			return output
		}

		// Fallback: Create a basic XML structure from binary plist
		return createBasicXMLFromBinaryPlist(plistContent)
	}

	// If not binary plist, return original content
	return plistContent
}

// createBasicXMLFromBinaryPlist creates a basic XML structure from binary plist
func createBasicXMLFromBinaryPlist(plistContent []byte) []byte {
	var result strings.Builder
	result.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	result.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	result.WriteString("<plist version=\"1.0\">\n<dict>\n")

	// Extract key-value pairs from binary plist
	keyValuePairs := extractKeyValuePairsFromBinaryPlist(plistContent)

	for key, value := range keyValuePairs {
		result.WriteString(fmt.Sprintf("  <key>%s</key>\n", key))
		result.WriteString(fmt.Sprintf("  <string>%s</string>\n", value))
	}

	result.WriteString("</dict>\n</plist>\n")
	return []byte(result.String())
}

// extractKeyValuePairsFromBinaryPlist extracts key-value pairs from binary plist
func extractKeyValuePairsFromBinaryPlist(plistContent []byte) map[string]string {
	pairs := make(map[string]string)

	// Simple extraction of readable strings
	content := string(plistContent)

	// Common iOS plist keys and their likely values
	commonKeys := []string{
		"CFBundleIdentifier", "CFBundleName", "CFBundleVersion", "CFBundleShortVersionString",
		"CFBundleExecutable", "CFBundlePackageType", "CFBundleSupportedPlatforms",
		"LSRequiresIPhoneOS", "MinimumOSVersion", "NSAppTransportSecurity",
		"NSCameraUsageDescription", "UIDeviceFamily", "UIMainStoryboardFile",
		"UIRequiredDeviceCapabilities", "UISupportedInterfaceOrientations",
		"CFBundleURLTypes", "CFBundleURLSchemes", "CFBundleURLName",
		"NSAllowsArbitraryLoads", "CFBundleIcons", "CFBundleIconFiles",
		"UILaunchImages", "UILaunchImageName", "UILaunchImageOrientation",
		"UILaunchImageSize", "UIInterfaceOrientationPortrait",
		"UIInterfaceOrientationPortraitUpsideDown", "UIInterfaceOrientationLandscapeLeft",
		"UIInterfaceOrientationLandscapeRight", "CFBundlePrimaryIcon",
		"CFBundleIconName", "CFBundleDevelopmentRegion", "CFBundleInfoDictionaryVersion",
		"DTPlatformBuild", "DTPlatformName", "DTPlatformVersion", "DTSDKBuild",
		"DTSDKName", "DTXcode", "DTXcodeBuild", "BuildMachineOSBuild",
		"CFBundleSignature", "CFBundleExecutable", "CFBundlePackageType",
		"CFBundleSupportedPlatforms", "CFBundleURLTypes", "CFBundleURLSchemes",
		"CFBundleURLName", "CFBundleURLTypes", "CFBundleURLSchemes",
		"CFBundleURLName", "CFBundleURLTypes", "CFBundleURLSchemes",
	}

	// Extract values for each key
	for _, key := range commonKeys {
		if strings.Contains(content, key) {
			// Try to find a value after the key
			keyIndex := strings.Index(content, key)
			if keyIndex != -1 {
				// Look for a value in the next 200 characters
				searchArea := content[keyIndex:min(keyIndex+200, len(content))]

				// Extract potential values (simplified)
				if strings.Contains(searchArea, "com.") {
					// Look for bundle identifier
					start := strings.Index(searchArea, "com.")
					if start != -1 {
						end := start
						for end < len(searchArea) && end < start+100 {
							if searchArea[end] < 32 || searchArea[end] > 126 {
								break
							}
							end++
						}
						if end > start {
							value := searchArea[start:end]
							if len(value) > 3 {
								pairs[key] = value
							}
						}
					}
				}
			}
		}
	}

	// If no pairs found, add a note
	if len(pairs) == 0 {
		pairs["Note"] = "Binary plist detected - use a proper plist viewer to see full content"
		pairs["Format"] = "Binary Property List (bplist00)"
	}

	return pairs
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func getEnv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

// detectProjectRoot attempts to find the apkX project root by:
// 1) Using APKX_ROOT if set
// 2) Walking up from the executable dir
// 3) Walking up from the current working directory
// A directory is considered the root if it contains either config/regexes.yaml or web-data/.
func detectProjectRoot() string {
	if root := os.Getenv("APKX_ROOT"); root != "" {
		return root
	}

	tryDirs := []string{}

	if exePath, err := os.Executable(); err == nil {
		tryDirs = append(tryDirs, filepath.Dir(exePath))
	}
	if cwd, err := os.Getwd(); err == nil {
		tryDirs = append(tryDirs, cwd)
	}

	for _, start := range tryDirs {
		dir := start
		for {
			if looksLikeRoot(dir) {
				return dir
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	return "."
}

func looksLikeRoot(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "config", "regexes.yaml")); err == nil {
		return true
	}
	if info, err := os.Stat(filepath.Join(dir, "web-data")); err == nil && info.IsDir() {
		return true
	}
	if info, err := os.Stat(filepath.Join(dir, ".git")); err == nil && info.IsDir() {
		return true
	}
	if modFile := filepath.Join(dir, "go.mod"); fileExists(modFile) {
		b, _ := os.ReadFile(modFile)
		if strings.Contains(string(b), "github.com/h0tak88r/apkX") {
			return true
		}
	}
	return false
}

// uploadReportToGitLab uploads all report files to GitLab storage
func uploadReportToGitLab(reportDir, reportID string) {
	log.Printf("📤 Uploading report %s to GitLab...", reportID)
	uploaded := 0
	failed := 0
	
	filepath.Walk(reportDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		
		// Get relative path from report dir
		relPath, err := filepath.Rel(reportDir, path)
		if err != nil {
			return nil
		}
		
		// Create GitLab storage path
		storagePath := fmt.Sprintf("reports/%s/%s", reportID, relPath)
		
		// Read and upload file
		f, err := os.Open(path)
		if err != nil {
			log.Printf("⚠️  Failed to open %s: %v", path, err)
			failed++
			return nil
		}
		defer f.Close()
		
		if err := storageBackend.SaveFile(storagePath, f); err != nil {
			log.Printf("⚠️  Failed to upload %s: %v", storagePath, err)
			failed++
		} else {
			uploaded++
		}
		
		return nil
	})
	
	log.Printf("✅ Report uploaded to GitLab: %d files uploaded, %d failed", uploaded, failed)
	
	// Cleanup temp report directory after successful upload
	if failed == 0 {
		go func() {
			time.Sleep(10 * time.Second)
			os.RemoveAll(reportDir)
			log.Printf("🗑️  Cleaned up temp report: %s", reportDir)
		}()
	}
}
