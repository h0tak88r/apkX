package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/apkX/internal/storage"
)

var (
	// Storage backend (GitLab or Local)
	storageBackend storage.StorageBackend
	useGitLabStorage bool
	
	// Temporary local directories for processing
	tempDir         string
	patternsPath    string
)

func init() {
	// Check if GitLab storage should be used
	if os.Getenv("USE_GITLAB_STORAGE") == "true" {
		gitlabProject := os.Getenv("GITLAB_PROJECT")
		gitlabToken := os.Getenv("GITLAB_TOKEN")
		
		if gitlabProject != "" && gitlabToken != "" {
			log.Printf("Using GitLab storage backend (project: %s)", gitlabProject)
			gitlab := storage.NewGitLabStorage(gitlabProject, gitlabToken)
			
			// Ensure storage branch exists
			if err := gitlab.EnsureBranchExists(); err != nil {
				log.Printf("Warning: Failed to ensure GitLab branch exists: %v", err)
				log.Printf("Falling back to local storage")
				storageBackend = storage.NewLocalStorage("web-data")
			} else {
				storageBackend = gitlab
				useGitLabStorage = true
			}
		} else {
			log.Printf("GitLab storage enabled but credentials missing (GITLAB_PROJECT or GITLAB_TOKEN)")
			log.Printf("Falling back to local storage")
			storageBackend = storage.NewLocalStorage("web-data")
		}
	} else {
		log.Printf("Using local filesystem storage")
		storageBackend = storage.NewLocalStorage("web-data")
	}
	
	// Setup temp directory for processing
	tempDir = os.Getenv("APKX_TEMP_DIR")
	if tempDir == "" {
		tempDir = "/tmp/apkx"
	}
	os.MkdirAll(tempDir, 0755)
	
	// Setup patterns path
	patternsPath = os.Getenv("APKX_PATTERNS_PATH")
	if patternsPath == "" {
		patternsPath = "config/regexes.yaml"
	}
}

// Optional global Discord webhook
var serverDefaultWebhook string

// Global MITM patching flag
var enableMITMPatch bool

// Job management (same as original)
type JobStatus string

const (
	Version                  = "v3.3.0-gitlab"
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

	job := &Job{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		PackageName: packageName,
		Version:     version,
		Source:      source,
		Status:      JobPending,
		CreatedAt:   time.Now(),
	}

	jm.jobs[job.ID] = job
	return job
}

func (jm *JobManager) GetJob(jobID string) (*Job, bool) {
	jm.mutex.RLock()
	defer jm.mutex.RUnlock()

	job, exists := jm.jobs[jobID]
	return job, exists
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

func main() {
	log.Printf("apkX v%s - GitLab Storage Edition", Version)
	log.Printf("Storage backend: %T", storageBackend)
	log.Printf("Temp directory: %s", tempDir)
	log.Printf("Patterns path: %s", patternsPath)

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/upload", handleUploadAsync)
	http.HandleFunc("/api/jobs", handleJobsAPI)
	http.HandleFunc("/api/job/", handleJobAPI)
	http.HandleFunc("/reports/", handleReportsProxy)

	// Address selection
	defaultAddr := ":" + getEnv("PORT", "9090")
	addr := flag.String("addr", defaultAddr, "HTTP listen address")
	webhook := flag.String("webhook", getEnv("DISCORD_WEBHOOK", ""), "Discord webhook URL")
	mitm := flag.Bool("mitm", false, "Enable MITM patching")
	flag.Parse()

	serverDefaultWebhook = *webhook
	enableMITMPatch = *mitm

	log.Printf("Starting server on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	// List reports from storage backend
	files, err := storageBackend.ListFiles("reports")
	if err != nil {
		log.Printf("Error listing reports: %v", err)
		files = []storage.FileInfo{}
	}

	data := struct {
		Version     string
		Storage     string
		ReportCount int
		Jobs        []*Job
	}{
		Version:     Version,
		Storage:     getStorageType(),
		ReportCount: len(files),
		Jobs:        jobManager.GetAllJobs(),
	}

	tmpl := template.Must(template.New("index").Parse(indexHTML))
	tmpl.Execute(w, data)
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

	// Save to temporary local storage first
	tempPath := filepath.Join(tempDir, "uploads", safeName(header.Filename))
	os.MkdirAll(filepath.Dir(tempPath), 0755)
	
	out, err := os.Create(tempPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	_, err = io.Copy(out, file)
	out.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Upload to storage backend
	f, err := os.Open(tempPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	storagePath := "uploads/" + safeName(header.Filename)
	if err := storageBackend.SaveFile(storagePath, f); err != nil {
		log.Printf("Failed to save file to storage: %v", err)
		http.Error(w, "failed to save file", http.StatusInternalServerError)
		return
	}

	// Create job
	fileName := filepath.Base(tempPath)
	job := jobManager.CreateJob(fileName, "", "upload")

	// Start background processing
	go processUploadJob(job, tempPath, r)

	// Redirect with success
	http.Redirect(w, r, "/?upload=success&job_id="+job.ID, http.StatusSeeOther)
}

func processUploadJob(job *Job, filePath string, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			jobManager.SetJobError(job.ID, fmt.Errorf("panic: %v", r))
		}
		// Cleanup temp file
		os.Remove(filePath)
	}()

	jobManager.UpdateJobStatus(job.ID, JobAnalyzing, "Starting analysis...")

	// Create temp report directory
	runID := time.Now().Format("20060102-150405")
	tempReportDir := filepath.Join(tempDir, "reports", runID)
	os.MkdirAll(tempReportDir, 0755)
	defer os.RemoveAll(tempReportDir) // Cleanup temp report dir

	// Run analysis (simplified - you'll need to adapt your full analysis logic)
	cmd := exec.Command("./apkx", "-apk", filePath, "-html", "-o", tempReportDir)
	if err := cmd.Run(); err != nil {
		jobManager.SetJobError(job.ID, fmt.Errorf("analysis failed: %v", err))
		return
	}

	// Upload all report files to storage
	filepath.Walk(tempReportDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(tempReportDir, path)
		storagePath := fmt.Sprintf("reports/%s/%s", runID, relPath)

		f, err := os.Open(path)
		if err != nil {
			log.Printf("Failed to open report file %s: %v", path, err)
			return nil
		}
		defer f.Close()

		if err := storageBackend.SaveFile(storagePath, f); err != nil {
			log.Printf("Failed to save report file %s: %v", storagePath, err)
		}
		return nil
	})

	jobManager.SetJobReportID(job.ID, runID)
	jobManager.UpdateJobStatus(job.ID, JobCompleted, "Analysis completed")
	log.Printf("Job %s completed, report ID: %s", job.ID, runID)
}

func handleReportsProxy(w http.ResponseWriter, r *http.Request) {
	// Extract path
	path := strings.TrimPrefix(r.URL.Path, "/reports/")
	storagePath := "reports/" + path

	// Read file from storage
	reader, err := storageBackend.ReadFile(storagePath)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	defer reader.Close()

	// Determine content type
	contentType := "text/html"
	if strings.HasSuffix(path, ".json") {
		contentType = "application/json"
	} else if strings.HasSuffix(path, ".xml") {
		contentType = "application/xml"
	}

	w.Header().Set("Content-Type", contentType)
	io.Copy(w, reader)
}

func handleJobsAPI(w http.ResponseWriter, r *http.Request) {
	jobs := jobManager.GetAllJobs()
	json.NewEncoder(w).Encode(jobs)
}

func handleJobAPI(w http.ResponseWriter, r *http.Request) {
	jobID := strings.TrimPrefix(r.URL.Path, "/api/job/")
	job, exists := jobManager.GetJob(jobID)
	if !exists {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(job)
}

func (jm *JobManager) GetAllJobs() []*Job {
	jm.mutex.RLock()
	defer jm.mutex.RUnlock()

	var jobs []*Job
	for _, job := range jm.jobs {
		jobs = append(jobs, job)
	}
	return jobs
}

func safeName(name string) string {
	name = filepath.Base(name)
	repl := strings.NewReplacer(" ", "-", "..", ".", "/", "-", "\\", "-")
	return repl.Replace(name)
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getStorageType() string {
	if useGitLabStorage {
		return "GitLab"
	}
	return "Local Filesystem"
}

const indexHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>apkX - GitLab Storage Edition</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: #4CAF50; color: white; padding: 20px; border-radius: 5px; }
        .info { background: #f0f0f0; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .upload-form { background: white; padding: 20px; border: 2px dashed #ccc; border-radius: 5px; margin: 20px 0; }
        input[type="file"] { padding: 10px; }
        button { background: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #45a049; }
        .jobs { margin-top: 20px; }
        .job { background: #f9f9f9; padding: 10px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 apkX - GitLab Storage Edition</h1>
        <p>Version: {{.Version}} | Storage: {{.Storage}}</p>
    </div>

    <div class="info">
        <h3>📊 System Status</h3>
        <p>Reports stored: {{.ReportCount}}</p>
        <p>Active jobs: {{len .Jobs}}</p>
    </div>

    <div class="upload-form">
        <h3>📤 Upload APK/IPA File</h3>
        <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="apk" accept=".apk,.ipa,.xapk" required>
            <button type="submit">Upload & Analyze</button>
        </form>
    </div>

    <div class="jobs">
        <h3>📋 Recent Jobs</h3>
        {{range .Jobs}}
        <div class="job">
            <strong>{{.PackageName}}</strong> - Status: {{.Status}}
            {{if .ReportID}}
            <a href="/reports/{{.ReportID}}/security-report.html">View Report</a>
            {{end}}
        </div>
        {{end}}
    </div>
</body>
</html>
`

