package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/apkX/internal/analyzer"
	"github.com/h0tak88r/apkX/internal/downloader"
	"github.com/h0tak88r/apkX/internal/utils"
)

const (
	version = "v3.2.0" // iOS support with ipatool integration
)

func printBanner() {
	fmt.Printf("\033[1;36m\n📅 Started at: %s\033[0m\n\n", time.Now().Format("2006-01-02 15:04:05"))
	banner := `         
	┌─┐┌─┐┬┌─═╗ ╦
	├─┤├─┘├┴┐╔╩╦╝
	┴ ┴┴  ┴ ┴╩ ╚═ by: h0tak88r
            				
`
	fmt.Printf("%s%s%s\n", utils.ColorHeader, banner, utils.ColorEnd)
	fmt.Printf(" Version: %s\n", version) // Add version display
	fmt.Println(" --")
	fmt.Println(" Scanning APK/IPA files for URIs, endpoints, secrets & security vulnerabilities")
	fmt.Println(" Supports: Android APK, iOS IPA, XAPK files")
	fmt.Println()
}

func main() {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime).Round(time.Second)
		fmt.Printf("\n%s🕒 Tool runtime: %s%s\n", utils.ColorBlue, duration, utils.ColorEnd)
	}()

	var (
		apkPath       string
		ipaPath       string
		bundleID      string
		iosVersion    string
		outputDir     string
		patternsPath  string
		workers       int
		webhookURL    string
		taskHijacking bool
		htmlOutput    bool
		janusScan     bool
		downloadIOS   bool
	)

	flag.StringVar(&apkPath, "apk", "", "Path to APK file")
	flag.StringVar(&ipaPath, "ipa", "", "Path to IPA file")
	flag.StringVar(&bundleID, "bundle-id", "", "iOS app bundle ID to download and analyze")
	flag.StringVar(&iosVersion, "ios-version", "", "iOS app version to download (optional)")
	flag.StringVar(&outputDir, "o", "apkx-output", "Output directory for results")
	flag.StringVar(&patternsPath, "p", "config/regexes.yaml", "Path to patterns file")
	flag.IntVar(&workers, "w", 3, "Number of concurrent workers")
	flag.StringVar(&webhookURL, "wh", "", "Discord webhook URL to send results")
	flag.BoolVar(&taskHijacking, "task-hijacking", false, "Only scan for task hijacking vulnerabilities")
	flag.BoolVar(&htmlOutput, "html", false, "Generate HTML report")
	flag.BoolVar(&janusScan, "janus", false, "Enable Janus vulnerability scanning")
	flag.BoolVar(&downloadIOS, "download-ios", false, "Download iOS app using ipatool")
	flag.Parse()

	// Get remaining arguments as files
	files := flag.Args()

	// Handle iOS app download
	if downloadIOS && bundleID != "" {
		if err := handleIOSDownload(bundleID, iosVersion, outputDir, patternsPath, webhookURL, htmlOutput); err != nil {
			fmt.Printf("%sError downloading iOS app: %v%s\n", utils.ColorRed, err, utils.ColorEnd)
			os.Exit(1)
		}
		return
	}

	// Handle IPA file analysis
	if ipaPath != "" {
		if err := handleIPAAnalysis(ipaPath, outputDir, patternsPath, webhookURL, htmlOutput); err != nil {
			fmt.Printf("%sError analyzing IPA: %v%s\n", utils.ColorRed, err, utils.ColorEnd)
			os.Exit(1)
		}
		return
	}

	// If no additional args but apkPath is set, use that
	if len(files) == 0 && apkPath != "" {
		files = []string{apkPath}
	}

	// Validate we have at least one file
	if len(files) == 0 {
		fmt.Printf("%sError: No files specified. Use -apk, -ipa, or -bundle-id%s\n", utils.ColorRed, utils.ColorEnd)
		flag.Usage()
		os.Exit(1)
	}

	printBanner()

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("%sError creating output directory: %v%s\n", utils.ColorRed, err, utils.ColorEnd)
		os.Exit(1)
	}

	// Create work channel and wait group
	jobs := make(chan string, len(files))
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(i, jobs, &wg, outputDir, patternsPath, webhookURL, taskHijacking, htmlOutput, janusScan)
	}

	// Queue jobs
	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			fmt.Printf("%sWarning: File not found: %s%s\n", utils.ColorYellow, file, utils.ColorEnd)
			continue
		}
		jobs <- file
	}
	close(jobs)

	// Wait for all workers to finish
	wg.Wait()
}

func worker(id int, jobs <-chan string, wg *sync.WaitGroup, outputDir, patternsPath, webhookURL string, taskHijacking, htmlOutput, janusScan bool) {
	defer wg.Done()

	for apkFile := range jobs {
		fmt.Printf("\n%s╭─ Worker %d ─╮%s\n", utils.ColorCyan, id, utils.ColorEnd)
		fmt.Printf("%s│ Processing: %s%s\n", utils.ColorCyan, filepath.Base(apkFile), utils.ColorEnd)
		fmt.Printf("%s╰───────────╯%s\n", utils.ColorCyan, utils.ColorEnd)

		// Create output file path based on APK name
		baseName := filepath.Base(apkFile)
		nameWithoutExt := strings.TrimSuffix(baseName, filepath.Ext(baseName))
		cleanName := cleanFileName(nameWithoutExt)
		outputFile := filepath.Join(outputDir, cleanName+"-apkx.json")

		config := analyzer.Config{
			APKPath:        apkFile,
			OutputDir:      outputDir,
			PatternsPath:   patternsPath,
			Workers:        id + 1,
			WebhookURL:     webhookURL,
			TaskHijackOnly: taskHijacking,
			HTMLOutput:     htmlOutput,
			JanusScan:      janusScan,
		}

		scanner := analyzer.NewAPKScanner(&config)
		if err := scanner.Run(); err != nil {
			fmt.Printf("\n%s╭─ Error ─╮%s\n", utils.ColorRed, utils.ColorEnd)
			fmt.Printf("%s│ Worker %d: Failed to process %s%s\n",
				utils.ColorRed, id, filepath.Base(apkFile), utils.ColorEnd)
			fmt.Printf("%s│ Error: %v%s\n", utils.ColorRed, err, utils.ColorEnd)
			fmt.Printf("%s╰─────────╯%s\n", utils.ColorRed, utils.ColorEnd)
			continue
		}

		if absPath, err := filepath.Abs(outputFile); err == nil {
			fmt.Printf("\n%s╭─ Success ─╮%s\n", utils.ColorGreen, utils.ColorEnd)
			fmt.Printf("%s│ Results saved to: %s%s\n",
				utils.ColorGreen, absPath, utils.ColorEnd)
			fmt.Printf("%s╰───────────╯%s\n", utils.ColorGreen, utils.ColorEnd)
		}
	}
}

// Helper function to clean filenames
func cleanFileName(name string) string {
	// Replace special characters and spaces
	replacer := strings.NewReplacer(
		" ", "-",
		":", "-",
		"/", "-",
		"\\", "-",
		"*", "",
		"?", "",
		"\"", "",
		"<", "",
		">", "",
		"|", "",
		".", "-",
	)
	cleaned := replacer.Replace(name)

	// Remove any double dashes
	for strings.Contains(cleaned, "--") {
		cleaned = strings.ReplaceAll(cleaned, "--", "-")
	}

	// Trim dashes from start and end
	cleaned = strings.Trim(cleaned, "-")

	return cleaned
}

// handleIOSDownload downloads and analyzes an iOS app using ipatool
func handleIOSDownload(bundleID, version, outputDir, patternsPath, webhookURL string, htmlOutput bool) error {
	fmt.Printf("Downloading iOS app: %s\n", bundleID)

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Create iOS downloader
	iosDownloader := downloader.NewIPAToolDownloader(filepath.Join(outputDir, "downloads"))

	// Download the app
	ipaPath, err := iosDownloader.DownloadApp(bundleID, version)
	if err != nil {
		return fmt.Errorf("failed to download iOS app: %v", err)
	}

	// Analyze the downloaded IPA
	return handleIPAAnalysis(ipaPath, outputDir, patternsPath, webhookURL, htmlOutput)
}

// handleIPAAnalysis analyzes an IPA file
func handleIPAAnalysis(ipaPath, outputDir, patternsPath, webhookURL string, htmlOutput bool) error {
	fmt.Printf("Analyzing iOS app: %s\n", filepath.Base(ipaPath))

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Create iOS analyzer
	config := &analyzer.Config{
		APKPath:      ipaPath,
		OutputDir:    outputDir,
		PatternsPath: patternsPath,
		Workers:      3,
		WebhookURL:   webhookURL,
		HTMLOutput:   htmlOutput,
	}

	iosAnalyzer := analyzer.NewIOSAnalyzer(config)

	// Analyze the IPA
	if err := iosAnalyzer.AnalyzeIPA(ipaPath); err != nil {
		return fmt.Errorf("failed to analyze IPA: %v", err)
	}

	fmt.Printf("iOS analysis completed successfully\n")
	return nil
}
