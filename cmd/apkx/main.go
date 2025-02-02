package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cyinnove/apkX/internal/analyzer"
	"github.com/cyinnove/apkX/internal/utils"
)

func printBanner() {
	banner := `         

	▗▞▀▜▌▄▄▄▄  █  ▄ ▗▖  ▗▖
	▝▚▄▟▌█   █ █▄▀   ▝▚▞▘ 
		 █▄▄▄▀ █ ▀▄   ▐▌  
		 █     █  █ ▗▞▘▝▚▖ by:h0tak88r
		 ▀                				
`
	fmt.Printf("%s%s%s\n", utils.ColorHeader, banner, utils.ColorEnd)
	fmt.Println(" --")
	fmt.Println(" Scanning APK file for URIs, endpoints & secrets")
	fmt.Println()
}

func main() {
	printBanner()
	// Define only the essential flags
	apkFile := flag.String("f", "", "APK file to analyze")
	outputFile := flag.String("o", "apkx-results.json", "JSON output file")
	patternsFile := flag.String("r", "config/regexes.yaml", "Regex patterns file")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%sAPKX - Android APK Analysis Tool%s\n\n", utils.ColorGreen, utils.ColorEnd)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  apkx -f <apk_file> [-o output.json] [-r patterns.yaml]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fmt.Fprintf(os.Stderr, "  -f string\n")
		fmt.Fprintf(os.Stderr, "    	APK file to analyze (required)\n")
		fmt.Fprintf(os.Stderr, "  -o string\n")
		fmt.Fprintf(os.Stderr, "    	JSON output file (default: apkx-results.json)\n")
		fmt.Fprintf(os.Stderr, "  -r string\n")
		fmt.Fprintf(os.Stderr, "    	Regex patterns file (default: config/regexes.yaml)\n")
	}

	flag.Parse()

	// Validate required flags
	if *apkFile == "" {
		fmt.Printf("%sError: APK file is required. Use -f flag.%s\n", utils.ColorRed, utils.ColorEnd)
		flag.Usage()
		os.Exit(1)
	}

	// Validate APK file exists
	if _, err := os.Stat(*apkFile); os.IsNotExist(err) {
		fmt.Printf("%sError: APK file not found: %s%s\n", utils.ColorRed, *apkFile, utils.ColorEnd)
		os.Exit(1)
	}

	// Create output directory if needed
	outputDir := filepath.Dir(*outputFile)
	if outputDir != "." {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			fmt.Printf("%sError creating output directory: %v%s\n", utils.ColorRed, err, utils.ColorEnd)
			os.Exit(1)
		}
	}

	// Initialize and run scanner
	config := analyzer.Config{
		APKFile:      *apkFile,
		OutputFile:   *outputFile,
		PatternsFile: *patternsFile,
	}

	scanner := analyzer.NewAPKScanner(&config)
	if err := scanner.Run(); err != nil {
		fmt.Printf("%sError: %v%s\n", utils.ColorRed, err, utils.ColorEnd)
		os.Exit(1)
	}

	// Show absolute path to the output file
	if absPath, err := filepath.Abs(*outputFile); err == nil {
		fmt.Printf("\n%sResults saved to: %s%s\n", utils.ColorBlue, absPath, utils.ColorEnd)
	}
}
