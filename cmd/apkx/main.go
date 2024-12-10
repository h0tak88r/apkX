package main

import (
	"flag"
	"fmt"
	"log"

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
	apkFile := flag.String("file", "", "APK file to scan")
	output := flag.String("output", "", "Output file (optional)")
	patterns := flag.String("patterns", "config/regexes.yaml", "Custom patterns YAML file")
	jadxArgs := flag.String("args", "", "Additional jadx arguments")
	jsonOutput := flag.Bool("json", false, "Save as JSON format")
	flag.Parse()

	if *apkFile == "" {
		log.Fatal("Please provide an APK file using -file flag")
	}

	scanner := analyzer.NewAPKScanner(&analyzer.Config{
		APKFile:      *apkFile,
		OutputFile:   *output,
		PatternsFile: *patterns,
		JadxArgs:     *jadxArgs,
		JSON:         *jsonOutput,
	})

	if err := scanner.Run(); err != nil {
		log.Fatal(err)
	}
}
