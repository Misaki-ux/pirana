package main

import (
	"bufio"
	"bytes" // Needed for capturing stderr
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// --- ASCII Art Banners ---
const piranaText = "   ___  _\n" +
	"  / _ \\(_)______ ____  ___ _\n" + // Corrected the line again just in case
	" / ___/ / __/ _ `/ _ \\/ _ `/\n" +
	"/_/  /_/_/  \\_,_/_//_/\\_,_/\n" +
	"                            " // No \n needed on the last line if it's just spaces

const piranaArt = "          ,---,\n" +
	"  _    _,-'    `--,\n" +
	" ( `-,'            `\\\n" + // Escaped backslash -> \\
	"  \\           ,    o \\\n" + // Escaped backslash -> \\
	"  /   ,       ;       \\\n" + // Escaped backslash -> \\
	" (_,-' \\       `, _  \"\"/\n" + // Escaped backslash -> \\, Escaped quotes -> \"\"
	"     pb `-,___ =='__,-'\n" +
	"              ````\n" // 

// --- Configuration Constants ---
const (
	defaultUserAgent = "PiranaScanner/1.0 (+https://github.com/Misaki-ux/pirana)" // Replace with your repo link
	outputDir        = "pirana_output"
)

var (
	// Flags
	targetDomain    = flag.String("d", "", "Single target domain (e.g., example.com)")
	targetList      = flag.String("l", "", "File containing list of target domains (one per line)")
	urlList         = flag.String("u", "", "File containing list of URLs to scan directly (skips discovery)")
	threads         = flag.Int("t", 10, "Number of concurrent threads/goroutines")
	userAgent       = flag.String("ua", defaultUserAgent, "Custom User-Agent for HTTP requests")
	excludeFile     = flag.String("ef", "", "File containing exclusion patterns (domains/subdomains, one per line)")
	skipDiscovery   = flag.Bool("skip-discovery", false, "Skip subdomain enumeration and URL discovery (use with -u)")
	skipXSS         = flag.Bool("skip-xss", false, "Skip Dalfox XSS scanning")
	outputPrefix    = flag.String("o", "", "Prefix for output files (default is domain name or 'list')")
	verbose         = flag.Bool("v", false, "Enable verbose output (show commands being run)") // Verbosity flag
	// --- Internal ---
	wg                sync.WaitGroup
	exclusionPatterns []string
	// File paths (will be updated with prefix later) - Simplified Output
	subsFile         = filepath.Join(outputDir, "subdomains.txt")          // Found subdomains (before filtering)
	aliveFile        = filepath.Join(outputDir, "alive_hosts.txt")         // Live hosts from httpx
	rawDiscoveryFile = filepath.Join(outputDir, "discovery_raw.tmp")     // Temp file for all discovery tools output
	tempAllUrlsFile  = filepath.Join(outputDir, "all_urls_unified.tmp")    // Temp file for unified URLs
	finalTargetsFile = filepath.Join(outputDir, "scan_targets_final.txt") // FINAL condensed output for XSS/HTMLi
	dalfoxLogFile    = filepath.Join(outputDir, "dalfox_scan.log")
)

// --- Helper Functions (Reduced Verbosity) ---

// runCommand runs a command, shows output only on error or if verbose.
func runCommand(name string, args ...string) error {
	if *verbose {
		log.Printf("[CMD] Running: %s %s\n", name, strings.Join(args, " "))
	}
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stdout = os.Stdout // Show stdout directly by default
	cmd.Stderr = &stderr   // Capture stderr

	err := cmd.Run()
	if err != nil {
		// Log error prominently, including stderr
		errOutput := stderr.String()
		log.Printf("[ERROR] Command '%s %s' failed: %v", name, strings.Join(args, " "), err)
		if errOutput != "" {
			log.Printf("[STDERR] %s\n%s", strings.Repeat("-", 10), errOutput)
		}
		return fmt.Errorf("command failed: %s", name)
	}
	if *verbose {
		log.Printf("[INFO] Command completed successfully: %s\n", name)
	}
	return nil
}

// runCommandToFile runs a command, saving stdout to a file. Logs minimally.
func runCommandToFile(outputFile string, name string, args ...string) error {
	if *verbose {
		log.Printf("[CMD] Running: %s %s > %s\n", name, strings.Join(args, " "), filepath.Base(outputFile))
	}
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	outfile, err := os.Create(outputFile)
	if err != nil {
		log.Printf("[ERROR] Failed to create output file %s: %v\n", outputFile, err)
		return err
	}
	defer outfile.Close()

	cmd.Stdout = outfile
	cmd.Stderr = &stderr // Capture stderr

	err = cmd.Run()
	outfile.Close() // Close file before checking error

	if err != nil {
		errOutput := stderr.String()
		log.Printf("[ERROR] Command '%s %s' failed: %v", name, strings.Join(args, " "), err)
		if errOutput != "" {
			log.Printf("[STDERR] %s\n%s", strings.Repeat("-", 10), errOutput)
		}
		// Keep the potentially partial output file
		time.Sleep(50 * time.Millisecond) // FS sync delay
		return fmt.Errorf("command failed: %s", name)
	}
	time.Sleep(100 * time.Millisecond) // FS sync delay on success
	if *verbose {
		log.Printf("[INFO] Command '%s' completed, output: %s\n", name, filepath.Base(outputFile))
	}
	return nil
}

// runCommandAppendToFile runs a command, *appending* stdout to a file.
func runCommandAppendToFile(outputFile string, name string, args ...string) error {
	if *verbose {
		log.Printf("[CMD] Running: %s %s >> %s\n", name, strings.Join(args, " "), filepath.Base(outputFile))
	}

	// Use shell redirection for simplicity in appending
	cmdStr := fmt.Sprintf("%s %s >> %s", name, strings.Join(args, " "), outputFile)
	cmd := exec.Command("sh", "-c", cmdStr)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr // Capture stderr

	err := cmd.Run()

	if err != nil {
		errOutput := stderr.String()
		log.Printf("[ERROR] Command '%s' (append) failed: %v", name, err)
		if errOutput != "" {
			log.Printf("[STDERR] %s\n%s", strings.Repeat("-", 10), errOutput)
		}
		time.Sleep(50 * time.Millisecond) // FS sync delay
		return fmt.Errorf("command append failed: %s", name)
	}
	time.Sleep(100 * time.Millisecond) // FS sync delay on success
	if *verbose {
		log.Printf("[INFO] Command '%s' append completed to: %s\n", name, filepath.Base(outputFile))
	}
	return nil
}

// Checks if a tool exists in PATH
func toolExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Reads lines from a file
func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	const maxCapacity = 5 * 1024 * 1024 // 5 MB buffer
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return lines, fmt.Errorf("error scanning file %s: %w", filename, err)
	}
	return lines, nil
}

// Writes lines to a file
func writeLines(filename string, lines []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(writer, line)
	}
	return writer.Flush()
}

// --- Exclusion Logic (Unchanged) ---
func loadExclusionPatterns(filename string) ([]string, error) {
	// ... (same as before) ...
	if filename == "" { return nil, nil }
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) { log.Printf("[WARN] Exclusion file '%s' not found.", filename); return nil, nil }
		return nil, fmt.Errorf("failed to open exclusion file %s: %w", filename, err)
	}
	defer file.Close()
	var patterns []string
	scanner := bufio.NewScanner(file)
	log.Printf("[INFO] Loading exclusion patterns from: %s", filename)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") { patterns = append(patterns, strings.ToLower(line)); log.Printf("  - Loaded: %s", line) }
	}
	if err := scanner.Err(); err != nil { return patterns, fmt.Errorf("error reading exclusion file %s: %w", filename, err) }
	log.Printf("[INFO] Loaded %d exclusion patterns.", len(patterns))
	return patterns, nil
}

func isExcluded(target string, patterns []string) (bool, error) {
	// ... (same as before) ...
	if len(patterns) == 0 { return false, nil }
	normalizedTarget := strings.ToLower(target)
	targetHost := normalizedTarget; var parseErr error
	if strings.Contains(normalizedTarget, "://") {
		parsedURL, err := url.Parse(normalizedTarget)
		if err != nil { log.Printf("[WARN] URL parse error during exclusion check: %s - %v", target, err); targetHost = ""; parseErr = err
		} else { targetHost = strings.ToLower(parsedURL.Hostname()) }
		if targetHost == "" && parseErr == nil { log.Printf("[WARN] Could not extract hostname for exclusion check: %s", target) }
	}
	for _, pattern := range patterns {
		if normalizedTarget == pattern || (targetHost != "" && targetHost == pattern) { return true, parseErr }
		if targetHost != "" && strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:]; if strings.HasSuffix(targetHost, suffix) && len(targetHost) > len(suffix) { return true, parseErr }
		}
	}
	return false, parseErr
}

func filterFile(inputFile, outputFile string, exclusionPatterns []string, tempDir string) error {
	// ... (same logic as before, maybe reduce logging slightly if needed) ...
	// This function is complex, keeping its internal logging might be useful even without -v
	// Let's keep it as is for now.
	if len(exclusionPatterns) == 0 && inputFile == outputFile { return nil }
	if len(exclusionPatterns) == 0 && inputFile != outputFile {
		// Copy inputFile to outputFile
		in, err := os.Open(inputFile); if err != nil { if os.IsNotExist(err) { writeLines(outputFile, []string{}); return nil }; return fmt.Errorf("copy src open err: %w", err) }; defer in.Close()
		out, err := os.Create(outputFile); if err != nil { return fmt.Errorf("copy dst create err: %w", err) }; defer out.Close()
		_, err = io.Copy(out, in); if err != nil { return fmt.Errorf("copy err: %w", err) }; return nil
	}
	log.Printf("[+] Applying exclusions: %s -> %s", filepath.Base(inputFile), filepath.Base(outputFile))
	tempFile, err := os.CreateTemp(tempDir, "pirana_filter_*.tmp"); if err != nil { return fmt.Errorf("create temp file err: %w", err) }
	tempFilePath := tempFile.Name(); defer func() { tempFile.Close(); os.Remove(tempFilePath) }()
	infile, err := os.Open(inputFile); if err != nil { if os.IsNotExist(err) { writeLines(outputFile, []string{}); return nil }; return fmt.Errorf("open input err: %w", err) }; defer infile.Close()
	writer := bufio.NewWriter(tempFile); scanner := bufio.NewScanner(infile)
	const maxCapacity = 5 * 1024 * 1024; buf := make([]byte, maxCapacity); scanner.Buffer(buf, maxCapacity)
	lineCount, excludedCount, writtenCount := 0, 0, 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text()); if line == "" { continue }; lineCount++
		excluded, checkErr := isExcluded(line, exclusionPatterns)
		if checkErr != nil { log.Printf("[WARN] Exclusion check error for '%s': %v. Including.", line, checkErr); excluded = false }
		if !excluded { fmt.Fprintln(writer, line); writtenCount++ } else { excludedCount++ }
	}
	if err := scanner.Err(); err != nil { return fmt.Errorf("scan input err: %w", err) }
	if err := writer.Flush(); err != nil { return fmt.Errorf("flush temp err: %w", err) }
	if err := tempFile.Close(); err != nil { return fmt.Errorf("close temp err: %w", err) }
	if err := os.Rename(tempFilePath, outputFile); err != nil { return fmt.Errorf("rename temp err: %w", err) }
	log.Printf("[INFO] Filtering complete: %d read, %d excluded, %d written to %s", lineCount, excludedCount, writtenCount, filepath.Base(outputFile))
	return nil
}


// --- Workflow Steps (Refactored) ---

func enumerateSubdomains(target string, outputFile string) error {
	if !toolExists("subfinder") {
		log.Println("[WARN] subfinder not found. Skipping subdomain enumeration.")
		writeLines(outputFile, []string{})
		return fmt.Errorf("subfinder not found")
	}
	log.Println("[+] Enumerating subdomains for:", target)
	return runCommandToFile(outputFile, "subfinder", "-d", target, "-silent")
}

func checkLiveDomains(inputFile, outputFile string, tempDir string) error {
	if !toolExists("httpx") {
		log.Println("[WARN] httpx not found. Skipping live domain check.")
		writeLines(outputFile, []string{})
		return fmt.Errorf("httpx not found")
	}
	info, err := os.Stat(inputFile)
	if err != nil || info.Size() == 0 {
		if *verbose { log.Printf("[INFO] Input file %s for httpx is empty/missing. Skipping.", inputFile) }
		writeLines(outputFile, []string{})
		return nil
	}

	filteredSubsFile := inputFile + ".filtered"
	err = filterFile(inputFile, filteredSubsFile, exclusionPatterns, tempDir)
	if err != nil { log.Printf("[ERROR] Failed to apply exclusions to %s: %v. Skipping httpx.", inputFile, err); writeLines(outputFile, []string{}); return err }
	defer os.Remove(filteredSubsFile)

	infoFiltered, errFiltered := os.Stat(filteredSubsFile)
	if errFiltered != nil || infoFiltered.Size() == 0 {
		if *verbose { log.Printf("[INFO] Input file %s empty after exclusions. Skipping httpx.", inputFile) }
		writeLines(outputFile, []string{}); return nil
	}

	log.Println("[+] Checking for live hosts...")
	return runCommandToFile(outputFile, "httpx", "-l", filteredSubsFile, "-H", fmt.Sprintf("User-Agent: %s", *userAgent), "-silent", "-threads", fmt.Sprintf("%d", *threads))
}


// discoverEndpoints now appends all output to rawDiscoveryFile
func discoverEndpoints(initialTargets []string, isDomainInput bool, tempDir string) error {
	log.Println("[+] Discovering endpoints (Katana, Hakrawler, Waybackurls, Gau, Paramspider)...")

	// Clean slate for raw discovery file
	os.Remove(rawDiscoveryFile)
	writeLines(rawDiscoveryFile, []string{}) // Create empty file

	// Filter aliveFile before use
	if _, err := os.Stat(aliveFile); err == nil {
		errFilter := filterFile(aliveFile, aliveFile, exclusionPatterns, tempDir)
		if errFilter != nil { log.Printf("[ERROR] Failed to filter %s before discovery: %v", aliveFile, errFilter) }
	}

	aliveInfo, aliveErr := os.Stat(aliveFile)
	isAliveUsable := aliveErr == nil && aliveInfo.Size() > 0


	// --- Katana ---
	if toolExists("katana") {
		if isAliveUsable {
			if *verbose { log.Println("  -> Running Katana...") }
			// Append using shell redirection
			cmdStr := fmt.Sprintf("katana -l %s -silent -H \"User-Agent: %s\" -c %d >> %s", aliveFile, *userAgent, *threads, rawDiscoveryFile)
			cmd := exec.Command("sh", "-c", cmdStr); cmd.Stderr = os.Stderr; cmd.Run() // Log errors implicitly via stderr redirection
			time.Sleep(100 * time.Millisecond)
		}
	} else if *verbose { log.Println("[WARN] katana not found.") }

	// --- Hakrawler ---
	if toolExists("hakrawler") {
		if isAliveUsable {
			if *verbose { log.Println("  -> Running Hakrawler...") }
			// Pipe input, append output
			cmdStr := fmt.Sprintf("cat %s | hakrawler -ua \"%s\" -t %d >> %s", aliveFile, *userAgent, *threads, rawDiscoveryFile)
			cmd := exec.Command("sh", "-c", cmdStr); cmd.Stderr = os.Stderr; cmd.Run()
			time.Sleep(100 * time.Millisecond)
		}
	} else if *verbose { log.Println("[WARN] hakrawler not found.") }


	// --- Waybackurls & Gau & Paramspider (run per initial target domain only if not excluded) ---
	if isDomainInput {
		waybackMissingLogged := !toolExists("waybackurls")
		gauMissingLogged := !toolExists("gau")
		paramspiderMissingLogged := !toolExists("paramspider")

		for _, domain := range initialTargets {
			excluded, _ := isExcluded(domain, exclusionPatterns)
			if excluded { continue }

			// Run Waybackurls
			if !waybackMissingLogged {
				if *verbose { log.Printf("    -> Running waybackurls for %s...\n", domain) }
				runCommandAppendToFile(rawDiscoveryFile, "waybackurls", domain)
			}

			// Run Gau
			if !gauMissingLogged {
				if *verbose { log.Printf("    -> Running gau for %s...\n", domain) }
				runCommandAppendToFile(rawDiscoveryFile, "gau", "--threads", fmt.Sprintf("%d", *threads), domain)
			}

			// Run Paramspider
			if !paramspiderMissingLogged {
				if *verbose { log.Printf("    -> Running paramspider for %s...\n", domain) }
				// Paramspider might output errors to stderr, let's capture if needed, but append stdout
				cmdStr := fmt.Sprintf("paramspider -d %s >> %s", domain, rawDiscoveryFile)
				cmd := exec.Command("sh", "-c", cmdStr); cmd.Stderr = os.Stderr; cmd.Run()
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	log.Println("[+] Endpoint discovery phase complete.")
	return nil
}

// unifyAndCleanUrls now takes the single raw discovery file
func unifyAndCleanUrls(inputFile, outputFile string, tempDir string) error {
	log.Println("[+] Unifying and cleaning discovered URLs...")
	uniqueUrls := make(map[string]bool)

	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		log.Printf("[INFO] Raw discovery file %s not found. Skipping unification.", inputFile)
		return writeLines(outputFile, []string{}) // Create empty temp output
	}

	file, err := os.Open(inputFile)
	if err != nil {
		log.Printf("[ERROR] Failed to open raw discovery file %s: %v\n", inputFile, err)
		return writeLines(outputFile, []string{}) // Create empty temp output
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	const maxCapacity = 5 * 1024 * 1024 // 5 MB buffer
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && (strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://")) {
			if fragIndex := strings.Index(line, "#"); fragIndex != -1 { line = line[:fragIndex] }
			uniqueUrls[line] = true
		}
	}
	if err := scanner.Err(); err != nil { log.Printf("[ERROR] Error scanning raw discovery file %s: %v\n", inputFile, err) }

	if len(uniqueUrls) == 0 {
		log.Println("[INFO] No valid URLs found after discovery. Creating empty output.")
		return writeLines(outputFile, []string{})
	}

	// Write unique URLs temporarily before filtering
	outputLines := make([]string, 0, len(uniqueUrls))
	for url := range uniqueUrls { outputLines = append(outputLines, url) }
	err = writeLines(outputFile, outputLines) // Write to the temporary unified file path
	if err != nil {
		log.Printf("[ERROR] Failed to write temporary unified URLs to %s: %v\n", outputFile, err)
		return err
	}

	log.Printf("[INFO] Found %d unique URLs from discovery sources.", len(outputLines))

	// Apply Exclusions to the unified list (Filter in-place on the temp file)
	err = filterFile(outputFile, outputFile, exclusionPatterns, tempDir)
	if err != nil {
		log.Printf("[ERROR] Failed to apply exclusions during unification: %v", err)
		writeLines(outputFile, []string{}) // Ensure temp file is empty on error
		return err
	}

	return nil
}

// filterUrlsWithParams now takes the temp unified file and outputs the final target file
func filterUrlsWithParams(inputFile, outputFile string) error {
	log.Println("[+] Filtering for URLs with parameters...")
	var urlsWithParams []string

	allUrls, err := readLines(inputFile) // Read from the temporary unified file
	if err != nil {
		if !os.IsNotExist(err) { // Only log error if it's not just 'file not found'
			log.Printf("[ERROR] Failed to read %s for parameter filtering: %v\n", inputFile, err)
		}
		return writeLines(outputFile, []string{}) // Create empty final output
	}

	if len(allUrls) == 0 {
		if *verbose { log.Println("[INFO] Input file for parameter filtering is empty.") }
		return writeLines(outputFile, []string{})
	}

	paramCount := 0
	for _, url := range allUrls {
		qIndex := strings.Index(url, "?")
		if qIndex != -1 && strings.Contains(url[qIndex:], "=") {
			urlsWithParams = append(urlsWithParams, url)
			paramCount++
		}
	}

	err = writeLines(outputFile, urlsWithParams) // Write to the final target file
	if err != nil {
		log.Printf("[ERROR] Failed to write final target URLs to %s: %v\n", outputFile, err)
		return err
	}

	log.Printf("[INFO] Found %d URLs with parameters for scanning. Saved to %s\n", paramCount, filepath.Base(outputFile))
	return nil
}

// scanForXSS takes the final target file
func scanForXSS(inputFile string, dalfoxLog string) error {
	if !toolExists("dalfox") {
		log.Println("[WARN] dalfox not found. Skipping XSS scan.")
		return fmt.Errorf("dalfox not found")
	}

	info, err := os.Stat(inputFile)
	if err != nil || info.Size() == 0 {
		if *verbose { log.Printf("[INFO] Input file %s for Dalfox is empty/missing. Skipping XSS scan.", inputFile) }
		return nil
	}

	log.Println("[+] Running Dalfox XSS scan...")
	log.Printf("    Input: %s", filepath.Base(inputFile))
	log.Printf("    Output Log: %s", filepath.Base(dalfoxLog))


	dalfoxArgs := []string{
		"pipe", "--silence", // Use pipe mode, keep output clean by default
		"--user-agent", *userAgent,
		"--multicast", "--skip-mining-all", "--deep-domxss", "--no-spinner",
		"--output", dalfoxLog,
	}
	if *verbose { // Add verbosity to dalfox if Pirana is verbose
		// Remove silence, maybe add other verbose flags for dalfox? Check its --help.
		// For now, just remove silence.
		for i, arg := range dalfoxArgs { if arg == "--silence" { dalfoxArgs = append(dalfoxArgs[:i], dalfoxArgs[i+1:]...); break } }
		// dalfoxArgs = append(dalfoxArgs, "-v") // Example if dalfox had a verbose flag
	}


	cmd := exec.Command("dalfox", dalfoxArgs...)
	infile, err := os.Open(inputFile)
	if err != nil { log.Printf("[ERROR] Failed to open input %s for Dalfox pipe: %v\n", inputFile, err); return err }
	defer infile.Close()
	cmd.Stdin = infile

	// Capture Dalfox output (stdout/stderr) to show findings/errors directly
	var outData bytes.Buffer
	var errData bytes.Buffer
	cmd.Stdout = &outData
	cmd.Stderr = &errData

	if *verbose { log.Printf("[CMD] Running: cat %s | dalfox %s\n", inputFile, strings.Join(dalfoxArgs, " ")) }
	err = cmd.Run()

	// Print Dalfox output ONLY if it found something or errored
	stdoutStr := strings.TrimSpace(outData.String())
	stderrStr := strings.TrimSpace(errData.String())

	if stdoutStr != "" {
		fmt.Println("--- Dalfox Output ---")
		fmt.Println(stdoutStr)
		fmt.Println("---------------------")
	}

	if err != nil {
		log.Printf("[WARN] Dalfox finished with non-zero status: %v.", err)
		if stderrStr != "" {
			log.Printf("[DALFOX STDERR]\n%s", stderrStr)
		}
	} else if stderrStr != "" {
		// Sometimes tools write non-error info to stderr
		log.Printf("[INFO] Dalfox stderr output:\n%s", stderrStr)
	}


	log.Printf("[+] Dalfox scan finished.")
	return nil // Don't return dalfox execution error as fatal
}

// --- Main Function ---

func main() {
	flag.Parse()

	// Input Validation
	inputCount := 0
	if *targetDomain != "" { inputCount++ }; if *targetList != "" { inputCount++ }; if *urlList != "" { inputCount++ }
	if inputCount != 1 {
		fmt.Println(piranaText); fmt.Println(piranaArt); fmt.Println("-----------------------------------------")
		fmt.Println("Usage: pirana [options]"); fmt.Println("Provide exactly one of: -d <domain>, -l <domain_list_file>, or -u <url_list_file>")
		flag.PrintDefaults(); fmt.Println("\nExample: ./pirana -d example.com -ef exclusions.txt -t 20 -v")
		os.Exit(1)
	}
	if *skipDiscovery && *urlList == "" {
		fmt.Println(piranaText); fmt.Println(piranaArt); fmt.Println("-----------------------------------------")
		log.Fatal("[ERROR] -skip-discovery requires -u <url_list_file> to be provided.")
	}

	// Print Banners
	fmt.Println(piranaText); fmt.Println(piranaArt); fmt.Println("-----------------------------------------")

	// Setup
	if *verbose { log.Println("--- Pirana Scanner Initializing (Verbose Mode) ---") } else { log.Println("--- Pirana Scanner Initializing ---") }
	log.Printf("User Agent: %s", *userAgent); log.Printf("Threads: %d", *threads)

	effectiveOutputDir := outputDir
	if err := os.MkdirAll(effectiveOutputDir, 0755); err != nil { log.Fatalf("[FATAL] Failed to create output directory %s: %v", effectiveOutputDir, err) }
	log.Printf("Output directory: %s", effectiveOutputDir)


	primaryTarget := "output"
	if *targetDomain != "" { primaryTarget = strings.ReplaceAll(*targetDomain, ".", "_") } else if *targetList != "" { primaryTarget = strings.TrimSuffix(filepath.Base(*targetList), filepath.Ext(*targetList)) + "_list" } else if *urlList != "" { primaryTarget = strings.TrimSuffix(filepath.Base(*urlList), filepath.Ext(*urlList)) + "_urls" }
	if *outputPrefix != "" { primaryTarget = *outputPrefix }

	// Update global file path variables
	subsFile = filepath.Join(effectiveOutputDir, primaryTarget+"_subdomains.txt")
	aliveFile = filepath.Join(effectiveOutputDir, primaryTarget+"_alive_hosts.txt")
	rawDiscoveryFile = filepath.Join(effectiveOutputDir, primaryTarget+"_discovery_raw.tmp") // Temp
	tempAllUrlsFile = filepath.Join(effectiveOutputDir, primaryTarget+"_all_urls_unified.tmp") // Temp
	finalTargetsFile = filepath.Join(effectiveOutputDir, primaryTarget+"_scan_targets_final.txt") // Final Output
	dalfoxLogFile = filepath.Join(effectiveOutputDir, primaryTarget+"_dalfox_scan.log")

	// Define temporary files for cleanup
	tempFiles := []string{rawDiscoveryFile, tempAllUrlsFile}
	defer func() { // Cleanup temporary files at the end
		if !*verbose { // Keep temp files only in verbose mode for debugging
			for _, f := range tempFiles {
				if *verbose { log.Printf("[DEBUG] Removing temp file: %s", f) }
				os.Remove(f)
			}
			// Also remove subs/alive if not verbose? Maybe keep them. Let's keep them for now.
			// os.Remove(subsFile)
			// os.Remove(aliveFile)
		} else {
			log.Println("[INFO] Verbose mode: Temporary files kept for debugging.")
			log.Printf("       Raw Discovery: %s", rawDiscoveryFile)
			log.Printf("       Unified URLs (pre-param filter): %s", tempAllUrlsFile)

		}
	}()


	// Load Exclusion Patterns
	var loadErr error
	exclusionPatterns, loadErr = loadExclusionPatterns(*excludeFile)
	if loadErr != nil { log.Printf("[ERROR] Failed to load exclusion patterns: %v. Proceeding without.", loadErr); exclusionPatterns = []string{} }

	// Prepare Initial Targets
	initialTargets := []string{}; isDomainInput := false
	if *targetDomain != "" { initialTargets = append(initialTargets, *targetDomain); isDomainInput = true } else if *targetList != "" { var err error; initialTargets, err = readLines(*targetList); if err != nil { log.Fatalf("[FATAL] Failed read target list %s: %v", *targetList, err) }; isDomainInput = true } else if *urlList != "" { var err error; initialTargets, err = readLines(*urlList); if err != nil { log.Fatalf("[FATAL] Failed read URL list %s: %v", *urlList, err) }; isDomainInput = false }


	// --- Workflow Execution ---
	startTime := time.Now()
	essentialToolsOk := true // Assume OK initially

	if !*skipDiscovery {
		log.Println("--- Starting Discovery Phase ---")
		if isDomainInput {
			// == Subdomain Enumeration ==
			if !toolExists("subfinder") { log.Printf("[WARN] Subfinder not found. Skipping.") } else {
				if err := enumerateSubdomains(initialTargets[0], subsFile); err != nil {
					log.Printf("[WARN] Subfinder failed for %s. Continuing.", initialTargets[0])
				}
				// TODO: Handle multiple domains for subfinder if needed, currently only does first.
			}

			// == Live Domain Check ==
			if !toolExists("httpx") { log.Printf("[WARN] httpx not found. Discovery severely impacted."); essentialToolsOk = false } else {
				if err := checkLiveDomains(subsFile, aliveFile, effectiveOutputDir); err != nil {
					log.Printf("[WARN] httpx failed. Discovery may be incomplete.")
					essentialToolsOk = false // Mark as failed if httpx fails
				}
			}
		} else { // Input was URL list
			log.Println("[INFO] Using provided URL list for discovery.")
			tempInitialURLs := filepath.Join(effectiveOutputDir, "temp_initial_urls.tmp"); defer os.Remove(tempInitialURLs)
			writeLines(tempInitialURLs, initialTargets)
			errFilter := filterFile(tempInitialURLs, aliveFile, exclusionPatterns, effectiveOutputDir)
			if errFilter != nil { log.Fatalf("[FATAL] Failed filter initial URL list %s: %v", *urlList, errFilter) }
			if _, err := os.Stat(aliveFile); os.IsNotExist(err) { writeLines(aliveFile, []string{}) }
			essentialToolsOk = true // Assume URLs are usable if provided
		}

		// == Endpoint Discovery (Appends to rawDiscoveryFile) ==
		if essentialToolsOk {
			discoverEndpoints(initialTargets, isDomainInput, effectiveOutputDir)
		} else { log.Println("[WARN] Skipping endpoint discovery due to earlier failures (e.g., httpx).") }

		// == Unify + Clean URLs (Uses rawDiscoveryFile -> tempAllUrlsFile) ==
		if err := unifyAndCleanUrls(rawDiscoveryFile, tempAllUrlsFile, effectiveOutputDir); err != nil {
			log.Printf("[ERROR] Failed during URL unification: %v. Final target list may be empty.", err)
		}

	} else { // Discovery Skipped
		log.Println("--- Skipping Discovery Phase ---")
		if *urlList == "" { log.Fatal("[FATAL] Cannot skip discovery without -u <url_list_file>.") }
		log.Println("[INFO] Using provided URL list directly.")
		tempInitialURLs := filepath.Join(effectiveOutputDir, "temp_initial_urls.tmp"); defer os.Remove(tempInitialURLs)
		writeLines(tempInitialURLs, initialTargets)
		// Filter initial URLs directly into the temp unified file path
		errFilter := filterFile(tempInitialURLs, tempAllUrlsFile, exclusionPatterns, effectiveOutputDir)
		if errFilter != nil { log.Fatalf("[FATAL] Failed to filter input URL list %s: %v", *urlList, errFilter) }
		if *verbose { log.Printf("[INFO] Filtered input URL list used for unification step.") }
	}


	// == Filter URLs with Parameters (Uses tempAllUrlsFile -> finalTargetsFile) ==
	if err := filterUrlsWithParams(tempAllUrlsFile, finalTargetsFile); err != nil {
		log.Printf("[ERROR] Failed during parameter filtering: %v. Final target list may be empty.", err)
	}


	// == Run Dalfox for XSS ==
	if !*skipXSS {
		log.Println("--- Starting XSS Scan Phase ---")
		scanForXSS(finalTargetsFile, dalfoxLogFile)
	} else { log.Println("--- Skipping XSS Scan Phase ---"); os.Remove(dalfoxLogFile) }


	// --- Completion ---
	duration := time.Since(startTime)
	log.Printf("--- Pirana Scan Completed ---")
	log.Printf("Total execution time: %s", duration)
	log.Printf("[✓] Done. Check the '%s' directory for main output.", effectiveOutputDir)
	log.Printf("    -> Final Scan Targets: %s", finalTargetsFile) // Primary output
	if !*skipXSS {
		if _, err := os.Stat(dalfoxLogFile); err == nil { log.Printf("    -> Dalfox Log: %s", dalfoxLogFile) }
	}
	if *verbose { log.Printf("[INFO] Use -v flag to see detailed command execution and keep temporary files.")}

}
