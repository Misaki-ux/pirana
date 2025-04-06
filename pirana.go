package main

import (
	"bufio"
	"bytes"
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
	"        `-,___ =='__,-'\n" +
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
	verbose         = flag.Bool("v", false, "Enable verbose output (show commands, tool output, keep temp files)") // Verbosity flag
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

// --- Helper Functions (More Robust Logging) ---

// runCommand runs a command, shows output only on error or if verbose.
func runCommand(name string, args ...string) error {
	// ... (same as previous version) ...
	if *verbose { log.Printf("[CMD] Running: %s %s\n", name, strings.Join(args, " ")) }
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stdout = os.Stdout; cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		errOutput := stderr.String()
		log.Printf("[ERROR] Command '%s %s' failed: %v", name, strings.Join(args, " "), err)
		if errOutput != "" { log.Printf("[STDERR] %s\n%s", strings.Repeat("-", 10), errOutput) }
		return fmt.Errorf("command failed: %s", name)
	}
	if *verbose { log.Printf("[INFO] Command completed successfully: %s\n", name) }
	return nil
}

// runCommandToFile runs a command, saving stdout to a file. Logs minimally.
func runCommandToFile(outputFile string, name string, args ...string) error {
	// ... (same as previous version) ...
	if *verbose { log.Printf("[CMD] Running: %s %s > %s\n", name, strings.Join(args, " "), filepath.Base(outputFile)) }
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	outfile, err := os.Create(outputFile); if err != nil { log.Printf("[ERROR] Create %s failed: %v", outputFile, err); return err }; defer outfile.Close()
	cmd.Stdout = outfile; cmd.Stderr = &stderr
	err = cmd.Run(); outfile.Close() // Close file before checking error
	if err != nil {
		errOutput := stderr.String(); log.Printf("[ERROR] Command '%s %s' failed: %v", name, strings.Join(args, " "), err)
		if errOutput != "" { log.Printf("[STDERR] %s\n%s", strings.Repeat("-", 10), errOutput) }
		time.Sleep(50 * time.Millisecond); return fmt.Errorf("command failed: %s", name)
	}
	time.Sleep(100 * time.Millisecond)
	if *verbose { log.Printf("[INFO] Command '%s' completed, output: %s\n", name, filepath.Base(outputFile)) }
	return nil
}

// runCommandAppendToFile runs a command, appending stdout using Go's file handling.
func runCommandAppendToFile(outputFile string, name string, args ...string) error {
	if *verbose {
		log.Printf("[CMD] Running (append): %s %s >> %s\n", name, strings.Join(args, " "), filepath.Base(outputFile))
	}
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer

	// Open file in append mode
	outfile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[ERROR] Failed to open %s for append: %v\n", outputFile, err)
		return err
	}
	defer outfile.Close()

	cmd.Stdout = outfile // Pipe command's stdout to the file handle
	cmd.Stderr = &stderr  // Capture command's stderr

	err = cmd.Run()
	outfile.Close() // Close file before checking error

	if err != nil {
		errOutput := stderr.String()
		// Log prominently if the command itself failed
		log.Printf("[ERROR] Command '%s' (append) execution failed: %v", name, err)
		if errOutput != "" {
			log.Printf("[STDERR] %s\n%s", strings.Repeat("-", 10), errOutput)
		}
		time.Sleep(50 * time.Millisecond) // FS sync delay
		return fmt.Errorf("command append failed: %s", name)
	}
	// Check stderr even on success, as some tools write info there
	errOutput := stderr.String()
	if *verbose && errOutput != "" {
		log.Printf("[INFO] Command '%s' stderr (append):\n%s", name, errOutput)
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

// Logs the size of a file, useful for debugging empty files
func logFileSize(filename string) int64 {
	info, err := os.Stat(filename)
	if err != nil {
		if !os.IsNotExist(err) { // Log error only if it's not "file not found"
			log.Printf("[WARN] Could not stat file %s: %v", filepath.Base(filename), err)
		}
		return 0 // Return 0 if file doesn't exist or error
	}
	size := info.Size()
	if *verbose { // Only log size in verbose mode to keep default output clean
		log.Printf("[DEBUG] File size %s: %d bytes", filepath.Base(filename), size)
	}
	return size
}


// Reads lines from a file
func readLines(filename string) ([]string, error) {
	// ... (same as before) ...
	file, err := os.Open(filename); if err != nil { return nil, err }; defer file.Close()
	var lines []string; scanner := bufio.NewScanner(file)
	const maxCapacity = 5 * 1024 * 1024; buf := make([]byte, maxCapacity); scanner.Buffer(buf, maxCapacity)
	for scanner.Scan() { lines = append(lines, scanner.Text()) }
	if err := scanner.Err(); err != nil { return lines, fmt.Errorf("error scanning file %s: %w", filename, err) }; return lines, nil
}

// Writes lines to a file
func writeLines(filename string, lines []string) error {
	// ... (same as before) ...
	file, err := os.Create(filename); if err != nil { return err }; defer file.Close()
	writer := bufio.NewWriter(file); for _, line := range lines { fmt.Fprintln(writer, line) }; return writer.Flush()
}

// --- Exclusion Logic (Unchanged) ---
func loadExclusionPatterns(filename string) ([]string, error) {
	// ... (same as before) ...
	if filename == "" { return nil, nil }
	file, err := os.Open(filename); if err != nil { if os.IsNotExist(err) { log.Printf("[WARN] Exclusion file '%s' not found.", filename); return nil, nil }; return nil, fmt.Errorf("open exclusion err: %w", err) }; defer file.Close()
	var patterns []string; scanner := bufio.NewScanner(file); log.Printf("[INFO] Loading exclusion patterns: %s", filename)
	for scanner.Scan() { line := strings.TrimSpace(scanner.Text()); if line != "" && !strings.HasPrefix(line, "#") { patterns = append(patterns, strings.ToLower(line)); if *verbose { log.Printf("  - Loaded: %s", line) } } }; if err := scanner.Err(); err != nil { return patterns, fmt.Errorf("read exclusion err: %w", err) }
	log.Printf("[INFO] Loaded %d exclusion patterns.", len(patterns)); return patterns, nil
}
func isExcluded(target string, patterns []string) (bool, error) {
	// ... (same as before) ...
	if len(patterns) == 0 { return false, nil }; normalizedTarget := strings.ToLower(target); targetHost := normalizedTarget; var parseErr error
	if strings.Contains(normalizedTarget, "://") { parsedURL, err := url.Parse(normalizedTarget); if err != nil { if *verbose{log.Printf("[WARN] URL parse err (exclude): %s - %v", target, err)}; targetHost = ""; parseErr = err } else { targetHost = strings.ToLower(parsedURL.Hostname()) }; if targetHost == "" && parseErr == nil { if *verbose{log.Printf("[WARN] No hostname (exclude): %s", target)} } }
	for _, pattern := range patterns { if normalizedTarget == pattern || (targetHost != "" && targetHost == pattern) { return true, parseErr }; if targetHost != "" && strings.HasPrefix(pattern, "*.") { suffix := pattern[1:]; if strings.HasSuffix(targetHost, suffix) && len(targetHost) > len(suffix) { return true, parseErr } } }; return false, parseErr
}
func filterFile(inputFile, outputFile string, exclusionPatterns []string, tempDir string) error {
	// ... (same logic as before, logging kept) ...
	if len(exclusionPatterns) == 0 && inputFile == outputFile { return nil }
	if len(exclusionPatterns) == 0 && inputFile != outputFile { in, err := os.Open(inputFile); if err != nil { if os.IsNotExist(err) { writeLines(outputFile, []string{}); return nil }; return fmt.Errorf("copy src open err: %w", err) }; defer in.Close(); out, err := os.Create(outputFile); if err != nil { return fmt.Errorf("copy dst create err: %w", err) }; defer out.Close(); _, err = io.Copy(out, in); if err != nil { return fmt.Errorf("copy err: %w", err) }; return nil }
	if *verbose { log.Printf("[+] Applying exclusions: %s -> %s", filepath.Base(inputFile), filepath.Base(outputFile)) }
	tempFile, err := os.CreateTemp(tempDir, "pirana_filter_*.tmp"); if err != nil { return fmt.Errorf("create temp file err: %w", err) }; tempFilePath := tempFile.Name(); defer func() { tempFile.Close(); os.Remove(tempFilePath) }()
	infile, err := os.Open(inputFile); if err != nil { if os.IsNotExist(err) { writeLines(outputFile, []string{}); return nil }; return fmt.Errorf("open input err: %w", err) }; defer infile.Close()
	writer := bufio.NewWriter(tempFile); scanner := bufio.NewScanner(infile); const maxCapacity = 5 * 1024 * 1024; buf := make([]byte, maxCapacity); scanner.Buffer(buf, maxCapacity)
	lineCount, excludedCount, writtenCount := 0, 0, 0
	for scanner.Scan() { line := strings.TrimSpace(scanner.Text()); if line == "" { continue }; lineCount++; excluded, checkErr := isExcluded(line, exclusionPatterns); if checkErr != nil { log.Printf("[WARN] Exclusion check error for '%s': %v. Including.", line, checkErr); excluded = false }; if !excluded { fmt.Fprintln(writer, line); writtenCount++ } else { excludedCount++ } }
	if err := scanner.Err(); err != nil { return fmt.Errorf("scan input err: %w", err) }; if err := writer.Flush(); err != nil { return fmt.Errorf("flush temp err: %w", err) }; if err := tempFile.Close(); err != nil { return fmt.Errorf("close temp err: %w", err) }; if err := os.Rename(tempFilePath, outputFile); err != nil { return fmt.Errorf("rename temp err: %w", err) }
	if excludedCount > 0 || writtenCount > 0 || *verbose { log.Printf("[INFO] Filtering complete: %d read, %d excluded, %d written to %s", lineCount, excludedCount, writtenCount, filepath.Base(outputFile))}; return nil
}


// --- Workflow Steps (Refactored with More Checks) ---

func enumerateSubdomains(target string, outputFile string) error {
	if !toolExists("subfinder") { log.Println("[WARN] subfinder not found."); writeLines(outputFile, []string{}); return fmt.Errorf("subfinder not found") }
	log.Println("[+] Enumerating subdomains for:", target)
	err := runCommandToFile(outputFile, "subfinder", "-d", target, "-silent")
	logFileSize(outputFile) // Log size after running
	return err
}

func checkLiveDomains(inputFile, outputFile string, tempDir string) error {
	if !toolExists("httpx") { log.Println("[WARN] httpx not found."); writeLines(outputFile, []string{}); return fmt.Errorf("httpx not found") }
	info, err := os.Stat(inputFile); if err != nil || info.Size() == 0 { writeLines(outputFile, []string{}); return nil } // Don't log if input empty, just exit step

	filteredSubsFile := inputFile + ".filtered"; defer os.Remove(filteredSubsFile)
	err = filterFile(inputFile, filteredSubsFile, exclusionPatterns, tempDir)
	if err != nil { log.Printf("[ERROR] Failed exclusion filtering before httpx: %v", err); writeLines(outputFile, []string{}); return err }

	infoFiltered, errFiltered := os.Stat(filteredSubsFile); if errFiltered != nil || infoFiltered.Size() == 0 { writeLines(outputFile, []string{}); return nil } // Don't log if filtered empty, just exit step

	log.Println("[+] Checking for live hosts...")
	err = runCommandToFile(outputFile, "httpx", "-l", filteredSubsFile, "-H", fmt.Sprintf("User-Agent: %s", *userAgent), "-silent", "-threads", fmt.Sprintf("%d", *threads))
	logFileSize(outputFile) // Log size after running
	return err
}


// discoverEndpoints now appends all output to rawDiscoveryFile using robust append
func discoverEndpoints(initialTargets []string, isDomainInput bool, tempDir string) error {
	log.Println("[+] Discovering endpoints (Katana, Hakrawler, Waybackurls, Gau, Paramspider)...")
	os.Remove(rawDiscoveryFile); writeLines(rawDiscoveryFile, []string{}) // Clean slate

	// Filter aliveFile before use
	if _, err := os.Stat(aliveFile); err == nil {
		if errFilter := filterFile(aliveFile, aliveFile, exclusionPatterns, tempDir); errFilter != nil { log.Printf("[ERROR] Failed to filter %s before discovery: %v", aliveFile, errFilter) }
	}

	aliveInfo, aliveErr := os.Stat(aliveFile); isAliveUsable := aliveErr == nil && aliveInfo.Size() > 0
	if !isAliveUsable { log.Println("[INFO] No live hosts found or usable after filtering. Discovery tools requiring hosts will be skipped.") }

	toolsRunCount := 0

	// --- Katana ---
	if toolExists("katana") {
		if isAliveUsable {
			if *verbose { log.Println("  -> Running Katana...") }
			// Use robust append function
			if err := runCommandAppendToFile(rawDiscoveryFile, "katana", "-l", aliveFile, "-silent", "-H", fmt.Sprintf("User-Agent: %s", *userAgent), "-c", fmt.Sprintf("%d", *threads)); err == nil {
				toolsRunCount++
			} else { log.Printf("[WARN] Katana command failed.") }
		}
	} else if *verbose { log.Println("[WARN] katana not found.") }

	// --- Hakrawler ---
	if toolExists("hakrawler") {
		if isAliveUsable {
			if *verbose { log.Println("  -> Running Hakrawler...") }
			// Hakrawler needs stdin, slightly different approach
			cmd := exec.Command("hakrawler", "-ua", *userAgent, "-t", fmt.Sprintf("%d", *threads))
			infile, err := os.Open(aliveFile); if err != nil { log.Printf("[ERROR] Failed to open %s for Hakrawler stdin: %v", aliveFile, err)} else {defer infile.Close(); cmd.Stdin = infile }

			outfile, err := os.OpenFile(rawDiscoveryFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); if err != nil { log.Printf("[ERROR] Failed to open %s for Hakrawler append: %v", rawDiscoveryFile, err)} else { defer outfile.Close(); cmd.Stdout = outfile }

			var stderr bytes.Buffer; cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil { log.Printf("[WARN] Hakrawler command failed: %v\nStderr: %s", err, stderr.String()) } else { toolsRunCount++ }
			time.Sleep(100 * time.Millisecond)
		}
	} else if *verbose { log.Println("[WARN] hakrawler not found.") }


	// --- Waybackurls & Gau & Paramspider ---
	if isDomainInput {
		waybackMissing := !toolExists("waybackurls"); gauMissing := !toolExists("gau"); paramspiderMissing := !toolExists("paramspider")
		for _, domain := range initialTargets {
			excluded, _ := isExcluded(domain, exclusionPatterns); if excluded { continue }
			if !waybackMissing { if err := runCommandAppendToFile(rawDiscoveryFile, "waybackurls", domain); err == nil { toolsRunCount++ } else { log.Printf("[WARN] waybackurls failed for %s", domain)} }
			if !gauMissing { if err := runCommandAppendToFile(rawDiscoveryFile, "gau", "--threads", fmt.Sprintf("%d", *threads), domain); err == nil { toolsRunCount++ } else { log.Printf("[WARN] gau failed for %s", domain)} }
			if !paramspiderMissing { if err := runCommandAppendToFile(rawDiscoveryFile, "paramspider", "-d", domain); err == nil { toolsRunCount++ } else { log.Printf("[WARN] paramspider failed for %s", domain)} }
		}
	}

	size := logFileSize(rawDiscoveryFile) // Log size after all appends
	if toolsRunCount > 0 && size == 0 {
		log.Printf("[WARN] Discovery tools ran but produced no output to %s.", filepath.Base(rawDiscoveryFile))
	} else if toolsRunCount == 0 {
		log.Println("[INFO] No applicable discovery tools were found or ran successfully.")
	}

	log.Println("[+] Endpoint discovery phase complete.")
	return nil
}

// unifyAndCleanUrls now takes the single raw discovery file
func unifyAndCleanUrls(inputFile, outputFile string, tempDir string) error {
	log.Println("[+] Unifying and cleaning discovered URLs...")

	// Check input size before proceeding
	rawSize := logFileSize(inputFile)
	if rawSize == 0 {
		log.Println("[INFO] Raw discovery file is empty. Skipping unification.")
		return writeLines(outputFile, []string{}) // Create empty temp output
	}

	uniqueUrls := make(map[string]bool)
	file, err := os.Open(inputFile); if err != nil { log.Printf("[ERROR] Failed open raw discovery %s: %v\n", inputFile, err); return writeLines(outputFile, []string{}) }; defer file.Close()
	scanner := bufio.NewScanner(file); const maxCapacity = 5 * 1024 * 1024; buf := make([]byte, maxCapacity); scanner.Buffer(buf, maxCapacity)
	for scanner.Scan() { line := strings.TrimSpace(scanner.Text()); if line != "" && (strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://")) { if fragIndex := strings.Index(line, "#"); fragIndex != -1 { line = line[:fragIndex] }; uniqueUrls[line] = true } }
	if err := scanner.Err(); err != nil { log.Printf("[ERROR] Error scanning raw discovery %s: %v\n", inputFile, err) }

	if len(uniqueUrls) == 0 { log.Println("[INFO] No valid URLs found after discovery scan. Creating empty output."); return writeLines(outputFile, []string{}) }

	outputLines := make([]string, 0, len(uniqueUrls))
	for url := range uniqueUrls { outputLines = append(outputLines, url) }
	err = writeLines(outputFile, outputLines); if err != nil { log.Printf("[ERROR] Failed write temp unified %s: %v\n", outputFile, err); return err }
	log.Printf("[INFO] Found %d unique URLs from sources.", len(outputLines))
	logFileSize(outputFile) // Log size before exclusion

	// Apply Exclusions
	err = filterFile(outputFile, outputFile, exclusionPatterns, tempDir)
	if err != nil { log.Printf("[ERROR] Failed apply exclusions during unification: %v", err); writeLines(outputFile, []string{}); return err }
	logFileSize(outputFile) // Log size after exclusion

	return nil
}

// filterUrlsWithParams now takes the temp unified file and outputs the final target file
func filterUrlsWithParams(inputFile, outputFile string) error {
	log.Println("[+] Filtering for URLs with parameters...")

	// Check input size
	unifiedSize := logFileSize(inputFile)
	if unifiedSize == 0 {
		log.Println("[INFO] Unified URL file is empty. Skipping parameter filtering.")
		return writeLines(outputFile, []string{})
	}

	allUrls, err := readLines(inputFile); if err != nil { log.Printf("[ERROR] Failed read %s for param filtering: %v\n", inputFile, err); return writeLines(outputFile, []string{}) }

	var urlsWithParams []string
	paramCount := 0
	for _, url := range allUrls { qIndex := strings.Index(url, "?"); if qIndex != -1 && strings.Contains(url[qIndex:], "=") { urlsWithParams = append(urlsWithParams, url); paramCount++ } }

	err = writeLines(outputFile, urlsWithParams); if err != nil { log.Printf("[ERROR] Failed write final targets %s: %v\n", outputFile, err); return err }

	finalSize := logFileSize(outputFile) // Log final size
	if finalSize > 0 {
		log.Printf("[INFO] Found %d URLs with parameters. Saved to %s\n", paramCount, filepath.Base(outputFile))
	} else {
		log.Printf("[INFO] No URLs with parameters found after filtering. Final target file (%s) is empty.", filepath.Base(outputFile))
	}
	return nil
}

// scanForXSS takes the final target file
func scanForXSS(inputFile string, dalfoxLog string) error {
	// ... (Mostly same as previous, logging improvements kept) ...
	if !toolExists("dalfox") { log.Println("[WARN] dalfox not found."); return fmt.Errorf("dalfox not found") }
	info, err := os.Stat(inputFile); if err != nil || info.Size() == 0 { return nil } // Silently skip if no input

	log.Println("[+] Running Dalfox XSS scan...")
	if *verbose { log.Printf("    Input: %s", filepath.Base(inputFile)); log.Printf("    Output Log: %s", filepath.Base(dalfoxLog)) }

	dalfoxArgs := []string{ "pipe", "--silence", "--user-agent", *userAgent, "--multicast", "--skip-mining-all", "--deep-domxss", "--no-spinner", "--output", dalfoxLog }
	if *verbose { for i, arg := range dalfoxArgs { if arg == "--silence" { dalfoxArgs = append(dalfoxArgs[:i], dalfoxArgs[i+1:]...); break } } }

	cmd := exec.Command("dalfox", dalfoxArgs)
	infile, err := os.Open(inputFile); if err != nil { log.Printf("[ERROR] Failed open %s for Dalfox pipe: %v\n", inputFile, err); return err }; defer infile.Close()
	cmd.Stdin = infile
	var outData bytes.Buffer; var errData bytes.Buffer; cmd.Stdout = &outData; cmd.Stderr = &errData
	if *verbose { log.Printf("[CMD] Running: cat %s | dalfox %s\n", inputFile, strings.Join(dalfoxArgs, " ")) }
	err = cmd.Run()
	stdoutStr := strings.TrimSpace(outData.String()); stderrStr := strings.TrimSpace(errData.String())
	if stdoutStr != "" { fmt.Println("--- Dalfox Output ---"); fmt.Println(stdoutStr); fmt.Println("---------------------") }
	if err != nil { log.Printf("[WARN] Dalfox finished with non-zero status: %v.", err); if stderrStr != "" { log.Printf("[DALFOX STDERR]\n%s", stderrStr) } } else if stderrStr != "" && *verbose { log.Printf("[INFO] Dalfox stderr output:\n%s", stderrStr) }
	log.Printf("[+] Dalfox scan finished.")
	return nil
}

// --- Main Function ---

func main() {
	flag.Parse() // Parse flags first

	// Print Banners
	fmt.Println(piranaText); fmt.Println(piranaArt); fmt.Println("-----------------------------------------")


	// Input Validation (Must happen AFTER flag.Parse())
	inputCount := 0
	if *targetDomain != "" { inputCount++ }; if *targetList != "" { inputCount++ }; if *urlList != "" { inputCount++ }
	if inputCount != 1 {
		fmt.Println("Usage: pirana [options]"); fmt.Println("Provide exactly one of: -d <domain>, -l <domain_list_file>, or -u <url_list_file>")
		flag.PrintDefaults(); fmt.Println("\nExample: ./pirana -d example.com -ef exclusions.txt -t 20 -v")
		os.Exit(1)
	}
	if *skipDiscovery && *urlList == "" { log.Fatal("[ERROR] -skip-discovery requires -u <url_list_file> to be provided.") }


	// Setup
	if *verbose { log.Println("--- Pirana Scanner Initializing (Verbose Mode) ---") } else { log.Println("--- Pirana Scanner Initializing ---") }
	log.Printf("User Agent: %s", *userAgent); log.Printf("Threads: %d", *threads)
	effectiveOutputDir := outputDir
	if err := os.MkdirAll(effectiveOutputDir, 0755); err != nil { log.Fatalf("[FATAL] Create output dir %s failed: %v", effectiveOutputDir, err) }
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
	defer func() { // Cleanup temp files unless verbose
		if !*verbose { for _, f := range tempFiles { os.Remove(f) } } else { log.Printf("[INFO] Verbose: Temp files kept: %s, %s", rawDiscoveryFile, tempAllUrlsFile) }
	}()

	// Load Exclusions
	var loadErr error; exclusionPatterns, loadErr = loadExclusionPatterns(*excludeFile)
	if loadErr != nil { log.Printf("[ERROR] Load exclusions failed: %v. Proceeding without.", loadErr); exclusionPatterns = []string{} }

	// Prepare Initial Targets
	initialTargets := []string{}; isDomainInput := false
	if *targetDomain != "" { initialTargets = append(initialTargets, *targetDomain); isDomainInput = true } else if *targetList != "" { var err error; initialTargets, err = readLines(*targetList); if err != nil { log.Fatalf("[FATAL] Read target list %s failed: %v", *targetList, err) }; isDomainInput = true } else if *urlList != "" { var err error; initialTargets, err = readLines(*urlList); if err != nil { log.Fatalf("[FATAL] Read URL list %s failed: %v", *urlList, err) }; isDomainInput = false }


	// --- Workflow Execution ---
	startTime := time.Now()
	essentialToolsOk := true

	if !*skipDiscovery {
		log.Println("--- Starting Discovery Phase ---")
		if isDomainInput {
			// == Subdomain Enumeration ==
			if err := enumerateSubdomains(initialTargets[0], subsFile); err != nil { log.Printf("[WARN] Subdomain enum failed for %s. Continuing.", initialTargets[0]) }
			// TODO: Handle multiple domains?

			// == Live Domain Check ==
			if !toolExists("httpx") { log.Printf("[WARN] httpx not found. Discovery severely impacted."); essentialToolsOk = false } else { if err := checkLiveDomains(subsFile, aliveFile, effectiveOutputDir); err != nil { log.Printf("[WARN] httpx failed. Discovery may be incomplete."); essentialToolsOk = false } }
		} else { // Input was URL list
			log.Println("[INFO] Using provided URL list for discovery.")
			tempInitialURLs := filepath.Join(effectiveOutputDir, "temp_initial_urls.tmp"); defer os.Remove(tempInitialURLs)
			writeLines(tempInitialURLs, initialTargets)
			if errFilter := filterFile(tempInitialURLs, aliveFile, exclusionPatterns, effectiveOutputDir); errFilter != nil { log.Fatalf("[FATAL] Failed filter initial URL list %s: %v", *urlList, errFilter) }
			if _, err := os.Stat(aliveFile); os.IsNotExist(err) { writeLines(aliveFile, []string{}) }
			essentialToolsOk = true // Assume URLs are usable
		}

		// == Endpoint Discovery (Appends to rawDiscoveryFile) ==
		if essentialToolsOk { discoverEndpoints(initialTargets, isDomainInput, effectiveOutputDir) } else { log.Println("[WARN] Skipping endpoint discovery due to earlier failures (e.g., httpx).") }

		// == Unify + Clean URLs (Uses rawDiscoveryFile -> tempAllUrlsFile) ==
		if err := unifyAndCleanUrls(rawDiscoveryFile, tempAllUrlsFile, effectiveOutputDir); err != nil { log.Printf("[ERROR] Failed during URL unification: %v. Final target list may be empty.", err) }

	} else { // Discovery Skipped
		log.Println("--- Skipping Discovery Phase ---")
		if *urlList == "" { log.Fatal("[FATAL] Cannot skip discovery without -u <url_list_file>.") }
		log.Println("[INFO] Using provided URL list directly.")
		tempInitialURLs := filepath.Join(effectiveOutputDir, "temp_initial_urls.tmp"); defer os.Remove(tempInitialURLs)
		writeLines(tempInitialURLs, initialTargets)
		if errFilter := filterFile(tempInitialURLs, tempAllUrlsFile, exclusionPatterns, effectiveOutputDir); errFilter != nil { log.Fatalf("[FATAL] Failed filter input URL list %s: %v", *urlList, errFilter) }
		logFileSize(tempAllUrlsFile) // Log size after filtering input URLs
	}

	// == Filter URLs with Parameters (Uses tempAllUrlsFile -> finalTargetsFile) ==
	if err := filterUrlsWithParams(tempAllUrlsFile, finalTargetsFile); err != nil { log.Printf("[ERROR] Failed during parameter filtering: %v. Final target list may be empty.", err) }

	// == Run Dalfox for XSS ==
	if !*skipXSS { log.Println("--- Starting XSS Scan Phase ---"); scanForXSS(finalTargetsFile, dalfoxLogFile) } else { log.Println("--- Skipping XSS Scan Phase ---"); os.Remove(dalfoxLogFile) }


	// --- Completion ---
	duration := time.Since(startTime)
	log.Printf("--- Pirana Scan Completed ---"); log.Printf("Total execution time: %s", duration)
	log.Printf("[✓] Done. Check the '%s' directory for main output.", effectiveOutputDir)
	log.Printf("    -> Final Scan Targets: %s (%d URLs)", finalTargetsFile, countLines(finalTargetsFile)) // Show URL count
	if !*skipXSS { if _, err := os.Stat(dalfoxLogFile); err == nil { log.Printf("    -> Dalfox Log: %s", dalfoxLogFile) } }
	if *verbose { log.Printf("[INFO] Use -v flag to see detailed command execution and keep temporary files.") }
}


// Helper to count lines in a file for summary
func countLines(filename string) int {
    f, err := os.Open(filename)
    if err != nil { return 0 }
    defer f.Close()
    scanner := bufio.NewScanner(f)
    count := 0
    for scanner.Scan() {
        if strings.TrimSpace(scanner.Text()) != "" { count++ }
    }
    return count
}
