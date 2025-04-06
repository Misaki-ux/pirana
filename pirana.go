package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url" // Added for URL parsing in exclusion logic
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// --- ASCII Art Banners ---
const piranaText = `   ___  _
  / _ \(_)______ ____  ___ _
 / ___/ / __/ _ `/ _ \/ _ `/
/_/  /_/_/  \_,_/_//_/\_,_/
                            `
const piranaArt = `          ,---,
  _    _,-'    `--,
 ( `-,'            `\
  \           ,    o \
  /   ,       ;       \
 (_,-' \       `, _  ""/
     pb `-,___ =='__,-'
              ````
`
// --- Configuration Constants ---
const (
	defaultUserAgent = "PiranaScanner/1.0 (+https://github.com/Misaki-ux/pirana.git)" // Mettez votre lien repo
	outputDir        = "pirana_output"                                           // Default output directory name
)

var (
	// Flags
	targetDomain    = flag.String("d", "", "Single target domain (e.g., example.com)")
	targetList      = flag.String("l", "", "File containing list of target domains (one per line)")
	urlList         = flag.String("u", "", "File containing list of URLs to scan directly (skips discovery)")
	threads         = flag.Int("t", 10, "Number of concurrent threads/goroutines")
	userAgent       = flag.String("ua", defaultUserAgent, "Custom User-Agent for HTTP requests")
	excludeFile     = flag.String("ef", "", "File containing exclusion patterns (domains/subdomains, one per line, e.g., *.internal.com, secrets.com)") // Exclusion flag
	skipDiscovery   = flag.Bool("skip-discovery", false, "Skip subdomain enumeration and URL discovery (use with -u)")
	skipXSS         = flag.Bool("skip-xss", false, "Skip Dalfox XSS scanning")
	outputPrefix    = flag.String("o", "", "Prefix for output files (default is domain name or 'list')")
	// --- Internal ---
	wg                sync.WaitGroup
	exclusionPatterns []string // Stores loaded exclusion patterns
	// File paths (will be updated with prefix later)
	domainFile      = filepath.Join(outputDir, "domains.txt") // Keep track of initial domains if list provided
	subsFile        = filepath.Join(outputDir, "subs.txt")
	aliveFile       = filepath.Join(outputDir, "alive.txt")
	katanaFile      = filepath.Join(outputDir, "katana.txt")
	hakrawlerFile   = filepath.Join(outputDir, "hakrawler.txt")
	waybackFile     = filepath.Join(outputDir, "wayback.txt")
	gauFile         = filepath.Join(outputDir, "gau.txt")
	paramspiderFile = filepath.Join(outputDir, "paramspider.txt") // paramspider output dir/file needs care
	allCleanFile    = filepath.Join(outputDir, "all_urls_clean.txt")
	paramsFile      = filepath.Join(outputDir, "urls_with_params.txt")
	dalfoxLogFile   = filepath.Join(outputDir, "dalfox_scan.log") // Dalfox often outputs to stdout/stderr
)

// Helper function to run external commands
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout // Show command output directly
	cmd.Stderr = os.Stderr // Show command errors directly
	log.Printf("[CMD] Running: %s %s\n", name, strings.Join(args, " "))
	err := cmd.Run()
	if err != nil {
		// Log error but don't necessarily exit; tool might just be missing
		log.Printf("[ERROR] Command '%s %s' failed: %v\n", name, strings.Join(args, " "), err)
		return fmt.Errorf("command failed: %s", name)
	}
	log.Printf("[INFO] Command completed successfully: %s\n", name)
	return nil
}

// Helper function to run command and capture output to a file
func runCommandToFile(outputFile string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	outfile, err := os.Create(outputFile)
	if err != nil {
		log.Printf("[ERROR] Failed to create output file %s: %v\n", outputFile, err)
		return err
	}
	defer outfile.Close()

	cmd.Stdout = outfile
	// Redirect stderr to capture errors if needed, or let it go to console
	cmd.Stderr = os.Stderr // Show errors from the tool on console

	log.Printf("[CMD] Running: %s %s > %s\n", name, strings.Join(args, " "), outputFile)
	err = cmd.Run()
	if err != nil {
		// Log error but keep the output file (it might contain partial results or error messages)
		log.Printf("[ERROR] Command '%s %s' failed: %v\n", name, strings.Join(args, " "), err)
		// Attempt to ensure file handle is released before returning
		outfile.Close()
		time.Sleep(50 * time.Millisecond) // Small delay for FS
		return fmt.Errorf("command failed: %s", name)
	}
	// Ensure file is written before proceeding
	outfile.Close()
	time.Sleep(100 * time.Millisecond) // Extra delay for filesystem sync
	log.Printf("[INFO] Command completed successfully: %s, output: %s\n", name, outputFile)
	return nil
}

// Checks if a tool exists in PATH
func toolExists(name string) bool {
	_, err := exec.LookPath(name)
	if err != nil {
		// Log only once if a tool is missing? Need a map for that. Let's log each time for now.
		// log.Printf("[WARN] Tool '%s' not found in PATH.", name)
	}
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
	// Increase buffer size for potentially long lines
	const maxCapacity = 2 * 1024 * 1024 // 2 MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		// Handle scanner errors (e.g., line too long)
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

// --- Exclusion Logic ---

// Loads exclusion patterns from the specified file
func loadExclusionPatterns(filename string) ([]string, error) {
	if filename == "" {
		return nil, nil // No exclusion file provided
	}

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[WARN] Exclusion file '%s' not found. Proceeding without exclusions.", filename)
			return nil, nil // File not found is not a fatal error
		}
		return nil, fmt.Errorf("failed to open exclusion file %s: %w", filename, err)
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)
	log.Printf("[INFO] Loading exclusion patterns from: %s", filename)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Ignore empty lines and comments (#)
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, strings.ToLower(line)) // Store patterns in lowercase
			log.Printf("  - Loaded exclusion pattern: %s", line)
		}
	}
	if err := scanner.Err(); err != nil {
		return patterns, fmt.Errorf("error reading exclusion file %s: %w", filename, err)
	}
	log.Printf("[INFO] Loaded %d exclusion patterns.", len(patterns))
	return patterns, nil
}

// Checks if a given target (domain or URL) matches any exclusion pattern
func isExcluded(target string, patterns []string) (bool, error) {
	if len(patterns) == 0 {
		return false, nil // No patterns to check against
	}

	normalizedTarget := strings.ToLower(target)
	targetHost := normalizedTarget
	var parseErr error

	// If it's a URL, extract the host for matching
	if strings.Contains(normalizedTarget, "://") {
		parsedURL, err := url.Parse(normalizedTarget)
		if err != nil {
			log.Printf("[WARN] Could not parse potential URL for exclusion check: %s - %v. Proceeding with string matching.", target, err)
			targetHost = "" // Mark as unable to get host
			parseErr = fmt.Errorf("url parse error: %w", err) // Keep track of parse error
		} else {
			targetHost = strings.ToLower(parsedURL.Hostname())
		}
		// Handle cases like file:// or mailto: where hostname might be empty or irrelevant
		if targetHost == "" && parseErr == nil { // If no host extracted AND no parse error occurred before
			log.Printf("[WARN] Could not extract hostname for exclusion check: %s. Performing basic string match.", target)
		}
	}

	for _, pattern := range patterns {
		// 1. Check for exact match (case-insensitive) against the original target OR the extracted host
		if normalizedTarget == pattern || (targetHost != "" && targetHost == pattern) {
			return true, parseErr // Excluded, return any parsing error encountered
		}

		// 2. Check for wildcard match (*.domain.tld) only against the extracted host
		if targetHost != "" && strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // Includes the leading dot, e.g., ".example.com"
			if strings.HasSuffix(targetHost, suffix) && len(targetHost) > len(suffix) {
				return true, parseErr // Excluded, return any parsing error encountered
			}
		}
	}

	return false, parseErr // Not excluded, return any parsing error
}

// Helper function to filter lines in a file based on exclusion patterns
// Writes the filtered output to outputFile using a temporary file for safety.
func filterFile(inputFile, outputFile string, exclusionPatterns []string, tempDir string) error {
	if len(exclusionPatterns) == 0 && inputFile == outputFile {
		log.Printf("[INFO] No exclusion patterns provided. Skipping filtering for %s.", filepath.Base(inputFile))
		// Ensure output file exists if input does, even if empty
		if _, err := os.Stat(inputFile); err == nil {
			return nil
		} else if os.IsNotExist(err) {
			emptyOut, createErr := os.Create(outputFile); if createErr != nil { return fmt.Errorf("failed to create empty output file %s: %w", outputFile, createErr)}; emptyOut.Close()
			return nil
		} else {
			return fmt.Errorf("failed to stat input file %s: %w", inputFile, err)
		}
	} else if len(exclusionPatterns) == 0 && inputFile != outputFile {
		// Copy inputFile to outputFile if no exclusions and paths differ
		log.Printf("[INFO] No exclusion patterns. Copying %s to %s.", filepath.Base(inputFile), filepath.Base(outputFile))
		in, err := os.Open(inputFile)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("[WARN] Input file %s does not exist for copying.", inputFile)
				emptyOut, createErr := os.Create(outputFile); if createErr != nil { return fmt.Errorf("failed to create empty output file %s: %w", outputFile, createErr)}; emptyOut.Close()
				return nil
			}
			return fmt.Errorf("failed to open input file %s for copy: %w", inputFile, err)
		}
		defer in.Close()
		out, err := os.Create(outputFile)
		if err != nil { return fmt.Errorf("failed to create output file %s for copy: %w", outputFile, err)}
		defer out.Close()
		_, err = io.Copy(out, in)
		if err != nil { return fmt.Errorf("failed to copy %s to %s: %w", inputFile, outputFile, err)}
		out.Close(); in.Close() // Ensure closed before returning
		return nil
	}


	log.Printf("[+] Applying exclusions to %s -> %s", filepath.Base(inputFile), filepath.Base(outputFile))

	// Create a temporary file in the specified tempDir (e.g., outputDir)
	tempFile, err := os.CreateTemp(tempDir, "pirana_filter_*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file in %s: %w", tempDir, err)
	}
	tempFilePath := tempFile.Name()
	// Ensure temp file is closed and removed if rename fails or process panics
	defer func() {
		tempFile.Close()      // Close it first
		os.Remove(tempFilePath) // Attempt removal
	}()


	infile, err := os.Open(inputFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[INFO] Filter input file %s does not exist, creating empty output %s", inputFile, outputFile)
			emptyOut, createErr := os.Create(outputFile); if createErr != nil { return fmt.Errorf("failed to create empty output file %s: %w", outputFile, createErr)}; emptyOut.Close()
			return nil
		}
		return fmt.Errorf("failed to open input file %s: %w", inputFile, err)
	}
	defer infile.Close() // Close input file when done

	writer := bufio.NewWriter(tempFile)
	scanner := bufio.NewScanner(infile)
	const maxCapacity = 2 * 1024 * 1024 // 2 MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	lineCount := 0
	excludedCount := 0
	writtenCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineCount++
		excluded, checkErr := isExcluded(line, exclusionPatterns)
		if checkErr != nil {
			log.Printf("[WARN] Error during exclusion check for line '%s': %v. Including line by default.", line, checkErr)
			excluded = false // Default to include if checking failed
		}

		if !excluded {
			fmt.Fprintln(writer, line)
			writtenCount++
		} else {
			excludedCount++
			// log.Printf("[DEBUG] Excluding line: %s", line) // Uncomment for debugging
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning input file %s: %w", inputFile, err)
	}

	// Flush writer and close temp file *before* renaming
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer for temp file %s: %w", tempFilePath, err)
	}
	if err := tempFile.Close(); err != nil {
		os.Remove(tempFilePath) // Attempt removal even if close fails
		return fmt.Errorf("failed to close temp file %s: %w", tempFilePath, err)
	}

	// Rename temporary file to the final output file (atomic on most systems)
	if err := os.Rename(tempFilePath, outputFile); err != nil {
		// If rename fails, the temp file might still exist. Defer should clean it.
		return fmt.Errorf("failed to rename temp file %s to %s: %w", tempFilePath, outputFile, err)
	}

	log.Printf("[INFO] Filtering complete for %s: %d lines read, %d excluded, %d written to %s", filepath.Base(inputFile), lineCount, excludedCount, writtenCount, filepath.Base(outputFile))
	return nil
}


// --- Workflow Steps ---

func enumerateSubdomains(target string, outputFile string) error {
	if !toolExists("subfinder") {
		log.Println("[WARN] subfinder not found in PATH. Skipping subdomain enumeration.")
		writeLines(outputFile, []string{})
		return fmt.Errorf("subfinder not found")
	}
	log.Println("[+] Enumerating subdomains for:", target)
	return runCommandToFile(outputFile, "subfinder", "-d", target, "-silent")
}

func checkLiveDomains(inputFile, outputFile string, tempDir string) error {
	if !toolExists("httpx") {
		log.Println("[WARN] httpx not found in PATH. Skipping live domain check.")
		writeLines(outputFile, []string{})
		return fmt.Errorf("httpx not found")
	}

	info, err := os.Stat(inputFile)
	if err != nil || info.Size() == 0 {
		log.Printf("[INFO] Input file %s for httpx is empty or doesn't exist. Skipping live check.", inputFile)
		writeLines(outputFile, []string{}) // Create empty alive file
		return nil
	}

	// Apply Exclusions BEFORE running httpx
	filteredSubsFile := inputFile + ".filtered"
	err = filterFile(inputFile, filteredSubsFile, exclusionPatterns, tempDir)
	if err != nil {
		log.Printf("[ERROR] Failed to apply exclusions to %s: %v. Skipping httpx.", inputFile, err)
		writeLines(outputFile, []string{})
		return err
	}
	defer os.Remove(filteredSubsFile) // Clean up intermediate file

	infoFiltered, errFiltered := os.Stat(filteredSubsFile)
	if errFiltered != nil || infoFiltered.Size() == 0 {
		log.Printf("[INFO] Input file %s became empty after applying exclusions. Skipping httpx.", inputFile)
		writeLines(outputFile, []string{}) // Create empty alive file
		return nil
	}

	log.Println("[+] Checking for live domains from filtered list:", filteredSubsFile)
	err = runCommandToFile(outputFile, "httpx", "-l", filteredSubsFile, "-H", fmt.Sprintf("User-Agent: %s", *userAgent), "-silent", "-threads", fmt.Sprintf("%d", *threads))
	if err != nil {
		log.Printf("[ERROR] httpx command failed. Output might be incomplete in %s.", outputFile)
		return err
	}

	return nil
}


func discoverEndpoints(initialTargets []string, isDomainInput bool, tempDir string) error {
	log.Println("[+] Discovering endpoints...")

	// Apply Exclusions to the 'alive' list BEFORE feeding to crawlers
	if _, err := os.Stat(aliveFile); err == nil { // Check if aliveFile exists
		errFilter := filterFile(aliveFile, aliveFile, exclusionPatterns, tempDir) // Filter in-place
		if errFilter != nil {
			log.Printf("[ERROR] Failed to apply exclusions to %s before discovery: %v. Proceeding with potentially unfiltered list.", aliveFile, errFilter)
		}
	} else {
		log.Printf("[INFO] %s not found, skipping exclusion filtering before discovery.", aliveFile)
	}

	aliveInfo, aliveErr := os.Stat(aliveFile)
	isAliveUsable := aliveErr == nil && aliveInfo.Size() > 0


	allSources := []string{katanaFile, hakrawlerFile, waybackFile, gauFile, paramspiderFile}
	for _, f := range allSources {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			os.Create(f) // Create empty file
		}
	}


	// --- Katana ---
	if toolExists("katana") {
		if isAliveUsable {
			log.Println("  -> Running Katana...")
			runCommandToFile(katanaFile, "katana", "-l", aliveFile, "-silent", "-H", fmt.Sprintf("User-Agent: %s", *userAgent), "-c", fmt.Sprintf("%d", *threads))
		} else {
			 log.Println("[INFO] Skipping Katana as input file is empty, missing, or filtered out:", aliveFile)
			 writeLines(katanaFile, []string{}) // Ensure empty output
		}
	} else {
		log.Println("[WARN] katana not found in PATH. Skipping.")
		writeLines(katanaFile, []string{}) // Ensure empty output
	}

	// --- Hakrawler ---
	if toolExists("hakrawler") {
		if isAliveUsable {
			log.Println("  -> Running Hakrawler...")
			cmdStr := fmt.Sprintf("cat %s | hakrawler -ua \"%s\" -t %d >> %s", aliveFile, *userAgent, *threads, hakrawlerFile)
			log.Printf("[CMD] Running: sh -c '%s'\n", cmdStr)
			cmd := exec.Command("sh", "-c", cmdStr)
			cmd.Stderr = os.Stderr // Show errors
			if err := cmd.Run(); err != nil {
				log.Printf("[ERROR] Failed to run hakrawler command: %v", err)
			}
			time.Sleep(100 * time.Millisecond) // Filesystem sync after append
		} else {
			 log.Println("[INFO] Skipping Hakrawler as input file is empty, missing, or filtered out:", aliveFile)
		}
	} else {
		log.Println("[WARN] hakrawler not found in PATH. Skipping.")
	}


	// --- Waybackurls & Gau (run per initial target domain only if not excluded) ---
	if isDomainInput {
		log.Println("  -> Running Waybackurls/Gau on initial non-excluded domains...")
		processedDomains := 0
		waybackMissingLogged := !toolExists("waybackurls")
		gauMissingLogged := !toolExists("gau")
		paramspiderMissingLogged := !toolExists("paramspider")

		if !waybackMissingLogged { log.Println("[INFO] waybackurls found.")} else {log.Println("[WARN] waybackurls not found in PATH.")}
		if !gauMissingLogged { log.Println("[INFO] gau found.")} else {log.Println("[WARN] gau not found in PATH.")}
		if !paramspiderMissingLogged { log.Println("[INFO] paramspider found.")} else {log.Println("[WARN] paramspider not found in PATH.")}


		for _, domain := range initialTargets {
			excluded, _ := isExcluded(domain, exclusionPatterns)
			if excluded {
				log.Printf("[INFO] Skipping Wayback/Gau/Paramspider for excluded initial domain: %s", domain)
				continue
			}
			processedDomains++

			// Run Waybackurls
			if !waybackMissingLogged {
				log.Printf("    -> Running waybackurls for %s...\n", domain)
				cmd := exec.Command("waybackurls", domain)
				outfile, err := os.OpenFile(waybackFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil { log.Printf("[ERROR] Cannot open %s for append: %v", waybackFile, err); continue }
				cmd.Stdout = outfile; cmd.Stderr = os.Stderr
				log.Printf("[CMD] Running: waybackurls %s >> %s\n", domain, waybackFile)
				if err := cmd.Run(); err != nil { log.Printf("[ERROR] waybackurls failed for %s: %v", domain, err) }
				outfile.Close(); time.Sleep(100 * time.Millisecond)
			}

			// Run Gau
			if !gauMissingLogged {
				log.Printf("    -> Running gau for %s...\n", domain)
				cmd := exec.Command("gau", "--threads", fmt.Sprintf("%d", *threads), domain)
				outfile, err := os.OpenFile(gauFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil { log.Printf("[ERROR] Cannot open %s for append: %v", gauFile, err); continue }
				cmd.Stdout = outfile; cmd.Stderr = os.Stderr
				log.Printf("[CMD] Running: gau --threads %d %s >> %s\n", *threads, domain, gauFile)
				if err := cmd.Run(); err != nil { log.Printf("[ERROR] gau failed for %s: %v", domain, err) }
				outfile.Close(); time.Sleep(100 * time.Millisecond)
			}

			// Run Paramspider
			if !paramspiderMissingLogged {
				log.Printf("    -> Running paramspider for %s...\n", domain)
				cmd := exec.Command("paramspider", "-d", domain)
				outfile, err := os.OpenFile(paramspiderFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil { log.Printf("[ERROR] Cannot open %s for append: %v", paramspiderFile, err); continue }
				cmd.Stdout = outfile; cmd.Stderr = os.Stderr
				log.Printf("[CMD] Running: paramspider -d %s >> %s\n", domain, paramspiderFile)
				if err := cmd.Run(); err != nil { log.Printf("[ERROR] paramspider failed for %s: %v", domain, err) }
				outfile.Close(); time.Sleep(100 * time.Millisecond)
			}
		}
		if processedDomains == 0 && len(initialTargets) > 0 {
			log.Println("[INFO] All initial domains were excluded or tools were missing. Skipping Waybackurls/Gau/Paramspider runs.")
		}

	} else {
		log.Println("[INFO] Skipping domain-based Waybackurls/Gau/Paramspider as input was a URL list.")
	}

	return nil
}

// Go-based unification and cleaning (replaces `uro`)
func unifyAndCleanUrls(inputs []string, outputFile string, tempDir string) error {
	log.Println("[+] Unifying and cleaning URLs from discovery sources...")
	uniqueUrls := make(map[string]bool)
	processedFiles := 0

	for _, inputFile := range inputs {
		if _, err := os.Stat(inputFile); os.IsNotExist(err) {
			// log.Printf("[DEBUG] Input file for unification not found: %s. Skipping.\n", inputFile) // Less noisy
			continue
		}
		fileInfo, _ := os.Stat(inputFile)
		if fileInfo.Size() == 0 {
			// log.Printf("[DEBUG] Input file for unification is empty: %s. Skipping.\n", inputFile) // Less noisy
			continue
		}

		processedFiles++
		log.Printf("  -> Processing %s\n", filepath.Base(inputFile))
		file, err := os.Open(inputFile)
		if err != nil {
			log.Printf("[ERROR] Failed to open %s for unification: %v\n", inputFile, err)
			continue // Skip this file
		}

		scanner := bufio.NewScanner(file)
		const maxCapacity = 5 * 1024 * 1024 // 5 MB buffer, adjust if needed
		buf := make([]byte, maxCapacity)
		scanner.Buffer(buf, maxCapacity)

		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line != "" && (strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://")) {
				// Basic normalization: remove fragment
				if fragIndex := strings.Index(line, "#"); fragIndex != -1 {
					line = line[:fragIndex]
				}
				uniqueUrls[line] = true
			} else if line != "" {
				// log.Printf("[DEBUG] Skipping malformed/non-HTTP line in %s:%d: %s", filepath.Base(inputFile), lineNum, line)
			}
		}
		file.Close() // Close file inside the loop
		if err := scanner.Err(); err != nil {
			log.Printf("[ERROR] Error scanning file %s: %v\n", inputFile, err)
		}
	}

	if processedFiles == 0 {
		log.Println("[INFO] No valid discovery source files found or processed to unify. Creating empty output.")
		return writeLines(outputFile, []string{})
	}


	// Write unique URLs temporarily before filtering
	tempUnifiedFile := outputFile + ".tmp_unified"
	outputLines := make([]string, 0, len(uniqueUrls))
	for url := range uniqueUrls {
		outputLines = append(outputLines, url)
	}
	err := writeLines(tempUnifiedFile, outputLines)
	if err != nil {
		log.Printf("[ERROR] Failed to write temporary unified URLs to %s: %v\n", tempUnifiedFile, err)
		return err
	}
	defer os.Remove(tempUnifiedFile) // Clean up temp file

	log.Printf("[INFO] Found %d unique URLs from sources.", len(outputLines))

	// Apply Exclusions to the unified list
	err = filterFile(tempUnifiedFile, outputFile, exclusionPatterns, tempDir) // Write to final file path
	if err != nil {
		log.Printf("[ERROR] Failed to apply exclusions during unification: %v", err)
		writeLines(outputFile, []string{}) // Create empty final file on error
		return err
	}

	return nil
}

// Go-based parameter filtering (replaces `grep '='`)
func filterUrlsWithParams(inputFile, outputFile string) error {
	log.Println("[+] Filtering URLs with parameters...")
	var urlsWithParams []string

	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		log.Printf("[WARN] Input file for parameter filtering not found: %s. Skipping.\n", inputFile)
		writeLines(outputFile, []string{}) // Create empty output
		return nil
	}

	allUrls, err := readLines(inputFile)
	if err != nil {
		log.Printf("[ERROR] Failed to read %s for parameter filtering: %v\n", inputFile, err)
		writeLines(outputFile, []string{})
		return err
	}

	if len(allUrls) == 0 {
		log.Println("[INFO] Input file for parameter filtering is empty. Nothing to filter.")
		writeLines(outputFile, []string{}) // Ensure output file is also empty
		return nil
	}

	paramCount := 0
	for _, url := range allUrls {
		// Check if '=' exists and is likely part of query parameters (after '?')
		qIndex := strings.Index(url, "?")
		if qIndex != -1 && strings.Contains(url[qIndex:], "=") {
			urlsWithParams = append(urlsWithParams, url)
			paramCount++
		}
	}

	err = writeLines(outputFile, urlsWithParams)
	if err != nil {
		log.Printf("[ERROR] Failed to write parameter URLs to %s: %v\n", outputFile, err)
		return err
	}

	log.Printf("[INFO] Found %d URLs with parameters. Saved to %s\n", paramCount, outputFile)
	return nil
}


func scanForXSS(inputFile string, dalfoxLog string) error {
	if !toolExists("dalfox") {
		log.Println("[WARN] dalfox not found in PATH. Skipping XSS scan.")
		return fmt.Errorf("dalfox not found")
	}

	info, err := os.Stat(inputFile)
	if err != nil || info.Size() == 0 {
		log.Printf("[INFO] Input file %s for Dalfox is empty or doesn't exist. Skipping XSS scan.", inputFile)
		return nil
	}

	log.Println("[+] Running Dalfox for XSS hunting on URLs from:", inputFile)

	dalfoxArgs := []string{
		"pipe",
		"--user-agent", *userAgent,
		"--multicast",
		"--skip-mining-all",
		"--deep-domxss",
		"--no-spinner",
		"--silence",
		"--output", dalfoxLog,
		// Add other flags as needed, e.g., for WAF bypass
		// "--waf-evasion",
	}

	cmd := exec.Command("dalfox", dalfoxArgs...)

	infile, err := os.Open(inputFile)
	if err != nil {
		log.Printf("[ERROR] Failed to open input file %s for Dalfox pipe: %v\n", inputFile, err)
		return err
	}
	defer infile.Close()
	cmd.Stdin = infile

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Printf("[CMD] Running: cat %s | dalfox %s\n", inputFile, strings.Join(dalfoxArgs, " "))
	err = cmd.Run()
	if err != nil {
		log.Printf("[WARN] Dalfox command finished with non-zero status: %v. Check logs/output.", err)
	}

	log.Printf("[INFO] Dalfox scan finished. Check console output and log file: %s\n", dalfoxLog)
	return nil
}

// --- Main Function ---

func main() {
	flag.Parse()

	// --- Input Validation ---
	inputCount := 0
	if *targetDomain != "" { inputCount++ }
	if *targetList != "" { inputCount++ }
	if *urlList != "" { inputCount++ }

	if inputCount != 1 {
		// Print banner even on error for branding
		fmt.Println(piranaText)
		fmt.Println(piranaArt)
		fmt.Println("-----------------------------------------")
		fmt.Println("Usage: pirana [options]")
		fmt.Println("Provide exactly one of: -d <domain>, -l <domain_list_file>, or -u <url_list_file>")
		flag.PrintDefaults()
		fmt.Println("\nExample: ./pirana -d example.com -ef exclusions.txt -t 20")
		os.Exit(1)
	}
	if *skipDiscovery && *urlList == "" {
		// Print banner even on error
		fmt.Println(piranaText)
		fmt.Println(piranaArt)
		fmt.Println("-----------------------------------------")
		log.Fatal("[ERROR] -skip-discovery requires -u <url_list_file> to be provided.")
	}

	// --- Print Banners ---
	// Use fmt directly for banners so they appear without log prefixes
	fmt.Println(piranaText)
	fmt.Println(piranaArt)
	fmt.Println("-----------------------------------------")


	// --- Setup ---
	log.Printf("--- Pirana Scanner Initializing ---")
	log.Printf("User Agent: %s", *userAgent)
	log.Printf("Threads: %d", *threads)

	effectiveOutputDir := outputDir
	if err := os.MkdirAll(effectiveOutputDir, 0755); err != nil {
		log.Fatalf("[FATAL] Failed to create output directory %s: %v", effectiveOutputDir, err)
	}
	log.Printf("Output directory: %s", effectiveOutputDir)


	primaryTarget := "output"
	if *targetDomain != "" {
		primaryTarget = strings.ReplaceAll(*targetDomain, ".", "_")
	} else if *targetList != "" {
		primaryTarget = strings.TrimSuffix(filepath.Base(*targetList), filepath.Ext(*targetList)) + "_list"
	} else if *urlList != "" {
		primaryTarget = strings.TrimSuffix(filepath.Base(*urlList), filepath.Ext(*urlList)) + "_urls"
	}
	if *outputPrefix != "" {
		primaryTarget = *outputPrefix
	}

	// Update global file path variables
	domainFile = filepath.Join(effectiveOutputDir, primaryTarget+"_initial_domains.txt")
	subsFile = filepath.Join(effectiveOutputDir, primaryTarget+"_subs.txt")
	aliveFile = filepath.Join(effectiveOutputDir, primaryTarget+"_alive.txt")
	katanaFile = filepath.Join(effectiveOutputDir, primaryTarget+"_katana.txt")
	hakrawlerFile = filepath.Join(effectiveOutputDir, primaryTarget+"_hakrawler.txt")
	waybackFile = filepath.Join(effectiveOutputDir, primaryTarget+"_wayback.txt")
	gauFile = filepath.Join(effectiveOutputDir, primaryTarget+"_gau.txt")
	paramspiderFile = filepath.Join(effectiveOutputDir, primaryTarget+"_paramspider.txt")
	allCleanFile = filepath.Join(effectiveOutputDir, primaryTarget+"_all_urls_clean.txt")
	paramsFile = filepath.Join(effectiveOutputDir, primaryTarget+"_urls_with_params.txt")
	dalfoxLogFile = filepath.Join(effectiveOutputDir, primaryTarget+"_dalfox_scan.log")


	// Load Exclusion Patterns
	var loadErr error
	exclusionPatterns, loadErr = loadExclusionPatterns(*excludeFile)
	if loadErr != nil {
		log.Printf("[ERROR] Failed to load exclusion patterns: %v. Proceeding without exclusions.", loadErr)
		exclusionPatterns = []string{}
	}


	// Prepare Initial Targets
	initialTargets := []string{}
	isDomainInput := false

	if *targetDomain != "" {
		initialTargets = append(initialTargets, *targetDomain)
		isDomainInput = true
	} else if *targetList != "" {
		var err error
		initialTargets, err = readLines(*targetList)
		if err != nil { log.Fatalf("[FATAL] Failed to read target list file %s: %v", *targetList, err) }
		isDomainInput = true
	} else if *urlList != "" {
		var err error
		initialTargets, err = readLines(*urlList)
		if err != nil { log.Fatalf("[FATAL] Failed to read URL list file %s: %v", *urlList, err) }
		isDomainInput = false
	}

	if isDomainInput {
		writeLines(domainFile, initialTargets)
	}


	// --- Workflow Execution ---
	startTime := time.Now()

	// Check essential tools early
	essentialToolsOk := true
	if !*skipDiscovery && isDomainInput && !toolExists("subfinder") {
		log.Printf("[WARN] Subfinder not found. Subdomain enumeration will be skipped.")
	}
	if !*skipDiscovery && !toolExists("httpx") {
		log.Printf("[WARN] httpx not found. Live host checking will be skipped, impacting discovery.")
		essentialToolsOk = false // httpx is quite crucial for discovery flow
	}
	if !*skipXSS && !toolExists("dalfox") {
		log.Printf("[WARN] Dalfox not found. XSS scanning will be skipped.")
	}
	// Add checks for other core tools if desired (katana, hakrawler etc.)


	if !*skipDiscovery {
		log.Println("--- Starting Discovery Phase ---")
		if isDomainInput {
			// == Subdomain Enumeration ==
			tempSubsFile := subsFile + ".raw" // Raw output before filtering
			if len(initialTargets) == 1 {
				enumerateSubdomains(initialTargets[0], tempSubsFile)
			} else { // Multiple domains
				log.Println("[+] Enumerating subdomains for multiple targets...")
				allSubsMap := make(map[string]bool)
				for _, domain := range initialTargets {
					tempSingleSubs := filepath.Join(effectiveOutputDir, fmt.Sprintf("temp_subs_%s.txt", strings.ReplaceAll(domain, ".", "_")))
					if err := enumerateSubdomains(domain, tempSingleSubs); err == nil {
						currentSubs, errRead := readLines(tempSingleSubs)
						os.Remove(tempSingleSubs)
						if errRead == nil {
							for _, sub := range currentSubs { allSubsMap[strings.ToLower(sub)] = true }
						} else { log.Printf("[WARN] Could not read subfinder results for %s: %v", domain, errRead) }
					} else { log.Printf("[WARN] Subfinder failed for domain: %s", domain) }
				}
				finalSubs := make([]string, 0, len(allSubsMap))
				for sub := range allSubsMap { finalSubs = append(finalSubs, sub) }
				writeLines(tempSubsFile, finalSubs)
				log.Printf("[INFO] Aggregated %d unique subdomains.", len(finalSubs))
			}


			// == Live Domain Check (includes pre-filtering of tempSubsFile) ==
			if essentialToolsOk { // Only run if httpx is found
				checkLiveDomains(tempSubsFile, aliveFile, effectiveOutputDir)
			} else {
				log.Println("[WARN] Skipping live domain check due to missing httpx.")
				writeLines(aliveFile, []string{}) // Ensure alive file is empty
			}
			os.Remove(tempSubsFile) // Clean up raw subs file

		} else { // Input was URL list
			log.Println("[INFO] Using provided URL list as input for discovery steps.")
			tempInitialURLs := filepath.Join(effectiveOutputDir, "temp_initial_urls.txt")
			writeLines(tempInitialURLs, initialTargets)
			errFilter := filterFile(tempInitialURLs, aliveFile, exclusionPatterns, effectiveOutputDir)
			os.Remove(tempInitialURLs)
			if errFilter != nil { log.Fatalf("[FATAL] Failed to filter initial URL list %s: %v", *urlList, errFilter) }
			if _, err := os.Stat(aliveFile); os.IsNotExist(err) { writeLines(aliveFile, []string{}) }
		}


		// == Endpoint Discovery (includes pre-filtering of aliveFile) ==
		if essentialToolsOk { // Only run if httpx likely produced results
			discoverEndpoints(initialTargets, isDomainInput, effectiveOutputDir)
		} else {
			log.Println("[WARN] Skipping endpoint discovery due to missing httpx.")
			// Ensure discovery output files are empty
			emptyFiles := []string{katanaFile, hakrawlerFile, waybackFile, gauFile, paramspiderFile}
			for _, f := range emptyFiles { writeLines(f, []string{})}
		}


		// == Unify + Clean URLs (includes post-filtering) ==
		endpointSourceFiles := []string{katanaFile, hakrawlerFile, waybackFile, gauFile, paramspiderFile}
		unifyAndCleanUrls(endpointSourceFiles, allCleanFile, effectiveOutputDir)

	} else { // Discovery Skipped
		log.Println("--- Skipping Discovery Phase ---")
		if *urlList == "" { log.Fatal("[FATAL] Cannot skip discovery without -u <url_list_file>.") }

		log.Println("[INFO] Using provided URL list directly.")
		tempInitialURLs := filepath.Join(effectiveOutputDir, "temp_initial_urls.txt")
		writeLines(tempInitialURLs, initialTargets) // initialTargets comes from -u file
		errFilter := filterFile(tempInitialURLs, allCleanFile, exclusionPatterns, effectiveOutputDir)
		os.Remove(tempInitialURLs)
		if errFilter != nil { log.Fatalf("[FATAL] Failed to filter input URL list %s: %v", *urlList, errFilter) }
		log.Printf("[INFO] Filtered input URL list saved to %s", allCleanFile)
		// Ensure discovery files are empty if discovery was skipped
		touchEmpty := []string{subsFile, aliveFile, katanaFile, hakrawlerFile, waybackFile, gauFile, paramspiderFile}
		for _, f := range touchEmpty { os.Remove(f); writeLines(f, []string{})}
	}


	// == Filter URLs with Parameters ==
	filterUrlsWithParams(allCleanFile, paramsFile)


	// == Run Dalfox for XSS ==
	if !*skipXSS {
		log.Println("--- Starting XSS Scan Phase ---")
		scanForXSS(paramsFile, dalfoxLogFile)
	} else {
		log.Println("--- Skipping XSS Scan Phase ---")
		os.Remove(dalfoxLogFile) // Remove any old log file if skipping
	}


	// --- Completion ---
	duration := time.Since(startTime)
	log.Printf("--- Pirana Scan Completed ---")
	log.Printf("Total execution time: %s", duration)
	log.Printf("[✓] Done. Check the '%s' directory for output files.", effectiveOutputDir)
	if !*skipXSS {
		if _, err := os.Stat(dalfoxLogFile); err == nil {
			log.Printf("    -> Dalfox results/log: %s", dalfoxLogFile)
		} else {
			// Check if paramsFile was empty, which would explain no log file
			paramsInfo, _ := os.Stat(paramsFile)
			if paramsInfo != nil && paramsInfo.Size() == 0 {
				log.Printf("    -> Dalfox scan skipped as no URLs with parameters were found in %s.", paramsFile)
			} else {
				log.Printf("    -> Dalfox scan attempted but log file '%s' not found or empty.", dalfoxLogFile)
			}
		}
	}
}
