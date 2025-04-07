
```

   ___  _
  / _ \7_)______ ____  ___ _
 / ___/ / __/ _ `/ _ \/ _ `/
/_/  /_/_/  \_,_/_//_/\_,_/
          ,---,
  _    _,-'    `--,_
 ( `-,'              \
  \           ,    o  \
  /   ,       (        \
 (_,-' \       `, _  """/
        `-,___ =='__,-'
              ````
```

Pirana is a Go-based tool designed to automate parts of the web reconnaissance workflow, focusing on subdomain enumeration, live host checking, extensive endpoint discovery, and preparing targets for XSS vulnerability scanning with Dalfox. It orchestrates several popular open-source tools to streamline the process.

## Features

*   **Subdomain Enumeration:** Uses `subfinder` to discover subdomains for given targets.
*   **Live Host Verification:** Uses `httpx` to check which discovered subdomains are hosting live web servers.
*   **Endpoint Discovery:** Leverages multiple tools (`katana`, `hakrawler`, `waybackurls`, `gau`, `paramspider`) to crawl and discover URLs and potential endpoints from various sources.
*   **URL Unification & Cleaning:** Consolidates URLs from all discovery sources and performs basic cleaning and deduplication.
*   **Parameter Filtering:** Isolates URLs containing query parameters (`?key=value`), which are often interesting targets for vulnerability scanning.
*   **Automated XSS Scanning:** Pipes URLs with parameters directly into `dalfox` for automated XSS hunting, including support for advanced techniques like DOM XSS checks.
*   **Target Exclusion:** Supports an exclusion file (`-ef`) to ignore specific domains, subdomains, or wildcard patterns (out-of-scope targets).
*   **Custom User-Agent:** Allows specifying a custom User-Agent string (`-ua`) for HTTP requests made by integrated tools (where supported).
*   **Configurable Concurrency:** Allows adjusting the number of concurrent operations (`-t`) for tools that support threading.
*   **Flexible Input:** Accepts a single domain (`-d`), a file with a list of domains (`-l`), or a file with a list of URLs (`-u`) to scan directly.
*   **Modular Workflow:** Allows skipping the discovery phase (`-skip-discovery`) or the final XSS scan (`-skip-xss`).
*   **Organized Output:** Saves results into a dedicated output directory (`pirana_output` by default or based on `-o` prefix) with clearly named files for each step.

## Dependencies

Pirana orchestrates several external tools. You **MUST** install them and ensure they are available in your system's `PATH` for Pirana to function correctly.

*   **Go:** Required to compile and run Pirana. ([Download Go](https://golang.org/dl/))
*   **subfinder:** `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
*   **httpx:** `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`
*   **katana:** `go install -v github.com/projectdiscovery/katana/cmd/katana@latest`
*   **hakrawler:** `go install -v github.com/hakluke/hakrawler@latest`
*   **waybackurls:** `go install -v github.com/tomnomnom/waybackurls@latest`
*   **gau:** `go install -v github.com/lc/gau/v2/cmd/gau@latest`
*   **paramspider:** `pip3 install paramspider` (or `pip`) - *Note: Python dependency*
*   **dalfox:** `go install -v github.com/hahwul/dalfox/v2@latest`
*   **nuclei** `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`
*   **fuff** `go install -v github.com/ffuf/ffuf@latest`
  
Verify each tool is installed and accessible by running commands like `subfinder -h`, `httpx -h`, etc., in your terminal.

## Installation

1.  **Install Go:** Ensure you have Go version 1.18 or later installed.
2.  **Install Dependencies:** Install all the tools listed in the [Dependencies](#dependencies) section above and confirm they are in your `PATH`.
3.  **Compile Pirana:**
    ```bash
    git clone https://github.com/your-repo/pirana.git # Replace with your repo URL if applicable
    cd pirana
    go build -o pirana pirana.go
    ```
    This will create the `pirana` executable in the current directory. You can move it to a directory in your `PATH` (like `/usr/local/bin`) for easier access:
    ```bash
    sudo mv pirana /usr/local/bin/
    ```
## Options / Options

*   `-d <domain>`:
    *   Specify a single target domain (e.g., `example.com`).

*   `-l <domain_list_file>`:
    *   Specify a file containing a list of target domains (one per line).

*   `-u <url_list_file>`:
    *   Specify a file containing a list of URLs to scan directly. Often used with `--skip-discovery`.

*   `-ef <exclude_file>`:
    *   Specify a file containing patterns (domains/subdomains) to exclude from the scan (one pattern per line, e.g., `*.internal.com`). See [Exclusion File Format](#exclusion-file-format).

*   `-t <threads>`:
    *   Number of concurrent threads/goroutines for tools that support it.
    *   Default: `10`.

*   `-ua <user_agent>`:
    *   Custom User-Agent string for HTTP requests made by integrated tools (where supported).
    *   Default: `PiranaScanner/1.0 (+https://github.com/Misaki-ux/pirana)` (Replace with your actual link if hosted).

*   `--skip-discovery`:
    *   Skip the initial Subdomain Enumeration, Live Host Checking, and Endpoint Discovery phases.
    *   Requires `-u` (URL list) to be provided as input for subsequent steps (like Nuclei, FFUF, Dalfox).

*   `--skip-nuclei`:
    *   Skip the Nuclei vulnerability scanning phase.
    *   Default: Nuclei scan is run.

*   `--skip-xss`:
    *   Skip the final Dalfox XSS scanning phase.
    *   Default: Dalfox scan is run if parameterized URLs are found.

*   `--ffuf`:
    *   Enable directory and file fuzzing using FFUF against live hosts.
    *   Requires the `-w` flag to specify a wordlist path.
    *   Default: FFUF fuzzing is skipped.

*   `-w <wordlist_path>`:
    *   Specifies the path to the wordlist file required by FFUF.
    *   Only used if `--ffuf` is enabled.

*   `-o <prefix>`:
    *   Specify a custom prefix for all output files within the `pirana_output` directory.
    *   Default: Prefix is automatically generated based on the input domain or list filename (e.g., `example_com`, `domains_list`).

*   `-v`:
    *   Enable verbose output mode. Shows the exact commands being executed by Pirana, provides more detailed logging, and prevents the deletion of temporary files (`.tmp`) upon completion for debugging purposes.
    *   Default: Verbose mode is disabled (output is cleaner).
      
## Usage

```bash
./pirana [options]

## Detailed
## Usage Examples / Exemples d'Utilisation

1.  **English:** Run a standard scan (Subdomain, Live Hosts, Endpoint Discovery, Nuclei, Dalfox).
    **Français:** Lancer un scan standard (Sous-domaines, Hôtes Actifs, Découverte Endpoints, Nuclei, Dalfox).
    ```bash
    ./pirana -d example.com
    ```

2.  **English:** Scan a single domain, but skip the Nuclei vulnerability scan.
    **Français:** Scanner un seul domaine, mais sauter le scan de vulnérabilités Nuclei.
    ```bash
    ./pirana -d example.com --skip-nuclei
    ```

3.  **English:** Scan a single domain and run FFUF directory fuzzing using a specific wordlist. (Nuclei also runs by default).
    **Français:** Scanner un seul domaine et lancer le fuzzing de répertoires FFUF avec une wordlist spécifique. (Nuclei est aussi lancé par défaut).
    ```bash
    ./pirana -d example.com --ffuf -w /path/to/your/wordlist.txt
    ```
    *(**Note:** Replace `/path/to/your/wordlist.txt` with the actual path to your wordlist)*

4.  **English:** Scan a list of domains with higher concurrency, exclusions, run FFUF, but skip the final Dalfox XSS scan.
    **Français:** Scanner une liste de domaines avec une concurrence accrue, des exclusions, lancer FFUF, mais sauter le scan XSS final Dalfox.
    ```bash
    ./pirana -l domains.txt -ef scope_exclusions.txt -t 25 --ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt --skip-xss
    ```
    *(**Note:** Example uses a common SecLists path, adjust as needed)*

5.  **English:** Scan a list of URLs directly (skip discovery), run Nuclei and FFUF on them.
    **Français:** Scanner directement une liste d'URLs (sauter la découverte), lancer Nuclei et FFUF dessus.
    ```bash
    ./pirana -u urls_to_scan.txt --skip-discovery --ffuf -w /path/to/your/wordlist.txt
    ```

6.  **English:** Scan a single domain, skip Nuclei, skip Dalfox, but run FFUF.
    **Français:** Scanner un seul domaine, sauter Nuclei, sauter Dalfox, mais lancer FFUF.
    ```bash
    ./pirana -d example.com --skip-nuclei --skip-xss --ffuf -w /path/to/your/wordlist.txt
    ```

7.  **English:** Scan a single domain with verbose output (shows commands, keeps temp files).
    **Français:** Scanner un seul domaine avec une sortie verbeuse (montre les commandes, conserve les fichiers temporaires).
    ```bash
    ./pirana -d example.com -v
    ```
