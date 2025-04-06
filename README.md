
---
   ___  _
  / _ \(_)______ ____  ___ _
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

## Usage

```bash
./pirana [options]

## Detailed

## Usage Examples / Exemples d'Utilisation

1.  **English:** Scan a single domain with 15 threads and a specific User-Agent.
    **Français:** Scanner un seul domaine avec 15 threads et un User-Agent spécifique.
    ```bash
    ./pirana -d example.com -t 15 -ua "MyCustomScanner/1.1"
    ```

2.  **English:** Scan a list of domains from a file using 20 threads.
    **Français:** Scanner une liste de domaines depuis un fichier avec 20 threads.
    ```bash
    ./pirana -l domains.txt -t 20
    ```

3.  **English:** Scan a list of URLs directly for XSS (skipping discovery) using 10 threads.
    **Français:** Scanner directement une liste d'URLs pour XSS (en sautant la découverte) avec 10 threads.
    ```bash
    ./pirana -u urls_to_scan.txt -skip-discovery -t 10
    ```

4.  **English:** Scan a domain but skip the final XSS scan.
    **Français:** Scanner un domaine mais sauter le scan XSS final.
    ```bash
    ./pirana -d example.com -skip-xss
    ```

5.  **English:** Specify a prefix for the output files.
    **Français:** Spécifier un préfixe pour les fichiers de sortie.
    ```bash
    ./pirana -d example.com -o my_scan_example
    ```
