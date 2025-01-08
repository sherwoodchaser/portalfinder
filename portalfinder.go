package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"
	"net/http"
)

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

// List of account creation paths to check
var createAccountPaths = []string{
	"signup", "register", "create-account", "account/create", "user/create", "account/signup",
}

func main() {
	// Banner with Tool Name in ProjectDiscovery style
	printBanner()

	// Parse command-line flags
	listFlag := flag.String("l", "", "Path to file containing subdomains (one per line)")
	outputFlag := flag.String("o", "", "Path to save valid subdomains")
	verboseFlag := flag.Bool("verbose", false, "Show all results (both with and without account portals)")
	flag.Parse()

	if *listFlag == "" {
		fmt.Println("Please provide a subdomains file with -l option")
		return
	}

	// Read subdomains from file
	subdomains, err := readSubdomainsFromFile(*listFlag)
	if err != nil {
		log.Fatalf("Error reading subdomains from file: %v", err)
		return
	}

	// Open the output file in append mode
	var outputFile *os.File
	if *outputFlag != "" {
		outputFile, err = os.OpenFile(*outputFlag, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Error opening output file: %v", err)
		}
		defer outputFile.Close()
	}

	var wg sync.WaitGroup
	indicatorDone := make(chan bool) // Channel to control animation
	progressChan := make(chan int)   // Channel to update progress
	var mu sync.Mutex               // Mutex to protect progress variable
	progress := 0                    // To track the progress of subdomains being processed

	// Start the animated indicator and progress tracking in separate goroutines
	go animatedIndicator(indicatorDone, len(subdomains), progressChan)

	// Iterate through each subdomain concurrently
	for idx, subdomain := range subdomains {
		wg.Add(1)
		go func(idx int, subdomain string) {
			defer wg.Done()
			if checkSubdomain(subdomain, *verboseFlag, outputFile) {
				// Directly write to file in the goroutine
			}
			// Update progress safely using mutex
			mu.Lock()
			progress++
			mu.Unlock()

			// Send the updated progress to the channel
			progressChan <- progress
		}(idx, subdomain)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Stop the animated indicator
	indicatorDone <- true
}

// Animated indicator for progress display
func animatedIndicator(done chan bool, total int, progressChan chan int) {
	animations := []string{"|", "/", "-", "\\"}
	progress := 0
	for {
		select {
		case <-done:
			return
		case progress = <-progressChan:
			// Print progress with the animation
			animationIndex := progress % len(animations)
			fmt.Printf("\r[%s] %d/%d subdomains checked", animations[animationIndex], progress, total)
		}
	}
}

// Read subdomains from a file
func readSubdomainsFromFile(filename string) ([]string, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	subdomains := strings.Split(string(content), "\n")
	for i := range subdomains {
		subdomains[i] = strings.TrimSpace(subdomains[i])
	}
	return subdomains, nil
}

// Check subdomain and directly save valid ones to the output file
func checkSubdomain(subdomain string, verbose bool, outputFile *os.File) bool {
	accountPortalFound := false
	redirectURL := ""
	detectionMethod := ""
	matchedKeyword := ""
	hasForm := false

	for _, path := range createAccountPaths {
		url := fmt.Sprintf("%s/%s", subdomain, path)
		resp, err := httpClient.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			redirectURL = resp.Header.Get("Location")
		}

		if resp.StatusCode != http.StatusOK && !strings.HasPrefix(fmt.Sprint(resp.StatusCode), "3") {
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		if len(body) > 10000 {
			continue
		}

		if matchedKeyword = findMatchingKeyword(string(body)); matchedKeyword != "" && containsForm(string(body)) {
			accountPortalFound = true
			detectionMethod = "Keywords in body with form"
			hasForm = true
			break
		}

		if containsCreateAccountLinks(string(body)) && containsForm(string(body)) {
			accountPortalFound = true
			detectionMethod = "Links or buttons in body with form"
			hasForm = true
			break
		}
	}

	fmt.Print("\r")

	if accountPortalFound && hasForm {
		if redirectURL != "" {
			fmt.Printf("\033[32m[v] Subdomain has account portal: %s\033[0m -> redirect to: %s [Detected via: %s, Keyword: %s]\n", subdomain, redirectURL, detectionMethod, matchedKeyword)
		} else {
			fmt.Printf("\033[32m[v] Subdomain has account portal: %s\033[0m [Detected via: %s, Keyword: %s]\n", subdomain, detectionMethod, matchedKeyword)
		}
		if outputFile != nil {
			// Write the valid subdomain to the output file immediately
			_, err := outputFile.WriteString(subdomain + "\n")
			if err != nil {
				log.Printf("Error writing to output file: %v", err)
			}
		}
		return true
	} else {
		if verbose {
			fmt.Printf("\033[31m[x] No account portal found: %s\033[0m\n", subdomain)
		}
		return false
	}
}

// Helper function to find matching keywords (this can be extended as needed)
func findMatchingKeyword(body string) string {
	keywords := []string{"create account", "sign up", "register", "join", "signup"}
	for _, keyword := range keywords {
		if strings.Contains(strings.ToLower(body), keyword) {
			return keyword
		}
	}
	return ""
}

// Helper function to check for forms in the body
func containsForm(body string) bool {
	return strings.Contains(body, "<form")
}

// Helper function to check for account creation links or buttons
func containsCreateAccountLinks(body string) bool {
	links := []string{"create account", "sign up", "register", "join"}
	for _, link := range links {
		if strings.Contains(strings.ToLower(body), link) {
			return true
		}
	}
	return false
}


func printBanner() {
	banner := `
	██████╗  ██████╗ ██████╗ ████████╗ █████╗ ██╗     ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
	██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██║     ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
	██████╔╝██║   ██║██████╔╝   ██║   ███████║██║     █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
	██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══██║██║     ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
	██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
	╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
 `
	fmt.Printf("\033[3m\033[1;34m%s\033[0m", banner)
	fmt.Printf("\t\t\033[1;32m⭐ PortalFinder - Account Portal Detection Tool 🗡️ | Built by Sherwood Chaser 🌟\033[0m\n\n")
}
