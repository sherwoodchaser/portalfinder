package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var createAccountPaths = []string{
	"login", "register", "signup", "signin", "create-account", "log-in", "sign-in", "sign-up", "authentication", "forgot-password", "reset-password",
}

var createAccountKeywords = []string{
	"login", "register", "signup", "signin", "create account", "log in", "sign in", "sign up", "authentication", "forgot password", "reset password",
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second, // Set a timeout for each request
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

	var validSubdomains []string
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
			if checkSubdomain(subdomain, *verboseFlag) {
				validSubdomains = append(validSubdomains, subdomain)
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

	// Save valid subdomains to the output file if specified
	if *outputFlag != "" {
		err := saveSubdomainsToFile(validSubdomains, *outputFlag)
		if err != nil {
			log.Fatalf("Error saving valid subdomains to file: %v", err)
		}
		fmt.Printf("\nValid subdomains saved to %s\n", *outputFlag)
	}
}

// Animated loading indicator with progress
func animatedIndicator(done chan bool, total int, progressChan chan int) {
	animation := []string{"\\", "|", "/", "-"}
	i := 0
	for {
		select {
		case <-done:
			return
		case progress := <-progressChan:
			// Update the progress with subdomains processed
			fmt.Printf("\rChecking subdomains (%d/%d) ... %s", progress, total, animation[i])
			i = (i + 1) % len(animation)
			time.Sleep(100 * time.Millisecond)
		}
	}
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



func readSubdomainsFromFile(filePath string) ([]string, error) {
	var subdomains []string
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subdomains = append(subdomains, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return subdomains, nil
}

func checkSubdomain(subdomain string, verbose bool) bool {
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
		return true
	} else {
		if verbose {
			fmt.Printf("\033[31m[x] No account portal found: %s\033[0m\n", subdomain)
		}
		return false
	}
}

func findMatchingKeyword(body string) string {
	for _, keyword := range createAccountKeywords {
		if strings.Contains(strings.ToLower(body), keyword) {
			return keyword
		}
	}
	return ""
}

func containsCreateAccountLinks(body string) bool {
	linkPattern := `<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>|<button[^>]*>(.*?)</button>`
	re := regexp.MustCompile(linkPattern)
	matches := re.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		if len(match) > 1 && findMatchingKeyword(match[1]) != "" {
			return true
		}
		if len(match) > 2 && findMatchingKeyword(match[2]) != "" {
			return true
		}
	}

	return false
}

func containsForm(body string) bool {
	formPattern := `<form[^>]*>`
	re := regexp.MustCompile(formPattern)
	return re.MatchString(body)
}

func saveSubdomainsToFile(subdomains []string, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, subdomain := range subdomains {
		_, err := file.WriteString(subdomain + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}
