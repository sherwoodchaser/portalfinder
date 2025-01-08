# PortalFinder - Account Portal Detection Tool

PortalFinder is a tool designed to detect account portals on a list of subdomains. It checks for login, registration, and other account-related pages, and provides feedback on the detection results. It supports multiple detection methods and displays progress while checking subdomains.

## Features

- Detects account portals using predefined paths and keywords.
- Identifies subdomains with forms or specific account-related links.
- Provides live progress updates while scanning.
- Supports saving valid subdomains to a file.
- Fully written in Go, fast and efficient.

## Installation

To build and use the tool locally, follow the steps below:

### Prerequisites

- Go version 1.18 or higher
- you should have list of working subdomains that start with http or https.
- Internet access for checking subdomains

### Steps to Build

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/PortalFinder.git
   cd PortalFinder
  ``

2. Build the executable:

```bash
go build -o portalfinder
```

3. Make the file executable (if on Linux/macOS):

```bash
chmod +x portalfinder
```

4. Now you can run the tool:

```bash
./portalfinder
```


Usage
The PortalFinder tool has a few command-line options for flexibility:

Command-Line Flags
-l <file-path>: Path to the file containing a list of subdomains (one per line).
-o <output-file-path>: Path to save the valid subdomains.
-verbose: Show detailed output for all subdomains, including those without an account portal.

Example Usage
```bash
./portalfinder -l subdomains.txt -o valid_subdomains.txt -verbose
```
This will scan all subdomains listed in subdomains.txt, and save any subdomains with account portals to valid_subdomains.txt. The -verbose flag will show additional details about subdomains without account portals.
