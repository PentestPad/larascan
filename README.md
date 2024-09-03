![](angry-golang.jpg "LaraScan Icon")


# LaraScan - Laravel Black-box Security Scanner

Laravel Scanner is a tool designed to help you identify potential vulnerabilities, perform reconnaissance, and gather information on Laravel-based applications. It offers various modules to detect issues such as Laravel version detection, Livewire usage, and more.

## Features
- **Framework Detection:** Identifies the presence of the Laravel framework on a target web application by analyzing headers, cookies, and exposed files (composer.json, composer.lock)
- **Livewire Detection:** Determines if the application uses Livewire and identifies whether it's using Livewire v2 or v3.
- **PHP Version Check:** Extracts the PHP version from the `X-Powered-By` header.
- **Subdomain Enumeration:** Attempts to enumerate common subdomains for the target domain.
- **Debug Mode Detection:** Identifies if the Laravel application's debug mode is enabled.
- **Exposed Development Tools Detection:** - Detects common Laravel development and admin tools (e.g., Laravel Debugbar, Telescope, Horizon) that are exposed publicly and may pose security risks.
- **Host Header Injection:** - Detects if application is vulnerable to Host Header Injection which used at password recovery could lead to account takeover

## Installation

### Prerequisites

- [Go](https://golang.org/doc/install) (version 1.16 or later)

### Steps

1. **Clone the repository:**

    ```bash
    git clone https://github.com/PentestPad/larascan.git
    cd larascan
    ```

2. **Install dependencies:**

   Run `go mod tidy` to install any necessary Go dependencies.

    ```bash
    go mod tidy
    ```

3. **Build the tool:**

   Compile the tool using the Go compiler.

    ```bash
    go build -o larascan cmd/main.go
    ```

4. **Run the tool:**

   You can run the tool using the following command:

    ```bash
    ./larascan --url http://example-laravel-app.com --threads=5
    ```

## Usage

The tool takes a single command-line argument, `--url`, which specifies the target Laravel application's base URL.

### Example

To scan a Laravel application hosted at `http://example-laravel-app.com`, run:

```bash
./larascan --url http://example-laravel-app.com --threads=5
