import requests
import threading
import argparse
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import time
import os
import sys

# Set the timeout limit (in seconds)
TIMEOUT = 10

# Output directory for organized file management
OUTPUT_DIR = "output"

# Global variables to track progress
total_urls = 0
processed_urls = 0

# ANSI escape sequences for color - vulnRecon Theme
BOLD = '\033[1m'
DIM = '\033[2m'
RED = '\033[91m'
BOLD_RED = '\033[1;91m'
GREEN = '\033[92m'
BRIGHT_GREEN = '\033[1;92m'
BLUE = '\033[94m'
CYAN = '\033[96m'
BOLD_CYAN = '\033[1;96m'
MAGENTA = '\033[95m'
BOLD_MAGENTA = '\033[1;95m'
YELLOW = '\033[93m'
BOLD_YELLOW = '\033[1;93m'
BOLD_WHITE = '\033[1;97m'
BOLD_GREEN = '\033[1;92m'
RESET = '\033[0m'

def ensure_output_dir():
    """Create output directory if it doesn't exist"""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"{BLUE}[INFO]{RESET} Created output directory: {CYAN}{OUTPUT_DIR}{RESET}")

def print_progress_percentage(current, total, prefix=""):
    """Print progress as percentage"""
    if total > 0:
        percentage = (current / total) * 100
        print(f"{BLUE}[INFO]{RESET} {prefix}Progress: {BOLD}{percentage:.1f}%{RESET} ({BOLD}{current}/{total}{RESET})")

def print_banner():
    banner = f"""
{BOLD_CYAN}             .__        __________
___  ____ __|  |   ____\\______   \\ ____   ____  ____   ____
\\  \\/ /  |  \\  |  /    \\|       _// __ \\_/ ___\\/  _ \\ /    \\
 \\   /|  |  /  |_|   |  \\    |   \\  ___/\\  \\__(  <_> )   |  \\
  \\_/ |____/|____/___|  /____|_  /\\___  >\\___  >____/|___|  /
                      \\/       \\/     \\/     \\/           \\/ {RESET}
{BOLD_MAGENTA}             .__        __________
___  ____ __|  |   ____\\______   \\ ____   ____  ____   ____
\\  \\/ /  |  \\  |  /    \\|       _// __ \\_/ ___\\/  _ \\ /    \\
 \\   /|  |  /  |_|   |  \\    |   \\  ___/\\  \\__(  <_> )   |  \\
  \\_/ |____/|____/___|  /____|_  /\\___  >\\___  >____/|___|  /
                      \\/       \\/     \\/     \\/           \\/ {RESET}
{BOLD_CYAN}════════════════════════════════════════════════════════════════════════════════
{BOLD_MAGENTA}    ■ Vulnerability Reconnaissance Framework{RESET}{BOLD_CYAN}
{BOLD_WHITE}    Query Parameter XSS Detection v2.0{RESET}{BOLD_CYAN}
═════════════════════════════════════════════════════════════════════════════════{RESET}"""
    print(banner)

def save_reflected_url(original_url, param_name, modified_params, output_file):
    """Save the modified URL with {payload} replacing the specific parameter."""
    # Ensure output directory exists
    ensure_output_dir()

    # Use output directory for output file
    output_path = os.path.join(OUTPUT_DIR, output_file)

    temp_params = modified_params.copy()

    # Save with {payload} in place of the current parameter without encoding
    temp_params[param_name] = "{payload}"
    query = "&".join(f"{k}={','.join(v)}" if isinstance(v, list) else f"{k}={v}" for k, v in temp_params.items())
    payload_url = urlunparse(urlparse(original_url)._replace(query=query))

    # Save the clean payload URL to the output file
    with open(output_path, 'a') as f:
        f.write(payload_url + '\n')

    print(f"{BRIGHT_GREEN}[✓ SAVED]{RESET} {CYAN}{payload_url}{RESET}")

def check_reflection(url, output_file):
    global processed_urls

    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Ensure empty parameters are handled
        for param in parsed_url.query.split("&"):
            key_value = param.split("=")
            if len(key_value) == 1 or key_value[1] == "":
                query_params[key_value[0]] = ["vulnReconXSS"]

        # Process each parameter individually
        for param in query_params:
            # Make a deep copy of query parameters to modify only one at a time
            modified_params = {k: v[:] for k, v in query_params.items()}

            # Temporarily set the current parameter to `vulnReconXSS`
            modified_params[param] = ['vulnReconXSS']

            # Reconstruct the modified URL
            query = "&".join(f"{k}={','.join(v)}" if isinstance(v, list) else f"{k}={v}" for k, v in modified_params.items())
            modified_url = urlunparse(parsed_url._replace(query=query))

            # Make a request with a timeout
            response = requests.get(modified_url, timeout=TIMEOUT)

            # Check if 'vulnReconXSS' is reflected in the response
            if 'vulnReconXSS' in response.text:
                print(f"{BRIGHT_GREEN}[+] REFLECTION FOUND{RESET} {CYAN}{modified_url}{RESET} {YELLOW}→{RESET} param: {BOLD_RED}{param}{RESET}")

                # Save URL with {payload} replacing only the current parameter
                save_reflected_url(url, param, modified_params, output_file)

    except requests.exceptions.Timeout:
        print(f"{RED}[!] TIMEOUT{RESET} {DIM}{url}{RESET}")
        time.sleep(2)
    except requests.exceptions.RequestException:
        print(f"{RED}[!] ERROR{RESET} {DIM}{url}{RESET}")
        time.sleep(2)
    finally:
        processed_urls += 1
        print(f"{BLUE}[INFO]{RESET} Progress: {BOLD}{processed_urls}/{total_urls}{RESET} URLs processed")

def main():
    global total_urls

    print_banner()

    parser = argparse.ArgumentParser(description="vulnRecon Reflection Checker - Query Parameter XSS Detection")
    parser.add_argument("file_path", type=str, help="Path to the text file containing URLs")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads to use (default: 5)")

    args = parser.parse_args()

    # Ensure output directory exists
    ensure_output_dir()

    # Try to find input file in output directory first, then in current directory
    input_file_path = args.file_path
    if not os.path.exists(input_file_path):
        # Try looking in output directory
        output_input_path = os.path.join(OUTPUT_DIR, args.file_path)
        if os.path.exists(output_input_path):
            input_file_path = output_input_path
            print(f"{BLUE}[INFO]{RESET} Found input file in output directory: {CYAN}{input_file_path}{RESET}")
        else:
            print(f"{RED}Error: Input file not found at {args.file_path} or {output_input_path}{RESET}")
            return

    # Read URLs from the file
    try:
        with open(input_file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        total_urls = len(urls)
        print(f"{BLUE}[INFO]{RESET} Loaded {BOLD}{total_urls}{RESET} URLs from {CYAN}{input_file_path}{RESET}")
    except Exception as e:
        print(f"{RED}Error reading file: {str(e)}{RESET}")
        return

    # Set the output file (will be saved in output directory)
    output_file = 'xss.txt'

    # Clear previous results in the output file
    output_path = os.path.join(OUTPUT_DIR, output_file)
    open(output_path, 'w').close()

    print(f"{YELLOW}[*] Starting reflection check with {args.threads} threads...{RESET}\n")

    threads = []
    for url in urls:
        while threading.active_count() - 1 >= args.threads:
            pass  # Wait for available thread slot

        thread = threading.Thread(target=check_reflection, args=(url, output_file))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Wait 5 seconds after completion and print progress
    print(f"\n{BLUE}[INFO]{RESET} Scan completed. Waiting 5 seconds before finalizing...")
    for i in range(1, 6):
        time.sleep(1)
        print_progress_percentage(i, 5, "Finalizing ")

    print(f"\n{MAGENTA}════════════════════════════════════════════════════════════════════════════════")
    print(f"{BRIGHT_GREEN}[✓] SCAN COMPLETE{RESET} {MAGENTA}════════════════════════════════════════════════════════════════════════════════")
    print(f"{BLUE}[INFO]{RESET} Results saved to: {CYAN}{output_path}{RESET}")
    if os.path.exists(output_path):
        with open(output_path, 'r') as f:
            count = len(f.readlines())
        print(f"{BLUE}[INFO]{RESET} Total reflected URLs found: {BOLD_RED}{count}{RESET}")
    print(f"{MAGENTA}════════════════════════════════════════════════════════════════════════════════{RESET}")

if __name__ == "__main__":
    import os
    main()