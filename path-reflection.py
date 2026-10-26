import requests
import threading
import argparse
from urllib.parse import urlparse, urlunparse
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
saved_urls = set()  # Set to track saved URLs

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
{BOLD_WHITE}    Path-Based XSS Detection v2.0{RESET}{BOLD_CYAN}
═════════════════════════════════════════════════════════════════════════════════{RESET}"""
    print(banner)

def save_reflected_url(url, modified_path, output_file):
    """Save reflected URLs with '{payload}' replacing 'vulnReconXSS'"""
    # Ensure output directory exists
    ensure_output_dir()

    # Use output directory for output file
    output_path = os.path.join(OUTPUT_DIR, output_file)

    payload_url = urlunparse(url._replace(path=modified_path)).replace("vulnReconXSS", "{payload}")
    if payload_url not in saved_urls:
        with open(output_path, 'a') as f:
            f.write(payload_url + '\n')
        saved_urls.add(payload_url)
        print(f"{BRIGHT_GREEN}[✓ SAVED]{RESET} {CYAN}{payload_url}{RESET}")

def check_reflection(url, output_file):
    global processed_urls

    # List of supported extensions
    SUPPORTED_EXTENSIONS = ['php', 'asp', 'aspx', 'jsp', 'jspx', 'html', 'htm', 'xhtml', 'shtml', 'js']

    try:
        parsed_url = urlparse(url)
        path_segments = parsed_url.path.strip('/').split('/')

        # Test each path segment individually
        for i, segment in enumerate(path_segments):
            modified_segments = path_segments.copy()

            # Inject 'vulnReconXSS' only for supported extensions
            if '.' in segment:
                base, ext = segment.rsplit('.', 1)
                if ext in SUPPORTED_EXTENSIONS:
                    modified_segments[i] = f'vulnReconXSS.{ext}'
            else:
                # For non-extension segments, inject 'vulnReconXSS'
                modified_segments[i] = 'vulnReconXSS'

            modified_path = '/' + '/'.join(modified_segments)
            modified_url = urlunparse(parsed_url._replace(path=modified_path))

            # Send the request
            response = requests.get(modified_url, timeout=TIMEOUT)
            if 'vulnReconXSS' in response.text:
                print(f"{BRIGHT_GREEN}[+] PATH REFLECTION FOUND{RESET} {CYAN}{modified_url}{RESET}")
                save_reflected_url(parsed_url, modified_path, output_file)

        # Test appending 'vulnReconXSS' at the end of the path
        appended_path = parsed_url.path.rstrip('/') + '/vulnReconXSS'
        appended_url = urlunparse(parsed_url._replace(path=appended_path))
        response = requests.get(appended_url, timeout=TIMEOUT)
        if 'vulnReconXSS' in response.text:
            print(f"{BRIGHT_GREEN}[+] PATH REFLECTION FOUND{RESET} {CYAN}{appended_url}{RESET}")
            save_reflected_url(parsed_url, appended_path, output_file)

    except requests.exceptions.Timeout:
        print(f"{RED}[!] TIMEOUT{RESET} {DIM}{url}{RESET}")
        time.sleep(2)
    except requests.exceptions.RequestException as e:
        print(f"{RED}[!] ERROR{RESET} {DIM}{url}{RESET} {YELLOW}- {str(e)}{RESET}")
        time.sleep(2)
    finally:
        processed_urls += 1
        print(f"{BLUE}[INFO]{RESET} Progress: {BOLD}{processed_urls}/{total_urls}{RESET} URLs processed")

def post_process_urls(input_file, output_file):
    """Post-process URLs to remove duplicates and replace 'vulnReconXSS' with '{payload}'"""
    print(f"{CYAN}[*] Post-processing URLs - replacing 'vulnReconXSS' with '{{payload}}'...{RESET}")
    temp_file = f"{output_file}.tmp"
    with open(input_file, 'r') as infile, open(temp_file, 'w') as outfile:
        urls = set()
        for line in infile:
            line = line.strip().replace("vulnReconXSS", "{payload}")
            urls.add(line)
        for url in sorted(urls):
            outfile.write(url + '\n')
    os.rename(temp_file, output_file)
    print(f"{BRIGHT_GREEN}[✓] Processed URLs saved to {CYAN}{output_file}{RESET}")

def main():
    global total_urls
    print_banner()

    parser = argparse.ArgumentParser(description="vulnRecon Path Reflection Checker - Path-Based XSS Detection")
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

    output_file = "path-xss.txt"
    processed_output = "path-xss-urls.txt"

    # Clear previous results (in output directory)
    output_path = os.path.join(OUTPUT_DIR, output_file)
    open(output_path, 'w').close()

    try:
        with open(input_file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        total_urls = len(urls)
        print(f"{BLUE}[INFO]{RESET} Loaded {BOLD}{total_urls}{RESET} URLs from {CYAN}{input_file_path}{RESET}")
    except Exception as e:
        print(f"{RED}Error: {str(e)}{RESET}")
        return

    # Start reflection checks
    print(f"{YELLOW}[*] Starting path reflection check with {args.threads} threads...{RESET}\n")

    threads = []
    for url in urls:
        while threading.active_count() - 1 >= args.threads:
            pass
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

    # Post-process URLs
    if os.path.isfile(output_path):
        print(f"\n{CYAN}[*] Reflection check complete. Post-processing results...{RESET}")
        # Post-process to output directory
        processed_output_path = os.path.join(OUTPUT_DIR, processed_output)
        post_process_urls(output_path, processed_output_path)
    else:
        print(f"{RED}[!] Error: {output_path} was not generated.{RESET}")

    print(f"\n{MAGENTA}════════════════════════════════════════════════════════════════════════════════")
    print(f"{BRIGHT_GREEN}[✓] SCAN COMPLETE{RESET} {MAGENTA}════════════════════════════════════════════════════════════════════════════════")
    print(f"{BLUE}[INFO]{RESET} Results saved to: {CYAN}{processed_output_path}{RESET}")
    if os.path.exists(processed_output_path):
        with open(processed_output_path, 'r') as f:
            count = len(f.readlines())
        print(f"{BLUE}[INFO]{RESET} Total path-reflected URLs found: {BOLD_RED}{count}{RESET}")
    print(f"{MAGENTA}════════════════════════════════════════════════════════════════════════════════{RESET}")

if __name__ == "__main__":
    main()