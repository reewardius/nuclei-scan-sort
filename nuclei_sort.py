import sys
from urllib.parse import urlparse
from colorama import Fore, Style, init
from argparse import ArgumentParser
from collections import defaultdict

def parse_severity(severity):
    severity_order = {'[critical]': 1, '[high]': 2, '[medium]': 3, '[low]': 4, '[info]': 5, '[unknown]': 6, '[]': 7}
    return severity_order.get(severity, 7)

def main(input_file):
    try:
        # Read file with nuclei scan and split it into lines
        with open(input_file, 'r') as file:
            scan_results = [result.strip() for result in file.readlines()]
    except FileNotFoundError:
        print(Fore.RED + '[!] Error: The input file does not exist or the path is incorrect.' + Style.RESET_ALL)
        sys.exit(1)

    unique_domains = defaultdict(list)
    garbage_info = []

    for result in scan_results[:]:
        parts = result.split(" ")
        if len(parts) < 4:
            # Check if scan file is valid
            print(Fore.RED + '[!] Error: Invalid Nuclei Scan format' + Style.RESET_ALL)
            sys.exit(1)
        
        severity, _, url = parts[2], parts[3], parts[3]
        
        if severity == '[INF]':
            # Handle garbage information
            garbage_info.append('Garbage: ' + result)
            scan_results.remove(result)
        else:
            # Extract domain from URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
            unique_domains[domain].append((severity, url))

    color_map = {
        '[critical]': Fore.MAGENTA,
        '[high]': Fore.RED,
        '[medium]': Fore.YELLOW,
        '[low]': Fore.GREEN,
        '[info]': Fore.CYAN,
        '[unknown]': Fore.WHITE,
        '[]': Fore.WHITE
    }

    sorted_results = []

    for domain, results in unique_domains.items():
        results.sort(key=lambda x: parse_severity(x[0]))
        for severity, url in results:
            sorted_results.append((domain, severity, url))

    sorted_results.sort(key=lambda x: (parse_severity(x[1]), x[2]))

    for domain, severity, url in sorted_results:
        color = color_map.get(severity, Fore.WHITE)
        print(f"{color}{severity}{Style.RESET_ALL} {url}")

    for garbage in garbage_info:
        print(garbage)

if __name__ == '__main__':
    init()
    parser = ArgumentParser()
    parser.add_argument('-i', '--input', help='Input file with Nuclei scan', required=True)
    args = parser.parse_args()

    main(args.input)
