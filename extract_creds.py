#!/usr/bin/env python3
"""
IPTV Checker Utility - Credential Extractor
Extracts unique username:password pairs from target files (supporting both slash
and pipe formats) and writes them to a clean wordlist file.
"""
import sys
import os
import re

def parse_line(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # Handle pipe format: http://host:port | username | password
    if '|' in line:
        parts = [p.strip() for p in line.split('|')]
        if len(parts) == 3:
            return parts[1], parts[2]

    # Handle slash format: http://host:port/username/password
    if line.startswith('http://') or line.startswith('https://'):
        try:
            # Strip protocol
            rest = line.split('://', 1)[1]
            parts = rest.split('/')
            if len(parts) >= 3:
                return parts[1], parts[2]
        except IndexError:
            pass

    # Handle colon format: host:port:username:password
    colon_parts = line.split(':')
    if len(colon_parts) == 4:
        return colon_parts[2], colon_parts[3]

    # Handle space format: host port username password
    space_parts = line.split()
    if len(space_parts) == 4:
        return space_parts[2], space_parts[3]

    return None

def main():
    input_file = "targets.txt"
    output_file = "wordlist.txt"

    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    if len(sys.argv) > 2:
        output_file = sys.argv[2]

    if not os.path.exists(input_file):
        print(f"[-] Input file '{input_file}' not found.")
        sys.exit(1)

    print(f"[*] Reading credentials from '{input_file}'...")
    
    unique_creds = set()
    total_parsed = 0

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            cred = parse_line(line)
            if cred:
                username, password = cred
                unique_creds.add((username, password))
                total_parsed += 1

    print(f"[*] Found {total_parsed} raw credentials ({len(unique_creds)} unique combinations).")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for username, password in sorted(unique_creds):
            f.write(f"{username}:{password}\n")

    print(f"[+] Successfully wrote clean wordlist to '{output_file}'.")

if __name__ == "__main__":
    main()
