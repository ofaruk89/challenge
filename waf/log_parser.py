#!/usr/bin/env python3

import json
import subprocess
import os
import logging
from datetime import datetime, timedelta, timezone
from collections import Counter
from pathlib import Path

LOG_FILE_PATH = Path("/root/waf/logs/modsec_audit.log")
BLACKLIST_FILE_PATH = Path("/root/waf/blacklist.txt")
SCRIPT_LOG_FILE = "/var/log/autoblocker.log"
DOCKER_CONTAINER = "waf-nginx"
TIME_WINDOW_MINUTES = 5
TRIGGER_COUNT = 5

# --- NEW ---
# Add a whitelist of IPs that should NEVER be blocked.
IP_WHITELIST = {
    "127.0.0.1",
    "localhost"
    # Buraya ofis IP'niz gibi başka güvenli IP'leri ekleyebilirsiniz
    # "88.88.88.88" 
}
# --- END NEW ---

def setup_logging():
    try:
        logging.basicConfig(
            filename=SCRIPT_LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filemode='a'
        )
    except IOError as e:
        print(f"Critical Error: Could not set up logging to {SCRIPT_LOG_FILE}: {e}")
        exit(1)

def parse_timestamp(ts_string: str) -> datetime:
    log_time_naive = datetime.strptime(ts_string, "%a %b %d %H:%M:%S %Y")
    log_time_utc = log_time_naive.replace(tzinfo=timezone.utc)
    return log_time_utc

def get_existing_blacklist(filepath: Path) -> set:
    if not filepath.exists():
        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            filepath.touch()
            logging.info(f"Blacklist file created at: {filepath}")
            return set()
        except IOError as e:
            logging.error(f"Could not create blacklist directory or file {filepath}: {e}")
            return set()
    
    try:
        with filepath.open('r') as f:
            return set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    except IOError as e:
        logging.error(f"Could not read blacklist file {filepath}: {e}")
        return set()

def reload_nginx(container_name: str):
    command = ["docker", "exec", container_name, "nginx", "-s", "reload"]
    logging.info(f"Executing command: {' '.join(command)}")
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        logging.info(f"Nginx successfully reloaded.")
        if result.stdout:
            logging.debug(f"Docker stdout: {result.stdout.strip()}")
        if result.stderr:
            logging.warning(f"Docker stderr: {result.stderr.strip()}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to reload Nginx. Command failed: {e.stderr}")
    except FileNotFoundError:
        logging.error("Fatal: 'docker' command not found. Is Docker installed and in PATH?")

def process_logs():
    now_utc = datetime.now(timezone.utc)
    time_limit = now_utc - timedelta(minutes=TIME_WINDOW_MINUTES)
    logging.info(f"Script started. Processing logs since {time_limit.isoformat()}")

    existing_ips = get_existing_blacklist(BLACKLIST_FILE_PATH)
    logging.info(f"Loaded {len(existing_ips)} IPs from existing blacklist.")
    logging.info(f"Whitelisted IPs that will be ignored: {IP_WHITELIST}")

    ip_counts = Counter()
    if not LOG_FILE_PATH.exists():
        logging.error(f"Log file not found: {LOG_FILE_PATH}")
        return

    try:
        with LOG_FILE_PATH.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                try:
                    log_entry = json.loads(line)
                    
                    transaction = log_entry.get("transaction", {})
                    ts_str = transaction.get("time_stamp")
                    client_ip = transaction.get("client_ip")
                    # --- NEW ---
                    # Check if the 'messages' array exists and is not empty
                    messages = transaction.get("messages")
                    # --- END NEW ---

                    if not ts_str or not client_ip:
                        continue 

                    log_time = parse_timestamp(ts_str)
                    
                    # --- MODIFIED ---
                    # Only count if it's in the time window AND 'messages' is not empty
                    if log_time >= time_limit and messages: 
                        ip_counts[client_ip] += 1
                    # --- END MODIFIED ---
                        
                except json.JSONDecodeError:
                    logging.warning("Skipped a malformed JSON line.")
                    continue
                except ValueError as e:
                    logging.warning(f"Skipped line with date format error: {ts_str} - {e}")
                    continue
                except Exception as e:
                    logging.error(f"Unknown error processing a line: {e}")

    except IOError as e:
        logging.error(f"Could not read log file {LOG_FILE_PATH}: {e}")
        return

    new_ips_to_block = []
    logging.info("--- Scan Results ---")
    for ip, count in ip_counts.items():
        # --- MODIFIED ---
        # Check trigger count AND if the IP is NOT in the whitelist
        if count >= TRIGGER_COUNT and ip not in IP_WHITELIST:
        # --- END MODIFIED ---
            if ip not in existing_ips:
                logging.info(f"NEW IP to block: {ip} (Violation count: {count})")
                new_ips_to_block.append(ip)
            else:
                logging.info(f"Already blocked IP: {ip} (Violation count: {count})")
        # --- NEW ---
        # Log if a whitelisted IP triggered the rule, but don't block it
        elif count >= TRIGGER_COUNT and ip in IP_WHITELIST:
             logging.info(f"Whitelisted IP {ip} triggered {count} violations, NOT blocking.")
        # --- END NEW ---

    if not ip_counts:
        logging.info("No relevant log entries (with rule violations) found in the time window.")

    if not new_ips_to_block:
        logging.info("No new IPs to block. Exiting.")
        return

    logging.info(f"Adding {len(new_ips_to_block)} new IPs to {BLACKLIST_FILE_PATH}...")
    try:
        with BLACKLIST_FILE_PATH.open('a') as f:
            f.write(f"\n# Automatically added by script on {now_utc.isoformat()}\n")
            for ip in new_ips_to_block:
                f.write(f"{ip}\n")
        
        reload_nginx(DOCKER_CONTAINER)

    except IOError as e:
        logging.error(f"Failed to write to blacklist file {BLACKLIST_FILE_PATH}: {e}")

def main():
    setup_logging()
    try:
        process_logs()
    except Exception as e:
        logging.critical(f"An uncaught exception occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
