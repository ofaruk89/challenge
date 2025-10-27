import requests

DVWA_BASE_URL = "https://webserver.mybank.local"

COOKIES = {
    "PHPSESSID": "jf7k7ram70kpnhu2tjp9gqt7t4",
    "security": "low"
}

requests.packages.urllib3.disable_warnings()
SESSION = requests.Session()
SESSION.verify = False
SESSION.cookies.update(COOKIES)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
}


def sim_sql_injection():
    print("[*] Simulation 1: SQL Injection (SQLi) starting...")
    target_url = f"{DVWA_BASE_URL}/vulnerabilities/sqli/"
    
    payload = {
        "id": "' OR '1'='1' -- ",
        "Submit": "Submit"
    }
    
    try:
        response = SESSION.get(target_url, params=payload, headers=HEADERS)
        print(f"    -> Target URL: {response.request.url}")
        print(f"    -> Status Code: {response.status_code}")
        
        if response.status_code == 403:
            print("    -> RESULT: Success! WAF caught and blocked the attack (403 Forbidden).")
        else:
            print(f"    -> RESULT: WAF allowed the payload (Status: {response.status_code}). It might be in 'DetectionOnly' mode.")
            
    except requests.exceptions.RequestException as e:
        print(f"    -> ERROR: Could not connect to {target_url}: {e}")


def sim_cross_site_scripting(method="GET"):
    print(f"[*] Simulation 2: XSS ({method}) starting...")
    
    payload = "<script>alert('WAF-TEST')</script>"
    
    try:
        if method == "GET":
            target_url = f"{DVWA_BASE_URL}/vulnerabilities/xss_r/"
            params = {"name": payload}
            response = SESSION.get(target_url, params=params, headers=HEADERS)
        else:
            target_url = f"{DVWA_BASE_URL}/vulnerabilities/xss_s/"
            data = {"txtName": payload, "mtxMessage": "test", "btnSign": "Sign Guestbook"}
            response = SESSION.post(target_url, data=data, headers=HEADERS)

        print(f"    -> Target URL: {target_url}")
        print(f"    -> Status Code: {response.status_code}")

        if response.status_code == 403:
            print("    -> RESULT: Success! WAF caught and blocked the attack (403 Forbidden).")
        else:
            print(f"    -> RESULT: WAF allowed the payload (Status: {response.status_code}). It might be in 'DetectionOnly' mode.")

    except requests.exceptions.RequestException as e:
        print(f"    -> ERROR: Could not connect to {target_url}: {e}")


def sim_command_injection():
    print("[*] Simulation 3: Command Injection starting...")
    target_url = f"{DVWA_BASE_URL}/vulnerabilities/exec/"
    
    payload = {
        "ip": "127.0.0.1 | ls",
        "Submit": "Submit"
    }
    
    try:
        response = SESSION.post(target_url, data=payload, headers=HEADERS)
        print(f"    -> Target URL: {target_url}")
        print(f"    -> Status Code: {response.status_code}")

        if response.status_code == 403:
            print("    -> RESULT: Success! WAF caught and blocked the attack (403 Forbidden).")
        else:
            print(f"    -> RESULT: WAF allowed the payload (Status: {response.status_code}). It might be in 'DetectionOnly' mode.")
            
    except requests.exceptions.RequestException as e:
        print(f"    -> ERROR: Could not connect to {target_url}: {e}")


def sim_local_file_inclusion():
    print("[*] Simulation 4: LFI / Directory Traversal starting...")
    target_url = f"{DVWA_BASE_URL}/vulnerabilities/fi/"
    
    payload = {
        "page": "../../../../../../../etc/passwd"
    }
    
    try:
        response = SESSION.get(target_url, params=payload, headers=HEADERS)
        print(f"    -> Target URL: {response.request.url}")
        print(f"    -> Status Code: {response.status_code}")

        if response.status_code == 403:
            print("    -> RESULT: Success! WAF caught and blocked the attack (403 Forbidden).")
        else:
            print(f"    -> RESULT: WAF allowed the payload (Status: {response.status_code}). It might be in 'DetectionOnly' mode.")
            
    except requests.exceptions.RequestException as e:
        print(f"    -> ERROR: Could not connect to {target_url}: {e}")


if __name__ == "__main__":
    print(f"Starting WAF Test Simulations -> {DVWA_BASE_URL}\n")
    sim_sql_injection()
    print("-" * 30)
    sim_cross_site_scripting(method="GET")
    print("-" * 30)
    sim_command_injection()
    print("-" * 30)
    sim_local_file_inclusion()
    print("\nTests completed. Check your WAF-01 logs.")