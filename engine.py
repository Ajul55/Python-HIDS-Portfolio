import time
import re
import json
import sys

# CONFIGURATION
LOG_FILE = "/var/log/auth.log"
RULES_FILE = "rules.json"
OUTPUT_FILE = "alerts.json"

# GLOBAL "SCOREBOARD"
# We use this to remember IP addresses and how many times they failed.
ip_scoreboard = {} 

def load_rules():
    """Reads the detection rules from the JSON file."""
    try:
        with open(RULES_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {RULES_FILE} not found. Create it first!")
        sys.exit(1)

def check_rules(line, rules):
    """
    The Brain: Matches a log line against our rules.
    1. Checks if the 'pattern' (e.g., 'Failed password') is in the line.
    2. Extracts the IP address using Regex.
    3. Updates the Scoreboard.
    4. Returns an Alert if the threshold is reached.
    """
    for rule in rules:
        # STEP 1: Does the line match the text pattern? (e.g., "Failed password")
        if rule['pattern'] in line:
            
            # STEP 2: Extract the IP Address using Regex
            # This looks for "from 192.168.x.x"
            ip_match = re.search(r"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            
            if ip_match:
                ip = ip_match.group(1) # We found an IP!
                
                # STEP 3: Update Scoreboard
                # If IP is new, start at 0. Add 1 failure.
                ip_scoreboard[ip] = ip_scoreboard.get(ip, 0) + 1
                
                print(f"[DEBUG] Suspicious Activity: {ip} -> Count: {ip_scoreboard[ip]}")

                # STEP 4: Check Threshold (Did they fail too many times?)
                if ip_scoreboard[ip] >= rule['threshold']:
                    return {
                        "timestamp": time.ctime(),
                        "rule_name": rule['name'],
                        "mitre_id": rule['mitre'],
                        "source_ip": ip,
                        "severity": rule['severity'],
                        "message": f"Threshold reached: {ip_scoreboard[ip]} attempts."
                    }
    return None

def monitor_log():
    """The Eyes: Tails the log file in real-time."""
    print(f"[*] Starting Mini-SIEM Engine...")
    print(f"[*] Monitoring {LOG_FILE}...")
    
    rules = load_rules()
    
    try:
        # Open the log file
        with open(LOG_FILE, 'r') as f:
            # Go to the end of file (so we only read NEW logs)
            f.seek(0, 2)
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1) # Wait briefly if no new line
                    continue
                
                # We got a new line! Send it to the Brain.
                alert = check_rules(line, rules)
                
                if alert:
                    print(f"\n[!!!] ALERT GENERATED: {alert['rule_name']}")
                    print(json.dumps(alert, indent=4))
                    
                    # Save alert to file (Evidence)
                    with open(OUTPUT_FILE, 'a') as alert_file:
                        alert_file.write(json.dumps(alert) + "\n")
                    
                    # Reset score for this IP so we don't alert forever
                    ip_scoreboard[alert['source_ip']] = 0

    except PermissionError:
        print("Error: Permission denied. Did you run 'sudo setfacl'?")
    except KeyboardInterrupt:
        print("\n[*] Stopping Engine.")

if __name__ == "__main__":
    monitor_log()
