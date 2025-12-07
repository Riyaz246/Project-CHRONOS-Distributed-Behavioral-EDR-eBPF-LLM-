#!/bin/bash
echo "--- Initiating Dropper Simulation (MITRE T1105) ---"

# 1. Network Event (Download)
# Simulates downloading a malicious payload
curl -s https://www.google.com > /tmp/malware.bin

# 2. File Event (Change Permissions)
# Attackers make the payload executable
chmod +x /tmp/malware.bin

# 3. Execution Event (Run it)
# Executing the payload
cat /tmp/malware.bin > /dev/null

echo "--- Kill Chain Complete ---"
