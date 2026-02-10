import os
import requests
import csv
from dotenv import load_dotenv

# --- 1. SETUP ---
load_dotenv()
api_key = os.getenv("VT_API_KEY")

# --- 2. THE LOGIC ---
def check_file_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats['malicious']
        return "Not Found"
    except:
        return "Connection Error"

# --- 3. THE EXECUTION & CSV GENERATION ---
input_file = "hashes.txt"
output_file = "security_report.csv"

print(f"🛡️  Security Engineering Tool: Auto-Investigator")
print(f"----------------------------------------------")

if os.path.exists(input_file):
    with open(input_file, "r") as f_in, open(output_file, "w", newline='') as f_out:
        writer = csv.writer(f_out)
        # Write the Header Row
        writer.writerow(["Timestamp", "File_Hash", "Malicious_Score"])
        
        for line in f_in:
            h = line.strip()
            if h:
                print(f"🔍 Investigating: {h[:20]}...")
                score = check_file_hash(h)
                # Write the result to the CSV
                writer.writerow(["2026-02-09", h, score])

    print(f"\n✅ SUCCESS: Report generated at {output_file}")
else:
    print(f"❌ Error: {input_file} not found.")