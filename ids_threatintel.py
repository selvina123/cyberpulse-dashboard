import json, requests

API_KEY = "your_abuseipdb_api_key"  # replace with your key

def parse_ids_log(file_path="snort_alerts.json"):
    with open(file_path) as f:
        logs = json.load(f)
    return logs

def enrich_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        res = requests.get(url, headers=headers, params=params).json()
        data = res.get("data", {})
        return {"score": data.get("abuseConfidenceScore", 0), "country": data.get("countryCode", "??")}
    except:
        return {"score": 0, "country": "??"}

def generate_risk_report():
    logs = parse_ids_log()
    report = []
    for log in logs:
        ip = log["src_ip"]
        intel = enrich_ip(ip)
        risk = "HIGH" if intel["score"] > 50 else "LOW"
        report.append({**log, **intel, "risk_level": risk})
    return report
