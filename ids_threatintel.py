import os, json, requests

API_KEY = "your_abuseipdb_api_key"  # replace with your AbuseIPDB API key

def parse_ids_log(file_path="snort_alerts.json"):
    if not os.path.exists(file_path):
        # 🔹 fallback demo logs if file missing
        return [
            {"timestamp": "2025-08-24T20:00:00Z", "src_ip": "192.168.1.10", "event_type": "failed_login"},
            {"timestamp": "2025-08-24T20:05:00Z", "src_ip": "45.83.12.7", "event_type": "port_scan"},
            {"timestamp": "2025-08-24T20:10:00Z", "src_ip": "203.0.113.15", "event_type": "suspicious_login"},
        ]
    with open(file_path) as f:
        logs = json.load(f)
    return logs

def enrich_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        res = requests.get(url, headers=headers, params=params, timeout=5).json()
        data = res.get("data", {})
        return {
            "score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "??")
        }
    except Exception as e:
        # 🔹 fallback if API fails or no key
        return {"score": 0, "country": "??"}

def generate_risk_report():
    logs = parse_ids_log()
    report = []
    for log in logs:
        ip = log.get("src_ip", "0.0.0.0")
        intel = enrich_ip(ip)
        risk = "HIGH" if intel["score"] > 50 else "LOW"
        report.append({**log, **intel, "risk_level": risk})
    return report
