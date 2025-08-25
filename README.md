🛡️ CyberPulse Dashboard
An interactive cybersecurity dashboard that analyzes IDS logs, enriches them with threat intelligence, detects anomalies using machine learning, and flags phishing attempts with NLP-based classification. Deployed on Streamlit Cloud with Docker and CI/CD support.

🚀 Features

IDS Log Monitoring → parses IDS logs (CSV/JSON) for suspicious events
Threat Intelligence Enrichment → AbuseIPDB API lookups for IP reputation
AI-Powered Anomaly Detection → Isolation Forest model for unusual activity
Phishing Detection → HuggingFace Transformers for spam vs safe emails
Risk Report Generator → produces actionable risk reports for quick insights
Deployment Ready → Dockerfile & GitHub Actions for CI/CD

🛠️ Tech Stack

Frontend / Visualization: Streamlit, Plotly
Backend / Data Handling: Python, Pandas, NumPy, Requests
Cybersecurity: IDS logs (Snort/Suricata), AbuseIPDB API
Machine Learning: Scikit-learn (Isolation Forest), HuggingFace Transformers
DevOps: Docker, GitHub Actions CI/CD
Deployment: Streamlit Cloud

Clone the Repo
git clone https://github.com/selvina123/cyberpulse-dashboard.git
cd cyberpulse-dashboard

Install Dependencies
pip install -r requirements.txt

Run Locally
streamlit run app.py

Open in Browser
App will be live at → http://localhost:8501

🌐 Live Demo

GitHub Repo: github.com/selvina123/cyberpulse-dashboard
Live App: https://cyberpulse-dashboard-0115.streamlit.app/
