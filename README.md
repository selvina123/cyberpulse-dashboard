# 🛡️ CyberPulse Dashboard

A **Blue Team SOC Dashboard** built with [Streamlit](https://streamlit.io/) to simulate and visualize security events such as **failed logins, port scans, suspicious logins, brute-force attacks, and IP risk mapping**.

🚀 Live Demo: 
https://cyberpulse-dashboard-0711.streamlit.app/

---

## ✨ Features

- 📊 **Dashboard KPIs** — Critical, High, Low severity events, Total Events, Unique IPs  
- 🔥 **Heatmap** — Event activity by hour and type  
- 🌍 **IP Risk Geo Map** — Visualizes high, medium, and low risk IP addresses  
- 📈 **Event Trends** — Events per minute with light purple neon theme  
- 🍩 **Event Type Split** — Donut chart showing proportions of event categories  
- ⚔️ **Attack Detection Rules**  
  - Brute Force Detection (≥6 failed logins in 2 min)  
  - Port Scan Detection (≥12 unique ports in 2 min)  
  - Suspicious Login Detection  

---

## 🛠️ Tech Stack

- **Python 3.9+**
- [Streamlit](https://streamlit.io/)
- [Plotly](https://plotly.com/python/)
- [Pandas](https://pandas.pydata.org/)
- [NumPy](https://numpy.org/)

---

## 📂 Project Structure

cyberpulse-dashboard/
│── app.py # Main Streamlit app
│── assets/
│ └── styles.css # Custom neon CSS styles
│── requirements.txt # Dependencies
│── README.md # Project documentation

yaml
Copy
Edit

---

## ⚡ Installation & Run Locally

 Clone the repo:
   ```bash
   git clone https://github.com/selvina123/cyberpulse-dashboard.git
   cd cyberpulse-dashboard
Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate   # Mac/Linux
venv\Scripts\activate      # Windows

Install dependencies:
pip install -r requirements.txt

Run Streamlit app:
streamlit run app.py

Open in your browser:
👉 http://localhost:8501
