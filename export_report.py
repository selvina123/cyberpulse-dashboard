import pandas as pd
from ids_threatintel import generate_risk_report

if __name__ == "__main__":
    report = generate_risk_report()
    df = pd.DataFrame(report)
    df.to_csv("cyberpulse_risk_report.csv", index=False)

