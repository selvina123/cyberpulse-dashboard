from sklearn.ensemble import IsolationForest
import numpy as np

def detect_anomalies(events):
    model = IsolationForest(contamination=0.1)
    X = np.array([[len(e["src_ip"]), hash(e["event_type"]) % 100] for e in events])
    model.fit(X)
    scores = model.decision_function(X)
    return [round(s, 3) for s in scores]
