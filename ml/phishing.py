from transformers import pipeline

# Use a spam detection model (public + stable)
nlp_model = pipeline("text-classification", model="mrm8488/bert-tiny-finetuned-sms-spam-detection")

def detect_phishing(email_text):
    result = nlp_model(email_text)[0]
    return {"label": result["label"], "score": round(result["score"], 3)}
