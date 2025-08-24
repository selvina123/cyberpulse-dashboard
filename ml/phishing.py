from transformers import pipeline

nlp_model = pipeline("text-classification", model="mrm8488/bert-tiny-finetuned-phishing")

def detect_phishing(email_text):
    result = nlp_model(email_text)[0]
    return {"label": result["label"], "score": round(result["score"], 3)}
