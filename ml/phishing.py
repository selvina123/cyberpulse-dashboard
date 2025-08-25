from transformers import pipeline

nlp_model = pipeline("text-classification", model="mrm8488/bert-tiny-finetuned-sms-spam-detection")

label_map = {
    "LABEL_0": "ham",   # Safe
    "LABEL_1": "spam"   # Phishing/Suspicious
}

def detect_phishing(email_text):
    result = nlp_model(email_text)[0]
    label = label_map.get(result["label"], result["label"])
    score = round(result["score"] * 100, 2)  # convert to % with 2 decimals
    return {"label": label, "score": score}