import torch
from transformers import BertTokenizer, BertForSequenceClassification

# ── Load Model ───────────────────────────────────────────────
model_path = "../models/phishing_model_v4"

tokenizer = BertTokenizer.from_pretrained(model_path)
model     = BertForSequenceClassification.from_pretrained(model_path)

# Use GPU if available
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)
model.eval()

print(f"Model loaded from: {model_path}")
print(f"Using device: {device}")
print("-" * 50)


# ── Predict Function ─────────────────────────────────────────
def predict_email(text: str) -> dict:
    """
    Predict whether an email is phishing or legitimate.

    Args:
        text: Email body text

    Returns:
        dict with label, confidence score
    """
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=256
    ).to(device)

    with torch.no_grad():
        outputs = model(**inputs)

    probabilities = torch.softmax(outputs.logits, dim=1)
    prediction    = torch.argmax(probabilities, dim=1).item()
    confidence    = probabilities[0][prediction].item() * 100

    label = "Phishing Email" if prediction == 1 else "Legitimate Email"

    return {
        "label":      label,
        "prediction": prediction,
        "confidence": f"{confidence:.2f}%"
    }


# ── Test Emails ──────────────────────────────────────────────
test_emails = [

    "URGENT: Your account has been suspended. Click here to verify your credentials now!",
    "Hi team, please find the meeting notes attached from today's standup.",
    "Congratulations! You have won a $1000 gift card. Claim it now at this link.",
]

for email in test_emails:
    result = predict_email(email)
    print(f"Email   : {email[:60]}...")
    print(f"Result  : {result['label']}")
    print(f"Confidence: {result['confidence']}")
    print("-" * 50)