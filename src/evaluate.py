import torch
import pandas as pd
from transformers import BertTokenizer, BertForSequenceClassification
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

# ── Load Model ───────────────────────────────────────────────
model_path = "../models/phishing_model_v4"

tokenizer = BertTokenizer.from_pretrained(model_path)
model     = BertForSequenceClassification.from_pretrained(model_path)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)
model.eval()

print(f"Model : {model_path}")
print(f"Device: {device}")
print("-" * 50)

# ── Load Dataset ─────────────────────────────────────────────
df = pd.read_csv("../data/phishing_email.csv")
df = df.dropna(subset=["text_combined", "label"])

print(f"Test samples : {len(df)}")
print(f"Label distribution:\n{df['label'].value_counts()}")
print("-" * 50)

# ── Predict ──────────────────────────────────────────────────
def predict_batch(texts, batch_size=32):
    all_preds = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        inputs = tokenizer(
            batch,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=256
        ).to(device)
        with torch.no_grad():
            outputs = model(**inputs)
        preds = torch.argmax(outputs.logits, dim=1).cpu().tolist()
        all_preds.extend(preds)
        print(f"  Processed {min(i + batch_size, len(texts))}/{len(texts)}", end="\r")
    return all_preds

print("Running predictions...")
texts  = df["text_combined"].tolist()
labels = df["label"].tolist()
preds  = predict_batch(texts)

# ── Metrics ──────────────────────────────────────────────────
acc = accuracy_score(labels, preds)
precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average="binary")
cm = confusion_matrix(labels, preds)

print(f"\n{'='*50}")
print(f"  EVALUATION RESULTS ON phishing_email.csv")
print(f"{'='*50}")
print(f"  Accuracy  : {acc*100:.2f}%")
print(f"  F1 Score  : {f1*100:.2f}%")
print(f"  Precision : {precision*100:.2f}%")
print(f"  Recall    : {recall*100:.2f}%")
print(f"\n  Confusion Matrix:")
print(f"  {'':10} Pred:0   Pred:1")
print(f"  Actual:0   {cm[0][0]:5}    {cm[0][1]:5}")
print(f"  Actual:1   {cm[1][0]:5}    {cm[1][1]:5}")
print(f"{'='*50}")
