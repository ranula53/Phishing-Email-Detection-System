import torch

from transformers import (
    BertTokenizer,
    BertForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding
)

from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# Import preprocessing functions
from preprocess import load_and_clean, split_data, tokenize_datasets


# ── GPU Check ────────────────────────────────────────────────
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

print(f"Using device: {device}")

if torch.cuda.is_available():
    print(f"GPU: {torch.cuda.get_device_name(0)}")


# ── Load Dataset ─────────────────────────────────────────────
df = load_and_clean(
    csv_path="../data/CEAS_08.csv",
    sample_n=None
)

train_df, val_df = split_data(df)


# ── Load Previous Model (v2) ─────────────────────────────────
model_path = "../models/phishing_model_v2"

tokenizer = BertTokenizer.from_pretrained(model_path)

model = BertForSequenceClassification.from_pretrained(
    model_path
)

print(f"\nModel loaded from: {model_path}")


# ── Tokenize ─────────────────────────────────────────────────
train_dataset, val_dataset = tokenize_datasets(
    train_df,
    val_df,
    tokenizer
)


# ── Metrics ──────────────────────────────────────────────────
def compute_metrics(pred):

    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)

    precision, recall, f1, _ = precision_recall_fscore_support(
        labels,
        preds,
        average="binary"
    )

    acc = accuracy_score(labels, preds)

    return {
        "accuracy": acc,
        "f1": f1,
        "precision": precision,
        "recall": recall
    }


# ── Training Arguments ───────────────────────────────────────
training_args = TrainingArguments(
    output_dir="../results/results_v4",

    eval_strategy="epoch",
    save_strategy="epoch",

    save_total_limit=2,

    learning_rate=2e-5,

    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,

    num_train_epochs=5,

    weight_decay=0.01,

    fp16=torch.cuda.is_available(),

    logging_dir="../logs",

    logging_strategy="epoch",

    load_best_model_at_end=True,
    metric_for_best_model="f1",
    greater_is_better=True
)


# ── Trainer ──────────────────────────────────────────────────
trainer = Trainer(
    model=model,
    args=training_args,

    train_dataset=train_dataset,
    eval_dataset=val_dataset,

    data_collator=DataCollatorWithPadding(
        tokenizer=tokenizer
    ),

    compute_metrics=compute_metrics
)


# ── Train ────────────────────────────────────────────────────
print("\nStarting training...\n")

trainer.train()


# ── Save New Model (v3) ──────────────────────────────────────
save_path = "../models/phishing_model_v4"

trainer.save_model(save_path)

tokenizer.save_pretrained(save_path)

print(f"\nModel saved to: {save_path}")