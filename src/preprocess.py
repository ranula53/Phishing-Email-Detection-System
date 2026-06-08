import pandas as pd
from sklearn.model_selection import train_test_split
from datasets import Dataset
from bs4 import BeautifulSoup
import re


# ── Clean HTML ───────────────────────────────────────────────
def clean_html(text):
    return BeautifulSoup(str(text), "html.parser").get_text()


# ── Remove URLs ──────────────────────────────────────────────
def replace_urls(text):
    return re.sub(r"http\S+|www\S+", "[URL]", str(text))



# ── Load & Clean ─────────────────────────────────────────────
def load_and_clean(csv_path: str, sample_n: int = None) -> pd.DataFrame:

    df = pd.read_csv(csv_path)

    print(df.head())
    print(df.columns.tolist())

    # Validate required columns
    required = {"sender", "subject", "body", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(
            f"CSV is missing required columns: {missing}. "
            f"Found: {df.columns.tolist()}"
        )

    # Remove nulls
    df.dropna(inplace=True)

    # Remove duplicate emails
    df.drop_duplicates(subset=["body"], inplace=True)

    # Rename label column
    df = df.rename(columns={"label": "labels"})
    df["labels"] = df["labels"].astype(int)

    # Combine important email fields with separator tokens
    df["text_combined"] = (
        "[CLS] " + df["sender"].astype(str) +
        " [SEP] " + df["subject"].astype(str) +
        " [SEP] " + df["body"].astype(str)
    )

    # Clean HTML
    df["text_combined"] = df["text_combined"].apply(clean_html)

    # Replace URLs with token (preserves signal that a URL existed)
    df["text_combined"] = df["text_combined"].apply(replace_urls)

    # Lowercase
    df["text_combined"] = df["text_combined"].str.lower()

    # Optional sampling
    if sample_n is not None:
        df = df.sample(n=sample_n, random_state=42).reset_index(drop=True)

    print(f"\nDataset size: {df.shape}")
    print(f"\nLabel distribution:\n{df['labels'].value_counts()}")

    return df


# ── Split ────────────────────────────────────────────────────
def split_data(df: pd.DataFrame):

    train_df, val_df = train_test_split(
        df,
        test_size=0.2,
        random_state=42,
        stratify=df["labels"]
    )

    train_df = train_df.reset_index(drop=True)
    val_df   = val_df.reset_index(drop=True)

    print(f"\nTrain: {len(train_df)}")
    print(f"Val  : {len(val_df)}")

    return train_df, val_df


# ── Tokenize ─────────────────────────────────────────────────
def tokenize_datasets(train_df, val_df, tokenizer):

    train_dataset = Dataset.from_pandas(
        train_df[["text_combined", "labels"]]
    )

    val_dataset = Dataset.from_pandas(
        val_df[["text_combined", "labels"]]
    )

    def tokenize(batch):
        return tokenizer(
            batch["text_combined"],
            truncation=True,
            padding=True,
            max_length=256
        )

    train_dataset = train_dataset.map(tokenize, batched=True)
    val_dataset   = val_dataset.map(tokenize, batched=True)

    print("\nTokenization complete.")

    return train_dataset, val_dataset