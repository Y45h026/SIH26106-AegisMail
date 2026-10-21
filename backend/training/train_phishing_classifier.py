"""Train/evaluate the AegisMail TF-IDF + Logistic Regression email model.

Example (after inspecting the local CSV headers and labels):
python backend/training/train_phishing_classifier.py backend/data/raw/source.csv \
  --subject-column subject --body-column body --label-column label \
  --legitimate-label ham --phishing-label phishing
Multiple source CSVs can be passed as positional paths. Labels are never guessed.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.modules.content.ml_classifier import normalize_texts

csv.field_size_limit(20_000_000)

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "models" / "phishing_text_classifier.joblib"
REPORT = ROOT / "training" / "training_report.json"
MANIFEST = ROOT / "data" / "dataset_manifest.json"


def normalize(text: Any) -> str:
    text = "" if text is None else str(text)
    return re.sub(r"\s+", " ", text).strip().lower()


def combine(subject: Any, body: Any) -> str:
    return f"subject: {subject or '[missing subject]'} body: {body or '[missing body]'}"


def make_pipeline() -> Pipeline:
    return Pipeline([
        ("normalize", FunctionTransformer(normalize_texts, validate=False)),
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_df=0.95,
                                  sublinear_tf=True, max_features=50000,
                                  token_pattern=r"(?u)\b\w[\w$%./:@-]*\b")),
        ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)),
    ])


def _metrics(y_true: list[int], y_pred: list[int]) -> dict[str, Any]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"accuracy": accuracy_score(y_true, y_pred), "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0), "f1": f1_score(y_true, y_pred, zero_division=0),
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "confusion_matrix": {"true_negative": int(tn), "false_positive": int(fp), "false_negative": int(fn), "true_positive": int(tp)}}


def _read_rows(paths: list[Path], args: argparse.Namespace) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows, inputs = [], []
    for path in paths:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            fields = reader.fieldnames or []
            requested = [args.label_column, *args.body_columns]
            if args.subject_column:
                requested.append(args.subject_column)
            missing = [name for name in requested if name not in fields]
            if missing:
                raise ValueError(f"{path}: missing requested columns {missing}; found {fields}")
            count = 0
            for row in reader:
                count += 1
                label = row.get(args.label_column, "").strip()
                if label not in (args.legitimate_label, args.phishing_label):
                    raise ValueError(f"Unmapped label {label!r} in {path}; explicitly map only known labels.")
                subject = row.get(args.subject_column, "") if args.subject_column else ""
                body = " ".join(row.get(col, "") or "" for col in args.body_columns)
                if not normalize(subject) and not normalize(body):
                    continue
                content = normalize(combine(subject, body))
                if not content:
                    continue
                rows.append({"text": content, "label": 1 if label == args.phishing_label else 0,
                             "source_name": path.stem, "subject": subject, "body": body})
            inputs.append({"path_name": path.name, "sha256": digest, "row_count": count})
    return rows, inputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="+", type=Path, help="One or more individual source CSV files")
    parser.add_argument("--label-column", required=True)
    parser.add_argument("--legitimate-label", required=True)
    parser.add_argument("--phishing-label", required=True)
    parser.add_argument("--subject-column", default="subject")
    parser.add_argument("--body-columns", nargs="+", default=["body"])
    parser.add_argument("--output", type=Path, default=ARTIFACT)
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    args = parser.parse_args()
    if args.legitimate_label == args.phishing_label:
        parser.error("legitimate and phishing labels must differ")
    paths = [path.resolve() for path in args.dataset]
    rows, inputs = _read_rows(paths, args)
    # Deduplicate normalized subject/body before the split, retaining one source record.
    unique: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = normalize(f"{row['subject']} {row['body']}")
        unique.setdefault(key, row)
    removed = len(rows) - len(unique)
    rows = list(unique.values())
    if len(rows) < 10 or len({row["label"] for row in rows}) != 2:
        raise ValueError("Need at least 10 non-empty unique records and both explicitly mapped classes.")
    print(f"Explicit label mapping: {args.legitimate_label!r} -> 0 (legitimate), {args.phishing_label!r} -> 1 (phishing)")
    print(f"Rows after cleaning: {len(rows)}; exact normalized subject/body duplicates removed: {removed}")
    print("Fitting stratified holdout model...", flush=True)
    texts, labels = [r["text"] for r in rows], [r["label"] for r in rows]
    indices = list(range(len(rows)))
    train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=42, stratify=labels)
    model = make_pipeline()
    model.fit([texts[i] for i in train_idx], [labels[i] for i in train_idx])
    pred = model.predict([texts[i] for i in test_idx]).tolist()
    evaluation = _metrics([labels[i] for i in test_idx], pred)
    sources = sorted({r["source_name"] for r in rows})
    per_source_holdout: dict[str, Any] = {}
    for source in sources:
        local = [position for position, index in enumerate(test_idx) if rows[index]["source_name"] == source]
        if local:
            per_source_holdout[source] = _metrics([labels[test_idx[position]] for position in local], [pred[position] for position in local])
    source_eval: dict[str, Any] = {}
    for source in sources:
        held = [i for i, row in enumerate(rows) if row["source_name"] == source]
        remaining = [i for i in indices if i not in set(held)]
        if not held or len(remaining) < 10 or len({labels[i] for i in remaining}) < 2 or len({labels[i] for i in held}) < 2:
            continue
        print(f"Running source-held-out evaluation for {source}...", flush=True)
        source_model = make_pipeline().fit([texts[i] for i in remaining], [labels[i] for i in remaining])
        source_eval[source] = _metrics([labels[i] for i in held], source_model.predict([texts[i] for i in held]).tolist())
        # One held-out corpus gives a robustness check; per-source holdout
        # metrics above still describe every source represented in random test.
        break
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output)
    report = {"created_at": datetime.now(timezone.utc).isoformat(), "model": "TF-IDF + LogisticRegression",
              "rows": len(rows), "duplicates_removed": removed, "label_mapping": {args.legitimate_label: 0, args.phishing_label: 1},
              "stratified_holdout_random_state": 42, "holdout": evaluation, "per_source_holdout": per_source_holdout, "source_held_out": source_eval,
              "per_source": {s: {"rows": sum(r["source_name"] == s for r in rows), "class_counts": {str(label): sum(r["source_name"] == s and r["label"] == label for r in rows) for label in (0, 1)}} for s in sources},
              "artifact": str(args.output), "artifact_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest()}
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest = {"dataset": "Phishing Email Dataset: Phish No More — Enron, Ling, CEAS, Nazario, Nigerian & SpamAssassin",
                "source_url": "https://doi.org/10.34740/kaggle/ds/5074342", "license": "CC BY-SA 4.0",
                "label_mapping": report["label_mapping"], "cleaning": "Subject/body only; lowercase whitespace normalization; empty records excluded; exact normalized subject/body deduplication before split.",
                "duplicates_removed": removed, "input_files": inputs}
    args.manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"holdout": evaluation, "source_held_out": source_eval, "report": str(args.report), "artifact": str(args.output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
