"""Locally installed, explainable content-only phishing classifier."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib

MODEL_PATH = Path(__file__).resolve().parents[3] / "models" / "phishing_text_classifier.joblib"
MODEL_NAME = "AegisMail TF-IDF Logistic Regression"
MODEL_VERSION = "1.0.0"
LIMITATIONS = [
    "This model analyses message content only.",
    "The final verdict also considers authentication, URLs, domains, relay hops, and other forensic signals.",
]


def build_email_text(subject: str | None, body: str | None) -> str:
    """Combine subject and body while preserving a stable missing-value marker."""
    return f"subject: {subject or '[missing subject]'}\nbody: {body or '[missing body]'}"


def normalize_texts(values: Any) -> list[str]:
    """Pickle-stable, deterministic preprocessing shared by training and serving."""
    return [re.sub(r"\s+", " ", str(value or "")).strip().lower() for value in values]


@lru_cache(maxsize=1)
def _load_pipeline() -> Any:
    # This fixed, repository-local artifact path is the only model loading path.
    return joblib.load(MODEL_PATH)


def clear_model_cache() -> None:
    _load_pipeline.cache_clear()


def analyze_content(subject: str | None, body: str | None) -> dict[str, Any]:
    body_text = body or ""
    text = build_email_text(subject, body)
    base = {"model_name": MODEL_NAME, "model_version": MODEL_VERSION,
            "input_summary": {"subject_included": bool(subject), "body_character_count": len(body_text)},
            "limitations": LIMITATIONS.copy()}
    if not (subject or body):
        return {**base, "enabled": False, "status": "empty_input", "message": "No subject or body text was available for ML analysis."}
    try:
        pipeline = _load_pipeline()
        probabilities = pipeline.predict_proba([text])[0]
        classes = list(pipeline.named_steps["classifier"].classes_)
        phishing_index = classes.index(1)
        probability = float(probabilities[phishing_index])
        prediction = "phishing" if probability >= 0.5 else "legitimate"
        confidence = "high" if max(probability, 1 - probability) >= 0.85 else "medium" if max(probability, 1 - probability) >= 0.65 else "low"
        indicators, explanation_status = _indicators(pipeline, text, phishing_index, prediction)
        return {**base, "enabled": True, "status": "success", "prediction": prediction,
                "phishing_probability": round(probability, 4), "confidence": confidence,
                "top_indicators": indicators, "explanation_status": explanation_status}
    except FileNotFoundError:
        pass
    except Exception:
        # Corrupt artifacts, incompatible sklearn versions, and prediction errors
        # must not disable any independent forensic checks.
        pass
    clear_model_cache()
    return {**base, "enabled": False, "status": "model_unavailable",
            "message": "ML content classifier is not installed or could not be loaded."}


def _indicators(pipeline: Any, text: str, phishing_index: int, prediction: str) -> tuple[list[dict[str, Any]], str]:
    try:
        vectorizer = pipeline.named_steps["tfidf"]
        classifier = pipeline.named_steps["classifier"]
        row = vectorizer.transform([text])
        names = vectorizer.get_feature_names_out()
        weights = classifier.coef_[0]
        if int(classifier.classes_[phishing_index]) != 1:
            weights = -weights
        products = row.multiply(weights).tocoo()
        ranked = sorted(((float(v), str(names[i])) for i, v in zip(products.col, products.data)), key=lambda pair: abs(pair[0]), reverse=True)
        result = []
        for value, term in ranked:
            clean = re.sub(r"[^a-z0-9$%./:_ -]", "", term.lower()).strip()
            if len(clean) < 2 or len(clean) > 48 or "@" in clean or "http" in clean:
                continue
            direction = "phishing" if value > 0 else "legitimate"
            result.append({"term": clean, "direction": direction, "relative_weight": round(abs(value), 3)})
            if len(result) == 3:
                break
        if prediction == "legitimate":
            result.sort(key=lambda item: item["direction"] != "legitimate")
        return result, "available" if result else "no_meaningful_features"
    except Exception:
        return [], "unavailable"
