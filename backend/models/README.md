# Local classifier artifact

Generate `phishing_text_classifier.joblib` locally by following the dataset instructions in `backend/data/README.md` and running the documented training command in the root README. The artifact is intentionally ignored by Git and is loaded only from this fixed backend directory. Never load `.joblib` or pickle files supplied by an API caller. The artifact is produced by the AegisMail training pipeline; it is not included in source control.
