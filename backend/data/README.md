# Local training data

Place the individual source CSV files from the Kaggle [Phishing Email Dataset: Phish No More](https://doi.org/10.34740/kaggle/ds/5074342) under `raw/` (or pass their local paths to the trainer). Do not commit the downloaded data, email evidence, or derived CSV files. The dataset is distributed under CC BY-SA 4.0; confirm attribution and share-alike obligations with the faculty mentor before public distribution of adapted dataset material.

The local source files were inspected and have `subject`, `body`, and `label` columns. For this dataset, label `0` is mapped to legitimate and `1` to spam/phishing, matching the dataset's published class totals. The aggregate `phishing_email.csv` must not be passed alongside the individual source files. The pipeline records input file hashes, row counts, label mapping, cleaning policy and duplicate count in a locally generated manifest.
