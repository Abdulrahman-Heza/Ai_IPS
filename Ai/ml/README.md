# Model artifacts

Place trained files here after running `python -m ml.training.train`:

- `lstm_ensemble_*.h5`
- `random_forest_*.joblib`
- `normalization_*.json`
- `training_report.json`

Binary model files (`.h5`, `.joblib`) are excluded from Git due to size. Normalization JSON and `training_report.json` are committed as reference.

To run inference locally, train models or copy artifacts into this folder, then start the AI service.
