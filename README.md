# IPS — AI-Powered Intrusion Prevention System

[![Repository](https://img.shields.io/badge/GitHub-redtubbypo%2FIPS-blue)](https://github.com/redtubbypo/IPS)

**English** | [العربية (README.ar.md)](README.ar.md)

IPS is a full-stack security platform that detects network threats using machine learning (LSTM ensemble + Random Forest on CICIDS2018-style features), blocks malicious traffic, and presents real-time alerts through a React dashboard.

---

## Table of contents

1. [Architecture](#architecture)
2. [Technology stack](#technology-stack)
3. [Repository structure](#repository-structure)
4. [Module reference](#module-reference)
5. [Important source files](#important-source-files)
6. [Prerequisites](#prerequisites)
7. [How to run the full project](#how-to-run-the-full-project)
8. [Training ML models](#training-ml-models)
9. [API overview](#api-overview)
10. [Docker](#docker)
11. [License & dataset](#license--dataset)

---

## Architecture

### System overview

![System architecture](docs/IPS_System_Architecture.png)

| Layer | Port | Role |
|-------|------|------|
| **Frontend** | 3000 | React dashboard, login, alerts, IPS controls, threat simulator |
| **Backend** | 5000 | REST API (`/api/v1`), JWT auth, SQLite, Socket.io real-time events |
| **AI service** | 5001 | FastAPI inference — LSTM + Random Forest ensemble |

Data flow: **Browser → Backend → AI service** for predictions; **Backend → SQLite** for persistence; **Backend ↔ Frontend** via WebSocket for live threat notifications.

### Module decomposition

![Module decomposition](docs/IPS_Module_Decomposition.png)

### Threat detection sequence

![Threat detection flow](docs/IPS_Threat_Detection_Flow.png)

PlantUML sources (editable): [`docs/architecture-system.puml`](docs/architecture-system.puml), [`docs/architecture-modules.puml`](docs/architecture-modules.puml), [`docs/sequence-threat-detection.puml`](docs/sequence-threat-detection.puml).

Regenerate PNGs:

```bash
cd docs
java -jar plantuml.jar -tpng *.puml
```

---

## Technology stack

| Area | Tools & libraries |
|------|-------------------|
| **Frontend** | React 19, TypeScript, Vite 5, Tailwind CSS 3.4, Recharts, Socket.io-client, Lucide icons |
| **Backend** | Node.js 18+, Express 4, Socket.io 4, TypeScript 5, SQLite3, JWT (jsonwebtoken), bcryptjs, Axios, Winston, Helmet, Zod/Joi |
| **AI / ML** | Python 3.10, FastAPI, Uvicorn, NumPy, TensorFlow/Keras (training), scikit-learn/joblib (Random Forest), imbalanced-learn (SMOTE), pandas |
| **DevOps** | Docker, Docker Compose (AI + backend) |
| **Dataset** | [CICIDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) (`MachineLearningCVE` CSVs) |

---

## Repository structure

```
IPS/
├── ai/                    # Python ML training + FastAPI inference
│   ├── inference/server.py
│   ├── ml/                # training, features, models, data loaders
│   ├── models/            # trained artifacts (*.h5, *.joblib, normalization JSON)
│   ├── data/              # CICIDS2018 CSVs (not in git — download separately)
│   ├── requirements.txt
│   └── Dockerfile
├── backend/               # Node.js API + WebSocket
│   ├── src/index.ts
│   ├── src/routes/
│   ├── src/services/
│   ├── src/database/sqlite.ts
│   └── Dockerfile
├── frontend/              # React dashboard
│   └── src/
├── docs/                  # PlantUML + architecture PNGs
├── docker-compose.yml
├── README.md              # English (this file)
└── README.ar.md           # Arabic
```

---

## Module reference

### 1. AI module (`ai/`)

| Component | Path | Description |
|-----------|------|-------------|
| **Inference API** | `ai/inference/server.py` | FastAPI app: `/health`, `/inference`, `/models`, `/status` |
| **Model manager** | `ai/ml/utils/model_utils.py` | Loads LSTM (`.h5`), Random Forest (`.joblib`), normalization JSON |
| **LSTM ensemble** | `ai/ml/models/lstm_ensemble.py` | Keras LSTM architecture + sklearn Random Forest wrapper |
| **Feature engineering** | `ai/ml/features/feature_engineering.py` | 50-dimensional feature vectors from flow data |
| **Data loader** | `ai/ml/data/cicids_loader.py` | Loads CICIDS2018 CSVs, SMOTE balancing |
| **Training pipeline** | `ai/ml/training/train.py` | End-to-end training; writes artifacts to `ai/models/` |

**Attack classes (example):** Benign, DoS, DDoS, PortScan, Botnet (configurable in training).

### 2. Backend module (`backend/`)

| Component | Path | Description |
|-----------|------|-------------|
| **Entry point** | `backend/src/index.ts` | Express app, middleware, routes, Socket.io, SQLite init |
| **AI client** | `backend/src/services/AIInferenceService.ts` | HTTP client to `AI_SERVICE_URL` (default `http://localhost:5001`) |
| **Threat pipeline** | `backend/src/services/ThreatProcessingService.ts` | Orchestrates inference, alerts, IPS actions |
| **IPS / blocking** | `backend/src/services/IPSService.ts` | Blocked IPs and firewall-style rules |
| **Alerts** | `backend/src/services/AlertService.ts` | Alert CRUD and notifications |
| **Self-healing** | `backend/src/services/SelfHealingEngine.ts` | Automated remediation hooks |
| **Drift detection** | `backend/src/services/DriftDetectionService.ts` | Model/data drift monitoring |
| **WebSocket** | `backend/src/websocket/PredictionEvents.ts` | Real-time prediction/threat events |
| **Database** | `backend/src/database/sqlite.ts` | SQLite at `backend/data/ips.db` (created on first run) |

**REST routes** (`/api/v1`): `auth`, `ips`, `alerts`, `network`, `dashboard`, `config`, `threats`.

### 3. Frontend module (`frontend/`)

| Page | Path | Description |
|------|------|-------------|
| Login | `frontend/src/pages/LoginPage.tsx` | JWT authentication |
| Dashboard | `frontend/src/pages/DashboardPage.tsx` | Metrics and charts (Recharts) |
| Alerts | `frontend/src/pages/AlertsPage.tsx` | Security alert list |
| IPS | `frontend/src/pages/IPSPage.tsx` | Blocked IPs and IPS controls |
| Simulator | `frontend/src/pages/SimulatorPage.tsx` | Inject test threats for demos |
| API client | `frontend/src/api/client.ts` | REST helpers with auth header |
| WebSocket | `frontend/src/hooks/useSocket.ts` | Subscribes to backend threat events |
| App shell | `frontend/src/App.tsx` | Routing, auth state, threat toasts + audio |

**Dev proxy:** `frontend/vite.config.ts` forwards `/api` and `/health` to `http://localhost:5000`.

---

## Important source files

| File | Why it matters |
|------|----------------|
| `ai/inference/server.py` | Production inference entry; ensemble prediction API |
| `ai/ml/training/train.py` | Train models before deployment |
| `ai/ml/utils/model_utils.py` | Shared load/predict logic for training and inference |
| `backend/src/index.ts` | Wires all routes, security middleware, Socket.io |
| `backend/src/services/AIInferenceService.ts` | Bridge between Node and Python AI |
| `backend/src/services/ThreatProcessingService.ts` | Core threat handling logic |
| `backend/src/database/sqlite.ts` | Schema and DB initialization |
| `frontend/src/App.tsx` | Main UI flow and real-time threat UX |
| `frontend/src/hooks/useSocket.ts` | Live dashboard updates |
| `docker-compose.yml` | Run AI + backend in containers |

---

## Prerequisites

- **Node.js** ≥ 18 and **npm** ≥ 9  
- **Python** 3.10+ (3.10 recommended for TensorFlow training)  
- **Java** 8+ (only to regenerate PlantUML PNGs)  
- **Git**  
- Optional: **Docker** & **Docker Compose**  
- For training: **CICIDS2018** CSV files under `ai/data/MachineLearningCVE/` (not committed — large download from [UNB CIC](https://www.unb.ca/cic/datasets/ids-2018.html))

---

## How to run the full project

Run all three services in **three terminals** (recommended for development).

### Step 0 — Clone

```bash
git clone https://github.com/redtubbypo/IPS.git
cd IPS
```

### Step 1 — AI service (port 5001)

```bash
cd ai
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
# source venv/bin/activate

pip install -r requirements.txt
# For inference with trained models, also install TensorFlow + joblib if not present:
# pip install tensorflow joblib scikit-learn

# Ensure model files exist in ai/models/ (see Training section)
python -m uvicorn inference.server:app --host 0.0.0.0 --port 5001 --reload
```

Verify: [http://localhost:5001/health](http://localhost:5001/health)

### Step 2 — Backend (port 5000)

```bash
cd backend
npm install
copy .env.example .env   # Windows — or: cp .env.example .env
npm run dev
```

Verify: [http://localhost:5000/health](http://localhost:5000/health)

Default env (`backend/.env.example`):

- `AI_SERVICE_URL=http://localhost:5001`
- `CORS_ORIGIN=http://localhost:3000`
- `JWT_SECRET` — change in production

SQLite database is created automatically at `backend/data/ips.db`.

### Step 3 — Frontend (port 3000)

```bash
cd frontend
npm install
# Uses .env.development: VITE_API_ORIGIN=http://localhost:5000
npm run dev
```

Open: [http://localhost:3000](http://localhost:3000)

### Quick health checklist

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| Backend health | http://localhost:5000/health |
| AI health | http://localhost:5001/health |

### PowerShell test script (optional)

From repo root:

```powershell
.\test-threat.ps1
```

---

## Training ML models

1. Download CICIDS2018 `MachineLearningCVE` CSVs into `ai/data/MachineLearningCVE/`.
2. Install training dependencies (in addition to `requirements.txt`):

```bash
pip install tensorflow pandas scikit-learn joblib imbalanced-learn
```

3. Run training from repository root:

```bash
cd ai
python -m ml.training.train
```

4. Confirm artifacts in `ai/models/`:

- `lstm_ensemble_*.h5`
- `random_forest_*.joblib`
- `normalization_*.json`
- `training_report.json`

Restart the AI service so `ModelManager.load_latest_models()` picks up new files.

---

## API overview

### AI service (`http://localhost:5001`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Service and model readiness |
| POST | `/inference` | Body: `{ "features": [50 floats], "flow_id": "..." }` |
| GET | `/models` | Loaded model metadata |
| GET | `/status` | Runtime metrics |

### Backend (`http://localhost:5000/api/v1`)

| Prefix | Purpose |
|--------|---------|
| `/auth` | Login, register, JWT |
| `/threats` | Submit / simulate threats |
| `/alerts` | Security alerts |
| `/ips` | Blocked IPs, IPS rules |
| `/dashboard` | Aggregated metrics |
| `/network` | Network nodes |
| `/config` | System configuration |

Authenticated routes require header: `Authorization: Bearer <token>`.

---

## Docker

Run **AI + backend** in containers; run the frontend locally for hot reload.

```bash
docker compose up --build
```

Then in another terminal:

```bash
cd frontend
npm install
npm run dev
```

Set `AI_SERVICE_URL=http://ai:5001` inside Compose (already configured in `docker-compose.yml`).

Mount trained models: `./ai/models` is mounted read-only into the AI container.

---

## License & dataset

- Application code: see repository license (add `LICENSE` file if needed).
- **CICIDS2018** is subject to the dataset provider’s terms; use only for research/education unless you have explicit permission for production traffic analysis.

---

## Contributing

1. Fork [redtubbypo/IPS](https://github.com/redtubbypo/IPS)  
2. Create a feature branch  
3. Open a pull request with a clear description and test plan  

For Arabic documentation, see [README.ar.md](README.ar.md).
