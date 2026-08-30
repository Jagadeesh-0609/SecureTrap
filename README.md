# SecureTrap

SecureTrap is a modular, honeypot-independent cybersecurity research framework for collecting, processing, analyzing, and monitoring honeypot activity.

The current implementation uses **Cowrie** as the active honeypot source and performs **unsupervised anomaly detection using IsolationForest**. Events are ingested, validated, processed, enriched, converted into a stable dataset representation, analyzed by the AI engine, converted into alerts, persisted in SQLite, and exposed through a read-only command-line interface.

> **Important:** SecureTrap currently has no verified ground-truth attack-label dataset. An anomaly is therefore **not** treated as a confirmed attack or as a supervised classification result.

---

## Architecture

```text
Cowrie
   │
   ▼
LiveJsonLogReader / JsonLogReader
   │
   ▼
CowrieAdapter
   │
   ▼
IngestionPipeline
   │
   ▼
LogProcessor
   │
   ▼
EventEnricher
   │
   ▼
DatasetBuilder / DatasetWriter / DatasetManager
   │
   ▼
FeatureExtractor / FeatureMatrixBuilder
   │
   ▼
ModelManager
   │
   ▼
IsolationForest
   │
   ▼
AnomalyResult
   │
   ├──────────────► AnomalyEvaluator
   │
   ▼
AlertDispatcher
   │
   ▼
Alert
   │
   ▼
AlertStore (SQLite)
   │
   ▼
AlertReporter
   │
   ▼
CLI

Runtime orchestration:
SecureTrapService
coordinates live detection → alert dispatch → persistence

The architecture isolates honeypot-specific behavior at the adapter layer. Future honeypots can be supported by implementing the existing BaseAdapter contract without changing the downstream processing pipeline.

Workflow
1. Ingestion

JsonLogReader reads existing JSON/JSONL events in batch mode.

LiveJsonLogReader follows a JSON log file and yields newly appended events for live processing.

The reader layer only reads raw event data.

2. Honeypot Adaptation

CowrieAdapter converts Cowrie-specific raw fields into SecureTrap's standard AttackEvent representation.

3. Validation

IngestionPipeline passes adapted events through the event validation layer.

Invalid events are reported through validation results and are not passed to downstream processing.

4. Processing

LogProcessor converts validated AttackEvent objects into ProcessedEvent objects.

It adds deterministic metadata such as:

category
severity
normalized command

The original event remains preserved.

5. Enrichment

EventEnricher derives directly observable command properties, including:

command presence
command length
URL-like content
IP-address-like content
file-path-like content
shell metacharacters

These features describe observable properties and do not directly infer attacker intent.

6. Dataset Representation

DatasetBuilder, DatasetWriter, and DatasetManager provide the stable DatasetRecord representation and CSV dataset handling.

The dataset contains fields such as:

timestamp
source_ip
session_id
protocol
honeypot
event_type
category
severity
command
has_command
command_length
has_url
has_ip_address
has_file_path
has_shell_metacharacters
7. Feature Extraction

FeatureExtractor converts a DatasetRecord into a deterministic numeric FeatureVector.

FeatureMatrixBuilder combines multiple vectors into an ordered FeatureMatrix.

Current features:

command_length
has_command
has_url
has_ip_address
has_file_path
has_shell_metacharacters

Boolean features are represented as 0 or 1.

8. Anomaly Detection

ModelManager separates model fitting from inference.

Baseline fitting:

DatasetRecord(s)
      ↓
FeatureMatrix
      ↓
ModelManager.fit()
      ↓
IsolationForest

Inference:

new DatasetRecord(s)
      ↓
FeatureMatrix
      ↓
ModelManager.predict()
      ↓
AnomalyResult

The model is fitted on baseline data and reused for later inference. Live events are not automatically used to retrain the model.

Machine Learning Approach
Model

The current model is:

sklearn.ensemble.IsolationForest

This is an unsupervised anomaly detector.

Why unsupervised?

The current project does not have a verified ground-truth dataset identifying which observed events are definitively attacks.

Using supervised learning without reliable labels would require assumptions or fabricated labels.

SecureTrap therefore currently focuses on identifying observations that are unusual relative to a learned baseline.

Prediction semantics

The model's original semantics are preserved:

 1  = inlier / normal
-1  = outlier / anomaly

These values are not converted into security verdicts.

In particular:

-1 != confirmed attack

and:

1 != proven benign activity

is_anomaly=True means only that the underlying IsolationForest model identified the observation as an outlier relative to the fitted data.

Model scores

IsolationForest decision scores are retained as model outputs.

They are:

not probabilities
not confidence percentages
not attack likelihoods

Generally, a lower score indicates greater deviation from the learned pattern.

Anomaly Results

AnomalyResult connects model output to the exact DatasetRecord that produced it.

It contains:

record
prediction
score
is_anomaly

The original DatasetRecord is preserved by identity while the result remains in memory.

This makes each anomaly result traceable to its source event, session, timestamp, and command.

Evaluation

AnomalyEvaluator provides descriptive statistics over AnomalyResult objects:

total_count
normal_count
anomaly_count
anomaly_rate
min_score
max_score
mean_score

Because verified ground-truth labels are not currently available, SecureTrap does not claim supervised metrics such as:

accuracy
precision
recall
F1-score
ROC-AUC

These can be introduced later when trustworthy labels exist.

Alerting

AlertBuilder converts an AnomalyResult into an operator-friendly Alert.

The alert preserves:

timestamp
source_ip
session_id
protocol
honeypot
event_type
command
prediction
score
is_anomaly

The original AnomalyResult remains reachable through the alert.

AlertDispatcher filters the inference stream so that only:

is_anomaly=True

results become runtime alerts.

Normal inference results are not dispatched as alerts.

Alert Persistence

AlertStore provides persistent local storage using Python's standard-library sqlite3.

Current flow:

Alert
  ↓
AlertStore
  ↓
SQLite

The prototype alert database is:

data/securetrap_live_alerts.db

The persisted fields include:

timestamp
source_ip
session_id
protocol
honeypot
event_type
command
prediction
score
is_anomaly

The storage layer is intentionally independent of AI inference and runtime event processing.

Runtime Service

SecureTrapService coordinates:

LiveDetectionPipeline
        ↓
AlertDispatcher
        ↓
AlertStore

Its responsibility is orchestration rather than implementation of detection logic.

The service:

processes the supplied event stream
persists alerts emitted by AlertDispatcher
does not train the model
does not implement anomaly filtering itself
Reporting

AlertReporter provides read-only summaries and recent-alert queries.

It exposes:

total alerts
anomaly alerts
normal alerts
latest timestamp
recent alerts

The reporter does not modify stored alerts.

Command-Line Interface

SecureTrap provides a simple read-only CLI.

Show summary
python -m core.cli.main summary

Example:

Total alerts: 1
Anomaly alerts: 1
Normal alerts: 0
Latest timestamp: 2026-08-30T11:42:08.966247Z
Show recent alerts
python -m core.cli.main alerts
Limit results
python -m core.cli.main alerts --limit 5
Use a custom database
python -m core.cli.main summary --db path/to/alerts.db

or:

python -m core.cli.main alerts --db path/to/alerts.db --limit 10

The CLI is read-only and delegates all alert querying to AlertReporter.

Repository Structure
SecureTrap/
├── core/
│   ├── event_engine/
│   ├── honeypot_engine/
│   ├── log_processor/
│   ├── dataset_manager/
│   ├── ai_engine/
│   ├── alert_engine/
│   ├── runtime/
│   └── cli/
│
├── tests/
│
├── data/
│   ├── securetrap_events.csv
│   └── securetrap_live_alerts.db
│
├── legacy/
│   ├── train_model.py
│   ├── ai_predict.py
│   └── live_ai.py
│
├── dataset.csv
├── test_logs.json
├── README.md
└── .gitignore
Legacy / Historical Implementation

The legacy/ directory contains SecureTrap's original prototype implementation.

These files are retained for historical reference:

legacy/
├── train_model.py
├── ai_predict.py
└── live_ai.py

The legacy implementation used:

dataset.csv
    ↓
CountVectorizer
    ↓
MultinomialNB
    ↓
model.pkl / vectorizer.pkl

It was a supervised command-string classification prototype.

The legacy implementation is not part of the current runtime architecture and is not used by the modular components under core/.

The current SecureTrap system instead uses:

FeatureExtractor
    ↓
FeatureMatrixBuilder
    ↓
IsolationForest
    ↓
ModelManager

The two approaches are not interchangeable, and no performance comparison between them is currently claimed.

The legacy scripts have been preserved without changing their internal behavior.

Real-Time Verification

The current implementation has been verified against a real Cowrie deployment.

A new live command:

echo http://1.2.3.4

was processed through:

LiveJsonLogReader
→ IngestionPipeline
→ LiveDetectionPipeline
→ ModelManager
→ AnomalyResult
→ AlertDispatcher
→ Alert
→ AlertStore

The observed IsolationForest output was:

prediction = -1
is_anomaly = True

The generated alert was successfully persisted into SQLite and subsequently displayed through the CLI.

This demonstrates working runtime integration, not supervised attack-detection accuracy.

Testing

SecureTrap contains isolated tests for each major component.

Run the complete suite with:

python -m pytest tests/ -v

The test suite covers:

event representation and validation
honeypot adaptation
JSON and live log reading
ingestion
processing and enrichment
session aggregation
dataset construction and persistence
feature extraction
feature matrix construction
anomaly detection
anomaly result mapping
inference
model lifecycle
anomaly evaluation
live detection
alert creation
alert dispatch
SQLite alert persistence
runtime service orchestration
reporting
CLI behavior

The authoritative test count is whatever the current repository reports when pytest is executed.

Current Limitations

The current prototype intentionally has several limitations:

No verified ground-truth attack dataset.
No supervised attack/benign classifier in the current runtime.
Small deterministic feature set.
No categorical/identifier encoding in the current model features.
No automatic online retraining.
No model persistence/version management yet.
Local SQLite storage is intended for the prototype.
No external notification service.
No web dashboard.
No automated threat-intelligence enrichment.

These limitations are explicit so that model outputs are not overstated.

Future Enhancements

Potential future directions include:

Verified ground-truth dataset creation.
Supervised evaluation when trustworthy labels are available.
Additional honeypot adapters such as Dionaea.
Expanded session-level and temporal features.
Explicit categorical/identifier encoding strategies.
Model persistence and versioning.
External notification channels.
Web-based operator dashboard.
SIEM integration.
Threat-intelligence enrichment.
Development Philosophy

SecureTrap follows:

Design
   ↓
Implementation
   ↓
Unit Tests
   ↓
Integration Test
   ↓
Real-System Verification
   ↓
Git Checkpoint

The project emphasizes clear boundaries between:

data collection
processing
feature extraction
model inference
alert generation
persistence
reporting
operator interaction
Disclaimer

SecureTrap is developed for cybersecurity research, experimentation, and educational purposes.

An anomaly result is not a definitive statement that malicious activity occurred. Operators should review the associated event and session context before making security decisions.

Author

Guduru Jagadeeshwar Reddy

Cybersecurity Department
Dayananda Sagar University, Bangalore

Keywords

Cybersecurity, Honeypot, Cowrie, SecureTrap, Anomaly Detection, IsolationForest, Machine Learning, Security Monitoring, Log Analysis, Intrusion Detection, Python, SQLite
