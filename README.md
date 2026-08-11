# AI-Driven Cyber Threat Detection Using Cowrie Honeypot and Machine Learning

## Overview

This project demonstrates the integration of Cybersecurity Monitoring and Machine Learning using the Cowrie SSH Honeypot. The system captures attacker interactions, processes security logs, and applies machine learning techniques to analyze command patterns and classify attacker behavior.

The objective of this project is to explore how Artificial Intelligence can assist cybersecurity professionals in understanding and analyzing suspicious activities captured through honeypot environments.

---

## Problem Statement

Traditional security systems generate large volumes of logs that require manual investigation and analysis. Identifying suspicious activities from these logs can be time-consuming and inefficient.

This project aims to automate the analysis of attacker commands collected through a honeypot and demonstrate how machine learning techniques can be applied to cybersecurity log analysis.

---

## Objectives

- Deploy and configure a Cowrie SSH Honeypot.
- Capture attacker interactions and command execution logs.
- Extract meaningful features from collected command data.
- Apply machine learning techniques for behavior analysis.
- Demonstrate the integration of Cybersecurity and Artificial Intelligence.

---

## System Architecture

```text
Attacker
    ↓
Cowrie SSH Honeypot
    ↓
Log Collection
    ↓
Data Preprocessing
    ↓
Feature Extraction (CountVectorizer)
    ↓
Machine Learning Classification (Naive Bayes)
    ↓
Behavior Analysis Results
```

---

## Technologies Used

### Cybersecurity
- Cowrie SSH Honeypot
- Linux (Kali Linux)
- Docker

### Machine Learning
- Python
- Scikit-learn
- CountVectorizer
- Naive Bayes Classifier

### Data Processing
- JSON
- CSV
- Log Analysis

---

## Project Workflow

1. An attacker connects to the Cowrie SSH Honeypot.
2. Commands executed during the session are recorded.
3. Logs are collected and preprocessed.
4. Command data is transformed into numerical features using CountVectorizer.
5. A Naive Bayes model is trained on labeled command data.
6. The trained model analyzes command patterns and produces classification results.

---

## Repository Structure

```text
AI-Driven-Cyber-Threat-Detection/
│
├── train_model.py
├── ai_predict.py
├── live_ai.py
├── dataset.csv
├── test_logs.json
├── README.md
└── .gitignore
```

---

## Key Features

- SSH Honeypot Deployment
- Security Log Collection
- Command Analysis
- Feature Extraction using NLP Techniques
- Machine Learning-Based Classification
- Cyber Threat Behavior Analysis

---

## Learning Outcomes

Through this project, I gained practical experience in:

- Honeypot Deployment and Monitoring
- Security Log Analysis
- Machine Learning Model Development
- Feature Extraction from Text Data
- Cybersecurity Data Processing
- Threat Intelligence Fundamentals

---

## Future Enhancements

- Real-Time Threat Monitoring Dashboard
- Larger Attacker Behavior Dataset
- Advanced Machine Learning Models
- Automated Alert Generation
- SIEM Integration
- Real-Time Threat Intelligence Analysis

---

## Disclaimer

This project was developed for academic and educational purposes to demonstrate the integration of cybersecurity monitoring and machine learning techniques.

---

## Author

**Guduru Jagadeeshwar Reddy**

Cybersecurity Department  
Dayananda Sagar University, Bangalore

---

## Keywords

Cybersecurity, Honeypot, Cowrie, Machine Learning, Threat Detection, Python, Scikit-learn, Log Analysis, Artificial Intelligence, SSH Security
