# Pre-Click Phishing Detection Engine

> Explainable, context-aware phishing risk analysis before a user opens a link.

**Live Demo:** https://pre-click-phishing-detection-engine.onrender.com

## Overview

The Pre-Click Phishing Detection Engine is a Flask-based web application that analyzes URLs before a user opens them and provides an explainable risk assessment.

Instead of relying only on a simple blacklist check, the system combines URL-level and message-context indicators to produce:

- A risk score from 0-100
- Risk classification: LOW, SUSPICIOUS, or HIGH RISK PHISHING
- A recommendation: OPEN, BE CAREFUL, or DO NOT OPEN
- A score breakdown showing contributing indicators
- Human-readable explanations for detected risk factors
- Email/message context such as urgency and sender-domain anomalies
- Pre-click interception before a link is opened

## Key Features

### URL Heuristic Analysis

The engine examines signals including:

- Brand impersonation and lexical squatting
- Suspicious TLDs and domain patterns
- Credential and sensitive-action keywords
- Raw IP addresses
- URL encoding and obfuscation indicators
- Deep subdomains
- HTTP vs HTTPS
- Known URL shorteners
- Shared-content hosting patterns

### Context-Aware Analysis

URL signals can be combined with message context such as:

- Urgency-related language
- Suspicious sender-domain patterns
- Credential/action requests
- Email context anomalies

### Explainable Risk Scoring

The dashboard shows the reasoning behind a result:

Risk Score -> Classification -> Score Breakdown -> Key Risk Reasons -> Recommendation

### Pre-Click Protection

Before opening a detected link, the dashboard allows the user to:

- Stay Safe (Cancel)
- Proceed to Open Link

## System Architecture

```mermaid
flowchart TD

    A["Email / Message Context"] --> B["URL Extraction"]
    B --> C["Pre-Click Analysis Engine"]

    subgraph ANALYSIS["MULTI-SIGNAL SECURITY ANALYSIS"]
        direction LR

        C1["Domain Analysis"]
        C2["Brand Impersonation"]
        C3["URL Structure"]
        C4["Redirect & Shortener Analysis"]
        C5["Page & Content Analysis"]
        C6["Message Context Analysis"]
    end

    C --> C1
    C --> C2
    C --> C3
    C --> C4
    C --> C5
    C --> C6

    C1 --> D["Risk Scoring Engine"]
    C2 --> D
    C3 --> D
    C4 --> D
    C5 --> D
    C6 --> D

    D --> E["Risk Score<br/>0 - 100"]

    E --> F["Explainable Security Assessment"]

    subgraph EXPLANATION["EXPLAINABILITY LAYER"]
        direction LR

        F1["Risk Classification"]
        F2["Score Breakdown"]
        F3["Risk Factors"]
        F4["Recommendation"]
    end

    F --> F1
    F --> F2
    F --> F3
    F --> F4

    F --> G["Pre-Click Protection"]
    G --> H{"User Decision"}

    H -->|Stay Safe| I["Cancel Navigation"]
    H -->|Proceed| J["Open Link"]


    %% Main flow colors
    classDef input fill:#E8F1FF,stroke:#2563EB,stroke-width:2px,color:#172033;
    classDef extraction fill:#F1EAFE,stroke:#7C3AED,stroke-width:2px,color:#172033;
    classDef engine fill:#E6F7F0,stroke:#059669,stroke-width:3px,color:#172033;

    %% Analysis colors
    classDef analysis fill:#F0FDF4,stroke:#16A34A,stroke-width:1.5px,color:#172033;

    %% Scoring colors
    classDef scoring fill:#FFF4E5,stroke:#EA580C,stroke-width:2.5px,color:#172033;
    classDef score fill:#FFF7ED,stroke:#F97316,stroke-width:3px,color:#172033;

    %% Explanation colors
    classDef explanation fill:#E8F7FF,stroke:#0284C7,stroke-width:2px,color:#172033;

    %% Protection colors
    classDef protection fill:#FFF0F0,stroke:#DC2626,stroke-width:2.5px,color:#172033;
    classDef decision fill:#FFF8E1,stroke:#D97706,stroke-width:2px,color:#172033;

    %% Final actions
    classDef safe fill:#EAF8EE,stroke:#16A34A,stroke-width:2px,color:#172033;
    classDef open fill:#FDECEC,stroke:#DC2626,stroke-width:2px,color:#172033;


    %% Apply colors
    class A input;
    class B extraction;
    class C engine;

    class C1,C2,C3,C4,C5,C6 analysis;

    class D scoring;
    class E score;

    class F,F1,F2,F3,F4 explanation;

    class G protection;
    class H decision;

    class I safe;
    class J open;


    %% Subgraph styling
    style ANALYSIS fill:#F7FAFC,stroke:#16A34A,stroke-width:2px,color:#166534;
    style EXPLANATION fill:#F7FAFC,stroke:#0284C7,stroke-width:2px,color:#075985;
```

## Risk Classification

| Score | Classification | Recommendation |
|---|---|---|
| 0-19 | CLEAN / LOW RISK | OPEN |
| 20-49 | SUSPICIOUS | BE CAREFUL |
| 50-100 | HIGH RISK PHISHING THREAT | DO NOT OPEN |

The score is a heuristic assessment and is not a guarantee that a URL is malicious or safe.

## Benchmark Evaluation

The heuristic engine was evaluated using a curated 25-case edge-case/stress-test benchmark.

- Accuracy: 100%
- Precision: 100%
- Recall: 100%
- F1-score: 100%
- True Positives: 15
- True Negatives: 10
- False Positives: 0
- False Negatives: 0

These results describe performance on the curated benchmark set and should not be interpreted as real-world phishing detection accuracy.

## Tech Stack

- Python
- Flask
- Flask-CORS
- Gunicorn
- tldextract
- Requests
- BeautifulSoup
- dnspython
- python-whois
- HTML
- CSS
- JavaScript
- Render

## Project Structure

```mermaid
flowchart TD

    ROOT["Pre-Click-Phishing-Detection-Engine"]

    ROOT --> A["analyzer/"]
    ROOT --> B["backend/"]
    ROOT --> C["database/"]
    ROOT --> D["frontend/"]
    ROOT --> E["benchmark_results.json"]
    ROOT --> F["benchmark_report.txt"]
    ROOT --> G["requirements.txt"]
    ROOT --> H["test_benchmark_edgecases.py"]

    A --> A1["brand_analyzer.py"]
    A --> A2["context_analyzer.py"]
    A --> A3["domain_analyzer.py"]
    A --> A4["engine.py"]
    A --> A5["page_analyzer.py"]
    A --> A6["redirect_analyzer.py"]
    A --> A7["url_analyzer.py"]

    B --> B1["app.py"]
    B --> B2["extractor.py"]
    B --> B3["risk_engine.py"]

    C --> C1["phishing.db"]
    C --> C2["schema.sql"]

    D --> D1["index.html"]
    D --> D2["script.js"]
    D --> D3["style.css"]
```

## Screenshots

### Dashboard

![Dashboard](screenshots/01-dashboard.png)

### High-Risk Phishing Detection

![High-risk phishing detection](screenshots/02-high-risk-phishing.png)

### Multiple URL Analysis

![Multiple URL analysis](screenshots/03-multiple-url-analysis.png)

### Message With No URLs

![Message with no URLs](screenshots/04-no-url-message.png)

## Running Locally

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the Flask application

```bash
python backend/app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Deployment

The application is deployed as a Python Web Service on Render.

Production start command:

```bash
gunicorn backend.app:app
```

**Live application:** https://pre-click-phishing-detection-engine.onrender.com

## Project Goal

The project focuses on explainable pre-click phishing protection rather than simply returning a binary phishing/legitimate label.

```text
Analyze -> Explain -> Warn -> Let the user decide
```

## Disclaimer

This project is an educational and research-oriented phishing analysis system. Its heuristic results are not a substitute for commercial security products, threat-intelligence services, browser security systems, or professional incident-response processes.
