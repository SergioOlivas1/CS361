# CS361 — AI-Assisted Phishing Detection for Healthcare Email Systems

## Overview
This project develops and validates an AI-assisted phishing detection system for a healthcare clinic email environment. The goal is to identify suspicious emails before users interact with them, reducing the risk of credential theft, malware infection, unauthorized access, and exposure of sensitive patient data (HIPAA).

## Project Status
| Checkpoint | Status | Focus |
|---|---|---|
| Checkpoint 1 | ✅ Complete | Scope, assets, initial threat assumptions |
| Checkpoint 2 | ✅ Complete | Baseline analysis, threat modeling, risk matrix |
| Checkpoint 3 | ✅ Complete | Defensive controls, validation, updated risk register |

---

## Selected Domain
Defensive AI in Cybersecurity — Phishing Email Detection

## Problem Statement
Phishing attacks remain one of the most common and effective cybersecurity threats in healthcare. Employees frequently interact with emails about patients, billing, scheduling, and external communication. Traditional spam filters miss sophisticated phishing attempts that imitate legitimate messages. This project studies how AI-assisted analysis can support early detection of suspicious emails before they reach or mislead end users.

## Organization / Use Case
Small healthcare clinic. Employees handle sensitive emails daily. The system acts as a filtering layer that reviews incoming email and flags suspicious messages before delivery.

---

## System Flow
```
Incoming Email
    → Preprocessing (extract sender, links, content)
    → Feature Extraction (keywords, metadata, structure, URLs)
    → AI Detection Engine (scoring against phishing indicators)
    → Risk Scoring (0–100)
    → Classification (Safe / Suspicious / Phishing)
    → Action (Deliver / Warn user / Quarantine + Log)
```

---

## Detection System — v2 (Checkpoint 3)

### What's New in v2
| Control | Description |
|---|---|
| Obfuscation Detection | Catches character-substitution evasion (v3rify, acc0unt, etc.) |
| Display-Name Spoofing | Flags emails where display name claims clinic but domain is external |
| Quarantine Flag | Phishing emails automatically marked quarantined=True |
| CSV Logging | Every analysis logged to phishing_log.csv with full audit trail |
| Expanded Keywords | 21 phishing keywords (was 15), 15 healthcare lures (was 8) |
| Expanded URL Patterns | 7 URL patterns (was 4), including login-page and verify-account patterns |

### Scoring System
| Signal | Points |
|---|---|
| Phishing keyword match | +15 per keyword |
| Healthcare-specific lure | +10 per lure |
| Suspicious sender pattern | +20 |
| Suspicious URL in body | +20 |
| Attachment present | +10 |
| Urgency signal (all-caps subject words) | +10 |
| Obfuscation pattern detected | +15 per pattern |
| Display-name spoofing | +25 |

### Classification Thresholds
| Score | Classification | Action |
|---|---|---|
| 0–29 | Safe | Deliver to inbox |
| 30–59 | Suspicious | Warn user; flag for IT review |
| 60–100 | Phishing | Quarantine immediately; do not deliver |

### Validation Results (Checkpoint 3)
- **15 test cases** run (5 regression from CP2 + 10 new)
- **13/15 passing** (2 documented edge cases)
- **Precision: 100%** — zero false positives
- **Recall: 88.9%** — 8 of 9 threats caught
- **F1 Score: 94.1%**
- **Accuracy: 93.3%** (up from estimated 60% in v1 baseline)

---

## Repository Structure
```
CS361/
├── README.md                        — This file
├── src/
│   ├── phishing_detector.py         — v1 baseline (Checkpoint 2)
│   └── phishing_detector_v2.py      — v2 with defensive controls (Checkpoint 3)
├── docs/
│   ├── diagram.png                  — System architecture diagram
│   └── workflow_diagram.png         — AI detection workflow diagram
├── data/
│   ├── sample_emails.txt            — Labeled sample emails (phishing + legitimate)
│   └── phishing_log.csv             — Auto-generated log from v2 test run
└── reports/
    ├── Checkpoint2_Final.docx       — CP2 submission
    └── Checkpoint3_Submission.docx  — CP3 submission
```

---

## Running the Detector

### Requirements
- Python 3.8+
- No external dependencies (uses standard library only)

### Run v2 (Checkpoint 3)
```bash
python src/phishing_detector_v2.py
```

This will:
1. Run all 15 test cases
2. Print classification, risk score, quarantine status, and flags for each
3. Print a validation summary with accuracy metrics and before/after comparison
4. Write `phishing_log.csv` with a timestamped entry for every email analyzed

### Run v1 (Checkpoint 2 baseline)
```bash
python src/phishing_detector.py
```

---

## Assets Protected
| Asset | Priority |
|---|---|
| Patient data (HIPAA) | Critical |
| Employee credentials | Critical |
| Email accounts | High |
| Email server / system | High |
| AI detection model | High |
| Internal network | High |
| Email attachments / links | Medium |
| Employee trust in system | Medium |

---

## Key Threats Identified
1. Phishing emails with healthcare lures
2. Credential harvesting via fake login pages
3. Malware delivery via email attachments
4. Social engineering / display-name spoofing
5. AI evasion via obfuscated keywords

---

## Scope Limitations
This project focuses on **detection only**. The following are out of scope for this timeline:
- Full enterprise email server integration
- Live connection to a real email provider
- Automated blocking infrastructure
- Production-level ML model training

---

## Team
| Name | Role |
|---|---|
| Sergio Olivas | Project Lead / Research |
| Khumbo Nyirenda | Data Collection |
| Cerilo Yousif | Development |
| Ernest Apollon | Development |
| Victor Olatunji | Documentation |

---

## References
- NIST SP 800-63B — Digital Identity Guidelines
- CIS Controls v8 — Control 9 (Email and Web Browser Protections)
- HIPAA Security Rule — 45 CFR Part 164
