# CS361 — AI-Assisted Phishing Detection for Healthcare Email Systems

> **Final Project — Checkpoint 4** | April 26, 2026

## Overview
This project designs, implements, and validates an AI-assisted phishing detection system for a small healthcare clinic email environment. The system analyzes incoming emails through a multi-stage pipeline and classifies each message as **Safe**, **Suspicious**, or **Phishing** — triggering delivery, a user warning, or quarantine accordingly.

The project was completed across four checkpoints over four weeks. All code, documentation, test cases, and evidence artifacts are in this repository.

---

## Project Status

| Checkpoint | Due | Status | Focus |
|---|---|---|---|
| CP1 | Apr 5 | ✅ 50/50 | Project definition, scope, GitHub setup |
| CP2 | Apr 12 | ✅ Complete | Baseline analysis, threat modeling, risk matrix |
| CP3 | Apr 19 | ✅ Complete | Defensive controls, 15-case validation, logging |
| CP4 | Apr 26 | ✅ Complete | Final report, slide deck, evidence appendix |

---

## Final Validation Results (v2)

| Metric | v1 Baseline (CP2) | v2 With Controls (CP3/CP4) |
|---|---|---|
| Test cases | 5 | 15 |
| Passed | 5/5 | 13/15 |
| Precision | 100% | **100%** |
| Recall | est. 60% | **88.9%** |
| F1 Score | est. 75% | **94.1%** |
| Accuracy | est. 60% | **93.3%** |
| False Positives | 0 | **0** |
| Logging | No | **Yes (CSV)** |
| Quarantine flag | No | **Yes** |

---

## System Pipeline

```
Incoming Email
  → Preprocessing       (sender, display name, links, content)
  → Feature Extraction  (keywords, metadata, URLs, structure)
  → AI Detection Engine (scoring: obfuscation, spoofing, patterns)
  → Risk Scoring        (0–100 weighted flag sum)
  → Classification      (Safe 0–29 / Suspicious 30–59 / Phishing 60+)
  → Action & Logging    (Deliver / Warn / Quarantine + phishing_log.csv)
```

---

## Defensive Controls (v2 — Checkpoint 3)

| ID | Control | Addresses | Validated By |
|---|---|---|---|
| C-01 | Obfuscation-Resistant Detection | AI evasion (Critical) | TC-10, TC-12 |
| C-02 | Display-Name Spoofing Detection | Social engineering (High) | TC-07, TC-14 |
| C-03 | Quarantine Flag | Phishing bypass (Critical) | All Phishing TCs |
| C-04 | CSV Audit Logging | Traceability gap | All 15 TCs |
| C-05 | Expanded Keyword Library | Detection coverage | TC-07,08,09,14 |
| C-06 | Extended URL Pattern Detection | Phishing link delivery | TC-07, TC-12 |

---

## Running the Detector

### Requirements
- Python 3.8+
- No external dependencies (standard library only)

### Run v2 — Current Version (Checkpoint 3/4)
```bash
python src/phishing_detector_v2.py
```

Output is organized into 6 clearly partitioned sections:
- **Section 1** — Regression tests (TC-01 to TC-05, carried from v1)
- **Section 2** — New legitimate email tests (false-positive checks)
- **Section 3** — Display-name spoofing detection (C-02)
- **Section 4** — Obfuscation / evasion detection (C-01)
- **Section 5** — Edge cases (TC-08, TC-09)
- **Section 6** — Validation summary & before/after comparison

The script automatically writes `phishing_log.csv` with a timestamped entry for every email analyzed.

### Run v1 — Baseline (Checkpoint 2)
```bash
python src/phishing_detector.py
```

---

## Scoring System

| Signal | Points |
|---|---|
| Phishing keyword match | +15 per keyword (21 total) |
| Healthcare-specific lure | +10 per lure (15 total) |
| Suspicious sender pattern | +20 |
| Suspicious URL in body | +20 |
| Attachment present | +10 |
| Urgency signal (all-caps subject) | +10 |
| Obfuscation pattern detected (v2) | +15 per pattern |
| Display-name spoofing (v2) | +25 |

---

## Repository Structure

```
CS361/
├── README.md
├── src/
│   ├── phishing_detector.py          # v1 — Checkpoint 2 baseline
│   └── phishing_detector_v2.py       # v2 — Checkpoint 3/4 with all controls
├── data/
│   ├── sample_emails.txt             # 15 labeled emails (phishing + legitimate)
│   └── phishing_log.csv              # Auto-generated audit log from v2 test run
├── docs/
│   ├── diagram.png                   # System architecture diagram
│   └── workflow_diagram.png          # AI detection workflow (trust boundaries)
└── reports/
    ├── Checkpoint2_Final.docx        # CP2 submission
    ├── Checkpoint3_Submission.docx   # CP3 submission
    ├── Final_Report.docx             # CP4 final report (this document)
    └── Final_Slide_Deck.pptx         # CP4 presentation slides
```

---

## Assets Protected

| Asset | Priority | Rationale |
|---|---|---|
| Patient Data (HIPAA) | Critical | Breach = regulatory fines, legal liability |
| Employee Credentials | Critical | Stolen logins enable full account takeover |
| Email Accounts | High | Primary attack surface |
| Email Server | High | Entry point for all external communication |
| AI Detection Model | High | Evasion = total loss of protection layer |
| Internal Network | High | Compromised endpoint → lateral movement |
| Attachments / Links | Medium | Common malware delivery mechanism |
| Employee Trust | Medium | Ignored warnings defeat all technical controls |

---

## Known Residual Risks

| Risk | Residual Score | Notes |
|---|---|---|
| Phishing bypass / AI evasion | 10 | Reduced from 25; novel techniques remain possible |
| Credential theft | 10 | Reduced from 25; domain lookalikes partially covered |
| Malware via attachment | 15 | No deep attachment scanning yet |
| Subdomain TLD spoof (TC-08) | 12 | New — threshold tuning needed |
| Compromised internal account | 10 | Internal spoofing not fully addressed |

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
- Verizon 2024 Data Breach Investigations Report — Healthcare sector phishing statistics
