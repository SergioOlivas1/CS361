"""
AI-Assisted Phishing Detection System
CS361 - Healthcare Email Security Project
Team: Sergio Olivas, Khumbo Nyirenda, Cerilo Yousif, Ernest Apollon, Victor Olatunji

This module implements a keyword and feature-based phishing detection system
designed for a healthcare clinic email environment.
"""

import re
from dataclasses import dataclass
from typing import List, Tuple


# ─────────────────────────────────────────────
#  Feature Definitions
# ─────────────────────────────────────────────

# High-risk keywords commonly found in phishing emails
PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "click here immediately",
    "account suspended", "urgent action required", "your password has expired",
    "update your billing", "unauthorized access detected", "validate your credentials",
    "reset your password now", "security alert", "account will be closed",
    "login attempt", "suspicious activity", "immediate response required",
]

# Healthcare-specific phishing lures
HEALTHCARE_LURES = [
    "patient portal", "hipaa compliance required", "insurance verification",
    "medical records update", "billing statement", "claim denied",
    "appointment confirmation required", "prescription refill",
]

# Suspicious sender patterns
SUSPICIOUS_SENDER_PATTERNS = [
    r"no[-_]?reply@(?!yourclinic\.org)",          # no-reply from unknown domains
    r"support@(?!yourclinic\.org|microsoft\.com)", # fake support addresses
    r"\d{4,}@",                                    # numeric usernames
    r"@.+\.(xyz|top|click|tk|ml|ga|cf)$",         # shady TLDs
]

# Suspicious URL patterns in email body
SUSPICIOUS_URL_PATTERNS = [
    r"http://",                          # non-HTTPS links
    r"bit\.ly|tinyurl|t\.co|ow\.ly",    # URL shorteners
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP address links
    r"@.+\.com",                         # @ in URL (redirect trick)
]


# ─────────────────────────────────────────────
#  Data Model
# ─────────────────────────────────────────────

@dataclass
class Email:
    sender: str
    subject: str
    body: str
    has_attachment: bool = False

@dataclass
class DetectionResult:
    classification: str       # "Safe", "Suspicious", or "Phishing"
    risk_score: int           # 0–100
    triggered_flags: List[str]
    recommended_action: str


# ─────────────────────────────────────────────
#  Detection Engine
# ─────────────────────────────────────────────

def analyze_email(email: Email) -> DetectionResult:
    """
    Analyzes an email and returns a risk classification.

    Scoring:
      - Each phishing keyword:        +15 points
      - Each healthcare lure:         +10 points
      - Suspicious sender pattern:    +20 points
      - Suspicious URL:               +20 points
      - Attachment present:           +10 points
      - Urgent/all-caps subject:      +10 points

    Risk Levels:
      0–29   → Safe
      30–59  → Suspicious
      60+    → Phishing
    """
    score = 0
    flags = []
    combined_text = (email.subject + " " + email.body).lower()

    # Check phishing keywords
    for keyword in PHISHING_KEYWORDS:
        if keyword in combined_text:
            score += 15
            flags.append(f"Phishing keyword detected: '{keyword}'")

    # Check healthcare-specific lures
    for lure in HEALTHCARE_LURES:
        if lure in combined_text:
            score += 10
            flags.append(f"Healthcare lure detected: '{lure}'")

    # Check suspicious sender
    for pattern in SUSPICIOUS_SENDER_PATTERNS:
        if re.search(pattern, email.sender, re.IGNORECASE):
            score += 20
            flags.append(f"Suspicious sender pattern: {email.sender}")
            break

    # Check suspicious URLs in body
    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, email.body, re.IGNORECASE):
            score += 20
            flags.append(f"Suspicious URL pattern detected in body")
            break

    # Attachment risk
    if email.has_attachment:
        score += 10
        flags.append("Email contains attachment")

    # Urgency in subject (all caps words)
    caps_words = len(re.findall(r'\b[A-Z]{4,}\b', email.subject))
    if caps_words >= 2:
        score += 10
        flags.append(f"High urgency detected in subject ({caps_words} all-caps words)")

    # Cap score at 100
    score = min(score, 100)

    # Classify
    if score < 30:
        classification = "Safe"
        action = "Deliver to inbox."
    elif score < 60:
        classification = "Suspicious"
        action = "Warn user before opening. Flag for IT review."
    else:
        classification = "Phishing"
        action = "Quarantine immediately. Do not deliver."

    return DetectionResult(
        classification=classification,
        risk_score=score,
        triggered_flags=flags,
        recommended_action=action,
    )


def print_result(email: Email, result: DetectionResult):
    print(f"\n{'='*55}")
    print(f"  FROM   : {email.sender}")
    print(f"  SUBJECT: {email.subject}")
    print(f"{'='*55}")
    print(f"  CLASSIFICATION : {result.classification}")
    print(f"  RISK SCORE     : {result.risk_score}/100")
    print(f"  ACTION         : {result.recommended_action}")
    if result.triggered_flags:
        print(f"  FLAGS:")
        for flag in result.triggered_flags:
            print(f"    - {flag}")
    print()


# ─────────────────────────────────────────────
#  Test Cases
# ─────────────────────────────────────────────

TEST_EMAILS = [
    Email(
        sender="billing@yourclinic.org",
        subject="Your appointment is confirmed for Tuesday",
        body="Hello, your appointment with Dr. Smith is confirmed for Tuesday at 2pm. Please call us if you need to reschedule.",
        has_attachment=False,
    ),
    Email(
        sender="no-reply@medicarе-update.xyz",
        subject="URGENT: Patient portal access will be SUSPENDED",
        body="Your patient portal account requires immediate verification. Click here to confirm your identity: http://bit.ly/verify-now. Failure to act will result in account closure.",
        has_attachment=False,
    ),
    Email(
        sender="support@insurance-verify.click",
        subject="Insurance Verification Required",
        body="Please update your billing information to avoid claim denial. Validate your credentials at http://192.168.1.1/login",
        has_attachment=True,
    ),
    Email(
        sender="hr@yourclinic.org",
        subject="Staff meeting notes attached",
        body="Please find the notes from today's staff meeting attached. Let me know if you have any questions.",
        has_attachment=True,
    ),
    Email(
        sender="noreply@123456789@mail.com",
        subject="Security Alert: Suspicious activity on your account",
        body="We detected unauthorized access to your account. Immediate response required. Reset your password now.",
        has_attachment=False,
    ),
]


if __name__ == "__main__":
    print("\n╔══════════════════════════════════════════════════════╗")
    print("║   AI-Assisted Phishing Detection System — CS361     ║")
    print("║   Healthcare Clinic Email Environment                ║")
    print("╚══════════════════════════════════════════════════════╝")

    for email in TEST_EMAILS:
        result = analyze_email(email)
        print_result(email, result)
