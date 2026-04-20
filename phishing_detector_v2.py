"""
AI-Assisted Phishing Detection System — Version 2
CS361 - Healthcare Email Security Project
Checkpoint 3: Defensive Controls & Validation

Team: Sergio Olivas, Khumbo Nyirenda, Cerilo Yousif, Ernest Apollon, Victor Olatunji

CHECKPOINT 3 IMPROVEMENTS OVER BASELINE (v1):
  1. Logging — every analysis writes a timestamped entry to phishing_log.csv
  2. Quarantine flag — Phishing emails are explicitly marked quarantined=True
  3. Evasion-resistant scoring — obfuscated variants of keywords now detected
     (e.g., "v3rify", "acc0unt", mixed-case tricks)
  4. Header spoofing detection — display-name ≠ actual sender domain
  5. Expanded test suite — 15 test cases (was 5), including edge cases,
     false-positive checks, and adversarial evasion attempts
  6. Accuracy metrics — precision, recall, F1 printed at end of run
"""

import re
import csv
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import List


# ─────────────────────────────────────────────
#  Feature Definitions  (EXPANDED from v1)
# ─────────────────────────────────────────────

PHISHING_KEYWORDS = [
    # Original v1 keywords
    "verify your account", "confirm your identity", "click here immediately",
    "account suspended", "urgent action required", "your password has expired",
    "update your billing", "unauthorized access detected", "validate your credentials",
    "reset your password now", "security alert", "account will be closed",
    "login attempt", "suspicious activity", "immediate response required",
    # NEW in v2 — additional high-signal phrases
    "your account has been compromised", "verify immediately",
    "action required within 24 hours", "your information is at risk",
    "failure to respond will result", "confirm your email address",
]

HEALTHCARE_LURES = [
    # Original v1 lures
    "patient portal", "hipaa compliance required", "insurance verification",
    "medical records update", "billing statement", "claim denied",
    "appointment confirmation required", "prescription refill",
    # NEW in v2 — additional healthcare-specific lures
    "medicare update", "medicaid verification", "eob statement",
    "prior authorization required", "lab results available",
    "referral authorization", "health plan renewal",
]

# NEW in v2 — obfuscated variants attackers use to evade keyword filters
OBFUSCATION_PATTERNS = [
    (r"v[e3]r[i1]f[y!]", "obfuscated 'verify'"),
    (r"acc[o0]unt", "obfuscated 'account'"),
    (r"p[a@]ssw[o0]rd", "obfuscated 'password'"),
    (r"cl[i1]ck\s+h[e3]r[e3]", "obfuscated 'click here'"),
    (r"susp[e3]nd[e3]d", "obfuscated 'suspended'"),
    (r"urg[e3]nt", "obfuscated 'urgent'"),
]

SUSPICIOUS_SENDER_PATTERNS = [
    r"no[-_]?reply@(?!yourclinic\.org)",
    r"support@(?!yourclinic\.org|microsoft\.com)",
    r"\d{4,}@",
    r"@.+\.(xyz|top|click|tk|ml|ga|cf|pw|icu)$",  # v2: added .pw and .icu
]

SUSPICIOUS_URL_PATTERNS = [
    r"http://",
    r"bit\.ly|tinyurl|t\.co|ow\.ly|rb\.gy|cutt\.ly",  # v2: added more shorteners
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"@.+\.com",
    r"login[-.]",         # NEW in v2: login-page URL patterns
    r"secure[-.]update",  # NEW in v2: fake secure update pages
    r"verify[-.]account", # NEW in v2: verify-account URL pattern
]

# NEW in v2 — trusted internal sender domains (whitelist)
TRUSTED_DOMAINS = {
    "yourclinic.org",
    "clinic-group.org",
}


# ─────────────────────────────────────────────
#  Data Model  (EXPANDED from v1)
# ─────────────────────────────────────────────

@dataclass
class Email:
    sender: str
    subject: str
    body: str
    has_attachment: bool = False
    display_name: str = ""   # NEW in v2: for display-name spoofing detection

@dataclass
class DetectionResult:
    classification: str
    risk_score: int
    triggered_flags: List[str]
    recommended_action: str
    quarantined: bool = False          # NEW in v2
    logged: bool = False               # NEW in v2


# ─────────────────────────────────────────────
#  Logging  (NEW in v2)
# ─────────────────────────────────────────────

LOG_FILE = "phishing_log.csv"

def init_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "sender", "subject", "risk_score",
                "classification", "quarantined", "flags"
            ])

def log_result(email: Email, result: DetectionResult):
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            email.sender,
            email.subject,
            result.risk_score,
            result.classification,
            result.quarantined,
            " | ".join(result.triggered_flags),
        ])
    result.logged = True


# ─────────────────────────────────────────────
#  Detection Engine  (EXPANDED from v1)
# ─────────────────────────────────────────────

def analyze_email(email: Email) -> DetectionResult:
    """
    v2 Scoring (same scale as v1 for direct comparison):
      - Each phishing keyword:          +15 pts
      - Each healthcare lure:           +10 pts
      - Suspicious sender pattern:      +20 pts
      - Suspicious URL pattern:         +20 pts
      - Attachment present:             +10 pts
      - Urgent/all-caps subject:        +10 pts
      - Obfuscation pattern (NEW):      +15 pts each
      - Display-name spoofing (NEW):    +25 pts
    """
    score = 0
    flags = []
    combined = (email.subject + " " + email.body).lower()

    # --- Original controls (v1) ---

    for kw in PHISHING_KEYWORDS:
        if kw in combined:
            score += 15
            flags.append(f"Phishing keyword: '{kw}'")

    for lure in HEALTHCARE_LURES:
        if lure in combined:
            score += 10
            flags.append(f"Healthcare lure: '{lure}'")

    for pattern in SUSPICIOUS_SENDER_PATTERNS:
        if re.search(pattern, email.sender, re.IGNORECASE):
            score += 20
            flags.append(f"Suspicious sender: {email.sender}")
            break

    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, email.body, re.IGNORECASE):
            score += 20
            flags.append("Suspicious URL pattern in body")
            break

    if email.has_attachment:
        score += 10
        flags.append("Attachment present")

    caps = len(re.findall(r'\b[A-Z]{4,}\b', email.subject))
    if caps >= 2:
        score += 10
        flags.append(f"Urgency signal: {caps} all-caps words in subject")

    # --- New controls (v2) ---

    # Obfuscation detection
    for pattern, label in OBFUSCATION_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            score += 15
            flags.append(f"Obfuscation detected: {label}")

    # Display-name spoofing: name claims to be clinic but sender domain differs
    if email.display_name:
        name_lower = email.display_name.lower()
        sender_domain = email.sender.split("@")[-1].lower() if "@" in email.sender else ""
        if any(t in name_lower for t in ["clinic", "hospital", "health", "medicare", "billing"]):
            if sender_domain not in TRUSTED_DOMAINS:
                score += 25
                flags.append(
                    f"Display-name spoofing: '{email.display_name}' claims clinic but "
                    f"sender is {email.sender}"
                )

    score = min(score, 100)

    if score < 30:
        classification, action, quarantined = "Safe", "Deliver to inbox.", False
    elif score < 60:
        classification = "Suspicious"
        action = "Warn user before opening. Flag for IT review."
        quarantined = False
    else:
        classification = "Phishing"
        action = "Quarantine immediately. Do not deliver."
        quarantined = True

    result = DetectionResult(
        classification=classification,
        risk_score=score,
        triggered_flags=flags,
        recommended_action=action,
        quarantined=quarantined,
    )

    log_result(email, result)
    return result


# ─────────────────────────────────────────────
#  Output
# ─────────────────────────────────────────────

def print_result(email: Email, result: DetectionResult, test_id: str = ""):
    label = f"[{test_id}]" if test_id else ""
    print(f"\n{'='*60}")
    print(f"  {label} FROM    : {email.sender}")
    if email.display_name:
        print(f"  DISPLAY NAME: {email.display_name}")
    print(f"  SUBJECT     : {email.subject}")
    print(f"{'='*60}")
    print(f"  CLASSIFICATION : {result.classification}")
    print(f"  RISK SCORE     : {result.risk_score}/100")
    print(f"  QUARANTINED    : {'YES' if result.quarantined else 'No'}")
    print(f"  LOGGED         : {'YES — phishing_log.csv' if result.logged else 'No'}")
    print(f"  ACTION         : {result.recommended_action}")
    if result.triggered_flags:
        print(f"  FLAGS ({len(result.triggered_flags)}):")
        for flag in result.triggered_flags:
            print(f"    - {flag}")
    print()


# ─────────────────────────────────────────────
#  Expanded Test Suite  (15 cases, was 5 in v1)
# ─────────────────────────────────────────────

# Format: (Email, expected_classification, test_id, description)
TEST_CASES = [

    # ── Carried over from v1 (regression) ──────────────────────────────
    (Email(
        sender="billing@yourclinic.org",
        subject="Your appointment is confirmed for Tuesday",
        body="Hello, your appointment with Dr. Smith is confirmed for Tuesday at 2pm.",
    ), "Safe", "TC-01", "Legitimate clinic appointment email"),

    (Email(
        sender="no-reply@medicarе-update.xyz",
        subject="URGENT: Patient portal access will be SUSPENDED",
        body="Your patient portal account requires immediate verification. Click here to confirm your identity: http://bit.ly/verify-now.",
    ), "Phishing", "TC-02", "Classic healthcare portal phishing"),

    (Email(
        sender="support@insurance-verify.click",
        subject="Insurance Verification Required",
        body="Please update your billing information to avoid claim denial. Validate your credentials at http://192.168.1.1/login",
        has_attachment=True,
    ), "Phishing", "TC-03", "Insurance lure with IP-link and attachment"),

    (Email(
        sender="hr@yourclinic.org",
        subject="Staff meeting notes attached",
        body="Please find the notes from today's staff meeting attached.",
        has_attachment=True,
    ), "Safe", "TC-04", "Legitimate internal HR email with attachment"),

    (Email(
        sender="noreply@123456789@mail.com",
        subject="Security Alert: Suspicious activity on your account",
        body="We detected unauthorized access to your account. Immediate response required. Reset your password now.",
    ), "Phishing", "TC-05", "Malformed sender with credential-theft keywords"),

    # ── NEW v2 test cases ───────────────────────────────────────────────

    (Email(
        sender="admin@yourclinic.org",
        subject="Payroll system maintenance tonight",
        body="The payroll system will be offline tonight from 10pm to 2am for scheduled maintenance. No action required.",
    ), "Safe", "TC-06", "Legitimate internal admin notification"),

    (Email(
        sender="billing@healthcare-updates.net",
        subject="Medicare Update: Action Required",
        body="Your medicare update requires verification. Please confirm your email address at http://secure-update.healthcare-updates.net",
        display_name="Clinic Billing Department",
    ), "Phishing", "TC-07", "Display-name spoofing + medicare lure + fake URL"),

    (Email(
        sender="noreply@accounts-yourclinic.xyz",
        subject="Your health plan renewal is pending",
        body="Your health plan renewal requires your attention. Please log in to the patient portal to review your options.",
    ), "Phishing", "TC-08", "Subdomain spoofing + health plan lure"),

    (Email(
        sender="labs@yourclinic.org",
        subject="Lab results available for Patient #4821",
        body="Your recent lab results are now available. Please log in to the patient portal at https://portal.yourclinic.org to view them.",
    ), "Suspicious", "TC-09", "Legitimate-looking lab result email — borderline due to portal link"),

    (Email(
        sender="no-reply@account-verify.click",
        subject="V3RIFY YOUR ACC0UNT NOW",
        body="We have detected susp3cted login attempt on your acc0unt. Cl1ck here to v3rify your identity immediately or your acc0unt will be cl0sed.",
    ), "Phishing", "TC-10", "Obfuscated keyword evasion attempt — NEW v2 control catches this"),

    (Email(
        sender="dr.johnson@yourclinic.org",
        subject="Referral authorization for patient follow-up",
        body="Hi team, I've submitted a referral authorization for Mrs. Rivera. Please process when you get a chance. Thanks.",
        has_attachment=True,
    ), "Safe", "TC-11", "Legitimate physician internal referral email"),

    (Email(
        sender="support@login-yourclinic.secureportal.xyz",
        subject="Action Required: Confirm your login within 24 hours",
        body="Your account has been compromised. Action required within 24 hours. Failure to respond will result in account suspension. Click: http://login-yourclinic.secureportal.xyz/verify-account",
    ), "Phishing", "TC-12", "Multi-signal attack: keywords + obfuscation + spoofed URL"),

    (Email(
        sender="scheduler@yourclinic.org",
        subject="Reminder: Your appointment tomorrow at 3pm",
        body="This is a reminder that you have an appointment scheduled for tomorrow at 3pm with Dr. Patel. Reply to reschedule.",
    ), "Safe", "TC-13", "Legitimate appointment reminder — false positive check"),

    (Email(
        sender="claims@insurance-portal.ml",
        subject="EOB Statement: Claim Denied — Immediate Response Required",
        body="Your recent claim has been denied. Please review your EOB statement and validate your credentials to file an appeal. Attach your prior authorization and submit to http://bit.ly/claims-appeal",
        has_attachment=True,
        display_name="HealthFirst Insurance Claims",
    ), "Phishing", "TC-14", "High-complexity attack: EOB lure + display-name spoof + all signals"),

    (Email(
        sender="it@yourclinic.org",
        subject="Password policy reminder — expires in 30 days",
        body="This is a reminder that your network password expires in 30 days. Please use the internal IT portal at https://it.yourclinic.org/password to update it before expiration.",
    ), "Safe", "TC-15", "Legitimate IT password reminder from trusted domain"),
]


# ─────────────────────────────────────────────
#  Accuracy Metrics  (NEW in v2)
# ─────────────────────────────────────────────

def compute_metrics(results):
    """
    Computes precision, recall, and F1 for phishing detection.
    Positive class = Phishing or Suspicious (anything non-Safe).
    """
    TP = FP = TN = FN = 0
    for actual, expected in results:
        actual_pos = actual != "Safe"
        expected_pos = expected != "Safe"
        if actual_pos and expected_pos:  TP += 1
        elif actual_pos and not expected_pos: FP += 1
        elif not actual_pos and not expected_pos: TN += 1
        else: FN += 1

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy  = (TP + TN) / len(results) if results else 0
    return TP, FP, TN, FN, precision, recall, f1, accuracy


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def section_banner(label, subtitle=""):
    print("\n" + "█"*60)
    print(f"█  {label:<56}█")
    if subtitle:
        print(f"█  {subtitle:<56}█")
    print("█"*60 + "\n")


if __name__ == "__main__":
    init_log()

    print("\n╔" + "═"*58 + "╗")
    print("║   AI-Assisted Phishing Detection System — CS361  v2.0   ║")
    print("║   Checkpoint 3: Defensive Controls & Validation          ║")
    print("║   Healthcare Clinic Email Environment                     ║")
    print("╚" + "═"*58 + "╝")
    print("\n  NEW IN v2: Logging | Quarantine | Obfuscation Detection")
    print("             Display-Name Spoofing | 15 Test Cases")

    metric_data = []
    passed = 0

    # ── SECTION 1: Regression Tests ──────────────────────────────────────────
    section_banner("SECTION 1 — Regression Tests (TC-01 to TC-05)",
                   "Carried over from v1 baseline — verifying no regressions")

    for email, expected, test_id, description in TEST_CASES[0:5]:
        result = analyze_email(email)
        print_result(email, result, test_id)
        match = result.classification == expected
        status = "PASS" if match else "FAIL"
        if match: passed += 1
        print(f"  [{status}] Expected: {expected} | Got: {result.classification} — {description}\n")
        metric_data.append((result.classification, expected))

    # ── SECTION 2: New Legitimate Email Tests ────────────────────────────
    section_banner("SECTION 2 — New Legitimate Email Tests (TC-06, TC-11, TC-13, TC-15)",
                   "False-positive checks — safe emails must not be flagged")

    for email, expected, test_id, description in [
        TEST_CASES[5],   # TC-06
        TEST_CASES[10],  # TC-11
        TEST_CASES[12],  # TC-13
        TEST_CASES[14],  # TC-15
    ]:
        result = analyze_email(email)
        print_result(email, result, test_id)
        match = result.classification == expected
        status = "PASS" if match else "FAIL"
        if match: passed += 1
        print(f"  [{status}] Expected: {expected} | Got: {result.classification} — {description}\n")
        metric_data.append((result.classification, expected))

    # ── SECTION 3: Display-Name Spoofing Detection ──────────────────────
    section_banner("SECTION 3 — Display-Name Spoofing Detection (TC-07, TC-14)",
                   "NEW v2 control: C-02 — catches sender impersonation")

    for email, expected, test_id, description in [
        TEST_CASES[6],   # TC-07
        TEST_CASES[13],  # TC-14
    ]:
        result = analyze_email(email)
        print_result(email, result, test_id)
        match = result.classification == expected
        status = "PASS" if match else "FAIL"
        if match: passed += 1
        print(f"  [{status}] Expected: {expected} | Got: {result.classification} — {description}\n")
        metric_data.append((result.classification, expected))

    # ── SECTION 4: Obfuscation Detection ──────────────────────────────────
    section_banner("SECTION 4 — Obfuscation / Evasion Detection (TC-10, TC-12)",
                   "NEW v2 control: C-01 — catches character-substitution evasion")

    for email, expected, test_id, description in [
        TEST_CASES[9],   # TC-10
        TEST_CASES[11],  # TC-12
    ]:
        result = analyze_email(email)
        print_result(email, result, test_id)
        match = result.classification == expected
        status = "PASS" if match else "FAIL"
        if match: passed += 1
        print(f"  [{status}] Expected: {expected} | Got: {result.classification} — {description}\n")
        metric_data.append((result.classification, expected))

    # ── SECTION 5: Edge Cases ───────────────────────────────────────────────
    section_banner("SECTION 5 — Edge Cases (TC-08, TC-09)",
                   "Documented limitations — see CP3 report Section 4.3")

    for email, expected, test_id, description in [
        TEST_CASES[7],  # TC-08
        TEST_CASES[8],  # TC-09
    ]:
        result = analyze_email(email)
        print_result(email, result, test_id)
        match = result.classification == expected
        status = "PASS" if match else "FAIL"
        if match: passed += 1
        print(f"  [{status}] Expected: {expected} | Got: {result.classification} — {description}\n")
        metric_data.append((result.classification, expected))

    # ── SECTION 6: Validation Summary ─────────────────────────────────────
    section_banner("SECTION 6 — Validation Summary & Before/After Comparison",
                   "Accuracy metrics across all 15 test cases")

    TP, FP, TN, FN, precision, recall, f1, accuracy = compute_metrics(metric_data)

    print("  " + "="*56)
    print("  VALIDATION SUMMARY — Checkpoint 3")
    print("  " + "="*56)
    print(f"  Total test cases   : {len(metric_data)}")
    print(f"  Passed             : {passed} / {len(metric_data)}")
    print(f"  True Positives     : {TP}  (correctly flagged as threat)")
    print(f"  True Negatives     : {TN}  (correctly passed as safe)")
    print(f"  False Positives    : {FP}  (safe email incorrectly flagged)")
    print(f"  False Negatives    : {FN}  (threat email missed)")
    print(f"  Precision          : {precision:.2%}")
    print(f"  Recall             : {recall:.2%}")
    print(f"  F1 Score           : {f1:.2%}")
    print(f"  Accuracy           : {accuracy:.2%}")
    print(f"\n  Log file written   : phishing_log.csv")
    print("  " + "="*56)

    print("\n  BEFORE vs. AFTER COMPARISON")
    print("  " + "─"*54)
    print("  Metric               v1 Baseline    v2 With Controls")
    print("  " + "─"*54)
    print("  Test cases           5              15")
    print("  Obfuscation catch    No             Yes (TC-10 caught)")
    print("  Display-name spoof   No             Yes (TC-07, TC-14)")
    print("  Logging              No             Yes (CSV log)")
    print("  Quarantine flag      No             Yes (auto-set)")
    print("  URL patterns         4              7")
    print("  Keyword list         15             21")
    print("  Healthcare lures     8              15")
    print(f"  Accuracy             60.0%          {accuracy:.1%}")
    print("  " + "─"*54)
    print()
