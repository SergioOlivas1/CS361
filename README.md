# CS361
# AI-Assisted Phishing Detection for Healthcare Email Systems

## Overview
This project focuses on developing a basic AI-assisted system to detect phishing emails in a healthcare environment. The goal is to identify suspicious emails before users interact with them, helping reduce the risk of credential theft, malware infection, unauthorized access, and exposure of sensitive patient information.

## Selected Domain
Defensive AI in Cybersecurity (Phishing Email Detection)

## Project Objective
The objective of this project is to design and implement a system that can identify potential phishing emails before users interact with them. By flagging suspicious messages early, the system aims to reduce the risk of compromised accounts, malicious email activity, and unauthorized access within a healthcare organization.

## Problem Statement
Phishing attacks remain one of the most common and effective cybersecurity threats, especially in healthcare environments where employees frequently interact with emails related to patients, billing, scheduling, and external communication. Traditional spam filters may not detect more sophisticated phishing attempts that imitate legitimate messages. This project studies how AI-assisted analysis can support early detection of suspicious emails before they reach or mislead end users.

## Organization / Use Case
This system is designed for a small healthcare clinic. Employees in this environment regularly handle emails that may contain sensitive information or links to internal systems. Because healthcare data is highly sensitive, small clinics are attractive targets for phishing campaigns. The proposed system acts as a basic filtering layer that reviews incoming emails and flags suspicious messages.

## Scope
This project focuses on detection only. The system will analyze email content, sender details, links, and message structure to identify suspicious emails. The scope is intentionally limited to a realistic one-month project timeline.

This project does not include:
- Full enterprise deployment
- Live integration with a real email provider
- Automated blocking or prevention actions
- Advanced production-level model training and optimization

## Main Assets to Protect
- Patient data (health records and personal information)
- Employee login credentials
- Employee email accounts
- Internal systems and network access

### Highest Priority Assets
1. Patient data
2. Employee login credentials
3. Internal systems and network access

## Initial Threat Assumptions
- Attackers may send phishing emails disguised as healthcare-related communication
- Employees may accidentally interact with malicious links or attachments
- Some phishing attempts may try to steal user credentials through fake login pages
- Malicious attachments may be used to deliver malware
- Compromised credentials may lead to unauthorized access to internal systems

## Initial Threat List
- Phishing emails
- Credential harvesting
- Malware attachments
- Social engineering
- Unauthorized access

## System Flow
Incoming Email → Preprocessing → Feature Extraction → AI Detection Model → Risk Scoring → Classification → User Notification

## Team Members and Roles
- Sergio Olivas — Project Lead / Research
- Khumbo Nyirenda — Data Collection
- Cerilo Yousif — Development
- Ernest Apollon — Development
- Victor Olatunji — Documentation

## Repository Structure
- `README.md` — project overview and scope
- `docs/` — diagrams, charter, and supporting documentation
- `src/` — project code and implementation files
- `data/` — sample or training data if used

## Initial Diagram
The project includes an initial system diagram showing the flow of an email through preprocessing, analysis, AI-assisted detection, and final classification.

## Future Improvements
- Improve detection accuracy with a larger dataset
- Add stronger feature extraction for links, headers, and sender behavior
- Integrate with a simulated email environment
- Expand the system to support alerting or quarantine workflows

## System Architecture
![System Diagram](docs/diagram.png)
