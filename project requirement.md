# Project Requirements: Internal Network Honeypot System (Docker-Based) – with Reporting

## Version History
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-06-04 | Security Engineering Team | Initial release |

---

## 1. Objective

Deploy a lightweight, scalable honeypot system within a Docker environment to detect unauthorized or suspicious internal activity (e.g., lateral movement, reconnaissance, malware propagation) and **provide actionable reports** to the security team for threat intelligence, incident response, and compliance auditing.

---

## 2. Key Requirements

### 2.1 Functional Requirements

#### Core Honeypot Capabilities
- **Emulated Services** – Simulate common internal services (e.g., SSH, HTTP, SMB, RDP, MySQL, Redis, FTP).
- **Interaction Logging** – Capture full network traffic (source IP, timestamp, protocol, payload, login attempts, commands executed).
- **Alerting** – Generate real-time alerts (e.g., via Slack, email, or SIEM) on suspicious patterns (e.g., brute force, anomalous commands).
- **Low/Medium Interaction** – Prefer medium-interaction honeypots (fake file system, fake credentials) but support low-interaction for high-scale deployment.
- **Deception Tokens** – Deploy fake credentials, configuration files, or database records to lure attackers.
- **Docker Native** – Each honeypot service runs as a separate container; orchestration via Docker Compose or Kubernetes.
- **Centralized Log Management** – All logs aggregated into a single volume or forwarded to a central logging system (e.g., ELK, Loki).
- **Isolation** – Honeypot network segment must be isolated from production (e.g., using Docker macvlan or a dedicated bridge with strict firewall rules).

#### Reporting Capabilities
- **Automated Report Generation** – Generate scheduled (daily, weekly, monthly) and on-demand reports.
- **Report Types**:
  - **Executive Summary** – High-level metrics: total attacks, top attackers, most targeted services, risk trend (graph/chart).
  - **Incident Report** – Detailed timeline of a specific attack: source IP, targeted honeypot, commands entered, files accessed, recommended actions.
  - **Attacker TTP Report** – MITRE ATT&CK mapping of observed behaviors (e.g., T1046 – Network Service Scanning, T1110 – Brute Force).
  - **Compliance Report** – Evidence of detection controls for internal audits (ISO 27001, SOC2, NIST, PCI DSS).
  - **Compromised Internal Host Report** – List of internal IPs that attempted malicious activity (potential patient zero).
  - **False Positive Analysis Report** – Whitelisted IPs vs. true positives.
- **Export Formats** – PDF, JSON, CSV, HTML (email-friendly).
- **Report Distribution** – Automatic email to security team, upload to S3/share drive, or push to SIEM/SOAR.
- **Custom Report Builder** – Allow analysts to filter by date range, source IP, honeypot type, or attack type.
- **Visual Dashboards** – Embedded charts (bar graphs, heatmaps, timeline) in reports showing attack frequency, top 10 attackers, hourly activity.
- **Historical Trends** – Compare attack patterns week-over-week, month-over-month.

### 2.2 Non-Functional Requirements

| Category | Requirement |
|----------|-------------|
| **Memory** | <100 MB RAM per honeypot instance |
| **Scalability** | Deploy 10–100 instances across internal subnets |
| **Isolation** | No production data exposure |
| **Deployment** | Single `docker-compose up` command |
| **Log Retention** | 30 days for forensic analysis and report generation |
| **Report Performance** | Generate 30-day report for 1M log entries within 60 seconds |
| **Storage** | Minimum 50GB persistent volume for logs and reports |

### 2.3 Security Team Use Cases

- Detect internal port scans or brute-force attempts.
- Identify compromised endpoints trying to spread laterally.
- Capture attacker TTPs (tools, commands, lateral movement patterns).
- Provide low-fidelity alerts (avoid false positives that waste analyst time).
- **Generate weekly threat intelligence report for management.**
- **Produce incident timeline for post-mortem or legal review.**
- **Demonstrate compliance with internal security controls during audits.**

---

## 3. Architecture Overview (Docker-Based with Reporting)
