🛡️ Quantra Correlate
AI-Powered Financial Fraud Detection & Cyber Intelligence Platform

Detect. Correlate. Investigate. Prevent.

Quantra Correlate is an advanced financial fraud detection and cyber intelligence platform designed to identify suspicious financial behavior across transactions, sessions, devices, accounts, and user activity.

Unlike traditional fraud detection systems that analyze transactions in isolation, Quantra Correlate connects multiple security signals together to identify complex and evolving fraud patterns.

🚨 The Problem

Modern financial fraud is no longer limited to a single suspicious transaction.

Attackers can:

Steal an active session
Use valid credentials from multiple accounts
Perform automated login attempts
Split large transactions into smaller amounts
Move money through multiple accounts
Abuse privileged access
Use legitimate devices and credentials to bypass traditional security systems

For example, a fraudster may avoid detection by sending:

₹5,000 → ₹5,000 → ₹10,000 → ₹15,000

Instead of sending one suspicious:

₹35,000

A traditional system may analyze each transaction separately.

Quantra Correlate analyzes the complete behavioral and transaction context.

💡 Our Solution

Quantra Correlate combines:

Transactions
     +
Sessions
     +
Devices
     +
IP Addresses
     +
Geolocation
     +
Behavior
     +
Account Relationships
     +
Security Events
     ↓
Unified Fraud Intelligence

The platform continuously correlates multiple signals to determine whether activity is:

Normal
Suspicious
High Risk
Fraudulent
🔐 Core Fraud Detection Capabilities
1. Account Takeover (ATO) Prevention

Detects suspicious activity when an attacker gains access to an existing user session or account.

The system compares:

Active Session ID
Device Fingerprint
IP Address
Geolocation
Browser Information
Login Behavior
Session Activity
Example
Legitimate User
       ↓
Active Session
       ↓
Attacker reuses same session
       ↓
Different Device
Different IP
Different Location
       ↓
ATO Detection
       ↓
Real User Verification
       ↓
Transaction Approved / Blocked

For high-risk transactions, the legitimate user can be asked:

"Are you trying to make this transaction?"

The transaction proceeds only when the required verification is successfully completed.

2. Credential Stuffing Detection

Detects automated attacks where stolen username-password combinations are tested across multiple accounts.

Detection Signals
Multiple failed login attempts
Multiple accounts targeted
Common suspicious IP addresses
Similar device fingerprints
Automated login patterns
Unusual geographic behavior
Flow
Multiple Login Attempts
          ↓
Pattern Correlation
          ↓
Suspicious IP / Device Detection
          ↓
Credential Stuffing Identified
          ↓
Account Protection
3. Insider Threat Detection

Identifies abnormal activity from users who already have legitimate access.

The system analyzes behavioral deviations such as:

Unusual login times
Abnormal transaction activity
Access to unusual data
Suspicious device activity
Abnormal location
Excessive access attempts
Unusual changes from historical behavior

A valid account does not automatically mean valid behavior.

4. Money Mule Network Detection

Fraudulent funds often move through multiple accounts to hide their original source.

Quantra Correlate uses transaction relationships to identify suspicious money-flow networks.

Example
Account A
    │ ₹50,000
    ▼
Account B
    │ ₹45,000
    ▼
Account C
    │ ₹40,000
    ▼
Account D

The platform visualizes these relationships through an interactive money-flow graph.

This helps investigators identify:

Suspicious receivers
Rapid fund movement
Connected accounts
Repeated transaction paths
Potential mule accounts
Multi-hop money movement
📊 Behavioral Profiling

Every user has a normal behavioral pattern.

Quantra Correlate can compare current activity against historical behavior.

Example
Historical Average Transaction: ₹5,000

Current Activity:
₹5,000
₹7,000
₹10,000
₹15,000
₹20,000

The system analyzes:

Amount deviation
Transaction frequency
Cumulative amount
Receiver behavior
Transaction timing
Session behavior

This enables detection of transaction splitting and layered fraud patterns.

🎯 Dynamic Fraud Risk Scoring

The platform continuously calculates a risk score based on multiple signals.

Transaction Risk
        +
Behavioral Deviation
        +
Session Risk
        +
Device Risk
        +
IP Risk
        +
Location Risk
        +
Receiver Risk
        ↓
Dynamic Risk Score

Example:

0 – 30     LOW RISK
31 – 70    MEDIUM RISK
71 – 100   HIGH RISK

The risk score is dynamically updated as new events occur.

🔗 Multi-Source Event Correlation

Instead of analyzing individual events independently:

Transaction
Session
Device
IP
Location
Login
Receiver
Behavior

Quantra Correlate combines them into a unified investigation context.

Example
Normal Transaction
        +
New Device
        +
New IP
        +
Unusual Location
        +
Abnormal Amount
        +
New Receiver
        ↓
HIGH-RISK BEHAVIOR

This correlation-based approach enables detection of complex attacks that may appear normal when individual events are analyzed separately.

👨‍💻 Cyber Analyst Portal

The analyst can investigate an account using:

Account Number
User ID
Email Address

The system generates a structured investigation view containing:

User information
Session activity
Transaction history
Behavioral analysis
Risk assessment
Connected accounts
Money-flow relationships
Security events

The goal is to provide investigators with one unified view of the complete threat context.

💸 Interactive Money Flow Graph

The system dynamically visualizes transactions from the database.

Example:

Hariharan
    │ ₹1,000
    ▼
Dev
    │ ₹10
    ▼
Suhail

The graph can be filtered by time:

Last 1 hour
Last 10 hours
Last 24 hours
Custom time range

The graph is dynamically updated using real transaction data.

📄 Audit-Ready Investigation Reports

Investigators can generate structured reports containing:

Subject identification
Transaction history
Session analysis
Behavioral anomalies
Risk signals
Connected accounts
Money-flow relationships
Investigation findings
Final risk assessment

Reports can be exported as PDF investigation documents for audit and review purposes.

🧠 Key Differentiators
Multi-Source Event Correlation
Behavioral Profiling & Adaptive Baselines
Dynamic Fraud Risk Scoring
Account Takeover Prevention
Multi-Session Transaction Verification
Credential Stuffing Detection
Insider Threat Detection
Interactive Money Mule Network Graph
Transaction Splitting Detection
Audit-Ready Investigation Reports
PDF Investigation Export
🏗️ System Architecture
┌──────────────────────────────┐
│        Banking User          │
│                              │
│  Login • Transactions        │
│  Sessions • Device Activity  │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│       Event Collection       │
│                              │
│ Transactions                 │
│ Sessions                     │
│ Telemetry                    │
│ Login Events                 │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│   Correlation & Analysis     │
│                              │
│ Behavioral Analysis          │
│ Session Analysis             │
│ Risk Scoring                 │
│ Network Analysis             │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│      Fraud Detection         │
│                              │
│ ATO                          │
│ Credential Stuffing          │
│ Insider Threat               │
│ Money Mule                   │
│ Transaction Splitting        │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│      Analyst Intelligence    │
│                              │
│ Investigation                │
│ Risk Decision                │
│ Money Flow Graph             │
│ PDF Report                   │
└──────────────────────────────┘
🗄️ Data Model

The platform is designed around structured security and financial data.

Core entities include:

Users
  │
  ├── Sessions
  │
  ├── Transactions
  │
  ├── Telemetry Events
  │
  ├── Risk Decisions
  │
  └── Behavioral Baselines

This allows the system to correlate:

User
 → Session
 → Device
 → IP
 → Transaction
 → Receiver
 → Risk Decision
🛠️ Technology Stack
Frontend
Next.js
React
JavaScript
HTML
CSS
Backend
Node.js
Express.js
REST APIs
Database
Supabase
PostgreSQL
Data Visualization
Interactive transaction graphs
Risk visualizations
Behavioral analytics
Timeline-based activity analysis
Reporting
PDF investigation reports
🔄 Complete Detection Workflow
1. User logs in
        ↓
2. Session is created
        ↓
3. User performs activity
        ↓
4. System collects events
        ↓
5. Events are correlated
        ↓
6. Behavior is compared with baseline
        ↓
7. Risk score is calculated
        ↓
8. Suspicious patterns are detected
        ↓
9. Transaction is monitored / verified / blocked
        ↓
10. Analyst investigates the activity
        ↓
11. Money flow is visualized
        ↓
12. Investigation report is generated
🎯 Project Objective

The objective of Quantra Correlate is to move financial fraud detection from:

Detecting Individual Suspicious Transactions

to:

Understanding Complete Fraud Behavior

By combining transaction intelligence, session intelligence, behavioral analytics, identity verification, and network analysis, the platform provides a unified approach to detecting and preventing modern financial fraud.
