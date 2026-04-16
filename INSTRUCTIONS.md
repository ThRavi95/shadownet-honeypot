# Project: ShadowNet Enterprise Honeypot
**Goal:** Build a real-time deception, telemetry, detection, and ATT&CK-aligned monitoring platform using our existing Docker/Node foundation.

**Strict Architectural Rules:**
* Never generate fake telemetry, mock background processing, or placeholder dashboard metrics. Everything must be backed by real backend processing.
* All detections and alerts MUST support MITRE ATT&CK mappings (Tactic, Technique, Technique ID).
* Use small, reviewable Git commits at the end of every phase.
* Wait for user confirmation before moving to the next phase.

**Target Monorepo Structure:**
* `/frontend`: React/Next.js live dashboard.
* `/backend`: Node/Express API, WebSocket updates, and ATT&CK mapping logic.
* `/ml-engine`: TensorFlow.js anomaly scoring and classification.
* `/sensors`: Cowrie (SSH), Suricata (IDS), and Envoy proxy configs.

**Execution Phases:**
1. Restructure the current local folder into `/backend`, `/sensors`, and `/ml-engine`.
2. Implement the normalized event schema and MITRE ATT&CK mapping models in the backend.
3. Integrate Suricata and Zeek alongside the existing Cowrie ingestion.
4. Add live APIs and WebSocket event streaming.
5. Build the React dashboard against real endpoints only.
6. Upgrade ML scoring for scan, auth anomaly, and beaconing behaviors.
7. Add validation scripts, end-to-end tests, and deployment instructions.