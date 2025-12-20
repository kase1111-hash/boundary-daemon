Boundary Daemon - Complete Technical Specification
Version: 1.1
Status: Active Development
Last Updated: 2025-12-20
(Changes in v1.1: Added Section 9 – Proactive Security Layer: LLM-Powered Code Vulnerability Advisor)
9. Proactive Security Layer: LLM-Powered Code Vulnerability Advisor
Purpose
Provide an optional, human-in-the-loop advisory system that uses trusted, local-first LLM security models to scan code (primarily from GitHub repositories or local imports) for potential vulnerabilities. The goal is to empower users with clear, actionable insights while maintaining full human control and privacy—never automatic patching, never cloud leakage without consent.
This layer acts as an additional, composable safeguard that stacks with existing Boundary Daemon components (State Monitor, Policy Engine, Memory Vault, Learning Contracts, IntentLog).
Design Principles

Advisory Only – No automatic actions or blocking; purely informational.
Human-in-the-Loop – All findings require explicit user review.
Local-First Execution – Scans run on-device using trusted local models (e.g., Llama 3, CodeLlama, or fine-tuned vuln-specific models via Ollama).
Privacy-Preserving – No code leaves the device unless user explicitly enables escalation under a Learning Contract.
Optional & Consent-Driven – Activated only via plain-language Learning Contract.
Educational Focus – Every flag includes suggested readings and explanations.

Integration Points

Boundary Mode Compatibility: Available in all modes (OPEN → COLDROOM). In AIRGAP/COLDROOM, uses strictly offline models.
Learning Contracts: Requires an explicit contract (e.g., “Allow Boundary Daemon to scan imported code for security issues using local models”).
Memory Vault: Scan reports can be stored as low-classification memories (Class 0-1) if desired.
IntentLog: All scan events and user decisions logged as prose commits for full auditability.
Tripwire System: No direct triggering—purely advisory.

Core Features
1. Code Intake Scanning

Triggered when importing code (e.g., GitHub clone, local directory import, PR review).
Optional toggle: “Enable security scan on import” (default: off).
Scans entire repo or specific files/commits using local LLM.

2. Continuous Monitoring (Optional)

On LLM model update (e.g., new fine-tune incorporating recent CVEs), optionally re-scan monitored repositories.
Background, low-priority process—never interferes with primary workflows.

3. Decentralized Node Auditing (Optional)

In collaborative or networked deployments, participating nodes can opt-in to audit incoming code/pull requests.
Each node runs independent local scan and shares only prose summary reports via IntentLog-style entries.
No raw code shared between nodes—preserves privacy.
Consensus emerges from multiple independent advisories (e.g., “3 nodes flagged potential injection in utils.py”).

4. Advisory Output Format
Every finding presented in plain language:
textSecurity Advisory – Potential Issue Detected

File: src/api/auth.py (line 42-55)
Issue: Potential SQL injection risk in query construction
Confidence: High
Explanation: The code builds SQL queries using string concatenation with user input, which could allow malicious injection.

Suggested Reading:
• OWASP SQL Injection Prevention Cheat Sheet – https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
• CVE-2024-XXXX example (similar pattern)

Recommended Action: Consider using parameterized queries or an ORM.

[ ] Mark as reviewed      [ ] Add to watch list      [Isolate Module] (quarantine in Memory Vault)
5. User Interaction Options

Review & Dismiss: Mark finding as reviewed (logged).
Watch List: Flag file for priority re-scan on next model update.
Optional Panic/Isolate Button: One-click to temporarily isolate the module/file in Memory Vault (prevents recall/use until cleared).
Override/Ignore: Explicitly ignore with reason (logged immutably).

Implementation Plan
Plan 7: LLM-Powered Code Vulnerability Advisor (Priority: HIGH – Enhancement)
Goal: Deliver a privacy-first, advisory-only security intelligence layer.
Duration: 6-8 weeks
Dependencies: Ollama or local inference runtime, fine-tuned security models
Phase 1: Core Advisor Engine (3-4 weeks)
Python# New module: daemon/security/code_advisor.py

class CodeVulnerabilityAdvisor:
    """Advisory-only code scanner using local LLMs"""

    def __init__(self, daemon):
        self.daemon = daemon
        self.model = "llama3.1:8b-instruct-q6_K"  # Local, secure model
        self.client = ollama.Client()

    def scan_repository(self, repo_path: str, commit: str = None) -> List[Advisory]:
        """Scan repo and return plain-language advisories"""
        advisories = []
        for file_path in self._relevant_files(repo_path):
            content = self._read_file(file_path)
            prompt = self._build_security_prompt(content, file_path)
            response = self.client.generate(model=self.model, prompt=prompt)
            advisories.extend(self._parse_advisories(response['response']))
        return advisories

    def rescan_on_model_update(self):
        """Hook called when local model is updated"""
        for repo in self.daemon.config.monitored_repos:
            new_advisories = self.scan_repository(repo.path)
            self.daemon.event_logger.log_event(
                EventType.SECURITY_SCAN,
                f"Re-scan triggered by model update: {len(new_advisories)} new advisories"
            )
Phase 2: UI & Integration (2-3 weeks)

Add to boundaryctl: scan-repo <path>, list-advisories, isolate <advisory_id>
Dashboard integration: Active advisories panel
IntentLog entries for all scans and decisions

Phase 3: Decentralized Auditing (1-2 weeks, optional)

Node-to-node prose report sharing via secure channel
Aggregated advisory view in collaborative mode

Deliverables

daemon/security/code_advisor.py
Updated CLI commands
Plain-language Learning Contract templates
Documentation in PROACTIVE_SECURITY.md

This enhancement transforms the Boundary Daemon from a reactive guardian into a proactive, empowering ally—helping users stay ahead of vulnerabilities while preserving sovereignty, privacy, and human supremacy.
Revision History

Version 1.1 – 2025-12-20 – Added Section 9: LLM-Powered Code Vulnerability Advisor
Document Status: ACTIVESecurity Classification: CONFIDENTIALMaintained By: Boundary Daemon Development Team
