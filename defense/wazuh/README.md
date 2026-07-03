# Wazuh SIEM Deployment & Scheduled Task Detection

## Overview

End-to-end Wazuh SIEM deployment with Windows Sysmon log forwarding, followed by a
simulated adversary technique (scheduled task creation and deferred command execution) to
validate detection coverage and produce a documented investigation.

This artifact covers the full chain: infrastructure deployment → telemetry verification →
adversary simulation → alert correlation → analyst triage.

---

## Contents

- [`wazuh-deployment.docx`](./wazuh-deployment.docx) — Wazuh manager install (Ubuntu), Windows agent
  install, agent registration, and Sysmon log forwarding configuration.
- [`wazuh-simulation.docx`](./wazuh-simulation.docx) — Simulated T1053.005 (Scheduled
  Task/Job) and resulting T1059.003 (Windows Command Shell) execution, with correlated
  Wazuh alerts and full triage narrative.

---

## Summary

**Environment:** [Windows agent/ Ubuntu Wazuh manager v4.14 — fill in]

**Simulation:** Used [TheAtomicPlaybook — T1053.005](https://cyberbuff.github.io/TheAtomicPlaybook/tactics/execution/T1053.005.html#t1053-005-scheduled-task)
to create a one-time scheduled task (`/SC ONCE`) configured to launch `cmd.exe` at a fixed
trigger time.

**Detections produced:**

| Stage | Rule ID | Description | Technique |
|---|---|---|---|
| Task creation | 92004 | Powershell process spawned Windows command shell instance | T1053.005 |
| Task execution | 92052 | Windows command prompt started by an abnormal process | T1059.003 |

**Correlation:** Task created at 21:15:25.598 UTC, configured to fire at 17:17 local
(21:17 UTC), executed at 21:17:00.662 UTC — within 1 second of the configured trigger,
confirming the scheduled task fired exactly as configured (~95 second creation-to-execution
window).

**Privilege context:** Confirmed the executed `cmd.exe` ran as the creating user (`jdham`),
not SYSTEM — no privilege escalation occurred. The `NT AUTHORITY\SYSTEM` context visible in
the alert belongs to the Task Scheduler service host (`svchost.exe`) that launched the task,
not the spawned process itself.

---

## Key Findings

- Confirmed `/SC ONCE` is a deferred-execution mechanism, not persistence — persistence
  requires a recurring trigger that survives reboot. Mislabeling this as "persistence"
  would have been a technique misclassification.
- Identified a likely rule-description mismatch: rule 92004 is labeled as detecting a
  "PowerShell → command shell" spawn, but the actual child process in this event was
  `schtasks.exe`, not `cmd.exe`. [Verify against rule 92004's decoder logic — noted here as
  a detection engineering observation, not yet confirmed as a rule bug.]
- Correlated two independent alerts (creation + execution) into a single causal chain using
  timestamp analysis, rather than treating either alert in isolation.

---

## Skills Demonstrated

- Wazuh SIEM deployment and Sysmon telemetry integration
- Adversary technique simulation (Atomic Red Team / TheAtomicPlaybook)
- Alert correlation across multiple Sysmon event types
- MITRE ATT&CK technique mapping and tactic classification
- Privilege-context analysis to rule out escalation
- Critical evaluation of detection rule accuracy against raw telemetry

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Scheduled Task/Job | T1053.005 | Execution |
| Windows Command Shell | T1059.003 | Execution |