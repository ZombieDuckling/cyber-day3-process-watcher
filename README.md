# Day 3/7: Suspicious process watcher (Python)

This is a small cybersecurity portfolio project for beginner-friendly endpoint
triage. It scans local running processes and applies basic suspicious flags
based on known keywords and simple behavior checks.

> **Warning:** This tool is for legal, authorized, defensive use only. Run it
> only on systems you own or have explicit permission to monitor.

## Workflow: research → learn → execute → push

This section captures the required process for this daily build.

### 1) Research

I used three credible references to shape a minimal detection approach:

1. MITRE ATT&CK T1059 (Command and Scripting Interpreter)
   - https://attack.mitre.org/techniques/T1059/
2. NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)
   - https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
3. CISA Advisory AA20-245A (Technical approaches to uncovering malicious
   activity)
   - https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-245a

### 2) Learn

Key learning points pulled into this project design:

- Process command lines are high-value telemetry for spotting suspicious script
  and command execution patterns.
- Incident response starts with collecting relevant host artifacts and logs.
  A local process snapshot is one of the fastest low-friction artifacts.
- Detection quality improves when you combine multiple weak signals rather than
  relying on one binary rule.
- For beginner tools, transparent rules are useful: keyword flags, unusual path
  hints, and high CPU outliers are easy to explain and tune.

### 3) Execute

Implemented `process_watcher.py` with these features:

- Reads process list using `ps` (no external Python packages required).
- Flags suspicious keywords in process command and arguments.
- Flags suspicious temp execution paths (`/tmp`, `/var/tmp`).
- Flags high CPU usage above a configurable threshold.
- Supports one-shot scan and watch mode.

### 4) Push

If `gh` is authenticated, publish to GitHub:

1. `git init`
2. `git add . && git commit -m "day3: add suspicious process watcher"`
3. `gh repo create ZombieDuckling/cyber-day3-process-watcher --public --source=. --remote=origin --push`

If `gh` is not authenticated, keep the local project and push later after
running `gh auth login`.

## How to run

From this folder:

```bash
python3 process_watcher.py
```

Watch mode every 5 seconds:

```bash
python3 process_watcher.py --watch --interval 5
```

Lower CPU threshold for demos:

```bash
python3 process_watcher.py --cpu-threshold 20
```

## Notes and limitations

- This is not an EDR and will produce false positives.
- It does not perform memory forensics, signature validation, or network IOC
  correlation.
- Extend it next by adding baseline learning, structured JSON output, and
  optional alerting.
