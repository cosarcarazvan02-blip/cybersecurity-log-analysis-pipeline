# Cybersecurity Log Analysis Pipeline 
Python pipeline that parses server logs, filters suspicious activity, and detects brute-force attacks (repeated failed attempts from the same IP).
```
raw_logs → parse_logs → filter_suspicious → detect_brute_force → report
```
**Example output:**
```
Unathorized acces detected | IP:176.111.90.1 | ATTEMPTS:2
```
**Run:**
```bash
python3 main.py
```
Built with Python 3, `re` only — no external dependencies.
