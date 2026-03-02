# MITRE ATT&CK Technique Docs (Offline Cache)

Authoritative source pages are downloaded from the official MITRE ATT&CK website and stored locally.

## Update

```bash
python scripts/sync_mitre_docs.py --all-from-rules --format both
```

## Check Staleness

Check if cached docs are older than 30 days:
```bash
python scripts/sync_mitre_docs.py --check-staleness
```

Automatically update stale docs:
```bash
python scripts/sync_mitre_docs.py --update-stale
```

## Techniques

| Technique | Source URL | HTML | Markdown | Retrieved (UTC) |
|---|---|---|---|---|
| T1027 | https://attack.mitre.org/techniques/T1027/ | html/T1027.html | markdown/T1027.md | 2026-03-02T22:44:24Z |
| T1055 | https://attack.mitre.org/techniques/T1055/ | html/T1055.html | markdown/T1055.md | 2026-03-02T22:44:24Z |
| T1059 | https://attack.mitre.org/techniques/T1059/ | html/T1059.html | markdown/T1059.md | 2026-03-02T22:44:24Z |
| T1071 | https://attack.mitre.org/techniques/T1071/ | html/T1071.html | markdown/T1071.md | 2026-03-02T22:44:24Z |
| T1105 | https://attack.mitre.org/techniques/T1105/ | html/T1105.html | markdown/T1105.md | 2026-03-02T22:44:24Z |
| T1218 | https://attack.mitre.org/techniques/T1218/ | html/T1218.html | markdown/T1218.md | 2026-03-02T22:44:24Z |
| T1543 | https://attack.mitre.org/techniques/T1543/ | html/T1543.html | markdown/T1543.md | 2026-03-02T22:44:24Z |
