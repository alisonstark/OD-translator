# MITRE ATT&CK Technique Docs (Offline Cache)

Authoritative source pages are downloaded from the official MITRE ATT&CK website and stored locally.

## Update

**Manual sync** (run when you want to update cached docs):
```bash
python scripts/sync_mitre_docs.py --all-from-rules --format both
```

**Force re-download** (overwrites existing files):
```bash
python scripts/sync_mitre_docs.py --all-from-rules --format both --force
```

> **Note:** Docs are not auto-updated. Run this command manually when MITRE publishes technique updates or when you add new techniques to your detection rules.

## Techniques

| Technique | Source URL | HTML | Markdown | Retrieved (UTC) |
|---|---|---|---|---|
| T1027 | https://attack.mitre.org/techniques/T1027/ | html/T1027.html | markdown/T1027.md | 2026-03-02T16:49:05Z |
| T1059 | https://attack.mitre.org/techniques/T1059/ | html/T1059.html | markdown/T1059.md | 2026-03-02T16:49:05Z |
| T1071 | https://attack.mitre.org/techniques/T1071/ | html/T1071.html | markdown/T1071.md | 2026-03-02T16:49:05Z |
| T1105 | https://attack.mitre.org/techniques/T1105/ | html/T1105.html | markdown/T1105.md | 2026-03-02T16:49:06Z |
| T1218 | https://attack.mitre.org/techniques/T1218/ | html/T1218.html | markdown/T1218.md | 2026-03-02T16:49:06Z |
