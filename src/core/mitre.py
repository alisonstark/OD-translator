import json
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parents[2]
CACHE_FILE = ROOT_DIR / "data" / "mitre" / "attackcti_t1059.json"


def _to_dict(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        return item
    if hasattr(item, "to_dict"):
        return item.to_dict()
    if hasattr(item, "serialize"):
        try:
            return json.loads(item.serialize())
        except Exception:
            return {}
    if hasattr(item, "__dict__"):
        return dict(item.__dict__)
    return {}


def _extract_external_id(dct: Dict[str, Any]) -> Optional[str]:
    for ref in dct.get("external_references", []):
        external_id = ref.get("external_id")
        if external_id and external_id.startswith("T"):
            return external_id
    return None


def _extract_tactic(dct: Dict[str, Any]) -> Optional[str]:
    """Extract the primary tactic from kill_chain_phases."""
    kill_chain_phases = dct.get("kill_chain_phases", [])
    if not kill_chain_phases:
        return None
    
    # Find a non-deprecated phase or just use the first one
    for phase in kill_chain_phases:
        phase_name = phase.get("phase_name", "")
        if phase_name:
            # Convert phase_name format (e.g., "execution" -> "Execution")
            return phase_name.replace("-", " ").title()
    
    return None


def _fetch_attackcti_items() -> List[Dict[str, Any]]:
    try:
        from attackcti import attack_client

        client = attack_client.AttackClient()
    except Exception:
        try:
            from attackcti import MitreAttackClient

            client = MitreAttackClient()
        except Exception as exc:
            raise RuntimeError("attackcti is not installed or could not be imported.") from exc

    if hasattr(client, "get_techniques"):
        try:
            return client.get_techniques(include_subtechniques=True)
        except TypeError:
            return client.get_techniques()
    if hasattr(client, "get_all_techniques"):
        return client.get_all_techniques()

    raise RuntimeError("attackcti client does not expose a technique retrieval method.")


def _build_t1059_index(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    index = {
        "technique_id": "T1059",
        "technique_name": None,
        "tactic": None,
        "subtechniques": {},
    }

    for item in items:
        dct = _to_dict(item)
        if dct.get("type") != "attack-pattern":
            continue

        external_id = _extract_external_id(dct)
        if not external_id:
            continue

        if external_id == "T1059":
            index["technique_name"] = dct.get("name")
            index["tactic"] = _extract_tactic(dct)
        elif external_id.startswith("T1059."):
            index["subtechniques"][external_id] = {
                "name": dct.get("name"),
                "tactic": _extract_tactic(dct),
            }

    if not index["technique_name"] and index["subtechniques"]:
        index["technique_name"] = "Command and Scripting Interpreter"

    return index


def load_cache() -> Optional[Dict[str, Any]]:
    if CACHE_FILE.exists():
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    return None


def save_cache(data: Dict[str, Any]) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def get_t1059_index(refresh: bool = False) -> Dict[str, Any]:
    if not refresh:
        cached = load_cache()
        if cached:
            return cached

    items = _fetch_attackcti_items()
    index = _build_t1059_index(items)
    save_cache(index)
    return index


def get_technique_name(refresh: bool = False) -> Optional[str]:
    return get_t1059_index(refresh=refresh).get("technique_name")


def get_subtechnique_name(sub_id: str, refresh: bool = False) -> Optional[str]:
    normalized = sub_id.strip()
    if normalized.startswith("T1059."):
        key = normalized
    else:
        key = f"T1059.{normalized.lstrip('.')}"

    return get_t1059_index(refresh=refresh).get("subtechniques", {}).get(key, {}).get("name")


def _build_technique_index(items: List[Dict[str, Any]], technique_id: str) -> Dict[str, Any]:
    """Build an index for any technique ID (T1059, T1218, T1027, etc.)."""
    index = {
        "technique_id": technique_id,
        "technique_name": None,
        "tactic": None,
    }

    for item in items:
        dct = _to_dict(item)
        if dct.get("type") != "attack-pattern":
            continue

        external_id = _extract_external_id(dct)
        if not external_id or external_id != technique_id:
            continue

        index["technique_name"] = dct.get("name")
        index["tactic"] = _extract_tactic(dct)
        break

    return index


def get_technique_tactic(technique_id: str, refresh: bool = False) -> Optional[str]:
    """Get the tactic for a given technique ID (e.g., 'T1059' -> 'Execution')."""
    # Special handling for T1059 which is cached
    if technique_id == "T1059":
        return get_t1059_index(refresh=refresh).get("tactic")

    # For other techniques, fetch from attackcti
    try:
        items = _fetch_attackcti_items()
        index = _build_technique_index(items, technique_id)
        return index.get("tactic")
    except Exception:
        return None
