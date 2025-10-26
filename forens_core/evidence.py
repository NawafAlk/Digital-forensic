# Handles evidence file registration and management
_evidence_db = {}
_next_id = 1

def add_evidence(path):
    global _next_id
    eid = f"E{_next_id:03d}"
    _evidence_db[eid] = {"path": path, "open": True}
    _next_id += 1
    return eid

def resolve_evidence(eid):
    return _evidence_db.get(eid)

def close_evidence(eid):
    if eid in _evidence_db:
        _evidence_db[eid]["open"] = False
        return True
    return False
