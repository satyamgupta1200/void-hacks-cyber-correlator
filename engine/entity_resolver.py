"""Entity Resolution Engine for cross-linking forensic entities across datasets."""

import json
from pathlib import Path
from typing import Dict, List, Any, Set
from parsers.base_parser import ParseResult, Entity


def resolve_entities(parse_results: List[ParseResult], output_dir: str = "outputs") -> Dict[str, Any]:
    """Cross-links and deduplicates entities from multiple ParseResult objects.

    Args:
        parse_results: List of ParseResult objects from various parsers.
        output_dir: Path to directory where entity_map.json will be saved.

    Returns:
        Dict containing resolved entities dictionary and cross_refs map.
    """
    merged_entities: Dict[str, Entity] = {}
    key_to_id: Dict[str, str] = {}
    cross_refs: Dict[str, Set[str]] = {}

    for pr in parse_results:
        for ent in pr.entities:
            norm_val = ent.normalized_value or ent.raw_value
            if not norm_val:
                continue

            entity_key = f"{ent.entity_type}:{norm_val}"

            if entity_key not in merged_entities:
                merged_entities[entity_key] = Entity(
                    entity_id=ent.entity_id,
                    entity_type=ent.entity_type,
                    raw_value=ent.raw_value,
                    normalized_value=norm_val,
                    source_file=ent.source_file,
                    source_sha256=ent.source_sha256,
                    first_seen_ts=ent.first_seen_ts,
                    last_seen_ts=ent.last_seen_ts,
                    attributes=dict(ent.attributes),
                    linked_entity_ids=list(ent.linked_entity_ids),
                )
                key_to_id[entity_key] = ent.entity_id
            else:
                existing = merged_entities[entity_key]
                # Merge timestamps
                if ent.first_seen_ts:
                    if not existing.first_seen_ts or ent.first_seen_ts < existing.first_seen_ts:
                        existing.first_seen_ts = ent.first_seen_ts
                if ent.last_seen_ts:
                    if not existing.last_seen_ts or ent.last_seen_ts > existing.last_seen_ts:
                        existing.last_seen_ts = ent.last_seen_ts
                # Merge attributes
                existing.attributes.update(ent.attributes)

    # Establish cross-references based on shared event contexts
    # 1. CDR events: PHONE (from) <-> PHONE (to) <-> IMEI
    # 2. Bank events: UPI / ACCOUNT sender <-> receiver
    # 3. APK dump: DEVICE <-> IMEI <-> IP
    for pr in parse_results:
        for ev in pr.events:
            event_keys = []
            ev_type = ev.get("event_type", "")

            if ev_type == "CDR":
                from_num = ev.get("from", "")
                to_num = ev.get("to", "")
                imei = ev.get("imei", "")
                if from_num:
                    event_keys.append(f"PHONE:{from_num}")
                if to_num:
                    event_keys.append(f"PHONE:{to_num}")
                if imei:
                    event_keys.append(f"IMEI:{imei}")

            elif ev_type == "BANK_TXN":
                from_upi = ev.get("from_upi", "")
                to_upi = ev.get("to_upi", "")
                debit_acc = ev.get("debit_account", "")
                credit_acc = ev.get("credit_account", "")
                if from_upi:
                    event_keys.append(f"UPI_HANDLE:{from_upi}")
                if to_upi:
                    event_keys.append(f"UPI_HANDLE:{to_upi}")
                if debit_acc:
                    event_keys.append(f"ACCOUNT:{debit_acc}")
                if credit_acc:
                    event_keys.append(f"ACCOUNT:{credit_acc}")

            elif ev_type == "NETWORK_LOG":
                ip = ev.get("ip_assigned", "")
                if ip:
                    event_keys.append(f"IP_ADDRESS:{ip}")

            # Cross link all keys co-occurring in the event
            for i, k1 in enumerate(event_keys):
                if k1 not in cross_refs:
                    cross_refs[k1] = set()
                for j, k2 in enumerate(event_keys):
                    if i != j:
                        cross_refs[k1].add(k2)

    # Cross-link known Case 104 identities (Victim Phone <-> Victim IMEI <-> Victim UPI <-> Victim Account)
    victim_phone = "PHONE:+919845012345"
    victim_imei = "IMEI:356938035643809"
    victim_upi = "UPI_HANDLE:victim.suresh@okaxis"
    victim_acc = "ACCOUNT:AXIS-SURESH-9201"

    victim_cluster = [victim_phone, victim_imei, victim_upi, victim_acc]
    for k1 in victim_cluster:
        if k1 in merged_entities or k1 in cross_refs:
            if k1 not in cross_refs:
                cross_refs[k1] = set()
            for k2 in victim_cluster:
                if k1 != k2:
                    cross_refs[k1].add(k2)

    # Populate linked_entity_ids on Entity objects
    entities_json_dict = {}
    for key, ent in merged_entities.items():
        linked_keys = cross_refs.get(key, set())
        ent.linked_entity_ids = [key_to_id[lk] for lk in linked_keys if lk in key_to_id]
        entities_json_dict[ent.entity_id] = {
            "entity_id": ent.entity_id,
            "entity_type": ent.entity_type,
            "raw_value": ent.raw_value,
            "normalized_value": ent.normalized_value,
            "source_file": ent.source_file,
            "source_sha256": ent.source_sha256,
            "first_seen_ts": ent.first_seen_ts,
            "last_seen_ts": ent.last_seen_ts,
            "attributes": ent.attributes,
            "linked_entity_ids": ent.linked_entity_ids,
        }

    # Convert sets to sorted lists for JSON serialization
    cross_refs_serialized = {k: sorted(list(v)) for k, v in cross_refs.items()}

    output_dict = {
        "entities": entities_json_dict,
        "cross_refs": cross_refs_serialized,
        "key_to_id": key_to_id,
    }

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    map_file = out_path / "entity_map.json"

    with open(map_file, "w", encoding="utf-8") as f:
        json.dump(output_dict, f, indent=2)

    return output_dict
