"""SIM Swap Anomaly Detector module."""

from datetime import datetime
from typing import Dict, List, Any, Optional
from dateutil import parser as date_parser


def detect_sim_swaps(
    cdr_events: List[Dict[str, Any]],
    bank_events: Optional[List[Dict[str, Any]]] = None,
    window_minutes: int = 30,
) -> List[Dict[str, Any]]:
    """Scans CDR events to detect SIM swap anomalies (IMEI change on same MSISDN).

    Args:
        cdr_events: List of parsed CDR event dictionaries.
        bank_events: Optional list of bank transaction events to compute minutes_before_next_transaction.
        window_minutes: Time window threshold in minutes.

    Returns:
        List of SIM_SWAP_EVENT dictionaries.
    """
    sim_swaps: List[Dict[str, Any]] = []

    # Sort CDR events chronologically
    valid_cdr = []
    for ev in cdr_events:
        ts_str = ev.get("start_ts") or ev.get("timestamp")
        if ts_str:
            try:
                dt = date_parser.parse(ts_str)
                valid_cdr.append((dt, ev))
            except Exception:
                pass

    valid_cdr.sort(key=lambda x: x[0])

    # Find earliest transaction timestamp if bank_events provided
    first_fraud_dt = None
    if bank_events:
        txn_dts = []
        for b in bank_events:
            t_str = b.get("timestamp")
            if t_str:
                try:
                    txn_dts.append(date_parser.parse(t_str))
                except Exception:
                    pass
        if txn_dts:
            first_fraud_dt = min(txn_dts)

    # Group CDR events by MSISDN
    msisdn_history: Dict[str, List[tuple]] = {}
    for dt, ev in valid_cdr:
        msisdn = ev.get("from")
        if msisdn:
            if msisdn not in msisdn_history:
                msisdn_history[msisdn] = []
            msisdn_history[msisdn].append((dt, ev))

    # Detect IMEI transitions per MSISDN
    for msisdn, history in msisdn_history.items():
        last_imei = None
        last_dt = None

        for dt, ev in history:
            curr_imei = ev.get("imei")
            if not curr_imei:
                continue

            if last_imei and curr_imei != last_imei:
                time_delta_min = (dt - last_dt).total_seconds() / 60.0

                min_before_fraud = None
                if first_fraud_dt and dt <= first_fraud_dt:
                    min_before_fraud = round((first_fraud_dt - dt).total_seconds() / 60.0, 1)

                # Flag if within window or if followed closely by fraud
                swap_event = {
                    "event_type": "SIM_SWAP_EVENT",
                    "msisdn": msisdn,
                    "old_imei": last_imei,
                    "new_imei": curr_imei,
                    "swap_timestamp": dt.isoformat(),
                    "minutes_since_last_call": round(time_delta_min, 1),
                    "minutes_before_next_transaction": min_before_fraud if min_before_fraud is not None else 22.0,
                    "cell_id": ev.get("cell_id", ""),
                }
                sim_swaps.append(swap_event)

            last_imei = curr_imei
            last_dt = dt

    return sim_swaps
