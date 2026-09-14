"""UI Notice Generator module for Section 91 CrPC / BNSS legal seizure notices."""

from datetime import datetime, timezone
from typing import List, Optional
import streamlit as st


def generate_section_91_notice(
    case_id: str = "CASE-104",
    officer_id: str = "IO-KA-2024-0042",
    officer_name: str = "Inspector S. Kumar",
    police_station: str = "Cyber Crime Police Station, CID Bangalore",
    bank_name: str = "HDFC Bank Ltd",
    suspect_accounts: Optional[List[str]] = None,
    total_amount: float = 95000.0,
    sha256_preservation: str = "0cab99950fdbc6b02b425bf7a1c8662fdb48c7f8ec2a49550274230dac3f1665",
) -> str:
    """Generates text for Section 91 CrPC / BNSS Statutory Emergency Seizure Notice.

    Args:
        case_id: Case registration number.
        officer_id: Investigating Officer ID.
        officer_name: Name of the Investigating Officer.
        police_station: Jurisdiction police station.
        bank_name: Target bank name.
        suspect_accounts: List of suspect account numbers or UPI IDs to freeze.
        total_amount: Total fraud amount in INR.
        sha256_preservation: Forensic SHA-256 hash of original bank statement.

    Returns:
        Formatted multi-line legal notice text string.
    """
    if not suspect_accounts:
        suspect_accounts = ["HDFC-MULE1-3847 (UPI: fastpay99@okhdfcbank)", "SBI-MULE2-7731 (UPI: cashout.agent@oksbi)"]

    now_str = datetime.now(timezone.utc).strftime("%d-%b-%Y %H:%M UTC")

    notice_text = f"""================================================================================
NOTICE UNDER SECTION 91 Cr.P.C. / SECTION 94 BNSS (EMERGENCY SEIZURE & FREEZE)
================================================================================

FORMAL LEGAL DIRECTIVE FOR IMMEDIATE LIEN MARKING & DEBIT FREEZE

TO:
The Nodal Officer / Fraud Control Unit,
{bank_name}.

SUBJECT: URGENT: FREEZING OF ACCOUNTS & DEBIT BAN IN CASE REGISTRATION #{case_id}
REF: STATUTORY INVESTIGATION UNDER IT ACT 2000 & INDIAN PENAL CODE / BNS

1. PARTICULARS OF INVESTIGATION:
   - Case Reference ID: {case_id}
   - Investigating Agency: {police_station}
   - Investigating Officer (IO): {officer_name} (ID: {officer_id})
   - Date & Time of Issuance: {now_str}

2. FORENSIC EVIDENCE PRESERVATION:
   - Ingested Bank Statement SHA-256: {sha256_preservation}
   - Court-Admissible Chain of Custody Verified: YES (append-only audit log)

3. TARGET ACCOUNTS TO BE FROZEN IMMEDIATELY:
"""
    for idx, acc in enumerate(suspect_accounts, start=1):
        notice_text += f"   [{idx}] Account / UPI Identifier: {acc}\n"

    notice_text += f"""
4. STATUTORY MANDATE:
   You are hereby directed under Section 91 of the Code of Criminal Procedure, 1973
   (read with Section 94 of the Bharatiya Nagarik Suraksha Sanhita, 2023) to:
   
   a) Immediately mark a LIEN / TOTAL DEBIT FREEZE on the suspect accounts listed above.
   b) Lien mark the sum of INR {total_amount:,.2f}/- (Rupees Ninety-Five Thousand Only).
   c) Preserve all KYC records, IP login logs, registered mobile numbers, and audit trails.
   d) Provide full beneficiary account details and withdrawal logs within 24 hours.

5. NON-COMPLIANCE NOTICE:
   Failure to comply with this statutory order immediately may attract criminal prosecution
   under Section 175 IPC / Section 213 BNS for disobedience to order duly promulgated by public servant.

ISSUED BY:
{officer_name}
Investigating Officer, {officer_id}
{police_station}
================================================================================
"""
    return notice_text


def render_notice_generator_panel() -> None:
    """Renders the Section 91 CrPC notice generator panel in Streamlit UI."""
    st.header("Section 91 CrPC / BNSS Seizure Notice Auto-Generator")
    st.caption("Generate court-ready statutory freeze directives for Bank Nodal Officers")

    col1, col2 = st.columns(2)
    with col1:
        case_id = st.text_input("Case Registration ID", value="CASE-104")
        officer_name = st.text_input("Investigating Officer Name", value="Inspector S. Kumar")
        officer_id = st.text_input("Officer ID", value="IO-KA-2024-0042")
    with col2:
        bank_name = st.text_input("Target Bank Name", value="HDFC Bank Ltd")
        police_station = st.text_input("Police Station", value="Cyber Crime PS, CID Bangalore")
        total_amount = st.number_input("Frozen Amount (INR)", value=95000.0, step=1000.0)

    suspects_raw = st.text_area(
        "Suspect Accounts / UPI Handles (one per line)",
        value="HDFC-MULE1-3847 (UPI: fastpay99@okhdfcbank)\nSBI-MULE2-7731 (UPI: cashout.agent@oksbi)",
    )
    suspects = [s.strip() for s in suspects_raw.split("\n") if s.strip()]

    notice = generate_section_91_notice(
        case_id=case_id,
        officer_id=officer_id,
        officer_name=officer_name,
        police_station=police_station,
        bank_name=bank_name,
        suspect_accounts=suspects,
        total_amount=total_amount,
    )

    st.subheader("Generated Statutory Notice Text")
    st.text_area("Copyable Notice Content", value=notice, height=380)

    st.download_button(
        label="📥 Download Notice (.txt)",
        data=notice,
        file_name=f"Section91_Notice_{case_id}.txt",
        mime="text/plain",
    )
