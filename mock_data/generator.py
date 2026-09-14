"""Synthetic Indian cyber fraud mock data generator (Case 104)."""

import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from faker import Faker


def generate_case_104_data(output_dir: str = "mock_data/case_104") -> None:
    """Generates synthetic Indian cyber fraud dataset for Case 104.

    Args:
        output_dir: Target directory path for Case 104 data files.
    """
    random.seed(104)
    fake = Faker('en_IN')
    Faker.seed(104)

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Key Case 104 constants
    victim_msisdn = "9845012345"
    victim_upi = "victim.suresh@okaxis"
    victim_acc = "AXIS-SURESH-9201"
    victim_orig_imei = "356938035643809"

    mule1_msisdn = "9731088421"
    mule1_upi = "fastpay99@okhdfcbank"
    mule1_acc = "HDFC-MULE1-3847"

    mule2_msisdn = "8197634520"
    mule2_upi = "cashout.agent@oksbi"
    mule2_acc = "SBI-MULE2-7731"

    attacker_imei = "490154203237518"

    # Base datetime: 2024-03-15 14:33:00 IST
    base_date = datetime(2024, 3, 15, 14, 33, 0)

    # -------------------------------------------------------------
    # 1. CDR Records (minimum 55 rows)
    # -------------------------------------------------------------
    cdr_rows = []
    # Victim normal call history (20 rows before fraud)
    curr_time = base_date - timedelta(days=3)
    for i in range(20):
        curr_time += timedelta(hours=random.randint(1, 4), minutes=random.randint(5, 45))
        called = f"9845{random.randint(100000, 999999)}"
        duration = random.randint(15, 300)
        end_time = curr_time + timedelta(seconds=duration)
        cdr_rows.append({
            "msisdn": victim_msisdn,
            "called_number": called,
            "call_start": curr_time.strftime("%Y-%m-%d %H:%M:%S"),
            "call_end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_sec": duration,
            "imei": victim_orig_imei,
            "imsi": "404450920139481",
            "cell_id": "BLR-KOR-001",
            "lac": "56001",
            "call_type": "VOICE",
            "roaming_flag": "N",
            "serving_operator": "Airtel"
        })

    # The SIM Swap event at 14:11:00 (22 min before fraud)
    sim_swap_start = datetime(2024, 3, 15, 14, 11, 0)
    sim_swap_end = sim_swap_start + timedelta(seconds=120)
    cdr_rows.append({
        "msisdn": victim_msisdn,
        "called_number": "199",  # Telecom customer care / SIM swap line
        "call_start": sim_swap_start.strftime("%Y-%m-%d %H:%M:%S"),
        "call_end": sim_swap_end.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_sec": 120,
        "imei": attacker_imei,  # Attacker IMEI post-swap
        "imsi": "404450920139481",
        "cell_id": "BLR-KOR-001",
        "lac": "56001",
        "call_type": "VOICE",
        "roaming_flag": "N",
        "serving_operator": "Airtel"
    })

    # Mule 1 to Mule 2 coordination call at 14:28:00 (3 min before fraud)
    mule_call_start = datetime(2024, 3, 15, 14, 28, 0)
    mule_call_end = mule_call_start + timedelta(seconds=45)
    cdr_rows.append({
        "msisdn": mule1_msisdn,
        "called_number": mule2_msisdn,
        "call_start": mule_call_start.strftime("%Y-%m-%d %H:%M:%S"),
        "call_end": mule_call_end.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_sec": 45,
        "imei": "864201049382019",
        "imsi": "404118302910293",
        "cell_id": "BLR-KOR-002",
        "lac": "56001",
        "call_type": "VOICE",
        "roaming_flag": "N",
        "serving_operator": "Jio"
    })

    # Victim data session during fraud window
    data_start = datetime(2024, 3, 15, 14, 32, 0)
    data_end = datetime(2024, 3, 15, 14, 40, 0)
    cdr_rows.append({
        "msisdn": victim_msisdn,
        "called_number": "DATA_SESSION",
        "call_start": data_start.strftime("%Y-%m-%d %H:%M:%S"),
        "call_end": data_end.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_sec": 480,
        "imei": attacker_imei,
        "imsi": "404450920139481",
        "cell_id": "BLR-KOR-001",
        "lac": "56001",
        "call_type": "DATA",
        "roaming_flag": "N",
        "serving_operator": "Airtel"
    })

    # Additional random calls to reach at least 55 rows
    curr_time = datetime(2024, 3, 12, 8, 0, 0)
    for _ in range(35):
        curr_time += timedelta(minutes=random.randint(30, 180))
        sender = fake.msisdn()[-10:]
        receiver = fake.msisdn()[-10:]
        duration = random.randint(10, 600)
        end_time = curr_time + timedelta(seconds=duration)
        cdr_rows.append({
            "msisdn": f"+91{sender}",
            "called_number": f"+91{receiver}",
            "call_start": curr_time.strftime("%Y-%m-%d %H:%M:%S"),
            "call_end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_sec": duration,
            "imei": f"35{random.randint(1000000000000, 9999999999999)}",
            "imsi": f"404{random.randint(10000000000, 99999999999)}",
            "cell_id": f"BLR-{random.choice(['IND', 'MG', 'JAY', 'WHITE'])}-00{random.randint(1, 9)}",
            "lac": "56001",
            "call_type": random.choice(["VOICE", "SMS"]),
            "roaming_flag": "N",
            "serving_operator": random.choice(["Airtel", "Jio", "Vi"])
        })

    # Write cdr_records.csv
    cdr_file = out_path / "cdr_records.csv"
    fieldnames_cdr = [
        "msisdn", "called_number", "call_start", "call_end",
        "duration_sec", "imei", "imsi", "cell_id", "lac",
        "call_type", "roaming_flag", "serving_operator"
    ]
    with open(cdr_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames_cdr)
        writer.writeheader()
        writer.writerows(cdr_rows)

    # -------------------------------------------------------------
    # 2. Bank Statement CSV (minimum 35 rows)
    # -------------------------------------------------------------
    bank_rows = []
    curr_balance = 100000.0

    # Normal transactions for victim
    start_bank_dt = datetime(2024, 3, 10, 9, 0, 0)
    for i in range(25):
        start_bank_dt += timedelta(hours=random.randint(4, 12))
        amt = round(random.uniform(100, 2500), 2)
        is_debit = random.choice([True, False])
        if is_debit:
            curr_balance -= amt
            row_data = {
                "txn_id": f"TXN20240310{i+100:04d}",
                "txn_timestamp": start_bank_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "debit_account": victim_acc,
                "credit_account": f"MERCHANT-STORE-{random.randint(10,99)}",
                "upi_handle_sender": victim_upi,
                "upi_handle_receiver": f"merchant{random.randint(1,50)}@paytm",
                "amount_inr": amt,
                "txn_type": "UPI",
                "bank_ref": f"REF{random.randint(100000,999999)}",
                "narration": "Grocery Purchase",
                "balance_after": round(curr_balance, 2)
            }
        else:
            curr_balance += amt
            row_data = {
                "txn_id": f"TXN20240310{i+100:04d}",
                "txn_timestamp": start_bank_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "debit_account": f"EMPLOYER-ACC-{random.randint(10,99)}",
                "credit_account": victim_acc,
                "upi_handle_sender": "salary@company",
                "upi_handle_receiver": victim_upi,
                "amount_inr": amt,
                "txn_type": "NEFT",
                "bank_ref": f"REF{random.randint(100000,999999)}",
                "narration": "Reimbursement",
                "balance_after": round(curr_balance, 2)
            }
        bank_rows.append(row_data)

    # Ensure balance before fraud is 97,341.50
    curr_balance = 97341.50

    # Fraud sequence back-to-back starting at 14:33:00
    # Row 1: Victim debited ₹95,000 -> Mule 1
    curr_balance -= 95000.00
    bank_rows.append({
        "txn_id": "TXN202403159901",
        "txn_timestamp": "2024-03-15 14:33:07",
        "debit_account": victim_acc,
        "credit_account": mule1_acc,
        "upi_handle_sender": victim_upi,
        "upi_handle_receiver": mule1_upi,
        "amount_inr": 95000.00,
        "txn_type": "UPI",
        "bank_ref": "UPI/407514920192/PAY",
        "narration": "UPI-FASTPAY-TRANSFER",
        "balance_after": round(curr_balance, 2)
    })

    # Row 2: Mule 1 debited ₹94,500 -> Mule 2
    bank_rows.append({
        "txn_id": "TXN202403159902",
        "txn_timestamp": "2024-03-15 14:35:22",
        "debit_account": mule1_acc,
        "credit_account": mule2_acc,
        "upi_handle_sender": mule1_upi,
        "upi_handle_receiver": mule2_upi,
        "amount_inr": 94500.00,
        "txn_type": "IMPS",
        "bank_ref": "IMPS/407514923481/CASHOUT",
        "narration": "IMPS-TRANSFER-MULE2",
        "balance_after": 500.00
    })

    # Row 3: Mule 2 debited ₹93,800 -> Account CASH-ATM-KORAMANGALA
    bank_rows.append({
        "txn_id": "TXN202403159903",
        "txn_timestamp": "2024-03-15 14:38:49",
        "debit_account": mule2_acc,
        "credit_account": "CASH-ATM-KORAMANGALA",
        "upi_handle_sender": mule2_upi,
        "upi_handle_receiver": "atm.withdrawal@sbi",
        "amount_inr": 93800.00,
        "txn_type": "ATM_WITHDRAWAL",
        "bank_ref": "ATM/BLR/KOR/92018",
        "narration": "ATM Cash Withdrawal Koramangala",
        "balance_after": 700.00
    })

    # Row 4: ATM withdrawal event log line
    bank_rows.append({
        "txn_id": "TXN202403159904",
        "txn_timestamp": "2024-03-15 14:39:01",
        "debit_account": "CASH-ATM-KORAMANGALA",
        "credit_account": "DISPENSED_CASH",
        "upi_handle_sender": "atm.withdrawal@sbi",
        "upi_handle_receiver": "cash.handover@mule2",
        "amount_inr": 93800.00,
        "txn_type": "CASH_OUT",
        "bank_ref": "ATM/BLR/KOR/92019",
        "narration": "Physical Cash Dispensed",
        "balance_after": 0.00
    })

    # Additional rows to meet >35 rows requirement
    extra_dt = datetime(2024, 3, 11, 10, 0, 0)
    for i in range(10):
        extra_dt += timedelta(hours=3)
        bank_rows.append({
            "txn_id": f"TXN20240311{i+500:04d}",
            "txn_timestamp": extra_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "debit_account": f"ACC-{random.randint(1000,9999)}",
            "credit_account": f"ACC-{random.randint(1000,9999)}",
            "upi_handle_sender": f"user{i}@okicici",
            "upi_handle_receiver": f"shop{i}@okaxis",
            "amount_inr": float(random.randint(50, 1500)),
            "txn_type": "UPI",
            "bank_ref": f"REF{random.randint(100000,999999)}",
            "narration": "General Transfer",
            "balance_after": 15000.00
        })

    # Write bank_statement.csv
    bank_file = out_path / "bank_statement.csv"
    fieldnames_bank = [
        "txn_id", "txn_timestamp", "debit_account", "credit_account",
        "upi_handle_sender", "upi_handle_receiver", "amount_inr",
        "txn_type", "bank_ref", "narration", "balance_after"
    ]
    with open(bank_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames_bank)
        writer.writeheader()
        writer.writerows(bank_rows)

    # -------------------------------------------------------------
    # 3. APK Dump JSON
    # -------------------------------------------------------------
    apk_data = {
        "device_info": {
            "imei": victim_orig_imei,
            "android_id": "a1b2c3d4e5f60718",
            "model": "Samsung Galaxy M32",
            "os_version": "Android 12",
            "capture_timestamp": "2024-03-15T16:00:00+05:30"
        },
        "installed_apps": [
            {
                "package_name": "com.hdfc.mobilebanking",
                "app_label": "HDFC Bank MobileBanking",
                "install_source": "com.android.vending",
                "install_ts": "2023-08-10T10:00:00+05:30",
                "permissions": ["INTERNET", "USE_FINGERPRINT"]
            },
            {
                "package_name": "com.hdfcbank.customerapp.update",
                "app_label": "HDFC Bank Update",
                "install_source": "apkpure.com",
                "install_ts": "2024-03-15T11:15:00+05:30",
                "permissions": [
                    "READ_SMS",
                    "BIND_ACCESSIBILITY_SERVICE",
                    "RECORD_AUDIO",
                    "SYSTEM_ALERT_WINDOW",
                    "INTERNET",
                    "RECEIVE_BOOT_COMPLETED"
                ]
            }
        ],
        "sms_log": [
            {
                "from": "VM-HDFCBK",
                "to": victim_msisdn,
                "body": "Your OTP for UPI transaction is 847291. Valid for 10 mins. Do not share.",
                "ts": "2024-03-15T14:32:55+05:30"
            },
            {
                "from": "VM-HDFCBK",
                "to": victim_msisdn,
                "body": "INR 95,000 debited from A/c XX9201 on 15-Mar-24. Available Bal: INR 2,341.50",
                "ts": "2024-03-15T14:33:09+05:30"
            }
        ],
        "call_log": [],
        "network_log": [
            {
                "ssid": "JioFiber-Home-Suresh",
                "bssid": "a4:c3:f0:85:ac:11",
                "connected_ts": "2024-03-15T08:00:00+05:30",
                "ip_assigned": "192.168.1.105"
            }
        ]
    }

    apk_file = out_path / "apk_dump.json"
    with open(apk_file, "w", encoding="utf-8") as f:
        json.dump(apk_data, f, indent=2)

    # -------------------------------------------------------------
    # 4. Phishing Email (.eml)
    # -------------------------------------------------------------
    eml_content = (
        "From: \"HDFC Bank\" <alerts@hdfcbank-kyc.in>\n"
        "To: suresh.k@gmail.com\n"
        "Subject: [URGENT] Your HDFC Bank Account Will Be Suspended – Verify KYC Immediately\n"
        "Date: Thu, 14 Mar 2024 23:11:44 +0530\n"
        "Message-ID: <20240314231144.920184@hdfcbank-kyc.in>\n"
        "Reply-To: support@hdfcbank-kyc.in\n"
        "X-Originating-IP: 196.216.2.45\n"
        "Received: from mail.hdfcbank-kyc.in (196.216.2.45)\n"
        "    by mx.google.com with ESMTPS id z182si9201824pga.12.2024.03.14.10.41.44;\n"
        "    Thu, 14 Mar 2024 23:11:44 +0530\n"
        "Authentication-Results: mx.google.com;\n"
        "    dkim=fail header.i=@hdfcbank-kyc.in;\n"
        "    spf=fail (google.com: domain of alerts@hdfcbank-kyc.in does not designate 196.216.2.45 as permitted sender) smtp.mailfrom=alerts@hdfcbank-kyc.in;\n"
        "    dmarc=fail (p=REJECT dis=NONE) header.from=hdfcbank-kyc.in\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/html; charset=UTF-8\n"
        "\n"
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<body>\n"
        "<h2>HDFC Bank KYC Update Required</h2>\n"
        "<p>Dear Customer,</p>\n"
        "<p>Your bank account safety mandates immediate KYC updating. Failure to update within 24 hours will result in temporary suspension of your account.</p>\n"
        "<p>Please click the secure link below to update your mobile banking application:</p>\n"
        "<p><a href=\"http://hdfcbank-kyc-update.xyz/verify?token=abc123\">http://hdfcbank-kyc-update.xyz/verify?token=abc123</a></p>\n"
        "<p>Thank you,<br>HDFC Security Team</p>\n"
        "</body>\n"
        "</html>\n"
    )

    eml_file = out_path / "phishing_email.eml"
    with open(eml_file, "w", encoding="utf-8") as f:
        f.write(eml_content)

    print(f"Case 104 data generated successfully in {out_path.resolve()}")


if __name__ == "__main__":
    generate_case_104_data()
