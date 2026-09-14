"""FastAPI API Server Stub for Cyber Fraud Correlator (Phase 1)."""

import os
import tempfile
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
import uvicorn

from parsers.hasher import hash_file
from parsers.cdr_parser import CDRParser
from parsers.bank_parser import BankParser
from parsers.apk_parser import APKParser
from parsers.email_parser import EmailParser

app = FastAPI(
    title="Cyber Fraud Correlator API",
    description="Forensic artifact ingestion & SHA-256 integrity server.",
    version="1.0.0",
)


@app.get("/health")
def health_check():
    """Health check endpoint returning service status and phase info."""
    return {"status": "ok", "phase": 1}


@app.post("/ingest")
async def ingest_artifact(
    file: UploadFile = File(...),
    case_id: str = "CASE-104",
    officer_id: str = "IO-DEFAULT-001",
):
    """Ingests a file artifact, computes SHA-256 audit entry, and parses entity count."""
    filename = file.filename or "uploaded_file"
    suffix = Path(filename).suffix

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        audit_entry = hash_file(
            filepath=tmp_path,
            case_id=case_id,
            officer_id=officer_id,
            output_dir="outputs",
        )
        sha256 = audit_entry["sha256"]

        entity_count = 0
        parser_used = "Unknown"

        if suffix.lower() == ".csv":
            if "cdr" in filename.lower():
                parser = CDRParser(sha256)
                parser_used = "CDRParser"
            else:
                parser = BankParser(sha256)
                parser_used = "BankParser"
            res = parser.parse(tmp_path)
            entity_count = len(res.entities)
        elif suffix.lower() == ".json":
            parser = APKParser(sha256)
            parser_used = "APKParser"
            res = parser.parse(tmp_path)
            entity_count = len(res.entities)
        elif suffix.lower() == ".eml":
            parser = EmailParser(sha256)
            parser_used = "EmailParser"
            res = parser.parse(tmp_path)
            entity_count = len(res.entities)

        return {
            "status": "success",
            "filename": filename,
            "sha256": sha256,
            "parser_used": parser_used,
            "entity_count": entity_count,
            "audit_entry": audit_entry,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
