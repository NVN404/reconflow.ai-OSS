"""
Scan Job Manager: Asynchronous Task Execution & State Tracking.
Multi-worker safe persistence: Writes jobs to disk in CACHE_DIR/jobs/{job_id}.json
so that multiple Uvicorn worker processes share identical job status.
"""

import os
import json
import time
import uuid
import logging
import threading
from pathlib import Path
from typing import Dict, Any, Optional

from app.config import CACHE_DIR
from app.schemas import ScanResult

logger = logging.getLogger("reconflow.jobs")

JOBS_DIR = CACHE_DIR / "jobs"
JOBS_DIR.mkdir(parents=True, exist_ok=True)

class ScanJobManager:
    def __init__(self, ttl_seconds: int = 3600):
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def _job_file(self, job_id: str) -> Path:
        safe_id = "".join(c for c in job_id if c.isalnum() or c in "-_")
        return JOBS_DIR / f"{safe_id}.json"

    def create_job(self, target: str, protocol: str = "rest") -> str:
        job_id = str(uuid.uuid4())
        now = time.time()
        job_data = {
            "job_id": job_id,
            "target": target,
            "protocol": protocol,
            "status": "pending",
            "progress": 0,
            "result": None,
            "error": None,
            "created_at": now,
            "updated_at": now
        }
        with self._lock:
            self._save_job_file(job_id, job_data)
            self._cleanup_expired()
        return job_id

    def update_job(
        self,
        job_id: str,
        status: str,
        progress: int = 0,
        result: Optional[ScanResult] = None,
        error: Optional[str] = None
    ) -> None:
        with self._lock:
            job_data = self._read_job_file(job_id)
            if not job_data:
                job_data = {
                    "job_id": job_id,
                    "target": "unknown",
                    "protocol": "rest",
                    "created_at": time.time()
                }
            job_data["status"] = status
            job_data["progress"] = progress
            job_data["updated_at"] = time.time()
            if result:
                job_data["result"] = result.model_dump()
            if error:
                job_data["error"] = error
            self._save_job_file(job_id, job_data)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._read_job_file(job_id)

    def _save_job_file(self, job_id: str, data: Dict[str, Any]) -> None:
        try:
            target_path = self._job_file(job_id)
            with open(target_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error("Failed to save job %s: %s", job_id, e)

    def _read_job_file(self, job_id: str) -> Optional[Dict[str, Any]]:
        target_path = self._job_file(job_id)
        if not target_path.exists():
            return None
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error("Failed to read job %s: %s", job_id, e)
            return None

    def _cleanup_expired(self) -> None:
        now = time.time()
        try:
            for item in JOBS_DIR.glob("*.json"):
                if now - item.stat().st_mtime > self._ttl:
                    item.unlink(missing_ok=True)
        except Exception:
            pass

job_manager = ScanJobManager()
