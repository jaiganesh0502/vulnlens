"""Data loader for VulnLens CSV and JSON files."""

import csv
import json
import logging
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.models import (
    CalibrationRecord,
    OrganizationProfile,
    Vulnerability,
    WeightModifiers,
)

logger = logging.getLogger(__name__)


def parse_boolean(value: Any) -> bool:
    """Safely parse a boolean from various string and primitive representations."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    val_str = str(value).strip().lower()
    return val_str in ("true", "1", "yes", "t", "y")


def parse_float_safe(
    value: Any, min_val: Optional[float] = None, max_val: Optional[float] = None
) -> Optional[float]:
    """Safely parse a float with optional range validation."""
    if value is None:
        return None
    val_str = str(value).strip()
    if not val_str or val_str.lower() in ("nan", "null", "none", ""):
        return None
    try:
        f_val = float(val_str)
        if min_val is not None and f_val < min_val:
            return None
        if max_val is not None and f_val > max_val:
            return None
        return f_val
    except (ValueError, TypeError):
        return None


def load_vulnerabilities(
    source: Union[str, Path, StringIO]
) -> List[Vulnerability]:
    """Load vulnerabilities from a CSV file path or StringIO.
    
    Robust against missing columns and malformed rows.
    """
    records: List[Vulnerability] = []
    
    if isinstance(source, (str, Path)) and not isinstance(source, StringIO):
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"Vulnerabilities file not found: {source}")
        with open(path, mode="r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    elif isinstance(source, StringIO):
        content = source.getvalue()
    else:
        content = str(source)

    reader = csv.DictReader(StringIO(content))
    for row_idx, row in enumerate(reader, start=1):
        if not row:
            continue
        
        # Extract cve_id and product_name with fallbacks
        cve_id = (row.get("cve_id") or row.get("CVE_ID") or row.get("cve") or "").strip()
        product_name = (
            row.get("product_name")
            or row.get("product")
            or row.get("Product")
            or ""
        ).strip()

        if not cve_id or not product_name:
            logger.warning(f"Row {row_idx} missing cve_id or product_name; skipping.")
            continue

        # Parse CVSS (0-10)
        cvss_raw = row.get("cvss_base_score") or row.get("cvss_score") or row.get("cvss")
        cvss_score = parse_float_safe(cvss_raw, min_val=0.0, max_val=10.0)

        # Parse KEV (boolean)
        kev_raw = row.get("cisa_kev") or row.get("in_kev") or row.get("kev")
        cisa_kev = parse_boolean(kev_raw)

        # Parse EPSS (0-1)
        epss_raw = row.get("first_epss") or row.get("epss_score") or row.get("epss")
        first_epss = parse_float_safe(epss_raw, min_val=0.0, max_val=1.0)

        records.append(
            Vulnerability(
                cve_id=cve_id,
                product_name=product_name,
                cvss_base_score=cvss_score,
                cisa_kev=cisa_kev,
                first_epss=first_epss,
                raw_data=dict(row),
            )
        )

    return records


def load_profiles(
    source: Union[str, Path, StringIO]
) -> List[OrganizationProfile]:
    """Load organization profiles from a JSON file path or StringIO."""
    if isinstance(source, (str, Path)) and not isinstance(source, StringIO):
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"Profiles file not found: {source}")
        with open(path, mode="r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    elif isinstance(source, StringIO):
        data = json.loads(source.getvalue())
    else:
        data = json.loads(str(source))

    org_list = data.get("organizations", [])
    if isinstance(data, list):
        org_list = data
    elif not org_list and isinstance(data, dict):
        if "org_id" in data or "name" in data:
            org_list = [data]

    profiles: List[OrganizationProfile] = []
    for org_data in org_list:
        try:
            profile = OrganizationProfile.from_dict(org_data)
            profiles.append(profile)
        except Exception as e:
            logger.warning(f"Failed to parse organization profile: {e}")
            continue

    return profiles


def load_gold_set(
    source: Union[str, Path, StringIO]
) -> List[CalibrationRecord]:
    """Load gold set calibration data from CSV."""
    records: List[CalibrationRecord] = []
    
    if isinstance(source, (str, Path)) and not isinstance(source, StringIO):
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"Gold set file not found: {source}")
        with open(path, mode="r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    elif isinstance(source, StringIO):
        content = source.getvalue()
    else:
        content = str(source)

    reader = csv.DictReader(StringIO(content))
    for row in reader:
        if not row:
            continue
        cve_id = (row.get("cve_id") or "").strip()
        product_name = (row.get("product_name") or "").strip()
        if not cve_id or not product_name:
            continue

        cvss = parse_float_safe(row.get("cvss_base_score"), 0.0, 10.0) or 0.0
        cisa_kev = parse_boolean(row.get("cisa_kev"))
        epss = parse_float_safe(row.get("first_epss"), 0.0, 1.0) or 0.0

        rank_bank = None
        rank_startup = None
        if "practitioner_rank_bank" in row:
            try:
                rank_bank = int(row["practitioner_rank_bank"])
            except (ValueError, TypeError):
                pass
        if "practitioner_rank_startup" in row:
            try:
                rank_startup = int(row["practitioner_rank_startup"])
            except (ValueError, TypeError):
                pass

        records.append(
            CalibrationRecord(
                cve_id=cve_id,
                product_name=product_name,
                cvss_base_score=cvss,
                cisa_kev=cisa_kev,
                first_epss=epss,
                practitioner_rank_bank=rank_bank,
                practitioner_rank_startup=rank_startup,
            )
        )

    return records
