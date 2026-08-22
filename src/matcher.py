"""Product name normalization and matching logic."""

import re
from typing import Dict, Iterable, Optional, Set, Tuple

# Documented canonical alias mapping for common product name variants
PRODUCT_ALIASES: Dict[str, str] = {
    "core banking framework": "Core Banking Framework",
    "core banking": "Core Banking Framework",
    "core-banking-framework": "Core Banking Framework",
    "identity provider saas": "Identity Provider SaaS",
    "identity provider": "Identity Provider SaaS",
    "idp saas": "Identity Provider SaaS",
    "idp": "Identity Provider SaaS",
    "cloud database engine": "Cloud Database Engine",
    "cloud database": "Cloud Database Engine",
    "cloud-db": "Cloud Database Engine",
    "enterprise router os": "Enterprise Router OS",
    "router os": "Enterprise Router OS",
    "enterprise router": "Enterprise Router OS",
    "embedded iot gateway": "Embedded IoT Gateway",
    "iot gateway": "Embedded IoT Gateway",
    "embedded iot": "Embedded IoT Gateway",
    "web application firewall": "Web Application Firewall",
    "waf": "Web Application Firewall",
}


def normalize_product_name(name: Optional[str]) -> str:
    """Normalize product name for reliable matching.
    
    Transforms strings:
    - Strips leading/trailing whitespace
    - Lowercases
    - Collapses multiple whitespace characters to a single space
    - Strips surrounding quotes or special wrapping
    """
    if not name:
        return ""
    
    # Strip whitespace and quotes
    cleaned = str(name).strip().strip("'\"`")
    # Lowercase
    cleaned = cleaned.lower()
    # Normalize multiple whitespace
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned


def resolve_canonical_product(name: Optional[str]) -> str:
    """Resolve a product string to its canonical form if found in alias table,
    otherwise return cleaned title-cased string.
    """
    norm = normalize_product_name(name)
    if not norm:
        return ""
    if norm in PRODUCT_ALIASES:
        return PRODUCT_ALIASES[norm]
    # Return cleanly capitalized original
    return str(name).strip()


def is_critical_product(product_name: Optional[str], critical_products: Iterable[str]) -> bool:
    """Determine whether a product matches an organization's critical products list.
    
    Uses normalized string comparison and alias resolution.
    """
    if not product_name or not critical_products:
        return False
        
    norm_target = normalize_product_name(product_name)
    canon_target = resolve_canonical_product(product_name).lower()
    
    for crit in critical_products:
        norm_crit = normalize_product_name(crit)
        canon_crit = resolve_canonical_product(crit).lower()
        
        if norm_target == norm_crit or canon_target == canon_crit:
            return True
            
    return False


def is_relevant_product(
    product_name: Optional[str],
    organization_products: Optional[Iterable[str]] = None,
) -> bool:
    """Check if a product is relevant to an organization.
    
    If organization_products is None or empty, all catalog products are considered relevant.
    Otherwise, tests normalized equality against the provided product list.
    """
    if not organization_products:
        return True
    if not product_name:
        return False
        
    norm_target = normalize_product_name(product_name)
    for org_prod in organization_products:
        if norm_target == normalize_product_name(org_prod):
            return True
    return False
