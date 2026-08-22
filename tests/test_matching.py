"""Tests for product normalization and critical product matching."""

import pytest

from src.matcher import (
    is_critical_product,
    is_relevant_product,
    normalize_product_name,
    resolve_canonical_product,
)


def test_normalize_product_name():
    """Verify whitespace, casing, and quote stripping during normalization."""
    assert normalize_product_name("Core Banking Framework") == "core banking framework"
    assert normalize_product_name("  CORE BANKING FRAMEWORK  ") == "core banking framework"
    assert normalize_product_name("core   banking   framework") == "core banking framework"
    assert normalize_product_name('"Identity Provider SaaS"') == "identity provider saas"
    assert normalize_product_name("") == ""
    assert normalize_product_name(None) == ""


def test_resolve_canonical_product_aliases():
    """Verify alias mapping to canonical product titles."""
    assert resolve_canonical_product("core banking") == "Core Banking Framework"
    assert resolve_canonical_product("CORE BANKING FRAMEWORK") == "Core Banking Framework"
    assert resolve_canonical_product("idp saas") == "Identity Provider SaaS"
    assert resolve_canonical_product("waf") == "Web Application Firewall"
    assert resolve_canonical_product("router os") == "Enterprise Router OS"
    assert resolve_canonical_product("iot gateway") == "Embedded IoT Gateway"
    assert resolve_canonical_product("unknown tool") == "unknown tool"


def test_is_critical_product_matching():
    """Verify critical product detection handles whitespace and casing variations."""
    critical_list = ["Core Banking Framework", "Identity Provider SaaS"]

    # Exact match
    assert is_critical_product("Core Banking Framework", critical_list) is True
    # Case mismatch
    assert is_critical_product("core banking framework", critical_list) is True
    # Extra whitespace
    assert is_critical_product("  Core Banking Framework  ", critical_list) is True
    # Alias variant
    assert is_critical_product("core banking", critical_list) is True
    assert is_critical_product("idp saas", critical_list) is True
    # Non-critical product
    assert is_critical_product("Cloud Database Engine", critical_list) is False
    assert is_critical_product("Enterprise Router OS", critical_list) is False


def test_is_relevant_product():
    """Verify relevance matching logic."""
    org_inventory = ["Cloud Database Engine", "Web Application Firewall"]
    assert is_relevant_product("Cloud Database Engine", org_inventory) is True
    assert is_relevant_product("cloud database engine", org_inventory) is True
    assert is_relevant_product("Core Banking Framework", org_inventory) is False
    # If inventory is None, all are relevant
    assert is_relevant_product("Any Product", None) is True
