"""Tests for the NexoraPay CLI interface commands and outputs."""

import io
import sys
from unittest.mock import patch

from nexorapay.cli import (
    main,
    parse_args,
    print_default_demo,
    print_table,
    run_live_scenario,
)
from nexorapay.models import RiskAppetite
from nexorapay.simulator import CyberRiskSimulator


def test_cli_default_output(capsys):
    simulator = CyberRiskSimulator()
    print_default_demo(simulator, cve_id="NXP-DEMO-002")

    captured = capsys.readouterr().out
    assert "NEXORAPAY CYBER RISK SIMULATOR" in captured
    assert "Customer Payment Portal" in captured
    assert "NXP-DEMO-002" in captured
    assert "8.4" in captured
    assert "YES" in captured
    assert "0.91" in captured
    assert "DEMO PRIORITY:\nURGENT" in captured
    assert "High technical severity" in captured
    assert "Known exploitation signal" in captured


def test_cli_table_output(capsys):
    simulator = CyberRiskSimulator()
    print_table(simulator, appetite=RiskAppetite.LOW)

    captured = capsys.readouterr().out
    assert "ORGANISATION SNAPSHOT" in captured
    assert "NXP-DEMO-001" in captured
    assert "NXP-DEMO-002" in captured
    assert "NXP-DEMO-003" in captured
    assert "NXP-DEMO-004" in captured
    assert "NXP-DEMO-005" in captured


def test_cli_live_scenario_non_interactive(capsys):
    simulator = CyberRiskSimulator()
    run_live_scenario(simulator, interactive=False)

    captured = capsys.readouterr().out
    assert "LIVE ANALYST SIMULATION" in captured
    assert "Customer Payment Portal" in captured
    assert "PRIORITY:\nURGENT" in captured
    assert "Exposure:\nInternet-facing\n->\nInternal" in captured
    assert "PRIORITY:\nHIGH" in captured
    assert "Critical\n->\nNormal" in captured
    assert "PRIORITY:\nMEDIUM" in captured
    assert "Severity remained 8.4" in captured
    assert "This manual reasoning is what VulnLens automates." in captured


def test_cli_main_what_if_flags(capsys):
    test_args = ["nexorapay.demo", "--exposure", "internal"]
    with patch.object(sys, "argv", test_args):
        main()

    captured = capsys.readouterr().out
    assert "BEFORE" in captured
    assert "Internet-facing" in captured
    assert "CHANGE" in captured
    assert "Internal" in captured
    assert "AFTER" in captured
    assert "WHY" in captured


def test_cli_main_profile_flag(capsys):
    test_args = ["nexorapay.demo", "--profile", "high"]
    with patch.object(sys, "argv", test_args):
        main()

    captured = capsys.readouterr().out
    assert "ORGANISATION SNAPSHOT" in captured
    assert "HIGH" in captured
