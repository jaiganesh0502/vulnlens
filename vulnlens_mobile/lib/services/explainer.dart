import '../models/models.dart';

String generatePlainTitle(Vulnerability vulnerability, ScoreBreakdown breakdown) {
  final product = vulnerability.productName;
  if (vulnerability.cisaKev) {
    return 'Active In-The-Wild Exploitation on $product';
  } else if (vulnerability.firstEpss != null && vulnerability.firstEpss! >= 0.5) {
    final epssPct = (vulnerability.firstEpss! * 100).toStringAsFixed(1);
    return 'High Exploitation Probability ($epssPct%) Threat on $product';
  } else if (vulnerability.cvssBaseScore != null &&
      vulnerability.cvssBaseScore! >= 9.0) {
    return 'Critical Technical Severity Flaw (CVSS ${vulnerability.cvssBaseScore}) on $product';
  } else if (vulnerability.cvssBaseScore != null &&
      vulnerability.cvssBaseScore! >= 7.0) {
    return 'High Severity Security Flaw on $product';
  } else {
    return 'Security Advisory for $product';
  }
}

String generateMatchedContext(
  Vulnerability vulnerability,
  OrganizationProfile profile,
  ScoreBreakdown breakdown,
) {
  if (breakdown.isCriticalProduct) {
    return 'Critical Core Asset (${vulnerability.productName}) for ${profile.name} [${profile.sector}]';
  }
  return 'Standard Deployed Asset (${vulnerability.productName}) for ${profile.name} [${profile.sector}]';
}

List<String> generateWhyThisMatters(
  Vulnerability vulnerability,
  OrganizationProfile profile,
  ScoreBreakdown breakdown,
) {
  final factors = <String>[];

  // KEV Factor
  if (vulnerability.cisaKev) {
    final kevPct = (profile.weightModifiers.cisaKevWeight * 100).toInt();
    factors.add(
      'Confirmed exploitation signal (CISA KEV active) — contributed +${breakdown.kevContribution.toStringAsFixed(1)} pts ($kevPct% profile weight)',
    );
  } else {
    factors.add('No confirmed in-the-wild exploitation reported in CISA KEV (0.0 pts)');
  }

  // CVSS Factor
  final cvss = vulnerability.cvssBaseScore;
  if (cvss != null) {
    String severityLabel;
    if (cvss >= 9.0) {
      severityLabel = 'Critical technical severity';
    } else if (cvss >= 7.0) {
      severityLabel = 'High technical severity';
    } else if (cvss >= 4.0) {
      severityLabel = 'Medium technical severity';
    } else {
      severityLabel = 'Low technical severity';
    }
    final cvssPct = (profile.weightModifiers.cvssWeight * 100).toInt();
    factors.add(
      '$severityLabel (CVSS ${cvss.toStringAsFixed(1)}/10) — contributed +${breakdown.cvssContribution.toStringAsFixed(1)} pts ($cvssPct% profile weight)',
    );
  } else {
    factors.add('Missing CVSS base score (0.0 pts assigned, reduced confidence)');
  }

  // EPSS Factor
  final epss = vulnerability.firstEpss;
  if (epss != null) {
    String epssLabel;
    if (epss >= 0.5) {
      epssLabel = 'High 30-day exploitation likelihood';
    } else if (epss >= 0.1) {
      epssLabel = 'Moderate 30-day exploitation likelihood';
    } else {
      epssLabel = 'Low 30-day exploitation likelihood';
    }
    final epssPct = (epss * 100).toStringAsFixed(1);
    final epssWeightPct = (profile.weightModifiers.firstEpssWeight * 100).toInt();
    factors.add(
      '$epssLabel (EPSS $epssPct%) — contributed +${breakdown.epssContribution.toStringAsFixed(1)} pts ($epssWeightPct% profile weight)',
    );
  } else {
    factors.add('Missing EPSS score (0.0 pts assigned, reduced confidence)');
  }

  // Critical Product Multiplier Factor
  if (breakdown.isCriticalProduct) {
    factors.add(
      'Critical Product status for ${profile.name} — applied ${breakdown.criticalMultiplier}x contextual priority multiplier',
    );
  } else {
    factors.add('Non-critical asset tier (standard 1.0x baseline weighting)');
  }

  return factors;
}

String generateSafeNextAction(
  Vulnerability vulnerability,
  ScoreBreakdown breakdown,
) {
  if (vulnerability.cisaKev) {
    return 'URGENT ACTION: Verify asset exposure and prioritize emergency patch verification or network isolation.';
  } else if (vulnerability.firstEpss != null && vulnerability.firstEpss! >= 0.5) {
    return 'HIGH PRIORITY: Verify if product is internet-facing, review vendor guidance, and schedule expedited patching.';
  } else if (vulnerability.cvssBaseScore != null &&
      vulnerability.cvssBaseScore! >= 8.5 &&
      breakdown.isCriticalProduct) {
    return 'ELEVATED DEFENSE: Core critical asset flaw. Review vendor mitigation guidelines and confirm deployment boundaries.';
  } else if (breakdown.isCriticalProduct) {
    return 'STANDARD REVIEW: Verify affected product installation and monitor vendor updates during routine maintenance.';
  } else {
    return 'ROUTINE MONITORING: Record vulnerability and track during standard periodic patch cycles.';
  }
}

(ConfidenceLevel, String) determineConfidence(Vulnerability vulnerability) {
  final hasValidCvss = vulnerability.isValidCvss;
  final hasValidEpss = vulnerability.isValidEpss;
  final hasProduct = vulnerability.productName.isNotEmpty;

  final missingFields = <String>[];
  if (!hasValidCvss) missingFields.add('CVSS base score');
  if (!hasValidEpss) missingFields.add('EPSS probability');
  if (!hasProduct) missingFields.add('Product name');

  if (missingFields.isEmpty) {
    final cvssStr = vulnerability.cvssBaseScore?.toStringAsFixed(1) ?? 'N/A';
    final epssStr = vulnerability.firstEpss?.toStringAsFixed(3) ?? 'N/A';
    final reason =
        'Complete verified telemetry: valid CVSS ($cvssStr), confirmed KEV state (${vulnerability.cisaKev}), valid EPSS ($epssStr), and exact product match (${vulnerability.productName}).';
    return (ConfidenceLevel.high, reason);
  } else if (missingFields.length == 1) {
    final reason =
        'Moderate data completeness: valid product match, but missing/unbounded ${missingFields.first}.';
    return (ConfidenceLevel.medium, reason);
  } else {
    final reason =
        'Low data completeness: multiple signals missing or malformed (${missingFields.join(', ')}).';
    return (ConfidenceLevel.low, reason);
  }
}

Map<String, dynamic> extractSourceInfo(Vulnerability vulnerability) {
  final cveId = vulnerability.cveId;
  return {
    'cve_id': cveId,
    'product_name': vulnerability.productName,
    'cvss_base_score': vulnerability.cvssBaseScore,
    'cisa_kev': vulnerability.cisaKev,
    'first_epss': vulnerability.firstEpss,
    'nvd_reference_url': 'https://nvd.nist.gov/vuln/detail/$cveId',
    'cisa_kev_catalog_url':
        'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    'first_epss_url': 'https://www.first.org/epss/',
    'raw_attributes': vulnerability.rawData,
  };
}
