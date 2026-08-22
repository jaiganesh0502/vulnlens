import '../models/models.dart';
import 'ranking.dart';

String explainNegativeTestResult(
  TriageResult triageItem,
  OrganizationProfile profile,
  int totalCandidates,
) {
  final breakdown = triageItem.scoreBreakdown;
  final vuln = triageItem.vulnerability;
  final reasons = <String>[];

  // 1. Check KEV
  if (!vuln.cisaKev) {
    final maxKevPts = (profile.weightModifiers.cisaKevWeight * 100).toInt();
    reasons.add(
        'Zero exploitation evidence in CISA KEV (0.0 pts awarded out of $maxKevPts max KEV points).');
  }

  // 2. Check EPSS
  final epss = vuln.firstEpss ?? 0.0;
  if (epss < 0.05) {
    final epssPct = (epss * 100).toStringAsFixed(2);
    reasons.add(
        'Extremely low 30-day exploitation probability (EPSS $epssPct% contributes only ${breakdown.epssContribution.toStringAsFixed(1)} pts).');
  } else if (epss < 0.20) {
    final epssPct = (epss * 100).toStringAsFixed(2);
    reasons.add(
        'Low exploitation probability (EPSS $epssPct% contributes only ${breakdown.epssContribution.toStringAsFixed(1)} pts).');
  }

  // 3. Check Critical Product Context
  if (!breakdown.isCriticalProduct) {
    final critList = profile.criticalProducts.join(', ');
    reasons.add(
        "Asset '${vuln.productName}' is NOT in ${profile.name}'s critical products list ($critList), forfeiting the 1.4x priority multiplier.");
  }

  // 4. Check Profile Weighting Impact
  final cvssWt = profile.weightModifiers.cvssWeight;
  if (cvssWt <= 0.35) {
    final cvssPct = (cvssWt * 100).toInt();
    reasons.add(
        "${profile.name}'s risk appetite allocates only $cvssPct% weight to theoretical severity (CVSS), prioritizing real-world exploitation signals instead.");
  }

  final cvssStr = vuln.cvssBaseScore?.toStringAsFixed(1) ?? 'N/A';
  final scoreStr = breakdown.finalScore.toStringAsFixed(1);
  return 'Despite a high technical severity of CVSS $cvssStr, ${vuln.cveId} ranked #${triageItem.rank} of $totalCandidates candidates (Score: $scoreStr/100, Priority: ${triageItem.priority.label}). Key de-prioritization factors: ${reasons.join(' ')}';
}

List<NegativeTestItem> findNegativeTestCandidates(
  List<Vulnerability> vulnerabilities,
  OrganizationProfile profile, {
  double minCvss = 9.0,
  int maxRankThreshold = 10,
}) {
  final allRanked = rankAllVulnerabilities(vulnerabilities, profile);
  final totalCandidates = allRanked.length;
  final candidates = <NegativeTestItem>[];

  for (final item in allRanked) {
    final cvss = item.vulnerability.cvssBaseScore ?? 0.0;
    if (cvss >= minCvss &&
        (item.rank > maxRankThreshold ||
            item.priority == PriorityLevel.low ||
            item.priority == PriorityLevel.medium)) {
      final reason = explainNegativeTestResult(item, profile, totalCandidates);
      candidates.add(
        NegativeTestItem(
          vulnerability: item.vulnerability,
          scoreBreakdown: item.scoreBreakdown,
          rank: item.rank,
          totalCandidates: totalCandidates,
          reasonLowOrExcluded: reason,
        ),
      );
    }
  }

  return candidates;
}
