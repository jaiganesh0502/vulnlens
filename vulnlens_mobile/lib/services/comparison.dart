import '../models/models.dart';
import 'ranking.dart';

ProfileComparisonReport compareProfiles(
  List<Vulnerability> vulnerabilities,
  OrganizationProfile profileA,
  OrganizationProfile profileB, {
  int topN = 5,
}) {
  final allListA = rankAllVulnerabilities(vulnerabilities, profileA);
  final allListB = rankAllVulnerabilities(vulnerabilities, profileB);

  final allA = {for (final item in allListA) item.vulnerability.cveId: item};
  final allB = {for (final item in allListB) item.vulnerability.cveId: item};

  final top5A = rankVulnerabilities(vulnerabilities, profileA, topN: topN);
  final top5B = rankVulnerabilities(vulnerabilities, profileB, topN: topN);

  final unionCves = <String>[];
  for (final item in top5A) {
    if (!unionCves.contains(item.vulnerability.cveId)) {
      unionCves.add(item.vulnerability.cveId);
    }
  }
  for (final item in top5B) {
    if (!unionCves.contains(item.vulnerability.cveId)) {
      unionCves.add(item.vulnerability.cveId);
    }
  }

  final comparisonItems = <ProfileComparisonItem>[];

  for (final cve in unionCves) {
    final itemA = allA[cve];
    final itemB = allB[cve];

    if (itemA == null && itemB == null) continue;

    final refVuln = itemA?.vulnerability ?? itemB!.vulnerability;
    final scoreA = itemA?.scoreBreakdown.finalScore ?? 0.0;
    final rankA = itemA?.rank;
    final critA = itemA?.scoreBreakdown.isCriticalProduct ?? false;

    final scoreB = itemB?.scoreBreakdown.finalScore ?? 0.0;
    final rankB = itemB?.rank;
    final critB = itemB?.scoreBreakdown.isCriticalProduct ?? false;

    final scoreDelta =
        double.parse((scoreB - scoreA).toStringAsFixed(2));
    final rankDelta = (rankA != null && rankB != null) ? (rankA - rankB) : null;

    final drivers = <String>[];
    if (critA != critB) {
      if (critB) {
        drivers.add('Critical asset in ${profileB.name} (+1.4x multiplier)');
      } else {
        drivers.add(
            'Critical asset in ${profileA.name} (lost 1.4x multiplier in ${profileB.name})');
      }
    }

    final epssWtDiff = profileB.weightModifiers.firstEpssWeight -
        profileA.weightModifiers.firstEpssWeight;
    final cvssWtDiff = profileB.weightModifiers.cvssWeight -
        profileA.weightModifiers.cvssWeight;
    final kevWtDiff = profileB.weightModifiers.cisaKevWeight -
        profileA.weightModifiers.cisaKevWeight;

    if (epssWtDiff.abs() >= 0.15 && (refVuln.firstEpss ?? 0.0) >= 0.4) {
      final epssPctA = (profileA.weightModifiers.firstEpssWeight * 100).toInt();
      final epssPctB = (profileB.weightModifiers.firstEpssWeight * 100).toInt();
      final vulnEpssPct = ((refVuln.firstEpss ?? 0.0) * 100).toStringAsFixed(1);
      drivers.add(
          'EPSS weight is $epssPctB% in ${profileB.name} vs $epssPctA% in ${profileA.name} (EPSS: $vulnEpssPct%)');
    }
    if (kevWtDiff.abs() >= 0.15 && refVuln.cisaKev) {
      final kevPctA = (profileA.weightModifiers.cisaKevWeight * 100).toInt();
      final kevPctB = (profileB.weightModifiers.cisaKevWeight * 100).toInt();
      drivers.add(
          'KEV weight is $kevPctB% in ${profileB.name} vs $kevPctA% in ${profileA.name}');
    }
    if (cvssWtDiff.abs() >= 0.15 && (refVuln.cvssBaseScore ?? 0.0) >= 8.0) {
      final cvssPctA = (profileA.weightModifiers.cvssWeight * 100).toInt();
      final cvssPctB = (profileB.weightModifiers.cvssWeight * 100).toInt();
      drivers.add(
          'CVSS weight is $cvssPctB% in ${profileB.name} vs $cvssPctA% in ${profileA.name}');
    }

    final driverText = drivers.isNotEmpty
        ? drivers.join('; ')
        : 'Subtle weight balancing difference';

    comparisonItems.add(
      ProfileComparisonItem(
        cveId: refVuln.cveId,
        productName: refVuln.productName,
        cvssBaseScore: refVuln.cvssBaseScore ?? 0.0,
        cisaKev: refVuln.cisaKev,
        firstEpss: refVuln.firstEpss ?? 0.0,
        rankA: rankA,
        scoreA: scoreA,
        isCriticalA: critA,
        rankB: rankB,
        scoreB: scoreB,
        isCriticalB: critB,
        scoreDelta: scoreDelta,
        rankDelta: rankDelta,
        driverSummary: driverText,
      ),
    );
  }

  final cvssA = (profileA.weightModifiers.cvssWeight * 100).toInt();
  final cvssB = (profileB.weightModifiers.cvssWeight * 100).toInt();
  final kevA = (profileA.weightModifiers.cisaKevWeight * 100).toInt();
  final kevB = (profileB.weightModifiers.cisaKevWeight * 100).toInt();
  final epssA = (profileA.weightModifiers.firstEpssWeight * 100).toInt();
  final epssB = (profileB.weightModifiers.firstEpssWeight * 100).toInt();

  final narrative =
      "Comparison between '${profileA.name}' (${profileA.sector}, Risk: ${profileA.riskAppetite}) and '${profileB.name}' (${profileB.sector}, Risk: ${profileB.riskAppetite}). Priority shifts are driven by asset criticality mappings and calibrated weights (CVSS: $cvssA% vs $cvssB%, KEV: $kevA% vs $kevB%, EPSS: $epssA% vs $epssB%).";

  return ProfileComparisonReport(
    orgA: profileA,
    orgB: profileB,
    top5A: top5A,
    top5B: top5B,
    comparisonItems: comparisonItems,
    overallNarrative: narrative,
  );
}
