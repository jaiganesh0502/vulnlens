import '../models/models.dart';
import 'scorer.dart';

double? computeSpearmanCorrelation(List<double> ranksX, List<double> ranksY) {
  final n = ranksX.length;
  if (n <= 1 || ranksY.length != n) return null;

  var dSqSum = 0.0;
  for (var i = 0; i < n; i++) {
    final diff = ranksX[i] - ranksY[i];
    dSqSum += diff * diff;
  }

  final rho = 1.0 - (6.0 * dSqSum) / (n * (n * n - 1));
  return double.parse(rho.toStringAsFixed(4));
}

CalibrationReport evaluateGoldSet(
  List<CalibrationRecord> goldRecords,
  OrganizationProfile profile, {
  String practitionerField = 'practitioner_rank_bank',
}) {
  final scoredCandidates =
      <(CalibrationRecord, Vulnerability, ScoreBreakdown, int?)>[];

  for (final rec in goldRecords) {
    final vuln = Vulnerability(
      cveId: rec.cveId,
      productName: rec.productName,
      cvssBaseScore: rec.cvssBaseScore,
      cisaKev: rec.cisaKev,
      firstEpss: rec.firstEpss,
    );
    final breakdown = calculateScore(vuln, profile);
    final pRank = (practitionerField == 'practitioner_rank_startup')
        ? rec.practitionerRankStartup
        : rec.practitionerRankBank;
    scoredCandidates.add((rec, vuln, breakdown, pRank));
  }

  scoredCandidates.sort((a, b) {
    final scoreComp = b.$3.finalScore.compareTo(a.$3.finalScore);
    if (scoreComp != 0) return scoreComp;

    final cvssComp = (b.$2.cvssBaseScore ?? 0.0)
        .compareTo(a.$2.cvssBaseScore ?? 0.0);
    if (cvssComp != 0) return cvssComp;

    final epssComp =
        (b.$2.firstEpss ?? 0.0).compareTo(a.$2.firstEpss ?? 0.0);
    if (epssComp != 0) return epssComp;

    return a.$2.cveId.compareTo(b.$2.cveId);
  });

  final items = <GoldSetEvaluationItem>[];
  final engineRanks = <double>[];
  final practitionerRanks = <double>[];
  final absErrors = <double>[];

  for (var i = 0; i < scoredCandidates.length; i++) {
    final rankIdx = i + 1;
    final rec = scoredCandidates[i].$1;
    final vuln = scoredCandidates[i].$2;
    final breakdown = scoredCandidates[i].$3;
    final pRank = scoredCandidates[i].$4;
    final delta = pRank != null ? (rankIdx - pRank) : null;

    final notes = <String>[];
    if (breakdown.isCriticalProduct) notes.add('Critical Asset (1.4x)');
    if (vuln.cisaKev) notes.add('KEV Active');
    if ((vuln.firstEpss ?? 0.0) >= 0.5) {
      final epssPct = ((vuln.firstEpss ?? 0.0) * 100).toStringAsFixed(1);
      notes.add('High EPSS ($epssPct%)');
    }
    if ((vuln.cvssBaseScore ?? 0.0) >= 9.0) {
      notes.add('CVSS ${vuln.cvssBaseScore}');
    }

    final itemNotes =
        notes.isNotEmpty ? notes.join(', ') : 'Standard priority signals';

    items.add(
      GoldSetEvaluationItem(
        cveId: rec.cveId,
        productName: rec.productName,
        cvssBaseScore: rec.cvssBaseScore,
        cisaKev: rec.cisaKev,
        firstEpss: rec.firstEpss,
        scoreBreakdown: breakdown,
        engineRank: rankIdx,
        practitionerRank: pRank,
        rankDelta: delta,
        notes: itemNotes,
      ),
    );

    if (pRank != null) {
      engineRanks.add(rankIdx.toDouble());
      practitionerRanks.add(pRank.toDouble());
      absErrors.add((rankIdx - pRank).abs().toDouble());
    }
  }

  final corr = engineRanks.length >= 3
      ? computeSpearmanCorrelation(engineRanks, practitionerRanks)
      : null;
  final meanErr = absErrors.isNotEmpty
      ? (absErrors.reduce((a, b) => a + b) / absErrors.length)
      : null;

  String alignment;
  if (corr != null && corr >= 0.8) {
    alignment =
        'Strong rank alignment (Spearman ρ = ${corr.toStringAsFixed(2)}, Mean Rank Delta = ${meanErr?.toStringAsFixed(2)})';
  } else if (corr != null && corr >= 0.5) {
    alignment =
        'Moderate rank alignment (Spearman ρ = ${corr.toStringAsFixed(2)}, Mean Rank Delta = ${meanErr?.toStringAsFixed(2)})';
  } else {
    final corrStr = corr?.toStringAsFixed(2) ?? 'N/A';
    alignment = 'Calibration benchmark computed (Spearman ρ = $corrStr)';
  }

  final summary =
      'Gold-set sanity check against practitioner ranking for ${profile.name}. $alignment. Evaluated across ${items.length} curated ground-truth records.';

  return CalibrationReport(
    orgName: profile.name,
    orgId: profile.orgId,
    items: items,
    spearmanCorrelation: corr,
    meanAbsoluteRankError: meanErr,
    summaryText: summary,
  );
}
