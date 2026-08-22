import '../models/models.dart';
import 'explainer.dart';
import 'matcher.dart';
import 'scorer.dart';

List<Vulnerability> deduplicateVulnerabilities(
    List<Vulnerability> vulnerabilities) {
  final seen = <String, Vulnerability>{};

  for (final v in vulnerabilities) {
    final key = '${v.cveId.trim().toUpperCase()}|${normalizeProductName(v.productName)}';
    if (!seen.containsKey(key)) {
      seen[key] = v;
    } else {
      final existing = seen[key]!;
      final currCvss = v.cvssBaseScore ?? 0.0;
      final existCvss = existing.cvssBaseScore ?? 0.0;
      if (currCvss > existCvss) {
        seen[key] = v;
      }
    }
  }

  return seen.values.toList();
}

List<TriageResult> rankAllVulnerabilities(
  List<Vulnerability> vulnerabilities,
  OrganizationProfile profile, {
  double criticalMultiplier = 1.4,
}) {
  final uniqueVulns = deduplicateVulnerabilities(vulnerabilities);

  final scoredItems = <(Vulnerability, ScoreBreakdown)>[];
  for (final vuln in uniqueVulns) {
    final breakdown = calculateScore(vuln, profile,
        criticalMultiplier: criticalMultiplier);
    scoredItems.add((vuln, breakdown));
  }

  // Sort deterministically:
  // 1. final_score DESC
  // 2. cvss_base_score DESC
  // 3. first_epss DESC
  // 4. cve_id ASC
  scoredItems.sort((a, b) {
    final scoreComp = b.$2.finalScore.compareTo(a.$2.finalScore);
    if (scoreComp != 0) return scoreComp;

    final cvssComp = (b.$1.cvssBaseScore ?? 0.0)
        .compareTo(a.$1.cvssBaseScore ?? 0.0);
    if (cvssComp != 0) return cvssComp;

    final epssComp =
        (b.$1.firstEpss ?? 0.0).compareTo(a.$1.firstEpss ?? 0.0);
    if (epssComp != 0) return epssComp;

    return a.$1.cveId.compareTo(b.$1.cveId);
  });

  final results = <TriageResult>[];
  for (var i = 0; i < scoredItems.length; i++) {
    final vuln = scoredItems[i].$1;
    final breakdown = scoredItems[i].$2;
    final priority = determinePriorityLevel(breakdown.finalScore);
    final plainTitle = generatePlainTitle(vuln, breakdown);
    final matchedContext = generateMatchedContext(vuln, profile, breakdown);
    final whyThisMatters = generateWhyThisMatters(vuln, profile, breakdown);
    final safeNextAction = generateSafeNextAction(vuln, breakdown);
    final (confidence, confidenceReason) = determineConfidence(vuln);
    final sourceInfo = extractSourceInfo(vuln);

    double? margin;
    if (i < scoredItems.length - 1) {
      margin = double.parse((breakdown.finalScore - scoredItems[i + 1].$2.finalScore).toStringAsFixed(2));
    }

    final counterfactuals = <CounterfactualOption>[];
    if (i > 0) {
      final threat = breakdown.technicalThreatScore;
      counterfactuals.add(
        CounterfactualOption(
          factor: 'Exposure → Internet-facing',
          multiplier: '×1.20',
          projectedScore: double.parse((threat * 1.20).toStringAsFixed(1)),
          projectedPriority: determinePriorityLevel(threat * 1.20).label,
        ),
      );
      counterfactuals.add(
        CounterfactualOption(
          factor: 'Importance → High',
          multiplier: '×1.10',
          projectedScore: double.parse((threat * 1.10).toStringAsFixed(1)),
          projectedPriority: determinePriorityLevel(threat * 1.10).label,
        ),
      );
      counterfactuals.add(
        CounterfactualOption(
          factor: 'Importance → Critical',
          multiplier: '×1.20',
          projectedScore: double.parse((threat * 1.20).toStringAsFixed(1)),
          projectedPriority: determinePriorityLevel(threat * 1.20).label,
        ),
      );
      counterfactuals.add(
        CounterfactualOption(
          factor: 'Internet-facing + Critical',
          multiplier: '×1.44',
          projectedScore: double.parse((threat * 1.44).toStringAsFixed(1)),
          projectedPriority: determinePriorityLevel(threat * 1.44).label,
        ),
      );
    }

    results.add(
      TriageResult(
        rank: i + 1,
        vulnerability: vuln,
        scoreBreakdown: breakdown,
        priority: priority,
        plainTitle: plainTitle,
        matchedContext: matchedContext,
        whyThisMatters: whyThisMatters,
        safeNextAction: safeNextAction,
        confidence: confidence,
        confidenceReason: confidenceReason,
        sourceInfo: sourceInfo,
        decisionMargin: margin,
        whatWouldChangeDecision: counterfactuals,
      ),
    );
  }

  return results;
}

List<TriageResult> rankVulnerabilities(
  List<Vulnerability> vulnerabilities,
  OrganizationProfile profile, {
  int topN = 5,
  double criticalMultiplier = 1.4,
}) {
  final all = rankAllVulnerabilities(vulnerabilities, profile,
      criticalMultiplier: criticalMultiplier);
  return all.take(topN).toList();
}
