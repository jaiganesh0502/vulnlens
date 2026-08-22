import '../models/models.dart';
import 'matcher.dart';

const double defaultCriticalProductMultiplier = 1.4;
const double priorityThresholdUrgent = 90.0;
const double priorityThresholdHigh = 75.0;
const double priorityThresholdMedium = 50.0;

ScoreBreakdown calculateScore(
  Vulnerability vulnerability,
  OrganizationProfile profile, {
  double criticalMultiplier = defaultCriticalProductMultiplier,
}) {
  // 1. CVSS signal
  final cvssVal = vulnerability.cvssBaseScore ?? 0.0;
  final cvssNorm = cvssVal / 10.0;
  final cvssWeight = profile.weightModifiers.cvssWeight;
  final cvssContribution = 100.0 * cvssWeight * cvssNorm;

  // 2. KEV signal
  final kevSignal = vulnerability.cisaKev ? 1.0 : 0.0;
  final kevWeight = profile.weightModifiers.cisaKevWeight;
  final kevContribution = 100.0 * kevWeight * kevSignal;

  // 3. EPSS signal
  final epssVal = vulnerability.firstEpss ?? 0.0;
  final epssWeight = profile.weightModifiers.firstEpssWeight;
  final epssContribution = 100.0 * epssWeight * epssVal;

  // 4. Base score
  final baseScore = cvssContribution + kevContribution + epssContribution;

  // 5. Critical product context
  final isCritical =
      isCriticalProduct(vulnerability.productName, profile.criticalProducts);
  final multiplier = isCritical ? criticalMultiplier : 1.0;
  final finalScore = baseScore * multiplier;

  return ScoreBreakdown(
    cvssBaseScore: cvssVal,
    cvssNormalized: cvssNorm,
    cvssWeight: cvssWeight,
    cvssContribution: double.parse(cvssContribution.toStringAsFixed(4)),
    cisaKev: vulnerability.cisaKev,
    kevSignal: kevSignal,
    cisaKevWeight: kevWeight,
    kevContribution: double.parse(kevContribution.toStringAsFixed(4)),
    firstEpss: epssVal,
    epssSignal: epssVal,
    firstEpssWeight: epssWeight,
    epssContribution: double.parse(epssContribution.toStringAsFixed(4)),
    baseScore: double.parse(baseScore.toStringAsFixed(4)),
    isCriticalProduct: isCritical,
    criticalMultiplier: multiplier,
    finalScore: double.parse(finalScore.toStringAsFixed(4)),
  );
}

PriorityLevel determinePriorityLevel(double score) {
  if (score >= priorityThresholdUrgent) {
    return PriorityLevel.urgent;
  } else if (score >= priorityThresholdHigh) {
    return PriorityLevel.high;
  } else if (score >= priorityThresholdMedium) {
    return PriorityLevel.medium;
  } else {
    return PriorityLevel.low;
  }
}
