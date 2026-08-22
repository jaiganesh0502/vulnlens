enum PriorityLevel {
  urgent('URGENT'),
  high('HIGH'),
  medium('MEDIUM'),
  low('LOW');

  final String label;
  const PriorityLevel(this.label);
}

enum ConfidenceLevel {
  high('HIGH'),
  medium('MEDIUM'),
  low('LOW'),
  needsVerification('NEEDS_VERIFICATION');

  final String label;
  const ConfidenceLevel(this.label);
}

class WeightModifiers {
  final double cvssWeight;
  final double cisaKevWeight;
  final double firstEpssWeight;

  WeightModifiers({
    required this.cvssWeight,
    required this.cisaKevWeight,
    required this.firstEpssWeight,
  });

  factory WeightModifiers.fromJson(Map<String, dynamic> json) {
    return WeightModifiers(
      cvssWeight: (json['cvss_weight'] as num?)?.toDouble() ?? 0.33,
      cisaKevWeight: (json['cisa_kev_weight'] as num?)?.toDouble() ?? 0.33,
      firstEpssWeight: (json['first_epss_weight'] as num?)?.toDouble() ?? 0.34,
    );
  }

  Map<String, dynamic> toJson() => {
        'cvss_weight': cvssWeight,
        'cisa_kev_weight': cisaKevWeight,
        'first_epss_weight': firstEpssWeight,
      };
}

class OrganisationFingerprint {
  final String orgName;
  final String orgId;
  final String sector;
  final String riskAppetite;
  final double cvssWeight;
  final double cisaKevWeight;
  final double firstEpssWeight;
  final String exposureImpact;
  final String criticalityImpact;
  final String priorityPhilosophy;

  OrganisationFingerprint({
    required this.orgName,
    required this.orgId,
    required this.sector,
    required this.riskAppetite,
    required this.cvssWeight,
    required this.cisaKevWeight,
    required this.firstEpssWeight,
    this.exposureImpact = "HIGH IMPACT (1.20x)",
    this.criticalityImpact = "HIGH IMPACT (1.20x)",
    required this.priorityPhilosophy,
  });

  factory OrganisationFingerprint.fromProfile(OrganizationProfile p) {
    final wKev = p.weightModifiers.cisaKevWeight;
    final wEpss = p.weightModifiers.firstEpssWeight;
    final wCvss = p.weightModifiers.cvssWeight;

    String philosophy;
    if (wKev >= wEpss && wKev >= wCvss && wKev >= 0.40) {
      philosophy =
          "Strong emphasis on known exploitation and active threat signals.";
    } else if (wEpss >= wKev && wEpss >= wCvss && wEpss >= 0.40) {
      philosophy =
          "Strong emphasis on forward-looking exploitation probability and weaponization likelihood.";
    } else if (wCvss >= wKev && wCvss >= wEpss && wCvss >= 0.40) {
      philosophy =
          "Strong emphasis on intrinsic technical severity and full compromise impact.";
    } else {
      philosophy =
          "Balanced threat-signal prioritisation across technical and active exploitation signals.";
    }

    return OrganisationFingerprint(
      orgName: p.name,
      orgId: p.orgId,
      sector: p.sector,
      riskAppetite: p.riskAppetite,
      cvssWeight: wCvss,
      cisaKevWeight: wKev,
      firstEpssWeight: wEpss,
      priorityPhilosophy: philosophy,
    );
  }
}

class OrganizationProfile {
  final String orgId;
  final String name;
  final String sector;
  final String riskAppetite;
  final WeightModifiers weightModifiers;
  final List<String> criticalProducts;

  OrganizationProfile({
    required this.orgId,
    required this.name,
    required this.sector,
    required this.riskAppetite,
    required this.weightModifiers,
    required this.criticalProducts,
  });

  OrganisationFingerprint get fingerprint =>
      OrganisationFingerprint.fromProfile(this);

  factory OrganizationProfile.fromJson(Map<String, dynamic> json) {
    final wmJson = json['weight_modifiers'] as Map<String, dynamic>? ?? {};
    final critList = (json['critical_products'] as List<dynamic>?)
            ?.map((e) => e.toString())
            .toList() ??
        [];

    return OrganizationProfile(
      orgId: json['org_id']?.toString() ?? 'ORG-CUSTOM',
      name: json['name']?.toString() ?? 'Custom Organization',
      sector: json['sector']?.toString() ?? 'General',
      riskAppetite: json['risk_appetite']?.toString() ?? 'Moderate',
      weightModifiers: WeightModifiers.fromJson(wmJson),
      criticalProducts: critList,
    );
  }

  Map<String, dynamic> toJson() => {
        'org_id': orgId,
        'name': name,
        'sector': sector,
        'risk_appetite': riskAppetite,
        'weight_modifiers': weightModifiers.toJson(),
        'critical_products': criticalProducts,
      };
}

class Vulnerability {
  final String cveId;
  final String productName;
  final double? cvssBaseScore;
  final bool cisaKev;
  final double? firstEpss;
  final Map<String, dynamic> rawData;

  Vulnerability({
    required this.cveId,
    required this.productName,
    this.cvssBaseScore,
    required this.cisaKev,
    this.firstEpss,
    this.rawData = const {},
  });

  bool get isValidCvss =>
      cvssBaseScore != null && cvssBaseScore! >= 0.0 && cvssBaseScore! <= 10.0;

  bool get isValidEpss =>
      firstEpss != null && firstEpss! >= 0.0 && firstEpss! <= 1.0;
}

class ScoreBreakdown {
  final double cvssBaseScore;
  final double cvssNormalized;
  final double cvssWeight;
  final double cvssContribution;
  final bool cisaKev;
  final double kevSignal;
  final double cisaKevWeight;
  final double kevContribution;
  final double firstEpss;
  final double epssSignal;
  final double firstEpssWeight;
  final double epssContribution;
  final double baseScore;
  final bool isCriticalProduct;
  final double criticalMultiplier;
  final double finalScore;

  // New Contextual Priority Fields
  final double technicalThreatScore;
  final double exposureMultiplier;
  final double importanceMultiplier;
  final double contextMultiplier;
  final double contextDelta;
  final double finalPriorityScore;

  ScoreBreakdown({
    required this.cvssBaseScore,
    required this.cvssNormalized,
    required this.cvssWeight,
    required this.cvssContribution,
    required this.cisaKev,
    required this.kevSignal,
    required this.cisaKevWeight,
    required this.kevContribution,
    required this.firstEpss,
    required this.epssSignal,
    required this.firstEpssWeight,
    required this.epssContribution,
    required this.baseScore,
    required this.isCriticalProduct,
    required this.criticalMultiplier,
    required this.finalScore,
    double? technicalThreatScore,
    double? exposureMultiplier,
    double? importanceMultiplier,
    double? contextMultiplier,
    double? contextDelta,
    double? finalPriorityScore,
  })  : technicalThreatScore = technicalThreatScore ?? baseScore,
        exposureMultiplier = exposureMultiplier ?? (isCriticalProduct ? 1.20 : 1.00),
        importanceMultiplier = importanceMultiplier ?? (isCriticalProduct ? 1.20 : 1.00),
        contextMultiplier = contextMultiplier ?? criticalMultiplier,
        contextDelta = contextDelta ?? (finalScore - baseScore),
        finalPriorityScore = finalPriorityScore ?? finalScore;
}

class CounterfactualOption {
  final String factor;
  final String multiplier;
  final double projectedScore;
  final String projectedPriority;

  CounterfactualOption({
    required this.factor,
    required this.multiplier,
    required this.projectedScore,
    required this.projectedPriority,
  });
}

class TriageResult {
  final int rank;
  final Vulnerability vulnerability;
  final ScoreBreakdown scoreBreakdown;
  final PriorityLevel priority;
  final String plainTitle;
  final String matchedContext;
  final List<String> whyThisMatters;
  final String safeNextAction;
  final ConfidenceLevel confidence;
  final String confidenceReason;
  final Map<String, dynamic> sourceInfo;
  final double? decisionMargin;
  final List<CounterfactualOption> whatWouldChangeDecision;

  TriageResult({
    required this.rank,
    required this.vulnerability,
    required this.scoreBreakdown,
    required this.priority,
    required this.plainTitle,
    required this.matchedContext,
    required this.whyThisMatters,
    required this.safeNextAction,
    required this.confidence,
    required this.confidenceReason,
    required this.sourceInfo,
    this.decisionMargin,
    this.whatWouldChangeDecision = const [],
  });
}

class NegativeTestItem {
  final Vulnerability vulnerability;
  final ScoreBreakdown scoreBreakdown;
  final int? rank;
  final int totalCandidates;
  final String reasonLowOrExcluded;

  NegativeTestItem({
    required this.vulnerability,
    required this.scoreBreakdown,
    this.rank,
    required this.totalCandidates,
    required this.reasonLowOrExcluded,
  });

  String get explanation => reasonLowOrExcluded;
  String get reason => reasonLowOrExcluded;
}

class CalibrationRecord {
  final String cveId;
  final String productName;
  final double cvssBaseScore;
  final bool cisaKev;
  final double firstEpss;
  final int? practitionerRankBank;
  final int? practitionerRankStartup;

  CalibrationRecord({
    required this.cveId,
    required this.productName,
    required this.cvssBaseScore,
    required this.cisaKev,
    required this.firstEpss,
    this.practitionerRankBank,
    this.practitionerRankStartup,
  });
}

class GoldSetEvaluationItem {
  final String cveId;
  final String productName;
  final double cvssBaseScore;
  final bool cisaKev;
  final double firstEpss;
  final ScoreBreakdown scoreBreakdown;
  final int engineRank;
  final int? practitionerRank;
  final int? rankDelta;
  final String notes;

  GoldSetEvaluationItem({
    required this.cveId,
    required this.productName,
    required this.cvssBaseScore,
    required this.cisaKev,
    required this.firstEpss,
    required this.scoreBreakdown,
    required this.engineRank,
    this.practitionerRank,
    this.rankDelta,
    required this.notes,
  });
}

class CalibrationReport {
  final String orgName;
  final String orgId;
  final List<GoldSetEvaluationItem> items;
  final double? spearmanCorrelation;
  final double? meanAbsoluteRankError;
  final String summaryText;

  CalibrationReport({
    required this.orgName,
    required this.orgId,
    required this.items,
    this.spearmanCorrelation,
    this.meanAbsoluteRankError,
    required this.summaryText,
  });
}

class ProfileComparisonItem {
  final String cveId;
  final String productName;
  final double cvssBaseScore;
  final bool cisaKev;
  final double firstEpss;
  final int? rankA;
  final double? scoreA;
  final bool isCriticalA;
  final int? rankB;
  final double? scoreB;
  final bool isCriticalB;
  final double scoreDelta;
  final int? rankDelta;
  final String driverSummary;

  ProfileComparisonItem({
    required this.cveId,
    required this.productName,
    required this.cvssBaseScore,
    required this.cisaKev,
    required this.firstEpss,
    this.rankA,
    this.scoreA,
    required this.isCriticalA,
    this.rankB,
    this.scoreB,
    required this.isCriticalB,
    required this.scoreDelta,
    this.rankDelta,
    required this.driverSummary,
  });
}

class ProfileComparisonReport {
  final OrganizationProfile orgA;
  final OrganizationProfile orgB;
  final List<TriageResult> top5A;
  final List<TriageResult> top5B;
  final List<ProfileComparisonItem> comparisonItems;
  final String overallNarrative;

  ProfileComparisonReport({
    required this.orgA,
    required this.orgB,
    required this.top5A,
    required this.top5B,
    required this.comparisonItems,
    required this.overallNarrative,
  });
}
