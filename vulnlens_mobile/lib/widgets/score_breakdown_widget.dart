import 'package:flutter/material.dart';
import '../models/models.dart';
import '../theme/app_theme.dart';

class ScoreBreakdownWidget extends StatelessWidget {
  final ScoreBreakdown breakdown;
  final OrganizationProfile profile;

  const ScoreBreakdownWidget({
    super.key,
    required this.breakdown,
    required this.profile,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'PRIORITY CONTRIBUTION BREAKDOWN',
          style: TextStyle(
            fontSize: 11,
            fontWeight: FontWeight.w900,
            color: VulnLensColors.textMuted,
            letterSpacing: 0.8,
          ),
        ),
        const SizedBox(height: 12),
        _buildProgressBar(
          'Confirmed Exploitation (CISA KEV)',
          breakdown.kevContribution,
          100 * profile.weightModifiers.cisaKevWeight,
          'Weight: ${(profile.weightModifiers.cisaKevWeight * 100).toInt()}% | Signal: ${breakdown.kevSignal.toInt()}',
        ),
        _buildProgressBar(
          'Exploit Probability (FIRST EPSS)',
          breakdown.epssContribution,
          100 * profile.weightModifiers.firstEpssWeight,
          'Weight: ${(profile.weightModifiers.firstEpssWeight * 100).toInt()}% | Likelihood: ${(breakdown.epssSignal * 100).toStringAsFixed(1)}%',
        ),
        _buildProgressBar(
          'Technical Severity (NVD CVSS)',
          breakdown.cvssContribution,
          100 * profile.weightModifiers.cvssWeight,
          'Weight: ${(profile.weightModifiers.cvssWeight * 100).toInt()}% | Score: ${(breakdown.cvssNormalized * 10).toStringAsFixed(1)} / 10',
        ),
        const SizedBox(height: 10),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: VulnLensColors.bgPrimary,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(
              color: breakdown.isCriticalProduct
                  ? VulnLensColors.emblemBlue
                  : VulnLensColors.borderSubtle,
            ),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    breakdown.isCriticalProduct
                        ? '⭐ Critical Core Asset Tier (×1.4 Multiplier)'
                        : 'Standard Asset Tier (×1.0 Multiplier)',
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w700,
                      color: breakdown.isCriticalProduct
                          ? VulnLensColors.highlight
                          : VulnLensColors.textSecondary,
                    ),
                  ),
                  Text(
                    'Base Score: ${breakdown.baseScore.toStringAsFixed(1)} pts',
                    style: const TextStyle(
                      fontSize: 11,
                      color: VulnLensColors.textMuted,
                    ),
                  ),
                ],
              ),
              Text(
                breakdown.finalScore.toStringAsFixed(1),
                style: const TextStyle(
                  fontSize: 22,
                  fontFamily: 'monospace',
                  fontWeight: FontWeight.w900,
                  color: Colors.white,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildProgressBar(
      String label, double value, double maxVal, String subtitle) {
    final pct = maxVal > 0 ? (value / maxVal).clamp(0.0, 1.0) : 0.0;

    return Padding(
      padding: const EdgeInsets.only(bottom: 12.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                label,
                style: const TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  color: VulnLensColors.textSecondary,
                ),
              ),
              Text(
                '+${value.toStringAsFixed(1)} pts',
                style: const TextStyle(
                  fontSize: 12,
                  fontFamily: 'monospace',
                  fontWeight: FontWeight.w800,
                  color: VulnLensColors.highlight,
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          Container(
            height: 8,
            width: double.infinity,
            decoration: BoxDecoration(
              color: VulnLensColors.bgPrimary,
              borderRadius: BorderRadius.circular(4),
              border: Border.all(color: VulnLensColors.borderSubtle, width: 0.5),
            ),
            child: FractionallySizedBox(
              alignment: Alignment.centerLeft,
              widthFactor: pct,
              child: Container(
                decoration: BoxDecoration(
                  gradient: VulnLensColors.brandGradient,
                  borderRadius: BorderRadius.circular(4),
                ),
              ),
            ),
          ),
          const SizedBox(height: 2),
          Text(
            subtitle,
            style: const TextStyle(fontSize: 10, color: VulnLensColors.textMuted),
          ),
        ],
      ),
    );
  }
}
