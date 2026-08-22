import 'package:flutter/material.dart';
import '../models/models.dart';
import '../theme/app_theme.dart';
import 'home_screen.dart';

class CalibrationScreen extends StatelessWidget {
  const CalibrationScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = TriageScope.of(context);
    final profile = state.currentProfile;

    if (profile == null) {
      return const Scaffold(
        backgroundColor: VulnLensColors.bgPrimary,
        body: Center(child: Text('Please select an organisation profile.')),
      );
    }

    final report = state.runGoldSetCalibration(profile);

    return Scaffold(
      backgroundColor: VulnLensColors.bgPrimary,
      appBar: AppBar(
        backgroundColor: VulnLensColors.bgSecondary,
        elevation: 0,
        title: const Text(
          'Gold Set Calibration',
          style: TextStyle(
            fontWeight: FontWeight.w900,
            fontSize: 18,
          ),
        ),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Isolation Guarantee Notice
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: VulnLensColors.bgSecondary,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: VulnLensColors.lowBorder),
              ),
              child: const Row(
                children: [
                  Icon(Icons.verified_outlined,
                      color: VulnLensColors.lowGreen, size: 20),
                  SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'Isolated Calibration Baseline: gold_set.csv is never merged into the production vulnerability catalog.',
                      style: TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                        color: Color(0xFF6EE7B7),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),

            // Correlation Metrics Cards
            Row(
              children: [
                Expanded(
                  child: _buildMetricCard(
                    'Spearman Correlation (ρ)',
                    report.spearmanCorrelation != null
                        ? report.spearmanCorrelation!.toStringAsFixed(2)
                        : 'N/A',
                    '1.00 = Perfect Agreement',
                    VulnLensColors.lowGreen,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: _buildMetricCard(
                    'Mean Rank Error',
                    report.meanAbsoluteRankError != null
                        ? report.meanAbsoluteRankError!.toStringAsFixed(2)
                        : '0.00',
                    'Lower is better',
                    VulnLensColors.electricBlue,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 14),

            // Summary text
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: VulnLensColors.bgSecondary,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: VulnLensColors.borderSubtle),
              ),
              child: Text(
                report.summaryText,
                style: const TextStyle(
                  fontSize: 12,
                  color: VulnLensColors.textSecondary,
                  height: 1.3,
                ),
              ),
            ),
            const SizedBox(height: 18),

            const Text(
              'GROUND TRUTH CALIBRATION RECORDS',
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w900,
                color: VulnLensColors.textMuted,
                letterSpacing: 0.8,
              ),
            ),
            const SizedBox(height: 8),

            ...report.items.map((item) {
              final deltaStr = item.rankDelta != null
                  ? (item.rankDelta! >= 0
                      ? '+${item.rankDelta}'
                      : '${item.rankDelta}')
                  : '0';

              return Container(
                margin: const EdgeInsets.only(bottom: 10),
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: VulnLensColors.bgSecondary,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: VulnLensColors.borderSubtle),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(
                          item.cveId,
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontWeight: FontWeight.bold,
                            fontSize: 14,
                            color: VulnLensColors.electricBlue,
                          ),
                        ),
                        Row(
                          children: [
                            Text(
                              'Engine #${item.engineRank}',
                              style: const TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.bold,
                                color: Colors.white,
                              ),
                            ),
                            const Text(' vs ',
                                style: TextStyle(
                                    fontSize: 11,
                                    color: VulnLensColors.textMuted)),
                            Text(
                              'Practitioner #${item.practitionerRank ?? "?"}',
                              style: const TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.bold,
                                color: VulnLensColors.lowGreen,
                              ),
                            ),
                            const SizedBox(width: 8),
                            Container(
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 6, vertical: 2),
                              decoration: BoxDecoration(
                                color: item.rankDelta == 0
                                    ? VulnLensColors.lowBg
                                    : VulnLensColors.mediumBg,
                                borderRadius: BorderRadius.circular(4),
                                border: Border.all(
                                    color: item.rankDelta == 0
                                        ? VulnLensColors.lowBorder
                                        : VulnLensColors.mediumBorder,
                                    width: 0.5),
                              ),
                              child: Text(
                                'Δ $deltaStr',
                                style: TextStyle(
                                  fontSize: 10,
                                  fontWeight: FontWeight.bold,
                                  color: item.rankDelta == 0
                                      ? const Color(0xFF6EE7B7)
                                      : const Color(0xFFFDE68A),
                                ),
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      item.productName,
                      style: const TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                        color: Colors.white,
                      ),
                    ),
                    const SizedBox(height: 6),
                    Row(
                      children: [
                        Text(
                          'Score: ${item.scoreBreakdown.finalScore.toStringAsFixed(1)}',
                          style: const TextStyle(
                              fontSize: 12,
                              fontFamily: 'monospace',
                              fontWeight: FontWeight.bold,
                              color: VulnLensColors.highlight),
                        ),
                        const SizedBox(width: 12),
                        Text(
                          'CVSS ${item.cvssBaseScore} | KEV: ${item.cisaKev} | EPSS: ${(item.firstEpss * 100).toStringAsFixed(1)}%',
                          style: const TextStyle(
                              fontSize: 11, color: VulnLensColors.textMuted),
                        ),
                      ],
                    ),
                    const SizedBox(height: 6),
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 8, vertical: 4),
                      decoration: BoxDecoration(
                        color: VulnLensColors.bgPrimary,
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(
                        'Signals: ${item.notes}',
                        style: const TextStyle(
                          fontSize: 11,
                          color: VulnLensColors.textSecondary,
                          fontStyle: FontStyle.italic,
                        ),
                      ),
                    ),
                  ],
                ),
              );
            }),
          ],
        ),
      ),
    );
  }

  Widget _buildMetricCard(
      String label, String value, String subtitle, Color color) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: VulnLensColors.bgSecondary,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: VulnLensColors.borderSubtle),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            value,
            style: TextStyle(
              fontSize: 24,
              fontFamily: 'monospace',
              fontWeight: FontWeight.w900,
              color: color,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            label,
            style: const TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.bold,
              color: Colors.white,
            ),
          ),
          Text(
            subtitle,
            style: const TextStyle(
              fontSize: 10,
              color: VulnLensColors.textMuted,
            ),
          ),
        ],
      ),
    );
  }
}
