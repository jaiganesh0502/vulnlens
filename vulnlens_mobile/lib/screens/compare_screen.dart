import 'package:flutter/material.dart';
import '../state/triage_state.dart';
import '../theme/app_theme.dart';

class CompareScreen extends StatefulWidget {
  const CompareScreen({super.key});

  @override
  State<CompareScreen> createState() => _CompareScreenState();
}

class _CompareScreenState extends State<CompareScreen> {
  int _orgAIdx = 0;
  int _orgBIdx = 1;

  @override
  Widget build(BuildContext context) {
    final state = TriageScope.of(context);
    final profiles = state.profiles;

    if (profiles.length < 2) {
      return const Scaffold(
        backgroundColor: VulnLensColors.bgPrimary,
        body: Center(child: Text('At least 2 profiles required for comparison.')),
      );
    }

    if (_orgAIdx >= profiles.length) _orgAIdx = 0;
    if (_orgBIdx >= profiles.length) _orgBIdx = 1;

    final orgA = profiles[_orgAIdx];
    final orgB = profiles[_orgBIdx];

    final report = state.compareTwoProfiles(orgA, orgB);

    return Scaffold(
      backgroundColor: VulnLensColors.bgPrimary,
      appBar: AppBar(
        backgroundColor: VulnLensColors.bgSecondary,
        elevation: 0,
        title: const Text(
          'Compare Organisations',
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
            // Dropdowns to select Org A and Org B
            Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'ORGANISATION A',
                        style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.bold,
                          color: VulnLensColors.textMuted,
                        ),
                      ),
                      const SizedBox(height: 4),
                      DropdownButtonFormField<int>(
                        value: _orgAIdx,
                        isExpanded: true,
                        dropdownColor: VulnLensColors.bgSecondary,
                        decoration: InputDecoration(
                          contentPadding: const EdgeInsets.symmetric(
                              horizontal: 8, vertical: 8),
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(8),
                            borderSide:
                                const BorderSide(color: VulnLensColors.borderSubtle),
                          ),
                          filled: true,
                          fillColor: VulnLensColors.bgPrimary,
                        ),
                        items: List.generate(profiles.length, (i) {
                          return DropdownMenuItem<int>(
                            value: i,
                            child: Text(
                              profiles[i].name,
                              style: const TextStyle(
                                  fontSize: 12,
                                  fontWeight: FontWeight.bold,
                                  color: Colors.white),
                              overflow: TextOverflow.ellipsis,
                            ),
                          );
                        }),
                        onChanged: (val) {
                          if (val != null) setState(() => _orgAIdx = val);
                        },
                      ),
                    ],
                  ),
                ),
                const Padding(
                  padding:
                      EdgeInsets.symmetric(horizontal: 8.0, vertical: 16.0),
                  child: Icon(Icons.compare_arrows,
                      color: VulnLensColors.electricBlue, size: 24),
                ),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'ORGANISATION B',
                        style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.bold,
                          color: VulnLensColors.textMuted,
                        ),
                      ),
                      const SizedBox(height: 4),
                      DropdownButtonFormField<int>(
                        value: _orgBIdx,
                        isExpanded: true,
                        dropdownColor: VulnLensColors.bgSecondary,
                        decoration: InputDecoration(
                          contentPadding: const EdgeInsets.symmetric(
                              horizontal: 8, vertical: 8),
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(8),
                            borderSide:
                                const BorderSide(color: VulnLensColors.borderSubtle),
                          ),
                          filled: true,
                          fillColor: VulnLensColors.bgPrimary,
                        ),
                        items: List.generate(profiles.length, (i) {
                          return DropdownMenuItem<int>(
                            value: i,
                            child: Text(
                              profiles[i].name,
                              style: const TextStyle(
                                  fontSize: 12,
                                  fontWeight: FontWeight.bold,
                                  color: Colors.white),
                              overflow: TextOverflow.ellipsis,
                            ),
                          );
                        }),
                        onChanged: (val) {
                          if (val != null) setState(() => _orgBIdx = val);
                        },
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),

            // Weights comparison card
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: VulnLensColors.bgSecondary,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: VulnLensColors.borderSubtle),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'WEIGHT & CONTEXT COMPARISON',
                    style: TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.w800,
                      color: VulnLensColors.textMuted,
                      letterSpacing: 0.8,
                    ),
                  ),
                  const SizedBox(height: 12),
                  _buildWeightRow(
                    'CVSS Technical Severity',
                    '${(orgA.weightModifiers.cvssWeight * 100).toInt()}%',
                    '${(orgB.weightModifiers.cvssWeight * 100).toInt()}%',
                  ),
                  _buildWeightRow(
                    'CISA KEV Exploitation',
                    '${(orgA.weightModifiers.cisaKevWeight * 100).toInt()}%',
                    '${(orgB.weightModifiers.cisaKevWeight * 100).toInt()}%',
                  ),
                  _buildWeightRow(
                    'FIRST EPSS Likelihood',
                    '${(orgA.weightModifiers.firstEpssWeight * 100).toInt()}%',
                    '${(orgB.weightModifiers.firstEpssWeight * 100).toInt()}%',
                  ),
                  const Divider(height: 20),
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              '${orgA.name} Critical:',
                              style: const TextStyle(
                                  fontSize: 11,
                                  fontWeight: FontWeight.bold,
                                  color: Colors.white),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              orgA.criticalProducts.join(', '),
                              style: const TextStyle(
                                  fontSize: 11, color: Color(0xFF6EE7B7)),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              '${orgB.name} Critical:',
                              style: const TextStyle(
                                  fontSize: 11,
                                  fontWeight: FontWeight.bold,
                                  color: Colors.white),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              orgB.criticalProducts.join(', '),
                              style: const TextStyle(
                                  fontSize: 11, color: Color(0xFF6EE7B7)),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),

            // Narrative Banner
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: VulnLensColors.bgPrimary,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                    color: VulnLensColors.electricBlue.withOpacity(0.4)),
              ),
              child: Text(
                report.overallNarrative,
                style: const TextStyle(
                  fontSize: 12,
                  color: VulnLensColors.highlight,
                  height: 1.35,
                ),
              ),
            ),
            const SizedBox(height: 20),

            // Prioritization Shift Analysis
            const Text(
              'PRIORITIZATION SHIFT ANALYSIS',
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w900,
                color: Colors.white,
                letterSpacing: 0.8,
              ),
            ),
            const SizedBox(height: 8),

            ...report.comparisonItems.map((ci) {
              final rankAStr = ci.rankA != null ? '#${ci.rankA}' : 'N/A';
              final rankBStr = ci.rankB != null ? '#${ci.rankB}' : 'N/A';
              final deltaStr =
                  ci.scoreDelta >= 0 ? '+${ci.scoreDelta}' : '${ci.scoreDelta}';

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
                      children: [
                        Text(
                          ci.cveId,
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontWeight: FontWeight.bold,
                            fontSize: 14,
                            color: VulnLensColors.electricBlue,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            ci.productName,
                            style: const TextStyle(
                              fontSize: 13,
                              fontWeight: FontWeight.w600,
                              color: Colors.white,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(
                          '${orgA.name.split(" ").first}: $rankAStr (${ci.scoreA?.toStringAsFixed(1) ?? "0.0"} pts)',
                          style: const TextStyle(
                              fontSize: 11,
                              fontWeight: FontWeight.bold,
                              color: VulnLensColors.textSecondary),
                        ),
                        const Icon(Icons.arrow_forward,
                            size: 14, color: VulnLensColors.textMuted),
                        Text(
                          '${orgB.name.split(" ").first}: $rankBStr (${ci.scoreB?.toStringAsFixed(1) ?? "0.0"} pts)',
                          style: const TextStyle(
                              fontSize: 11,
                              fontWeight: FontWeight.bold,
                              color: Colors.white),
                        ),
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: ci.scoreDelta >= 0
                                ? VulnLensColors.lowBg
                                : VulnLensColors.urgentBg,
                            borderRadius: BorderRadius.circular(4),
                            border: Border.all(
                                color: ci.scoreDelta >= 0
                                    ? VulnLensColors.lowBorder
                                    : VulnLensColors.urgentBorder,
                                width: 0.5),
                          ),
                          child: Text(
                            '$deltaStr pts',
                            style: TextStyle(
                              fontSize: 11,
                              fontFamily: 'monospace',
                              fontWeight: FontWeight.bold,
                              color: ci.scoreDelta >= 0
                                  ? const Color(0xFF6EE7B7)
                                  : const Color(0xFFFCA5A5),
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: VulnLensColors.bgPrimary,
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: Text(
                        '💡 Why did this change? ${ci.driverSummary}',
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

  Widget _buildWeightRow(String label, String wtA, String wtB) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4.0),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label,
              style: const TextStyle(
                  fontSize: 12, color: VulnLensColors.textSecondary)),
          Row(
            children: [
              Text(wtA,
                  style: const TextStyle(
                      fontSize: 12,
                      fontFamily: 'monospace',
                      fontWeight: FontWeight.bold,
                      color: Colors.white)),
              const Text(' vs ',
                  style: TextStyle(
                      fontSize: 11, color: VulnLensColors.textMuted)),
              Text(wtB,
                  style: const TextStyle(
                      fontSize: 12,
                      fontFamily: 'monospace',
                      fontWeight: FontWeight.bold,
                      color: VulnLensColors.highlight)),
            ],
          ),
        ],
      ),
    );
  }
}
