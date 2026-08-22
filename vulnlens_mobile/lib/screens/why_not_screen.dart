import 'package:flutter/material.dart';
import '../models/models.dart';
import '../theme/app_theme.dart';
import '../widgets/priority_badge.dart';
import 'home_screen.dart';

class WhyNotScreen extends StatefulWidget {
  const WhyNotScreen({super.key});

  @override
  State<WhyNotScreen> createState() => _WhyNotScreenState();
}

class _WhyNotScreenState extends State<WhyNotScreen> {
  String? _selectedCveId;
  String _searchQuery = '';

  @override
  Widget build(BuildContext context) {
    final state = TriageScope.of(context);
    final profile = state.currentProfile;
    final allRanked = state.currentAllRanked;
    final negCandidates = state.currentNegativeTestCandidates;

    if (profile == null) {
      return const Scaffold(
        backgroundColor: VulnLensColors.bgPrimary,
        body: Center(child: Text('Please select an organisation profile.')),
      );
    }

    if (_selectedCveId == null && negCandidates.isNotEmpty) {
      _selectedCveId = negCandidates.first.vulnerability.cveId;
    } else if (_selectedCveId == null && allRanked.isNotEmpty) {
      _selectedCveId = allRanked.first.vulnerability.cveId;
    }

    final inspectedResult = allRanked.firstWhere(
      (r) => r.vulnerability.cveId == _selectedCveId,
      orElse: () => allRanked.first,
    );

    final filteredCves = allRanked.where((r) {
      if (_searchQuery.isEmpty) return true;
      final q = _searchQuery.toLowerCase();
      return r.vulnerability.cveId.toLowerCase().contains(q) ||
          r.vulnerability.productName.toLowerCase().contains(q);
    }).toList();

    return Scaffold(
      backgroundColor: VulnLensColors.bgPrimary,
      appBar: AppBar(
        backgroundColor: VulnLensColors.bgSecondary,
        elevation: 0,
        title: const Text(
          'Why Not This CVE? (Negative Test)',
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
            // Core Principle Banner
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: VulnLensColors.bgSecondary,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: VulnLensColors.urgentBorder),
              ),
              child: const Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('🔴', style: TextStyle(fontSize: 20)),
                  SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'High CVSS ≠ High Priority',
                          style: TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.bold,
                            color: Colors.white,
                          ),
                        ),
                        SizedBox(height: 4),
                        Text(
                          'Sorting purely by theoretical severity floods teams with non-exploitable flaws on non-critical systems. Contextual exploitability (CISA KEV, EPSS) and asset criticality drive real operational priority.',
                          style: TextStyle(
                            fontSize: 12,
                            color: VulnLensColors.textSecondary,
                            height: 1.35,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),

            // Severe Flaws De-prioritized
            Text(
              'SEVERE FLAWS (CVSS ≥ 9.0) DE-PRIORITIZED FOR ${profile.name.toUpperCase()}',
              style: const TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w900,
                color: VulnLensColors.textMuted,
                letterSpacing: 0.8,
              ),
            ),
            const SizedBox(height: 10),

            if (negCandidates.isEmpty)
              const Text(
                'No severe CVSS ≥ 9.0 candidates were de-prioritized for this profile.',
                style: TextStyle(fontSize: 12, color: VulnLensColors.textMuted),
              )
            else
              SizedBox(
                height: 140,
                child: ListView.builder(
                  scrollDirection: Axis.horizontal,
                  itemCount: negCandidates.length,
                  itemBuilder: (context, idx) {
                    final item = negCandidates[idx];
                    final v = item.vulnerability;
                    final b = item.scoreBreakdown;
                    final isSelected = v.cveId == _selectedCveId;

                    return GestureDetector(
                      onTap: () {
                        setState(() {
                          _selectedCveId = v.cveId;
                        });
                      },
                      child: Container(
                        width: 220,
                        margin: const EdgeInsets.only(right: 12, bottom: 4),
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: isSelected
                              ? VulnLensColors.blueGlow
                              : VulnLensColors.bgSecondary,
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(
                            color: isSelected
                                ? VulnLensColors.electricBlue
                                : VulnLensColors.borderSubtle,
                            width: isSelected ? 2 : 1,
                          ),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Row(
                              mainAxisAlignment: MainAxisAlignment.spaceBetween,
                              children: [
                                Text(
                                  v.cveId,
                                  style: const TextStyle(
                                    fontFamily: 'monospace',
                                    fontWeight: FontWeight.bold,
                                    fontSize: 13,
                                    color: VulnLensColors.electricBlue,
                                  ),
                                ),
                                Container(
                                  padding: const EdgeInsets.symmetric(
                                      horizontal: 6, vertical: 2),
                                  decoration: BoxDecoration(
                                    color: VulnLensColors.urgentBg,
                                    borderRadius: BorderRadius.circular(4),
                                    border: Border.all(
                                        color: VulnLensColors.urgentBorder,
                                        width: 0.5),
                                  ),
                                  child: Text(
                                    'CVSS ${v.cvssBaseScore?.toStringAsFixed(1)}',
                                    style: const TextStyle(
                                      color: Color(0xFFFCA5A5),
                                      fontWeight: FontWeight.bold,
                                      fontSize: 10,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                            Text(
                              v.productName,
                              style: const TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.w600,
                                color: Colors.white,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                            Row(
                              mainAxisAlignment: MainAxisAlignment.spaceBetween,
                              children: [
                                Text(
                                  'Rank #${item.rank}',
                                  style: const TextStyle(
                                    fontSize: 12,
                                    fontWeight: FontWeight.w800,
                                    color: VulnLensColors.textMuted,
                                  ),
                                ),
                                Text(
                                  'Score: ${b.finalScore.toStringAsFixed(1)}',
                                  style: const TextStyle(
                                    fontSize: 12,
                                    fontFamily: 'monospace',
                                    fontWeight: FontWeight.bold,
                                    color: VulnLensColors.highlight,
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    );
                  },
                ),
              ),

            const SizedBox(height: 20),

            // Diagnostic Inspector Card
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
                  Row(
                    children: [
                      const Icon(Icons.analytics,
                          color: VulnLensColors.electricBlue, size: 20),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'WHY NOT RANKED HIGHER? — ${inspectedResult.vulnerability.cveId}',
                          style: const TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w900,
                            color: Colors.white,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 14),

                  // Signal Matrix
                  Row(
                    children: [
                      _buildSignalBox(
                        'Technical Severity',
                        'CVSS ${inspectedResult.vulnerability.cvssBaseScore?.toStringAsFixed(1) ?? "0.0"}',
                        (inspectedResult.vulnerability.cvssBaseScore ?? 0.0) >=
                                9.0
                            ? 'High Flaw'
                            : 'Moderate',
                        (inspectedResult.vulnerability.cvssBaseScore ?? 0.0) >=
                                9.0
                            ? VulnLensColors.urgentRed
                            : VulnLensColors.mediumAmber,
                      ),
                      const SizedBox(width: 8),
                      _buildSignalBox(
                        'CISA KEV',
                        inspectedResult.vulnerability.cisaKev
                            ? 'Active'
                            : 'None',
                        inspectedResult.vulnerability.cisaKev
                            ? 'Weaponized'
                            : '✕ No In-Wild Exploits',
                        inspectedResult.vulnerability.cisaKev
                            ? VulnLensColors.urgentRed
                            : VulnLensColors.textMuted,
                      ),
                      const SizedBox(width: 8),
                      _buildSignalBox(
                        'FIRST EPSS',
                        '${((inspectedResult.vulnerability.firstEpss ?? 0.0) * 100).toStringAsFixed(1)}%',
                        (inspectedResult.vulnerability.firstEpss ?? 0.0) >= 0.5
                            ? 'High Prob'
                            : '✕ Low Likelihood',
                        (inspectedResult.vulnerability.firstEpss ?? 0.0) >= 0.5
                            ? VulnLensColors.urgentRed
                            : VulnLensColors.textMuted,
                      ),
                      const SizedBox(width: 8),
                      _buildSignalBox(
                        'Critical Asset',
                        inspectedResult.scoreBreakdown.isCriticalProduct
                            ? 'Yes (×1.4)'
                            : '✕ Non-Critical',
                        inspectedResult.scoreBreakdown.isCriticalProduct
                            ? 'Crown Jewel'
                            : 'Standard Tier',
                        inspectedResult.scoreBreakdown.isCriticalProduct
                            ? VulnLensColors.lowGreen
                            : VulnLensColors.textMuted,
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),

                  // Final Decision Row
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: VulnLensColors.bgPrimary,
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: VulnLensColors.borderSubtle),
                    ),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text(
                              'TRIAGE DECISION',
                              style: TextStyle(
                                fontSize: 10,
                                fontWeight: FontWeight.bold,
                                color: VulnLensColors.textMuted,
                              ),
                            ),
                            Text(
                              inspectedResult.rank > 10
                                  ? 'DE-PRIORITIZED (Rank #${inspectedResult.rank})'
                                  : 'ACTIVE PRIORITY (Rank #${inspectedResult.rank})',
                              style: const TextStyle(
                                fontSize: 13,
                                fontWeight: FontWeight.w900,
                                color: Colors.white,
                              ),
                            ),
                          ],
                        ),
                        PriorityBadge(
                          priority: inspectedResult.priority,
                          score: inspectedResult.scoreBreakdown.finalScore,
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 14),

                  const Text(
                    'REASONING LOG:',
                    style: TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.w800,
                      color: VulnLensColors.textMuted,
                    ),
                  ),
                  const SizedBox(height: 6),
                  ...inspectedResult.whyThisMatters.map(
                    (factor) => Padding(
                      padding: const EdgeInsets.symmetric(vertical: 2.0),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text('• ',
                              style: TextStyle(
                                  color: VulnLensColors.highlight,
                                  fontWeight: FontWeight.bold)),
                          Expanded(
                            child: Text(
                              factor,
                              style: const TextStyle(
                                fontSize: 12,
                                color: VulnLensColors.textSecondary,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),

            // Search catalog
            const Text(
              'INSPECT ANY CVE IN CATALOG',
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w900,
                color: VulnLensColors.textMuted,
                letterSpacing: 0.8,
              ),
            ),
            const SizedBox(height: 6),
            TextField(
              style: const TextStyle(color: Colors.white),
              decoration: InputDecoration(
                hintText: 'Search CVE ID or product name...',
                hintStyle: const TextStyle(color: VulnLensColors.textMuted),
                prefixIcon: const Icon(Icons.search,
                    color: VulnLensColors.textMuted, size: 20),
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: const BorderSide(color: VulnLensColors.borderSubtle),
                ),
                enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: const BorderSide(color: VulnLensColors.borderSubtle),
                ),
                filled: true,
                fillColor: VulnLensColors.bgSecondary,
              ),
              onChanged: (val) {
                setState(() {
                  _searchQuery = val;
                });
              },
            ),
            const SizedBox(height: 8),

            Container(
              height: 220,
              decoration: BoxDecoration(
                color: VulnLensColors.bgSecondary,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: VulnLensColors.borderSubtle),
              ),
              child: ListView.separated(
                itemCount: filteredCves.length,
                separatorBuilder: (_, __) =>
                    const Divider(height: 1, color: VulnLensColors.borderSubtle),
                itemBuilder: (context, idx) {
                  final item = filteredCves[idx];
                  final isSelected =
                      item.vulnerability.cveId == _selectedCveId;

                  return ListTile(
                    dense: true,
                    selected: isSelected,
                    selectedTileColor: VulnLensColors.blueGlow,
                    title: Text(
                      '${item.vulnerability.cveId} - ${item.vulnerability.productName}',
                      style: TextStyle(
                        fontFamily: 'monospace',
                        fontWeight:
                            isSelected ? FontWeight.bold : FontWeight.normal,
                        fontSize: 12,
                        color: isSelected
                            ? VulnLensColors.highlight
                            : Colors.white,
                      ),
                    ),
                    subtitle: Text(
                      'CVSS: ${item.vulnerability.cvssBaseScore?.toStringAsFixed(1) ?? "0.0"} | KEV: ${item.vulnerability.cisaKev} | Score: ${item.scoreBreakdown.finalScore.toStringAsFixed(1)} (Rank #${item.rank})',
                      style: const TextStyle(
                          fontSize: 11, color: VulnLensColors.textMuted),
                    ),
                    trailing: Text(
                      '#${item.rank}',
                      style: const TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 13,
                        color: VulnLensColors.textMuted,
                      ),
                    ),
                    onTap: () {
                      setState(() {
                        _selectedCveId = item.vulnerability.cveId;
                      });
                    },
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSignalBox(
      String title, String value, String tag, Color tagColor) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 8),
        decoration: BoxDecoration(
          color: VulnLensColors.bgPrimary,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: VulnLensColors.borderSubtle),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            Text(
              title,
              textAlign: TextAlign.center,
              style: const TextStyle(
                fontSize: 10,
                color: VulnLensColors.textMuted,
                fontWeight: FontWeight.w600,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 4),
            Text(
              value,
              textAlign: TextAlign.center,
              style: const TextStyle(
                fontSize: 11,
                fontFamily: 'monospace',
                fontWeight: FontWeight.bold,
                color: Colors.white,
              ),
            ),
            const SizedBox(height: 2),
            Text(
              tag,
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.w800,
                color: tagColor,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}
