import 'package:flutter/material.dart';
import '../models/models.dart';
import '../state/triage_state.dart';
export '../state/triage_state.dart';
import '../theme/app_theme.dart';
import '../widgets/offline_status_badge.dart';
import '../widgets/priority_badge.dart';
import '../widgets/vulnlens_logo.dart';
import 'about_screen.dart';
import 'import_profile_screen.dart';
import 'vulnerability_detail_dialog.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = TriageScope.of(context);

    if (state.isLoading) {
      return const Scaffold(
        backgroundColor: VulnLensColors.bgPrimary,
        body: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              CircularProgressIndicator(color: VulnLensColors.electricBlue),
              SizedBox(height: 16),
              Text(
                'Initializing offline vulnerability engine...',
                style: TextStyle(color: VulnLensColors.textSecondary),
              ),
            ],
          ),
        ),
      );
    }

    if (state.errorMessage != null) {
      return Scaffold(
        backgroundColor: VulnLensColors.bgPrimary,
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24.0),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.error_outline,
                    color: VulnLensColors.urgentRed, size: 48),
                const SizedBox(height: 12),
                Text(
                  state.errorMessage!,
                  textAlign: TextAlign.center,
                  style: const TextStyle(color: VulnLensColors.urgentRed),
                ),
                const SizedBox(height: 16),
                ElevatedButton(
                  onPressed: () => state.initialize(),
                  child: const Text('Retry'),
                ),
              ],
            ),
          ),
        ),
      );
    }

    final currentProfile = state.currentProfile;
    final top5 = state.currentTop5;

    return Scaffold(
      backgroundColor: VulnLensColors.bgPrimary,
      appBar: AppBar(
        backgroundColor: VulnLensColors.bgSecondary,
        elevation: 0,
        title: const VulnLensLogo(size: 32, fontSize: 18),
        actions: [
          const OfflineStatusBadge(),
          IconButton(
            icon: const Icon(Icons.info_outline,
                color: VulnLensColors.textMuted),
            onPressed: () {
              Navigator.of(context).push(
                MaterialPageRoute(builder: (_) => const AboutScreen()),
              );
            },
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Organisation Selector Dropdown Card
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: VulnLensColors.bgSecondary,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: VulnLensColors.borderSubtle),
                boxShadow: [
                  BoxShadow(
                    color: VulnLensColors.blueGlow.withOpacity(0.3),
                    blurRadius: 12,
                    offset: const Offset(0, 4),
                  ),
                ],
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text(
                        'TARGET ORGANISATION',
                        style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w800,
                          color: VulnLensColors.electricBlue,
                          letterSpacing: 0.8,
                        ),
                      ),
                      TextButton.icon(
                        onPressed: () async {
                          final added = await Navigator.of(context).push<bool>(
                            MaterialPageRoute(
                              builder: (_) => const ImportProfileScreen(),
                            ),
                          );
                          if (added == true && context.mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                content: Text('New profile added!'),
                                backgroundColor: VulnLensColors.lowGreen,
                              ),
                            );
                          }
                        },
                        icon: const Icon(Icons.add, size: 14),
                        label: const Text('Add Profile',
                            style: TextStyle(fontSize: 11)),
                        style: TextButton.styleFrom(
                          foregroundColor: VulnLensColors.highlight,
                          padding: EdgeInsets.zero,
                          minimumSize: Size.zero,
                          tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  DropdownButtonHideUnderline(
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 12),
                      decoration: BoxDecoration(
                        color: VulnLensColors.bgPrimary,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(
                            color: VulnLensColors.electricBlue
                                .withOpacity(0.4)),
                      ),
                      child: DropdownButton<String>(
                        value: currentProfile?.orgId,
                        isExpanded: true,
                        dropdownColor: VulnLensColors.bgSecondary,
                        icon: const Icon(Icons.keyboard_arrow_down,
                            color: VulnLensColors.electricBlue),
                        items: state.profiles.map((p) {
                          return DropdownMenuItem<String>(
                            value: p.orgId,
                            child: Text(
                              '${p.name} (${p.orgId})',
                              style: const TextStyle(
                                fontWeight: FontWeight.w700,
                                fontSize: 13,
                                color: Colors.white,
                              ),
                            ),
                          );
                        }).toList(),
                        onChanged: (newId) {
                          if (newId != null) {
                            state.selectProfileById(newId);
                          }
                        },
                      ),
                    ),
                  ),
                  if (currentProfile != null) ...[
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        _buildTag(
                          currentProfile.sector,
                          VulnLensColors.bgPrimary,
                          VulnLensColors.highlight,
                        ),
                        const SizedBox(width: 8),
                        _buildTag(
                          'Risk: ${currentProfile.riskAppetite}',
                          VulnLensColors.bgPrimary,
                          VulnLensColors.mediumAmber,
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceAround,
                      children: [
                        _buildWeightMetric(
                          'CVSS Wt',
                          '${(currentProfile.weightModifiers.cvssWeight * 100).toInt()}%',
                        ),
                        _buildWeightMetric(
                          'KEV Wt',
                          '${(currentProfile.weightModifiers.cisaKevWeight * 100).toInt()}%',
                        ),
                        _buildWeightMetric(
                          'EPSS Wt',
                          '${(currentProfile.weightModifiers.firstEpssWeight * 100).toInt()}%',
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: VulnLensColors.bgPrimary,
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: Text(
                        '💡 "${currentProfile.fingerprint.priorityPhilosophy}"',
                        style: const TextStyle(
                          fontSize: 11,
                          fontStyle: FontStyle.italic,
                          color: VulnLensColors.highlight,
                        ),
                      ),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 20),

            // Top 5 Header
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Text(
                  'YOUR TOP 5 PRIORITIES',
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w900,
                    color: VulnLensColors.textPrimary,
                    letterSpacing: 0.8,
                  ),
                ),
                Text(
                  '${state.vulnerabilities.length} records analysed',
                  style: const TextStyle(
                    fontSize: 12,
                    color: VulnLensColors.textMuted,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),

            if (top5.isEmpty)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: VulnLensColors.bgSecondary,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: VulnLensColors.borderSubtle),
                ),
                child: const Text(
                  'Nothing matched this profile in the supplied data.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: VulnLensColors.textMuted),
                ),
              )
            else
              ...top5.map((result) =>
                  _buildVulnerabilityCard(context, result, currentProfile!)),
          ],
        ),
      ),
    );
  }

  Widget _buildVulnerabilityCard(
    BuildContext context,
    TriageResult result,
    OrganizationProfile profile,
  ) {
    final v = result.vulnerability;
    final b = result.scoreBreakdown;

    Color leftBorderColor;
    switch (result.priority) {
      case PriorityLevel.urgent:
        leftBorderColor = VulnLensColors.urgentRed;
        break;
      case PriorityLevel.high:
        leftBorderColor = VulnLensColors.highOrange;
        break;
      case PriorityLevel.medium:
        leftBorderColor = VulnLensColors.mediumAmber;
        break;
      case PriorityLevel.low:
        leftBorderColor = VulnLensColors.lowGreen;
        break;
    }

    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      decoration: BoxDecoration(
        color: VulnLensColors.bgSecondary,
        borderRadius: BorderRadius.circular(14),
        border: Border(
          top: const BorderSide(color: VulnLensColors.borderSubtle, width: 1),
          right: const BorderSide(color: VulnLensColors.borderSubtle, width: 1),
          bottom: const BorderSide(color: VulnLensColors.borderSubtle, width: 1),
          left: BorderSide(color: leftBorderColor, width: 4),
        ),
        boxShadow: [
          BoxShadow(
            color: VulnLensColors.blueGlow.withOpacity(0.2),
            blurRadius: 10,
            offset: const Offset(0, 3),
          ),
        ],
      ),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Top Header Row
            Row(
              children: [
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: VulnLensColors.bgPrimary,
                    borderRadius: BorderRadius.circular(6),
                    border: Border.all(color: VulnLensColors.borderSubtle),
                  ),
                  child: Text(
                    '#${result.rank}',
                    style: const TextStyle(
                      color: VulnLensColors.highlight,
                      fontWeight: FontWeight.w900,
                      fontSize: 13,
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                Text(
                  v.cveId,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontWeight: FontWeight.bold,
                    fontSize: 16,
                    color: VulnLensColors.electricBlue,
                  ),
                ),
                const Spacer(),
                PriorityBadge(priority: result.priority, score: b.finalPriorityScore),
              ],
            ),
            const SizedBox(height: 10),

            // Product Name
            Text(
              v.productName,
              style: const TextStyle(
                fontSize: 15,
                fontWeight: FontWeight.w700,
                color: Colors.white,
              ),
            ),
            const SizedBox(height: 4),

            // Plain Language Title
            Text(
              result.plainTitle,
              style: const TextStyle(
                fontSize: 13,
                color: VulnLensColors.textSecondary,
                fontWeight: FontWeight.w500,
              ),
            ),
            const SizedBox(height: 10),

            // Contextual Priority Metrics Row
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
              decoration: BoxDecoration(
                color: VulnLensColors.bgPrimary,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: VulnLensColors.borderSubtle, width: 0.5),
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceAround,
                children: [
                  _buildMetricCell('THREAT', b.technicalThreatScore.toStringAsFixed(1), Colors.white),
                  _buildMetricCell('CONTEXT', '×${b.contextMultiplier.toStringAsFixed(2)}', VulnLensColors.highlight),
                  _buildMetricCell('DELTA', '+${b.contextDelta.toStringAsFixed(1)}', VulnLensColors.lowGreen),
                  _buildMetricCell('PRIORITY', b.finalPriorityScore.toStringAsFixed(1), VulnLensColors.electricBlue),
                ],
              ),
            ),
            const SizedBox(height: 10),

            // Technical Telemetry Chips Row
            Row(
              children: [
                _buildTechChip(
                  'CVSS',
                  v.cvssBaseScore?.toStringAsFixed(1) ?? '0.0',
                  (v.cvssBaseScore ?? 0.0) >= 9.0
                      ? VulnLensColors.urgentRed
                      : VulnLensColors.highlight,
                ),
                const SizedBox(width: 8),
                _buildTechChip(
                  'KEV',
                  v.cisaKev ? 'YES' : 'NO',
                  v.cisaKev
                      ? VulnLensColors.urgentRed
                      : VulnLensColors.textMuted,
                ),
                const SizedBox(width: 8),
                _buildTechChip(
                  'EPSS',
                  '${((v.firstEpss ?? 0.0) * 100).toStringAsFixed(1)}%',
                  (v.firstEpss ?? 0.0) >= 0.5
                      ? VulnLensColors.urgentRed
                      : VulnLensColors.highlight,
                ),
                if (result.decisionMargin != null) ...[
                  const Spacer(),
                  Text(
                    'Margin: +${result.decisionMargin} vs #${result.rank + 1}',
                    style: const TextStyle(
                      fontSize: 10,
                      fontFamily: 'monospace',
                      color: VulnLensColors.highlight,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ],
            ),
            const SizedBox(height: 12),

            // Bottom action row
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Row(
                  children: [
                    const Text(
                      'Confidence: ',
                      style: TextStyle(
                          fontSize: 12, color: VulnLensColors.textMuted),
                    ),
                    Text(
                      result.confidence.label,
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                        color: result.confidence == ConfidenceLevel.high
                            ? VulnLensColors.lowGreen
                            : VulnLensColors.mediumAmber,
                      ),
                    ),
                  ],
                ),
                ElevatedButton.icon(
                  onPressed: () {
                    showDialog(
                      context: context,
                      builder: (_) => VulnerabilityDetailDialog(
                        result: result,
                        profile: profile,
                      ),
                    );
                  },
                  icon: const Icon(Icons.analytics_outlined, size: 16),
                  label: const Text('Why This Matters'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: VulnLensColors.electricBlue,
                    foregroundColor: Colors.white,
                    elevation: 0,
                    padding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 8),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildMetricCell(String label, String value, Color color) {
    return Column(
      children: [
        Text(
          label,
          style: const TextStyle(
            fontSize: 9,
            fontWeight: FontWeight.w800,
            color: VulnLensColors.textMuted,
            letterSpacing: 0.5,
          ),
        ),
        const SizedBox(height: 2),
        Text(
          value,
          style: TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.w900,
            fontFamily: 'monospace',
            color: color,
          ),
        ),
      ],
    );
  }

  Widget _buildTechChip(String label, String value, Color valColor) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: VulnLensColors.bgPrimary,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: VulnLensColors.borderSubtle, width: 0.5),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            '$label: ',
            style: const TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.bold,
              color: VulnLensColors.textMuted,
            ),
          ),
          Text(
            value,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w800,
              color: valColor,
              fontFamily: 'monospace',
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTag(String text, Color bg, Color textCol) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: textCol.withOpacity(0.3)),
      ),
      child: Text(
        text,
        style: TextStyle(
          fontSize: 11,
          fontWeight: FontWeight.bold,
          color: textCol,
        ),
      ),
    );
  }

  Widget _buildWeightMetric(String label, String val) {
    return Column(
      children: [
        Text(
          label,
          style: const TextStyle(
            fontSize: 11,
            color: VulnLensColors.textMuted,
            fontWeight: FontWeight.w500,
          ),
        ),
        const SizedBox(height: 2),
        Text(
          val,
          style: const TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w800,
            color: VulnLensColors.highlight,
            fontFamily: 'monospace',
          ),
        ),
      ],
    );
  }
}
