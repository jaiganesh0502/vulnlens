import 'package:flutter/material.dart';
import '../theme/app_theme.dart';
import 'home_screen.dart';

class JudgeDemoScreen extends StatefulWidget {
  const JudgeDemoScreen({super.key});

  @override
  State<JudgeDemoScreen> createState() => _JudgeDemoScreenState();
}

class _JudgeDemoScreenState extends State<JudgeDemoScreen> {
  int _currentStep = 0;

  final List<(String, String, String)> _steps = const [
    (
      'STEP 1: Select Global Retail Bank',
      'Start with a low risk-appetite financial institution.',
      'Demonstrates baseline configuration prioritizing active KEV exploitation on Core Banking assets.',
    ),
    (
      'STEP 2: Review Personalised Top 5',
      'Show the 5 actionable decision cards generated deterministically.',
      'Every card displays consequence title, matched context, and safe defensive action without fluff.',
    ),
    (
      'STEP 3: Inspect Card #1 Score Breakdown',
      'Open "Why This Matters" for #1 (CVE-2023-1262).',
      'Show the exact mathematical proof: CVSS pts + KEV pts + EPSS pts multiplied by 1.4 for critical asset tier.',
    ),
    (
      'STEP 4: Switch to Agile Cloud Tech Startup',
      'Switch to an organization with a 60% EPSS weight modifier.',
      'Notice how priorities immediately re-weight toward high 30-day exploitation likelihood.',
    ),
    (
      'STEP 5: Compare Multi-Org Rank Shifts',
      'Navigate to the Compare tab to show rank deltas side-by-side.',
      'Explain the exact weight modifiers and critical product mappings driving the divergence.',
    ),
    (
      'STEP 6: Demonstrate Negative Test ("Why Not?")',
      'Open Why Not? tab to highlight CVSS ≥ 9.0 flaws ranked low.',
      'Show that CVE-2026-2678 (CVSS 9.9) ranks #60+ due to zero KEV and non-critical asset tier. High CVSS ≠ High Priority!',
    ),
    (
      'STEP 7: Import Unseen Profile D',
      'Open Import Profile to ingest a healthcare organization profile JSON.',
      'Validates schema locally and proves zero hard-coding.',
    ),
    (
      'STEP 8: Verify Profile D Top 5 Generation',
      'Return to Home screen to see Profile D triaged immediately.',
      'Shows instant, offline triage without internet or server dependency.',
    ),
    (
      'STEP 9: Audit Source Provenance',
      'Open provenance links on any card to trace NIST NVD and CISA KEV catalog keys.',
      'Proves data integrity with zero invented or hallucinated fields.',
    ),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: VulnLensColors.bgPrimary,
      appBar: AppBar(
        backgroundColor: VulnLensColors.bgSecondary,
        elevation: 0,
        title: const Text(
          'Judge Demo Guide (3-Min Flow)',
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
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: VulnLensColors.bgSecondary,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: VulnLensColors.borderSubtle),
              ),
              child: const Row(
                children: [
                  Icon(Icons.play_circle_outline,
                      color: VulnLensColors.electricBlue, size: 22),
                  SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'Presenter Mode: Follow this structured 3-minute flow to demonstrate Personalisation, Explainability, Negative Testing, and Unseen Profile Ingestion.',
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: VulnLensColors.highlight,
                        height: 1.35,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),

            ...List.generate(_steps.length, (idx) {
              final step = _steps[idx];
              final isCurrent = idx == _currentStep;
              final isDone = idx < _currentStep;

              return Container(
                margin: const EdgeInsets.only(bottom: 12),
                decoration: BoxDecoration(
                  color: VulnLensColors.bgSecondary,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(
                    color: isCurrent
                        ? VulnLensColors.electricBlue
                        : (isDone
                            ? VulnLensColors.lowBorder
                            : VulnLensColors.borderSubtle),
                    width: isCurrent ? 2 : 1,
                  ),
                ),
                child: Theme(
                  data: Theme.of(context)
                      .copyWith(dividerColor: Colors.transparent),
                  child: ExpansionTile(
                    initiallyExpanded: isCurrent,
                    leading: CircleAvatar(
                      radius: 14,
                      backgroundColor: isDone
                          ? VulnLensColors.lowGreen
                          : (isCurrent
                              ? VulnLensColors.electricBlue
                              : VulnLensColors.bgPrimary),
                      child: Text(
                        '${idx + 1}',
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 12,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                    title: Text(
                      step.$1,
                      style: TextStyle(
                        fontSize: 13,
                        fontWeight:
                            isCurrent ? FontWeight.w800 : FontWeight.bold,
                        color: isCurrent
                            ? VulnLensColors.highlight
                            : Colors.white,
                      ),
                    ),
                    subtitle: Text(
                      step.$2,
                      style: const TextStyle(
                          fontSize: 12, color: VulnLensColors.textMuted),
                    ),
                    children: [
                      Padding(
                        padding: const EdgeInsets.fromLTRB(16, 0, 16, 14),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Container(
                              width: double.infinity,
                              padding: const EdgeInsets.all(12),
                              decoration: BoxDecoration(
                                color: VulnLensColors.bgPrimary,
                                borderRadius: BorderRadius.circular(8),
                                border: Border.all(
                                    color: VulnLensColors.borderSubtle),
                              ),
                              child: Text(
                                '💡 Goal: ${step.$3}',
                                style: const TextStyle(
                                  fontSize: 12,
                                  color: VulnLensColors.textSecondary,
                                  fontStyle: FontStyle.italic,
                                ),
                              ),
                            ),
                            const SizedBox(height: 10),
                            Row(
                              mainAxisAlignment: MainAxisAlignment.end,
                              children: [
                                if (idx > 0)
                                  TextButton(
                                    onPressed: () {
                                      setState(() {
                                        _currentStep = idx - 1;
                                      });
                                    },
                                    child: const Text('Previous',
                                        style: TextStyle(
                                            color: VulnLensColors.textMuted)),
                                  ),
                                ElevatedButton(
                                  onPressed: () {
                                    setState(() {
                                      if (idx < _steps.length - 1) {
                                        _currentStep = idx + 1;
                                      }
                                    });
                                  },
                                  style: ElevatedButton.styleFrom(
                                    backgroundColor: VulnLensColors.electricBlue,
                                    foregroundColor: Colors.white,
                                  ),
                                  child: Text(idx == _steps.length - 1
                                      ? 'Demo Complete'
                                      : 'Next Step'),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              );
            }),
          ],
        ),
      ),
    );
  }
}
