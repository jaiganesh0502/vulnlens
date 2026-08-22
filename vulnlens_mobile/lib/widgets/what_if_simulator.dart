import 'package:flutter/material.dart';
import '../models/models.dart';
import '../services/scorer.dart';
import '../theme/app_theme.dart';
import 'priority_badge.dart';

class WhatIfSimulator extends StatefulWidget {
  final Vulnerability vulnerability;
  final OrganizationProfile profile;

  const WhatIfSimulator({
    super.key,
    required this.vulnerability,
    required this.profile,
  });

  @override
  State<WhatIfSimulator> createState() => _WhatIfSimulatorState();
}

class _WhatIfSimulatorState extends State<WhatIfSimulator> {
  late bool _isCritical;
  late bool _isInternetFacing;

  @override
  void initState() {
    super.initState();
    _isCritical = widget.profile.criticalProducts.any((cp) =>
        widget.vulnerability.productName
            .toLowerCase()
            .contains(cp.toLowerCase()));
    _isInternetFacing = true;
  }

  @override
  Widget build(BuildContext context) {
    final v = widget.vulnerability;
    final p = widget.profile;

    // Simulation calculation
    final cvssNorm = (v.cvssBaseScore ?? 0.0) / 10.0;
    final kevSig = v.cisaKev ? 1.0 : 0.0;
    final epssSig = v.firstEpss ?? 0.0;

    // Simulate exposure factor adjustment (0.8x if internal only)
    final exposureFactor = _isInternetFacing ? 1.0 : 0.75;
    final baseScore = 100.0 *
        (p.weightModifiers.cvssWeight * cvssNorm +
            p.weightModifiers.cisaKevWeight * kevSig +
            p.weightModifiers.firstEpssWeight * epssSig) *
        exposureFactor;

    final multiplier = _isCritical ? 1.4 : 1.0;
    final simScore = baseScore * multiplier;
    final simPriority = determinePriorityLevel(simScore);

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: VulnLensColors.bgSecondary,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: VulnLensColors.electricBlue.withValues(alpha: 0.4)),
        boxShadow: [
          BoxShadow(
            color: VulnLensColors.bgGlow.withValues(alpha: 0.5),
            blurRadius: 16,
            spreadRadius: 2,
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(6),
                decoration: const BoxDecoration(
                  gradient: VulnLensColors.brandGradient,
                  shape: BoxShape.circle,
                ),
                child: const Icon(Icons.bolt, color: Colors.white, size: 16),
              ),
              const SizedBox(width: 10),
              const Text(
                'WHAT-IF CONTEXT SIMULATOR',
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w900,
                  color: Colors.white,
                  letterSpacing: 0.5,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),

          // Toggles
          Row(
            children: [
              Expanded(
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                  decoration: BoxDecoration(
                    color: VulnLensColors.bgPrimary,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: VulnLensColors.borderSubtle),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text(
                        'Exposure:',
                        style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
                      ),
                      Switch(
                        value: _isInternetFacing,
                        activeColor: VulnLensColors.electricBlue,
                        onChanged: (val) {
                          setState(() => _isInternetFacing = val);
                        },
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                  decoration: BoxDecoration(
                    color: VulnLensColors.bgPrimary,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: VulnLensColors.borderSubtle),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text(
                        'Critical Asset:',
                        style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
                      ),
                      Switch(
                        value: _isCritical,
                        activeColor: VulnLensColors.electricBlue,
                        onChanged: (val) {
                          setState(() => _isCritical = val);
                        },
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),

          // Transition Results Display
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
                    Row(
                      children: [
                        const Text(
                          'Technical CVSS: ',
                          style: TextStyle(fontSize: 11, color: VulnLensColors.textMuted),
                        ),
                        Text(
                          '${v.cvssBaseScore?.toStringAsFixed(1) ?? "0.0"} → ${v.cvssBaseScore?.toStringAsFixed(1) ?? "0.0"}',
                          style: const TextStyle(
                            fontSize: 12,
                            fontFamily: 'monospace',
                            fontWeight: FontWeight.bold,
                            color: VulnLensColors.highlight,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 3),
                    const Text(
                      '✓ Technical severity unchanged',
                      style: TextStyle(
                        fontSize: 10,
                        color: VulnLensColors.lowGreen,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const Text(
                      '✓ Organisational context changed',
                      style: TextStyle(
                        fontSize: 10,
                        color: VulnLensColors.electricBlue,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
                PriorityBadge(
                  priority: simPriority,
                  score: simScore,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
