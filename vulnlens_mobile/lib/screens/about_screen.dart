import 'package:flutter/material.dart';
import '../theme/app_theme.dart';
import '../widgets/vulnlens_logo.dart';

class AboutScreen extends StatelessWidget {
  const AboutScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: VulnLensColors.bgPrimary,
      appBar: AppBar(
        backgroundColor: VulnLensColors.bgSecondary,
        elevation: 0,
        title: const Text(
          'About & Architecture',
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
            // App Identity Header
            const Center(
              child: Column(
                children: [
                  VulnLensLogo(size: 64, showText: false),
                  SizedBox(height: 12),
                  Text(
                    'VulnLens',
                    style: TextStyle(
                      fontSize: 24,
                      fontWeight: FontWeight.w900,
                      color: Colors.white,
                      letterSpacing: 0.5,
                    ),
                  ),
                  Text(
                    'Personalised Vulnerability Triage — v1.0.0',
                    style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w500,
                      color: VulnLensColors.midBlue,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 24),

            // Offline Architecture diagram
            const Text(
              'OFFLINE ARCHITECTURE',
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w900,
                color: VulnLensColors.textMuted,
                letterSpacing: 0.8,
              ),
            ),
            const SizedBox(height: 8),

            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: VulnLensColors.bgSecondary,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: VulnLensColors.borderSubtle),
              ),
              child: Column(
                children: [
                  _buildArchStep('1. Bundled Datasets',
                      'vulnerabilities.csv, profiles.json, gold_set.csv assets'),
                  _buildArchArrow(),
                  _buildArchStep('2. Local Profile Ingestion',
                      'Weight modifiers & critical product mappings'),
                  _buildArchArrow(),
                  _buildArchStep('3. Local Matching Engine',
                      'Canonical name normalization & alias resolution'),
                  _buildArchArrow(),
                  _buildArchStep('4. Deterministic Scoring',
                      'CVSS + KEV + EPSS weighted sum × 1.4 Critical multiplier'),
                  _buildArchArrow(),
                  _buildArchStep('5. Explainable Top 5',
                      'Ranked decisions, safe actions, confidence reasons'),
                ],
              ),
            ),
            const SizedBox(height: 20),

            // Privacy & Defensive Ethics
            const Text(
              'PRIVACY & DEFENSIVE ETHICS',
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w900,
                color: VulnLensColors.textMuted,
                letterSpacing: 0.8,
              ),
            ),
            const SizedBox(height: 8),

            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: VulnLensColors.bgSecondary,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: VulnLensColors.borderSubtle),
              ),
              child: const Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '🛡️ Zero Telemetry or Tracking',
                    style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                  ),
                  SizedBox(height: 4),
                  Text(
                    'VulnLens does not collect names, emails, location, analytics, device identifiers, or network traffic. All computations run exclusively in device RAM.',
                    style: TextStyle(
                        fontSize: 12,
                        color: VulnLensColors.textSecondary,
                        height: 1.35),
                  ),
                  SizedBox(height: 12),
                  Text(
                    '🔒 Defensive Decision-Support Only',
                    style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                  ),
                  SizedBox(height: 4),
                  Text(
                    'No network scanning, exploit execution, or offensive probes. Recommendations focus exclusively on patch prioritization, exposure verification, and mitigation.',
                    style: TextStyle(
                        fontSize: 12,
                        color: VulnLensColors.textSecondary,
                        height: 1.35),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),

            // Judge QR Installation Info
            const Text(
              'JUDGE INSTALLATION INSTRUCTIONS',
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w900,
                color: VulnLensColors.textMuted,
                letterSpacing: 0.8,
              ),
            ),
            const SizedBox(height: 8),

            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: VulnLensColors.bgSecondary,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: VulnLensColors.borderSubtle),
              ),
              child: const Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Standalone Android APK: VulnLens-Demo.apk',
                    style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.bold,
                      color: VulnLensColors.highlight,
                    ),
                  ),
                  SizedBox(height: 6),
                  Text(
                    '1. Scan distribution QR or download VulnLens-Demo.apk directly.\n'
                    '2. Install APK on Android phone or tablet.\n'
                    '3. Open VulnLens.\n'
                    '4. Disable Wi-Fi / Mobile Data (Airplane Mode).\n'
                    '5. Enjoy 100% offline vulnerability prioritization.',
                    style: TextStyle(
                      fontSize: 12,
                      color: VulnLensColors.textSecondary,
                      height: 1.4,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildArchStep(String title, String subtitle) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: VulnLensColors.bgPrimary,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: VulnLensColors.borderSubtle),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: const TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.bold,
              color: Colors.white,
            ),
          ),
          Text(
            subtitle,
            style: const TextStyle(
                fontSize: 11, color: VulnLensColors.textMuted),
          ),
        ],
      ),
    );
  }

  Widget _buildArchArrow() {
    return const Padding(
      padding: EdgeInsets.symmetric(vertical: 3.0),
      child: Icon(Icons.arrow_downward,
          size: 14, color: VulnLensColors.electricBlue),
    );
  }
}
