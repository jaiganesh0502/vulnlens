import 'package:flutter/material.dart';
import '../theme/app_theme.dart';
import '../widgets/vulnlens_logo.dart';
import 'main_scaffold.dart';

class SplashScreen extends StatelessWidget {
  const SplashScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: VulnLensColors.bgPrimary,
      body: SafeArea(
        child: Container(
          decoration: const BoxDecoration(
            gradient: VulnLensColors.heroRadialGlow,
          ),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 28.0, vertical: 24.0),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Spacer(),
                const Center(
                  child: VulnLensLogo(size: 88, showText: false),
                ),
                const SizedBox(height: 24),
                const Text(
                  'VULNLENS',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: Colors.white,
                    fontFamily: 'Inter',
                    fontSize: 34,
                    fontWeight: FontWeight.w900,
                    letterSpacing: 2.0,
                  ),
                ),
                const SizedBox(height: 6),
                const Text(
                  'Personalised Vulnerability Triage',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: VulnLensColors.midBlue,
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 24),
                Container(
                  padding: const EdgeInsets.all(18),
                  decoration: BoxDecoration(
                    color: VulnLensColors.bgSecondary,
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(color: VulnLensColors.borderSubtle),
                    boxShadow: [
                      BoxShadow(
                        color: VulnLensColors.blueGlow.withOpacity(0.3),
                        blurRadius: 16,
                        spreadRadius: 2,
                      ),
                    ],
                  ),
                  child: const Text(
                    '"Turn hundreds of vulnerability records into five explainable security actions that matter to your organisation."',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: VulnLensColors.textSecondary,
                      fontSize: 14,
                      fontStyle: FontStyle.italic,
                      height: 1.45,
                    ),
                  ),
                ),
                const SizedBox(height: 28),
                _buildFeatureItem(Icons.check_circle_outline, 'Runs 100% locally on device'),
                _buildFeatureItem(Icons.analytics_outlined, 'Transparent, explainable scoring'),
                _buildFeatureItem(Icons.cloud_off_outlined, 'Zero live API or backend dependency'),
                _buildFeatureItem(Icons.business_outlined, 'Organisation-specific asset priorities'),
                const Spacer(),
                ElevatedButton(
                  onPressed: () {
                    Navigator.of(context).pushReplacement(
                      MaterialPageRoute(builder: (_) => const MainScaffold()),
                    );
                  },
                  style: ElevatedButton.styleFrom(
                    backgroundColor: VulnLensColors.electricBlue,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                    elevation: 4,
                  ),
                  child: const Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(
                        'Start Offline Analysis',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          letterSpacing: 0.5,
                        ),
                      ),
                      SizedBox(width: 8),
                      Icon(Icons.arrow_forward, size: 20),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
                const Text(
                  'No login, tracking, or network required.',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: VulnLensColors.textMuted,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildFeatureItem(IconData icon, String text) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6.0),
      child: Row(
        children: [
          Icon(icon, color: VulnLensColors.lowGreen, size: 20),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              text,
              style: const TextStyle(
                color: VulnLensColors.textSecondary,
                fontSize: 14,
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
