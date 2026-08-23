import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

class OfflineStatusBadge extends StatelessWidget {
  const OfflineStatusBadge({super.key});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: VulnLensColors.bgSecondary,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: VulnLensColors.borderSubtle),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 7,
            height: 7,
            decoration: BoxDecoration(
              color: VulnLensColors.lowGreen,
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: VulnLensColors.lowGreen.withOpacity(0.6),
                  blurRadius: 6,
                  spreadRadius: 1,
                ),
              ],
            ),
          ),
          const SizedBox(width: 6),
          const Text(
            'OFFLINE READY',
            style: TextStyle(
              color: VulnLensColors.highlight,
              fontSize: 11,
              fontWeight: FontWeight.w800,
              letterSpacing: 0.5,
            ),
          ),
        ],
      ),
    );
  }
}
