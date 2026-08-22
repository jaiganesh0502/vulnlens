import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

class VulnLensLogo extends StatelessWidget {
  final double size;
  final bool showText;
  final double fontSize;

  const VulnLensLogo({
    super.key,
    this.size = 40,
    this.showText = true,
    this.fontSize = 20,
  });

  @override
  Widget build(BuildContext context) {
    Widget emblem = Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        boxShadow: [
          BoxShadow(
            color: VulnLensColors.emblemBlue.withValues(alpha: 0.45),
            blurRadius: size * 0.4,
            spreadRadius: 1,
          ),
        ],
      ),
      child: ClipOval(
        child: Image.asset(
          'assets/images/vulnlens_logo.png',
          width: size,
          height: size,
          fit: BoxFit.cover,
          errorBuilder: (_, __, ___) => Container(
            decoration: const BoxDecoration(
              gradient: VulnLensColors.brandGradient,
              shape: BoxShape.circle,
            ),
            child: Icon(
              Icons.shield,
              color: Colors.white,
              size: size * 0.6,
            ),
          ),
        ),
      ),
    );

    if (!showText) return emblem;

    return Row(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        emblem,
        const SizedBox(width: 10),
        RichText(
          text: TextSpan(
            style: TextStyle(
              fontFamily: 'Inter',
              fontWeight: FontWeight.w900,
              fontSize: fontSize,
              letterSpacing: 0.5,
              color: Colors.white,
            ),
            children: const [
              TextSpan(text: 'VULN'),
              TextSpan(
                text: 'LENS',
                style: TextStyle(color: VulnLensColors.electricBlue),
              ),
            ],
          ),
        ),
      ],
    );
  }
}
