import 'package:flutter/material.dart';

class VulnLensColors {
  // Official Fixed Brand Palette
  static const Color bgPrimary = Color(0xFF030E33);
  static const Color bgSecondary = Color(0xFF041648);
  static const Color bgGlow = Color(0xFF051E5E);
  static const Color blueGlow = Color(0xFF03297C);
  static const Color electricBlue = Color(0xFF0D7FFD);
  static const Color emblemBlue = Color(0xFF2358F9);
  static const Color emblemViolet = Color(0xFF4F3DF5);
  static const Color highlight = Color(0xFF93E2FC);
  static const Color midBlue = Color(0xFF4CB7FC);

  // Text & Surface Colors
  static const Color textPrimary = Color(0xFFFFFFFF);
  static const Color textSecondary = Color(0xFFCBD5E1);
  static const Color textMuted = Color(0xFF94A3B8);
  static const Color borderSubtle = Color(0x330D7FFD);
  static const Color borderHover = Color(0x664CB7FC);

  // Semantic Security Colors
  static const Color urgentRed = Color(0xFFEF4444);
  static const Color urgentBg = Color(0x33EF4444);
  static const Color urgentBorder = Color(0x73EF4444);

  static const Color highOrange = Color(0xFFF97316);
  static const Color highBg = Color(0x33F97316);
  static const Color highBorder = Color(0x73F97316);

  static const Color mediumAmber = Color(0xFFFBBF24);
  static const Color mediumBg = Color(0x33FBBF24);
  static const Color mediumBorder = Color(0x73FBBF24);

  static const Color lowGreen = Color(0xFF10B981);
  static const Color lowBg = Color(0x3310B981);
  static const Color lowBorder = Color(0x7310B981);

  // Gradients
  static const LinearGradient brandGradient = LinearGradient(
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
    colors: [emblemBlue, emblemViolet],
  );

  static const LinearGradient highlightGradient = LinearGradient(
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
    colors: [highlight, midBlue, emblemBlue, emblemViolet],
  );

  static const RadialGradient heroRadialGlow = RadialGradient(
    center: Alignment(0.0, -0.4),
    radius: 0.8,
    colors: [bgGlow, blueGlow, bgPrimary],
    stops: [0.0, 0.45, 1.0],
  );
}

class VulnLensTheme {
  static ThemeData get darkTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: VulnLensColors.bgPrimary,
      primaryColor: VulnLensColors.electricBlue,
      colorScheme: const ColorScheme.dark(
        primary: VulnLensColors.electricBlue,
        secondary: VulnLensColors.emblemViolet,
        surface: VulnLensColors.bgSecondary,
        surfaceContainerLowest: VulnLensColors.bgPrimary,
      ),
      fontFamily: 'Roboto',
      appBarTheme: const AppBarTheme(
        backgroundColor: VulnLensColors.bgSecondary,
        elevation: 0,
        centerTitle: false,
        iconTheme: IconThemeData(color: VulnLensColors.textPrimary),
        titleTextStyle: TextStyle(
          color: VulnLensColors.textPrimary,
          fontSize: 18,
          fontWeight: FontWeight.w900,
          letterSpacing: 0.5,
        ),
      ),
      bottomNavigationBarTheme: const BottomNavigationBarThemeData(
        backgroundColor: VulnLensColors.bgSecondary,
        selectedItemColor: VulnLensColors.electricBlue,
        unselectedItemColor: VulnLensColors.textMuted,
        selectedLabelStyle: TextStyle(fontWeight: FontWeight.bold, fontSize: 11),
        unselectedLabelStyle: TextStyle(fontWeight: FontWeight.w500, fontSize: 11),
        type: BottomNavigationBarType.fixed,
        elevation: 8,
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: VulnLensColors.electricBlue,
          foregroundColor: Colors.white,
          elevation: 2,
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
          textStyle: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: VulnLensColors.highlight,
          side: const BorderSide(color: VulnLensColors.borderSubtle),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        ),
      ),
      dividerTheme: const DividerThemeData(
        color: VulnLensColors.borderSubtle,
        thickness: 1,
      ),
    );
  }
}
