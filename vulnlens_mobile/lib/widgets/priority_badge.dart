import 'package:flutter/material.dart';
import '../models/models.dart';
import '../theme/app_theme.dart';

class PriorityBadge extends StatelessWidget {
  final PriorityLevel priority;
  final double? score;

  const PriorityBadge({
    super.key,
    required this.priority,
    this.score,
  });

  @override
  Widget build(BuildContext context) {
    Color bg;
    Color fg;
    Color border;
    String symbol;

    switch (priority) {
      case PriorityLevel.urgent:
        bg = VulnLensColors.urgentBg;
        fg = const Color(0xFFFCA5A5);
        border = VulnLensColors.urgentBorder;
        symbol = '🔴';
        break;
      case PriorityLevel.high:
        bg = VulnLensColors.highBg;
        fg = const Color(0xFFFDBA74);
        border = VulnLensColors.highBorder;
        symbol = '🟠';
        break;
      case PriorityLevel.medium:
        bg = VulnLensColors.mediumBg;
        fg = const Color(0xFFFDE68A);
        border = VulnLensColors.mediumBorder;
        symbol = '🟡';
        break;
      case PriorityLevel.low:
        bg = VulnLensColors.lowBg;
        fg = const Color(0xFF6EE7B7);
        border = VulnLensColors.lowBorder;
        symbol = '🟢';
        break;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: border, width: 1),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(symbol, style: const TextStyle(fontSize: 10)),
          const SizedBox(width: 5),
          Text(
            priority.label,
            style: TextStyle(
              color: fg,
              fontWeight: FontWeight.w800,
              fontSize: 12,
              letterSpacing: 0.5,
            ),
          ),
          if (score != null) ...[
            const SizedBox(width: 8),
            Container(
              width: 1,
              height: 12,
              color: border,
            ),
            const SizedBox(width: 8),
            Text(
              score!.toStringAsFixed(1),
              style: TextStyle(
                color: Colors.white,
                fontFamily: 'monospace',
                fontWeight: FontWeight.w900,
                fontSize: 12,
              ),
            ),
          ],
        ],
      ),
    );
  }
}
