import 'package:flutter/material.dart';
import 'screens/home_screen.dart';
import 'screens/splash_screen.dart';
import 'state/triage_state.dart';
import 'theme/app_theme.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final triageState = TriageState();
  triageState.initialize();

  runApp(VulnLensApp(triageState: triageState));
}

class VulnLensApp extends StatelessWidget {
  final TriageState triageState;

  const VulnLensApp({super.key, required this.triageState});

  @override
  Widget build(BuildContext context) {
    return TriageScope(
      notifier: triageState,
      child: MaterialApp(
        title: 'VulnLens',
        debugShowCheckedModeBanner: false,
        theme: VulnLensTheme.darkTheme,
        home: const SplashScreen(),
      ),
    );
  }
}
