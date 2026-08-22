import 'dart:convert';
import 'package:flutter/material.dart';
import '../models/models.dart';
import '../theme/app_theme.dart';
import 'home_screen.dart';

class ImportProfileScreen extends StatefulWidget {
  const ImportProfileScreen({super.key});

  @override
  State<ImportProfileScreen> createState() => _ImportProfileScreenState();
}

class _ImportProfileScreenState extends State<ImportProfileScreen> {
  late TextEditingController _jsonController;
  String? _validationError;
  bool _importSuccess = false;
  OrganizationProfile? _importedProfile;

  static const String _defaultSampleJson = '''{
  "org_id": "ORG-004",
  "name": "Regional Healthcare Hospital",
  "sector": "Healthcare",
  "risk_appetite": "Low",
  "weight_modifiers": {
    "cvss_weight": 0.40,
    "cisa_kev_weight": 0.45,
    "first_epss_weight": 0.15
  },
  "critical_products": [
    "Identity Provider SaaS",
    "Cloud Database Engine"
  ]
}''';

  @override
  void initState() {
    super.initState();
    _jsonController = TextEditingController(text: _defaultSampleJson);
  }

  @override
  void dispose() {
    _jsonController.dispose();
    super.dispose();
  }

  void _handleImport() {
    setState(() {
      _validationError = null;
      _importSuccess = false;
    });

    final state = TriageScope.of(context);
    final rawText = _jsonController.text.trim();

    if (rawText.isEmpty) {
      setState(() {
        _validationError = 'Please provide profile JSON.';
      });
      return;
    }

    try {
      state.addCustomProfile(rawText);
      final parsed = jsonDecode(rawText);
      final profile = OrganizationProfile.fromJson(parsed);

      setState(() {
        _importedProfile = profile;
        _importSuccess = true;
      });
    } catch (e) {
      setState(() {
        _validationError = 'Validation Error: $e';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: VulnLensColors.bgPrimary,
      appBar: AppBar(
        backgroundColor: VulnLensColors.bgSecondary,
        elevation: 0,
        title: const Text(
          'Import Profile (Judge Demo)',
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
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(Icons.offline_pin_outlined,
                      color: VulnLensColors.electricBlue, size: 20),
                  SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'Zero-Network Ingestion: Unseen profiles are parsed, validated, and triaged entirely in local device memory without touching an external server.',
                      style: TextStyle(
                        fontSize: 12,
                        color: VulnLensColors.highlight,
                        height: 1.35,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 18),

            const Text(
              'PASTE OR EDIT PROFILE JSON (E.G. PROFILE D)',
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w900,
                color: VulnLensColors.textMuted,
                letterSpacing: 0.8,
              ),
            ),
            const SizedBox(height: 8),

            TextField(
              controller: _jsonController,
              maxLines: 12,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 12,
                color: VulnLensColors.highlight,
              ),
              decoration: InputDecoration(
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10),
                  borderSide: const BorderSide(color: VulnLensColors.borderSubtle),
                ),
                enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10),
                  borderSide: const BorderSide(color: VulnLensColors.borderSubtle),
                ),
                filled: true,
                fillColor: VulnLensColors.bgSecondary,
              ),
            ),
            const SizedBox(height: 14),

            Row(
              children: [
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _handleImport,
                    icon: const Icon(Icons.check_circle_outline),
                    label: const Text('Validate & Ingest Profile'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: VulnLensColors.electricBlue,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                OutlinedButton(
                  onPressed: () {
                    _jsonController.text = _defaultSampleJson;
                  },
                  child: const Text('Reset Sample'),
                ),
              ],
            ),
            const SizedBox(height: 16),

            if (_validationError != null)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: VulnLensColors.urgentBg,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: VulnLensColors.urgentBorder),
                ),
                child: Text(
                  _validationError!,
                  style: const TextStyle(
                    color: Color(0xFFFCA5A5),
                    fontWeight: FontWeight.w600,
                    fontSize: 12,
                  ),
                ),
              ),

            if (_importSuccess && _importedProfile != null)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: VulnLensColors.bgSecondary,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: VulnLensColors.lowBorder),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      '✓ PROFILE VALIDATED & INGESTED',
                      style: TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w900,
                        color: VulnLensColors.lowGreen,
                        letterSpacing: 0.5,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      '${_importedProfile!.name} (${_importedProfile!.orgId})',
                      style: const TextStyle(
                        fontSize: 15,
                        fontWeight: FontWeight.bold,
                        color: Colors.white,
                      ),
                    ),
                    const SizedBox(height: 8),
                    _buildCheck('Schema valid & verified'),
                    _buildCheck('Analysed 100% locally on device'),
                    _buildCheck('Personalised Top 5 generated instantly'),
                    const SizedBox(height: 14),
                    ElevatedButton(
                      onPressed: () {
                        Navigator.of(context).pop();
                      },
                      style: ElevatedButton.styleFrom(
                        backgroundColor: VulnLensColors.lowGreen,
                        foregroundColor: Colors.white,
                      ),
                      child: const Text('View Triage on Home Screen'),
                    ),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildCheck(String text) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2.0),
      child: Row(
        children: [
          const Icon(Icons.check, color: VulnLensColors.lowGreen, size: 16),
          const SizedBox(width: 6),
          Text(
            text,
            style: const TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w600,
              color: VulnLensColors.textSecondary,
            ),
          ),
        ],
      ),
    );
  }
}
