import 'package:flutter/foundation.dart';
import '../models/models.dart';
import '../services/calibration.dart';
import '../services/comparison.dart';
import '../services/loader_service.dart';
import '../services/negative_test.dart';
import '../services/ranking.dart';

class TriageState extends ChangeNotifier {
  bool _isLoading = true;
  String? _errorMessage;

  List<Vulnerability> _vulnerabilities = [];
  List<OrganizationProfile> _profiles = [];
  List<CalibrationRecord> _goldRecords = [];

  int _selectedProfileIndex = 0;
  double _criticalMultiplier = 1.4;

  bool get isLoading => _isLoading;
  String? get errorMessage => _errorMessage;

  List<Vulnerability> get vulnerabilities => _vulnerabilities;
  List<OrganizationProfile> get profiles => _profiles;
  List<CalibrationRecord> get goldRecords => _goldRecords;

  int get selectedProfileIndex => _selectedProfileIndex;
  double get criticalMultiplier => _criticalMultiplier;

  OrganizationProfile? get currentProfile =>
      _profiles.isNotEmpty && _selectedProfileIndex < _profiles.length
          ? _profiles[_selectedProfileIndex]
          : null;

  List<TriageResult> get currentTop5 {
    if (currentProfile == null || _vulnerabilities.isEmpty) return [];
    return rankVulnerabilities(
      _vulnerabilities,
      currentProfile!,
      topN: 5,
      criticalMultiplier: _criticalMultiplier,
    );
  }

  List<TriageResult> get currentAllRanked {
    if (currentProfile == null || _vulnerabilities.isEmpty) return [];
    return rankAllVulnerabilities(
      _vulnerabilities,
      currentProfile!,
      criticalMultiplier: _criticalMultiplier,
    );
  }

  List<NegativeTestItem> get currentNegativeTestCandidates {
    if (currentProfile == null || _vulnerabilities.isEmpty) return [];
    return findNegativeTestCandidates(
      _vulnerabilities,
      currentProfile!,
      minCvss: 9.0,
      maxRankThreshold: 10,
    );
  }

  Future<void> initialize() async {
    _isLoading = true;
    _errorMessage = null;
    notifyListeners();

    try {
      final vulnsFuture = LoaderService.loadBundledVulnerabilities();
      final profilesFuture = LoaderService.loadBundledProfiles();
      final goldFuture = LoaderService.loadBundledGoldSet();

      final results = await Future.wait([vulnsFuture, profilesFuture, goldFuture]);
      _vulnerabilities = results[0] as List<Vulnerability>;
      _profiles = results[1] as List<OrganizationProfile>;
      _goldRecords = results[2] as List<CalibrationRecord>;

      _isLoading = false;
      notifyListeners();
    } catch (e) {
      _isLoading = false;
      _errorMessage = 'Failed to load bundled offline datasets: $e';
      notifyListeners();
    }
  }

  void selectProfile(int index) {
    if (index >= 0 && index < _profiles.length) {
      _selectedProfileIndex = index;
      notifyListeners();
    }
  }

  void setCriticalMultiplier(double multiplier) {
    _criticalMultiplier = multiplier;
    notifyListeners();
  }

  bool addCustomProfile(String jsonString) {
    try {
      final profile = LoaderService.validateAndParseCustomProfile(jsonString);
      // Check if orgId already exists, replace or add
      final existingIdx = _profiles.indexWhere((p) => p.orgId == profile.orgId);
      if (existingIdx >= 0) {
        _profiles[existingIdx] = profile;
        _selectedProfileIndex = existingIdx;
      } else {
        _profiles.add(profile);
        _selectedProfileIndex = _profiles.length - 1;
      }
      notifyListeners();
      return true;
    } catch (e) {
      rethrow;
    }
  }

  ProfileComparisonReport compareTwoProfiles(
      OrganizationProfile orgA, OrganizationProfile orgB) {
    return compareProfiles(_vulnerabilities, orgA, orgB, topN: 5);
  }

  CalibrationReport runGoldSetCalibration(OrganizationProfile profile) {
    var targetField = 'practitioner_rank_bank';
    if (profile.name.toLowerCase().contains('startup') ||
        profile.sector.toLowerCase().contains('tech')) {
      targetField = 'practitioner_rank_startup';
    }
    return evaluateGoldSet(_goldRecords, profile, practitionerField: targetField);
  }
}
