import 'dart:convert';
import 'package:flutter/services.dart' show rootBundle;
import '../models/models.dart';

class LoaderService {
  static bool parseBoolean(dynamic value) {
    if (value is bool) return value;
    if (value == null) return false;
    final valStr = value.toString().trim().toLowerCase();
    return valStr == 'true' ||
        valStr == '1' ||
        valStr == 'yes' ||
        valStr == 't' ||
        valStr == 'y';
  }

  static double? parseFloatSafe(dynamic value,
      {double? minVal, double? maxVal}) {
    if (value == null) return null;
    final valStr = value.toString().trim().toLowerCase();
    if (valStr.isEmpty ||
        valStr == 'nan' ||
        valStr == 'null' ||
        valStr == 'none') {
      return null;
    }
    final fVal = double.tryParse(valStr);
    if (fVal == null) return null;
    if (minVal != null && fVal < minVal) return null;
    if (maxVal != null && fVal > maxVal) return null;
    return fVal;
  }

  static List<List<String>> parseCsvLines(String csvContent) {
    final rows = <List<String>>[];
    final lines = const LineSplitter().convert(csvContent);

    for (final line in lines) {
      if (line.trim().isEmpty) continue;
      final row = <String>[];
      var inQuotes = false;
      final sb = StringBuffer();

      for (var i = 0; i < line.length; i++) {
        final char = line[i];
        if (char == '"') {
          inQuotes = !inQuotes;
        } else if (char == ',' && !inQuotes) {
          row.add(sb.toString().trim());
          sb.clear();
        } else {
          sb.write(char);
        }
      }
      row.add(sb.toString().trim());
      rows.add(row);
    }
    return rows;
  }

  static List<Vulnerability> parseVulnerabilitiesFromCsv(String csvContent) {
    final rows = parseCsvLines(csvContent);
    if (rows.isEmpty) return [];

    final headers =
        rows.first.map((h) => h.toLowerCase().replaceAll('"', '')).toList();
    final cveIdx = headers.indexWhere((h) => h.contains('cve'));
    final prodIdx = headers.indexWhere((h) => h.contains('product'));
    final cvssIdx = headers.indexWhere((h) => h.contains('cvss'));
    final kevIdx = headers.indexWhere((h) => h.contains('kev'));
    final epssIdx = headers.indexWhere((h) => h.contains('epss'));

    final list = <Vulnerability>[];

    for (var i = 1; i < rows.length; i++) {
      final row = rows[i];
      if (row.isEmpty) continue;

      final cveId = (cveIdx >= 0 && cveIdx < row.length) ? row[cveIdx] : '';
      final product = (prodIdx >= 0 && prodIdx < row.length) ? row[prodIdx] : '';

      if (cveId.isEmpty || product.isEmpty) continue;

      final cvssRaw =
          (cvssIdx >= 0 && cvssIdx < row.length) ? row[cvssIdx] : null;
      final cvss = parseFloatSafe(cvssRaw, minVal: 0.0, maxVal: 10.0);

      final kevRaw = (kevIdx >= 0 && kevIdx < row.length) ? row[kevIdx] : null;
      final cisaKev = parseBoolean(kevRaw);

      final epssRaw =
          (epssIdx >= 0 && epssIdx < row.length) ? row[epssIdx] : null;
      final epss = parseFloatSafe(epssRaw, minVal: 0.0, maxVal: 1.0);

      final raw = <String, dynamic>{};
      for (var col = 0; col < headers.length && col < row.length; col++) {
        raw[headers[col]] = row[col];
      }

      list.add(
        Vulnerability(
          cveId: cveId,
          productName: product,
          cvssBaseScore: cvss,
          cisaKev: cisaKev,
          firstEpss: epss,
          rawData: raw,
        ),
      );
    }

    return list;
  }

  static List<OrganizationProfile> parseProfilesFromJson(String jsonContent) {
    final dynamic data = jsonDecode(jsonContent);
    final profiles = <OrganizationProfile>[];

    List<dynamic> orgList = [];
    if (data is Map<String, dynamic>) {
      if (data.containsKey('organizations')) {
        orgList = data['organizations'] as List<dynamic>;
      } else {
        orgList = [data];
      }
    } else if (data is List<dynamic>) {
      orgList = data;
    }

    for (final orgJson in orgList) {
      if (orgJson is Map<String, dynamic>) {
        try {
          profiles.add(OrganizationProfile.fromJson(orgJson));
        } catch (_) {
          // Graceful skip of corrupt profile entry
        }
      }
    }
    return profiles;
  }

  static List<CalibrationRecord> parseGoldSetFromCsv(String csvContent) {
    final rows = parseCsvLines(csvContent);
    if (rows.isEmpty) return [];

    final headers =
        rows.first.map((h) => h.toLowerCase().replaceAll('"', '')).toList();
    final cveIdx = headers.indexWhere((h) => h.contains('cve'));
    final prodIdx = headers.indexWhere((h) => h.contains('product'));
    final cvssIdx = headers.indexWhere((h) => h.contains('cvss'));
    final kevIdx = headers.indexWhere((h) => h.contains('kev'));
    final epssIdx = headers.indexWhere((h) => h.contains('epss'));
    final bankRankIdx = headers.indexWhere((h) => h.contains('rank_bank'));
    final startupRankIdx =
        headers.indexWhere((h) => h.contains('rank_startup'));

    final list = <CalibrationRecord>[];

    for (var i = 1; i < rows.length; i++) {
      final row = rows[i];
      if (row.isEmpty) continue;

      final cveId = (cveIdx >= 0 && cveIdx < row.length) ? row[cveIdx] : '';
      final product = (prodIdx >= 0 && prodIdx < row.length) ? row[prodIdx] : '';
      if (cveId.isEmpty || product.isEmpty) continue;

      final cvss = parseFloatSafe(
              (cvssIdx >= 0 && cvssIdx < row.length) ? row[cvssIdx] : null,
              minVal: 0.0,
              maxVal: 10.0) ??
          0.0;
      final cisaKev = parseBoolean(
          (kevIdx >= 0 && kevIdx < row.length) ? row[kevIdx] : null);
      final epss = parseFloatSafe(
              (epssIdx >= 0 && epssIdx < row.length) ? row[epssIdx] : null,
              minVal: 0.0,
              maxVal: 1.0) ??
          0.0;

      int? rankBank;
      if (bankRankIdx >= 0 && bankRankIdx < row.length) {
        rankBank = int.tryParse(row[bankRankIdx]);
      }

      int? rankStartup;
      if (startupRankIdx >= 0 && startupRankIdx < row.length) {
        rankStartup = int.tryParse(row[startupRankIdx]);
      }

      list.add(
        CalibrationRecord(
          cveId: cveId,
          productName: product,
          cvssBaseScore: cvss,
          cisaKev: cisaKev,
          firstEpss: epss,
          practitionerRankBank: rankBank,
          practitionerRankStartup: rankStartup,
        ),
      );
    }

    return list;
  }

  static Future<List<Vulnerability>> loadBundledVulnerabilities() async {
    final content =
        await rootBundle.loadString('assets/data/vulnerabilities.csv');
    return parseVulnerabilitiesFromCsv(content);
  }

  static Future<List<OrganizationProfile>> loadBundledProfiles() async {
    final content = await rootBundle.loadString('assets/data/profiles.json');
    return parseProfilesFromJson(content);
  }

  static Future<List<CalibrationRecord>> loadBundledGoldSet() async {
    final content = await rootBundle.loadString('assets/data/gold_set.csv');
    return parseGoldSetFromCsv(content);
  }

  static OrganizationProfile validateAndParseCustomProfile(String jsonString) {
    final dynamic data = jsonDecode(jsonString);
    if (data is! Map<String, dynamic>) {
      throw const FormatException(
          'Profile JSON must be a valid JSON object.');
    }
    if (!data.containsKey('name') && !data.containsKey('org_id')) {
      throw const FormatException(
          "Profile missing required identifier ('org_id' or 'name').");
    }
    return OrganizationProfile.fromJson(data);
  }
}
