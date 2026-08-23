import 'package:flutter_test/flutter_test.dart';
import 'package:vulnlens_mobile/models/models.dart';
import 'package:vulnlens_mobile/services/calibration.dart';
import 'package:vulnlens_mobile/services/matcher.dart';
import 'package:vulnlens_mobile/services/ranking.dart';
import 'package:vulnlens_mobile/services/scorer.dart';

void main() {
  group('Matcher Tests', () {
    test('Product name normalization', () {
      expect(normalizeProductName('Core Banking Framework'),
          equals('core banking framework'));
      expect(normalizeProductName('  CORE BANKING FRAMEWORK  '),
          equals('core banking framework'));
      expect(normalizeProductName('"Identity Provider SaaS"'),
          equals('identity provider saas'));
    });

    test('Canonical alias resolution', () {
      expect(resolveCanonicalProduct('core banking'),
          equals('Core Banking Framework'));
      expect(resolveCanonicalProduct('idp saas'),
          equals('Identity Provider SaaS'));
      expect(resolveCanonicalProduct('waf'),
          equals('Web Application Firewall'));
    });

    test('Critical product identification', () {
      final critList = ['Core Banking Framework', 'Identity Provider SaaS'];
      expect(isCriticalProduct('Core Banking Framework', critList), isTrue);
      expect(isCriticalProduct('core banking', critList), isTrue);
      expect(isCriticalProduct('Cloud Database Engine', critList), isFalse);
    });
  });

  group('Scorer Tests', () {
    final profile = OrganizationProfile(
      orgId: 'ORG-001',
      name: 'Global Retail Bank',
      sector: 'Financial Services',
      riskAppetite: 'Low',
      weightModifiers: WeightModifiers(
        cvssWeight: 0.30,
        cisaKevWeight: 0.45,
        firstEpssWeight: 0.25,
      ),
      criticalProducts: ['Core Banking Framework'],
    );

    test('Standard non-critical product scoring', () {
      final vuln = Vulnerability(
        cveId: 'CVE-2025-0001',
        productName: 'Standard Router OS',
        cvssBaseScore: 8.0, // 100 * 0.3 * 0.8 = 24.0
        cisaKev: true, // 100 * 0.45 * 1.0 = 45.0
        firstEpss: 0.4, // 100 * 0.25 * 0.4 = 10.0
      );
      final b = calculateScore(vuln, profile, criticalMultiplier: 1.4);
      expect(b.baseScore, closeTo(79.0, 0.01));
      expect(b.isCriticalProduct, isFalse);
      expect(b.finalScore, closeTo(79.0, 0.01));
    });

    test('Critical product 1.4x multiplier', () {
      final vuln = Vulnerability(
        cveId: 'CVE-2025-0002',
        productName: 'Core Banking Framework',
        cvssBaseScore: 10.0, // 100 * 0.3 * 1.0 = 30.0
        cisaKev: true, // 100 * 0.45 * 1.0 = 45.0
        firstEpss: 0.5, // 100 * 0.25 * 0.5 = 12.5
      );
      final b = calculateScore(vuln, profile, criticalMultiplier: 1.4);
      expect(b.baseScore, closeTo(87.5, 0.01));
      expect(b.isCriticalProduct, isTrue);
      expect(b.finalScore, closeTo(122.5, 0.01));
      expect(determinePriorityLevel(b.finalScore), equals(PriorityLevel.urgent));
    });
  });

  group('Ranking & Deduplication Tests', () {
    final profile = OrganizationProfile(
      orgId: 'ORG-001',
      name: 'Global Retail Bank',
      sector: 'Finance',
      riskAppetite: 'Low',
      weightModifiers: WeightModifiers(
        cvssWeight: 0.3,
        cisaKevWeight: 0.45,
        firstEpssWeight: 0.25,
      ),
      criticalProducts: ['Core Banking Framework'],
    );

    test('Deduplicate by (CVE, Product)', () {
      final vulns = [
        Vulnerability(
            cveId: 'CVE-001',
            productName: 'App A',
            cvssBaseScore: 6.0,
            cisaKev: false,
            firstEpss: 0.1),
        Vulnerability(
            cveId: 'CVE-001',
            productName: 'App A',
            cvssBaseScore: 8.0,
            cisaKev: false,
            firstEpss: 0.1),
        Vulnerability(
            cveId: 'CVE-001',
            productName: 'App B',
            cvssBaseScore: 7.0,
            cisaKev: false,
            firstEpss: 0.1),
      ];
      final deduped = deduplicateVulnerabilities(vulns);
      expect(deduped.length, equals(2));
      final appA = deduped.firstWhere((v) => v.productName == 'App A');
      expect(appA.cvssBaseScore, equals(8.0));
    });

    test('Top 5 bounding', () {
      final vulns = List.generate(
        15,
        (i) => Vulnerability(
          cveId: 'CVE-2025-${i.toString().padLeft(4, "0")}',
          productName: 'Tool $i',
          cvssBaseScore: (i % 10).toDouble(),
          cisaKev: i % 2 == 0,
          firstEpss: (i * 0.05).clamp(0.0, 1.0),
        ),
      );
      final top5 = rankVulnerabilities(vulns, profile, topN: 5);
      expect(top5.length, equals(5));
      expect(top5.first.rank, equals(1));
      expect(top5.last.rank, equals(5));
    });
  });

  group('Negative Test (High CVSS != High Priority)', () {
    test('CVSS 9.9 ranks below CVSS 5.1 contextual threat', () {
      final profile = OrganizationProfile(
        orgId: 'ORG-001',
        name: 'Global Retail Bank',
        sector: 'Finance',
        riskAppetite: 'Low',
        weightModifiers: WeightModifiers(
          cvssWeight: 0.3,
          cisaKevWeight: 0.45,
          firstEpssWeight: 0.25,
        ),
        criticalProducts: ['Core Banking Framework'],
      );

      final highCvssVuln = Vulnerability(
        cveId: 'CVE-2026-HIGH-CVSS',
        productName: 'Unused Cloud DB',
        cvssBaseScore: 9.9,
        cisaKev: false,
        firstEpss: 0.01,
      );

      final activeThreat = Vulnerability(
        cveId: 'CVE-2025-ACTIVE-THREAT',
        productName: 'Core Banking Framework',
        cvssBaseScore: 5.1,
        cisaKev: true,
        firstEpss: 0.85,
      );

      final results =
          rankVulnerabilities([highCvssVuln, activeThreat], profile, topN: 2);
      expect(results.first.vulnerability.cveId, equals('CVE-2025-ACTIVE-THREAT'));
      expect(results.first.priority, equals(PriorityLevel.urgent));
      expect(results.last.vulnerability.cveId, equals('CVE-2026-HIGH-CVSS'));
      expect(results.last.priority, equals(PriorityLevel.low));
    });
  });

  group('Calibration & Correlation Tests', () {
    test('Spearman rank correlation', () {
      final x = [1.0, 2.0, 3.0, 4.0, 5.0];
      final y = [1.0, 2.0, 3.0, 4.0, 5.0];
      expect(computeSpearmanCorrelation(x, y), equals(1.0));
    });
  });
}
