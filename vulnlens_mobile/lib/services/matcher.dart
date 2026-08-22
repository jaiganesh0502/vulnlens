const Map<String, String> productAliases = {
  'core banking framework': 'Core Banking Framework',
  'core banking': 'Core Banking Framework',
  'core-banking-framework': 'Core Banking Framework',
  'identity provider saas': 'Identity Provider SaaS',
  'identity provider': 'Identity Provider SaaS',
  'idp saas': 'Identity Provider SaaS',
  'idp': 'Identity Provider SaaS',
  'cloud database engine': 'Cloud Database Engine',
  'cloud database': 'Cloud Database Engine',
  'cloud-db': 'Cloud Database Engine',
  'enterprise router os': 'Enterprise Router OS',
  'router os': 'Enterprise Router OS',
  'enterprise router': 'Enterprise Router OS',
  'embedded iot gateway': 'Embedded IoT Gateway',
  'iot gateway': 'Embedded IoT Gateway',
  'embedded iot': 'Embedded IoT Gateway',
  'web application firewall': 'Web Application Firewall',
  'waf': 'Web Application Firewall',
};

String normalizeProductName(String? name) {
  if (name == null || name.isEmpty) return '';
  String cleaned = name.trim();
  // Strip surrounding quotes
  if ((cleaned.startsWith('"') && cleaned.endsWith('"')) ||
      (cleaned.startsWith("'") && cleaned.endsWith("'")) ||
      (cleaned.startsWith('`') && cleaned.endsWith('`'))) {
    cleaned = cleaned.substring(1, cleaned.length - 1).trim();
  }
  cleaned = cleaned.toLowerCase();
  // Collapse whitespace
  cleaned = cleaned.replaceAll(RegExp(r'\s+'), ' ');
  return cleaned;
}

String resolveCanonicalProduct(String? name) {
  final norm = normalizeProductName(name);
  if (norm.isEmpty) return '';
  if (productAliases.containsKey(norm)) {
    return productAliases[norm]!;
  }
  return name!.trim();
}

bool isCriticalProduct(String? productName, Iterable<String> criticalProducts) {
  if (productName == null || criticalProducts.isEmpty) return false;
  final normTarget = normalizeProductName(productName);
  final canonTarget = resolveCanonicalProduct(productName).toLowerCase();

  for (final crit in criticalProducts) {
    final normCrit = normalizeProductName(crit);
    final canonCrit = resolveCanonicalProduct(crit).toLowerCase();

    if (normTarget == normCrit || canonTarget == canonCrit) {
      return true;
    }
  }
  return false;
}

bool isRelevantProduct(
    String? productName, Iterable<String>? organizationProducts) {
  if (organizationProducts == null || organizationProducts.isEmpty) return true;
  if (productName == null || productName.isEmpty) return false;

  final normTarget = normalizeProductName(productName);
  for (final orgProd in organizationProducts) {
    if (normTarget == normalizeProductName(orgProd)) {
      return true;
    }
  }
  return false;
}
