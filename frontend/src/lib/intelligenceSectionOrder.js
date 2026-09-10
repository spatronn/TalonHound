// Canonical top-to-bottom layout contract for IOC Details -> Intelligence.
//
// The order is deterministic and identical for every supported IOC type
// (IP, domain, URL, MD5/SHA1/SHA256 and other hash subtypes). Only whether a
// section is *present* varies by type; its relative position never does.
//
//   1. Intelligence Summary              (always)
//   2. Automated Intelligence            (always)
//   3. IOC-type / provider-specific sections
//        - Derived Infrastructure        (URL IOCs with an extractable host)
//        - File Information              (hash IOCs)
//   4. Analyst Intelligence              (ALWAYS LAST)
//
// Analyst Intelligence must be rendered exactly once and always after every
// other intelligence section, regardless of IOC type.

export const ANALYST_INTELLIGENCE_SECTION = 'analyst';

// Ordered keys of the type-specific sections that sit between Automated
// Intelligence and Analyst Intelligence. New type-specific sections should be
// added here (before 'analyst') so they can never render below the analyst
// section by accident.
const TYPE_SPECIFIC_SECTION_ORDER = ['derivedInfrastructure', 'fileInformation'];

export function buildIntelligenceSectionOrder(flags = {}) {
  const {
    showDerivedInfrastructure = false,
    showFileInformation = false
  } = flags;

  const present = {
    derivedInfrastructure: Boolean(showDerivedInfrastructure),
    fileInformation: Boolean(showFileInformation)
  };

  const order = ['summary', 'automated'];
  for (const key of TYPE_SPECIFIC_SECTION_ORDER) {
    if (present[key]) order.push(key);
  }
  // Analyst Intelligence is invariably the final section.
  order.push(ANALYST_INTELLIGENCE_SECTION);
  return order;
}
