# Reviewed PHP advisory rules

The bundled catalog is `src/azure_php_scout/data/advisories.json`, reviewed on
2026-10-21. It currently covers two PHP core advisories:

- [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

Both have upstream fixes in 8.2.35, 8.3.36, 8.4.27, and 8.5.12. The catalog maps
**each branch to its fixed release**. A version on 8.2 is compared only to the 8.2
threshold. A release candidate at the threshold remains earlier than the stable
fix. Partial version strings and conflicting header versions require verification.

Older branches are flagged for upstream support/vendor verification. Upstream
provided source backports for some older branches; those do not restore upstream
support. Distribution and LTS packages can carry security fixes under an older
version number. An HTTP header cannot establish that package/build status.

The reviewed lifecycle table stores active/security end dates. The service compares
them to assessment time and reports the catalog review date. Future/unlisted
branches have unknown advisory coverage and are not labeled safe. The catalog is
a source-controlled snapshot and is not automatically synchronized with every CVE.
Historical assessment dates before the catalog review date require verification;
the snapshot cannot reconstruct the advisory or support knowledge available then.

To add or revise a rule, submit a PR with:

1. Primary maintainer/vendor advisory URLs and a review date.
2. A separate fixed threshold for each supported affected branch.
3. Documented uncertainty for older branches, vendor packages, and configuration.
4. Tests just below/at/above each fix, plus prereleases, incomplete versions,
   conflicting versions, and backport suffixes.
5. Updated scope wording, docs, and UI catalog count if the tracked set changes.

The service never sends an exploit to confirm a CVE. Use the official
[PHP announcement](https://www.php.net/archive/2026.php#2026-10-21-5) and the advisory
links for operational remediation and configuration guidance.
