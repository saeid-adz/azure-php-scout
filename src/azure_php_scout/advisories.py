"""Conservative upstream version assessment; no exploitation or remediation execution."""
from datetime import date
from functools import lru_cache
from importlib.resources import files
import json
import re

ASSESSMENT_FIELDS = ["assessment", "riskLevel", "cves", "assessmentBasis", "remediation", "phpSupport", "advisoryReviewedAt"]
NGINX_FIELDS = ["nginxAssessment", "nginxRiskLevel", "nginxCves", "nginxBasis", "nginxRemediation"]


@lru_cache(maxsize=1)
def catalog():
    return json.loads(files("azure_php_scout").joinpath("data/advisories.json").read_text(encoding="utf-8"))


def parse_version(value):
    """Require a patch number; retain prerelease and vendor-build uncertainty."""
    match = re.fullmatch(r"(?:PHP[/ ]+)?(\d+)\.(\d+)\.(\d+)(.*)", str(value or "").strip(), re.I)
    if not match:
        return None
    suffix = match.group(4)
    prerelease = bool(re.fullmatch(r"[-_.]?(?:alpha|beta|rc|dev)\d*(?:[-+][a-zA-Z0-9.+:~_-]+)?", suffix, re.I))
    if suffix and re.match(r"[-_.]?(?:alpha|beta|rc|dev)", suffix, re.I) and not prerelease:
        return None
    if suffix and not prerelease and not re.fullmatch(r"[-+][a-zA-Z0-9.+:~_-]+", suffix):
        return None
    return tuple(map(int, match.group(1, 2, 3))), prerelease, bool(suffix and not prerelease)


def _assess(row, *, as_of=None, rules=None):
    rules = rules or catalog()
    as_of = as_of or date.today()
    result = dict(assessment="undetermined", riskLevel="info", cves="", phpSupport="unknown",
                  advisoryReviewedAt=rules["reviewed_at"],
                  assessmentBasis="No observed PHP runtime version is available.",
                  remediation="Confirm the executing runtime and its package security status with the service owner.",
                  matches=[], catalogScope=rules["scope"])
    if as_of < date.fromisoformat(rules["reviewed_at"]):
        result.update(assessment="verify_version", riskLevel="medium",
                      assessmentBasis="The requested assessment date precedes this catalog's review date. Historical advisory and lifecycle coverage is unavailable.")
        return result
    raw = str(row.get("phpVersion") or "").strip()
    variants = {part.strip() for part in str(row.get("phpVersions") or raw).split(",") if part.strip()}
    php_signal = row.get("php") in ("yes", "probable") or row.get("wordpress") in ("yes", "probable")
    if not raw:
        if row.get("configuredPhpVersion"):
            result.update(assessment="configuration_only", riskLevel="medium",
                          assessmentBasis="Azure reports a PHP configuration value; the executing web runtime was not identified.")
        elif php_signal:
            result.update(assessment="verify_version", riskLevel="medium",
                          assessmentBasis="PHP or WordPress signatures were observed without a complete PHP version.")
        return result
    parsed = parse_version(raw)
    if len(variants) > 1 or (variants and raw not in variants) or parsed is None:
        result.update(assessment="verify_version", riskLevel="medium",
                      assessmentBasis="The reported PHP version is incomplete, ambiguous, or conflicting.")
        return result
    version, prerelease, vendor = parsed
    branch = "{}.{}".format(*version[:2])
    lifecycle = rules["lifecycle"].get(branch)
    if lifecycle:
        result["phpSupport"] = ("end_of_life" if as_of > date.fromisoformat(lifecycle["security_until"]) else
                                "security_fixes" if as_of > date.fromisoformat(lifecycle["active_until"]) else "active")
    elif version < tuple(map(int, rules["legacy_eol_before"].split("."))):
        result["phpSupport"] = "end_of_life"
    for advisory in rules["advisories"]:
        fixed = advisory["fixed"].get(branch)
        if fixed:
            fixed_tuple = tuple(map(int, fixed.split(".")))
            if version < fixed_tuple or (version == fixed_tuple and prerelease):
                result["matches"].append(dict(id=advisory["id"], title=advisory["title"], severity=advisory["severity"],
                                              fixedVersion=fixed, url=advisory["url"]))
    if result["matches"]:
        result.update(assessment="potentially_affected", riskLevel="critical",
                      cves=", ".join(match["id"] for match in result["matches"]),
                      assessmentBasis="The reported upstream version falls within tracked advisory ranges. Exploitability and vendor backports require verification.",
                      remediation="Update the executing PHP runtime to {} or a later supported release, or apply a vendor-confirmed security backport. Restart/redeploy workers and verify the runtime serving traffic.".format(result["matches"][0]["fixedVersion"]))
    elif result["phpSupport"] == "end_of_life":
        result.update(assessment="end_of_life", riskLevel="high",
                      assessmentBasis="This PHP branch is outside upstream security support. CVE fixes on older branches require vendor/build verification.",
                      remediation="Plan an upgrade to a supported PHP branch. Ask your vendor to confirm fixes for the tracked CVEs, including any backports, and verify the deployed runtime.")
    elif lifecycle and not prerelease:
        result.update(assessment="no_catalog_match", riskLevel="info",
                      assessmentBasis="The reported version is outside the ranges in this catalog. This does not establish that the service is free of vulnerabilities.",
                      remediation="Verify the serving package/build and continue checking current vendor security advisories.")
    else:
        result.update(assessment="verify_version", riskLevel="medium",
                      assessmentBasis="This branch or prerelease is outside the reviewed advisory coverage.")
    if vendor:
        result["assessmentBasis"] += " A vendor build suffix was reported; upstream numbers cannot establish backport status."
    if result["matches"] and result["phpSupport"] == "end_of_life":
        result["assessmentBasis"] += " This branch is also outside upstream security support."
        result["remediation"] = "Upgrade to a supported PHP branch with current security fixes, or obtain a supported vendor-confirmed security backport. Restart/redeploy workers and verify the serving runtime and package build."
    return result


def assess(row, *, as_of=None, rules=None):
    result = _assess(row, as_of=as_of, rules=rules)
    if row.get("evidenceSource") == "guest":
        result["assessmentBasis"] = "Guest package/disk inventory; this does not confirm the PHP runtime executing HTTP requests. " + result["assessmentBasis"]
        if row.get("guestSource") == "package":
            result["remediation"] += " Verify the distribution/vendor security status of the complete package version."
    return result


def parse_nginx_version(value):
    """NGINX versions are MAJOR.MINOR.PATCH; vendor suffixes such as '(Ubuntu)' are handled by the caller."""
    match = re.fullmatch(r"(?:nginx/)?(\d+)\.(\d+)\.(\d+)", str(value or "").strip(), re.I)
    return tuple(map(int, match.groups())) if match else None


def assess_nginx(row, *, rules=None):
    """Conservative NGINX HTTP/2 assessment from the observed Server version and negotiated protocol."""
    rules = rules or catalog()["nginx"]
    result = dict(nginxAssessment="undetermined", nginxRiskLevel="info", nginxCves="", matches=[],
                  nginxBasis="No NGINX signal was observed.", nginxRemediation="")
    state = row.get("nginx")
    if state not in ("yes", "probable"):
        return result
    result.update(nginxAssessment="verify_version", nginxRiskLevel="medium",
                  nginxBasis="NGINX was detected without a version. Version hiding (server_tokens off) is common.",
                  nginxRemediation="Confirm the running NGINX binary version on the host and that it includes the HTTP/2 fixes. Restart the service after upgrading; a reload does not replace the binary.")
    version = parse_nginx_version(row.get("nginxVersion"))
    if row.get("nginxVersion") and version is None:
        result["nginxBasis"] = "The reported NGINX version is incomplete or not a plain MAJOR.MINOR.PATCH value."
        return result
    if version is None:
        return result
    for advisory in rules["advisories"]:
        if any(tuple(map(int, low.split("."))) <= version <= tuple(map(int, high.split(".")))
               for low, high in advisory["ranges"]):
            result["matches"].append(dict(id=advisory["id"], title=advisory["title"], severity=advisory["severity"],
                                          fixedVersion=advisory["fixed"].get("{}.{}".format(*version[:2])) or min(advisory["fixed"].values()),
                                          url=advisory["url"]))
    http2 = row.get("http2")
    if not result["matches"]:
        result.update(nginxAssessment="no_catalog_match", nginxRiskLevel="info",
                      nginxBasis="The reported NGINX version is outside the ranges in this catalog. This does not establish that the service is free of vulnerabilities.",
                      nginxRemediation="Continue checking current F5/NGINX security advisories.")
        return result
    fixed = result["matches"][0]["fixedVersion"]
    result["nginxCves"] = ", ".join(match["id"] for match in result["matches"])
    if http2 == "yes":
        result.update(nginxAssessment="potentially_affected", nginxRiskLevel="critical",
                      nginxBasis="The reported NGINX version is within tracked advisory ranges and the endpoint negotiated HTTP/2. Exploitability and vendor backports require verification.")
    else:
        result.update(nginxAssessment="verify_http2", nginxRiskLevel="high",
                      nginxBasis="The reported NGINX version is within tracked advisory ranges. HTTP/2 was {} on this endpoint; other listeners or ports on the same server may accept HTTP/2.".format(
                          "not negotiated" if http2 == "no" else "not confirmed"))
    if "(" in str(row.get("server", "")) or re.search(r"[-+~]", str(row.get("nginxVersion", ""))):
        result["nginxBasis"] += " A distribution build was reported; upstream numbers cannot establish backport status."
    result["nginxRemediation"] = ("Upgrade NGINX to {} or later (or a vendor-confirmed backport), then restart the service or redeploy containers; a reload does not replace the running binary. "
                                  "Until patched, disabling client-facing HTTP/2 on affected listeners reduces exposure.").format(fixed)
    return result


def enrich(row, **kwargs):
    assessment = assess(row, **kwargs)
    nginx = assess_nginx(row)
    return dict(row, **{key: assessment[key] for key in ASSESSMENT_FIELDS}, **{key: nginx[key] for key in NGINX_FIELDS})
