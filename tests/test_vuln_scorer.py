"""Tests for vulnerability scorer."""

from utils.vuln_scorer import VulnScorer, Severity


class TestSeverity:
    def test_from_cvss_critical(self):
        assert Severity.from_cvss(9.8) == Severity.CRITICAL

    def test_from_cvss_high(self):
        assert Severity.from_cvss(7.5) == Severity.HIGH

    def test_from_cvss_medium(self):
        assert Severity.from_cvss(5.0) == Severity.MEDIUM

    def test_from_cvss_low(self):
        assert Severity.from_cvss(2.0) == Severity.LOW

    def test_from_cvss_zero(self):
        assert Severity.from_cvss(0) == Severity.INFO

    def test_numeric_ordering(self):
        assert Severity.CRITICAL.numeric > Severity.HIGH.numeric > Severity.MEDIUM.numeric


class TestVulnScorer:
    def test_score_nmap_eternalblue(self, sample_nmap_hosts):
        scorer = VulnScorer()
        findings = scorer.score_nmap_scripts(sample_nmap_hosts)
        assert len(findings) >= 1
        eternalblue = [
            f for f in findings if "eternalblue" in f.title.lower() or "ms17-010" in f.title.lower()
        ]
        assert len(eternalblue) >= 1
        assert eternalblue[0].severity == Severity.CRITICAL

    def test_score_nmap_expired_ssl(self, sample_nmap_hosts):
        scorer = VulnScorer()
        findings = scorer.score_nmap_scripts(sample_nmap_hosts)
        ssl_findings = [
            f for f in findings if "ssl" in f.title.lower() or "expired" in f.title.lower()
        ]
        assert len(ssl_findings) >= 1

    def test_score_exploit_match(self):
        scorer = VulnScorer()
        exploits = [
            {
                "title": "Apache 2.4.49 RCE CVE-2021-41773",
                "host": "1.1.1.1",
                "port": 80,
                "query": "Apache 2.4.49",
                "path": "/exploit/12345",
            },
        ]
        findings = scorer.score_exploit_match(exploits)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_score_credential(self):
        scorer = VulnScorer()
        f = scorer.score_credential("admin", "1.1.1.1", "ssh", admin=True)
        assert f.severity == Severity.CRITICAL
        assert f.cvss_score == 9.0

    def test_risk_rating_critical(self, sample_nmap_hosts):
        scorer = VulnScorer()
        scorer.score_nmap_scripts(sample_nmap_hosts)
        risk = scorer.compute_risk_rating()
        assert risk["overall_risk"] == "CRITICAL"
        assert risk["risk_score"] > 0

    def test_risk_rating_empty(self):
        scorer = VulnScorer()
        risk = scorer.compute_risk_rating()
        assert risk["overall_risk"] == "INFORMATIONAL"
        assert risk["total_findings"] == 0

    def test_findings_sorted_by_severity(self):
        scorer = VulnScorer()
        scorer.score_misconfiguration("Low thing", "1.1.1.1", Severity.LOW, 2.0)
        scorer.score_misconfiguration("Critical thing", "1.1.1.1", Severity.CRITICAL, 9.8)
        scorer.score_misconfiguration("Medium thing", "1.1.1.1", Severity.MEDIUM, 5.0)
        findings = scorer.get_findings()
        assert findings[0].severity == Severity.CRITICAL
        assert findings[-1].severity == Severity.LOW

    def test_attack_narrative(self, sample_nmap_hosts):
        scorer = VulnScorer()
        scorer.score_nmap_scripts(sample_nmap_hosts)
        scorer.score_credential("admin", "1.1.1.1", "ssh", admin=True)
        risk = scorer.compute_risk_rating()
        assert len(risk["attack_narrative"]) > 20

    def test_cve_extraction(self, sample_nmap_hosts):
        scorer = VulnScorer()
        findings = scorer.score_nmap_scripts(sample_nmap_hosts)
        cve_findings = [f for f in findings if f.cve_ids]
        assert len(cve_findings) >= 1
        assert any("CVE-2017-0144" in f.cve_ids for f in cve_findings)

    def test_to_report_data(self):
        scorer = VulnScorer()
        scorer.score_misconfiguration("Test", "1.1.1.1", Severity.HIGH, 7.5)
        data = scorer.to_report_data()
        assert "risk_rating" in data
        assert "findings" in data
        assert len(data["findings"]) == 1
