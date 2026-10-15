import unittest
from phishing_core import analyze_rules, extract_urls, analyze_message

class PhishLensTests(unittest.TestCase):
    def test_suspicious_bank_message_scores_high(self):
        text = "URGENT: Your account will be suspended. Verify your password immediately at http://192.0.2.44/login and send OTP now."
        score, level, findings, urls = analyze_rules(text)
        self.assertGreaterEqual(score, 55)
        self.assertEqual(level, "High")
        self.assertTrue(findings)
        self.assertEqual(len(urls), 1)

    def test_legitimate_neutral_message_no_findings(self):
        text = "Reminder: Your library book is due Friday. Please visit the library desk if you have questions."
        score, level, findings, urls = analyze_rules(text)
        self.assertEqual(score, 0)
        self.assertEqual(level, "Low")
        self.assertEqual(findings, [])
        self.assertEqual(urls, [])

    def test_shortened_url_found(self):
        urls = extract_urls("Open this link: https://bit.ly/test-now.")
        self.assertEqual(urls, ["https://bit.ly/test-now"])

    def test_offline_result_is_created(self):
        result = analyze_message("Please confirm your password immediately at https://bit.ly/login", "rules")
        self.assertIn(result.risk_level, {"Low", "Medium", "High"})
        self.assertTrue(result.ai_explanation)
        self.assertEqual(result.ai_provider, "Rules-only (offline)")

    def test_low_score_does_not_claim_safe(self):
        result = analyze_message("Hello, the meeting is at 10 AM.", "rules")
        self.assertIn("does not establish", result.ai_explanation.lower())

if __name__ == "__main__":
    unittest.main()
