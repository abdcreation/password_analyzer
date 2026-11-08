"""
Unit tests for password strength analyzer, Shannon entropy,
pattern detection, dictionary checks, and crack time estimation.
"""

import unittest
from security.analyzer import (
    calculate_shannon_entropy,
    calculate_theoretical_entropy,
    detect_patterns,
    analyze_password,
    generate_secure_password
)
from security.dictionary import check_dictionary, normalize_leetspeak

class TestPasswordAnalyzer(unittest.TestCase):

    def test_shannon_entropy_calculation(self):
        # Repetitive single character has zero Shannon entropy
        self.assertEqual(calculate_shannon_entropy("aaaaaaa"), 0.0)
        
        # High diversity password has positive Shannon entropy
        high_entropy = calculate_shannon_entropy("aB3$kL9#mP")
        self.assertGreater(high_entropy, 3.0)

    def test_theoretical_pool_entropy(self):
        # Lowercase only: pool size 26
        lower_result = calculate_theoretical_entropy("abcdefgh")
        self.assertEqual(lower_result["pool_size"], 26)
        
        # Lower + Upper + Digits + Symbols: pool size 95
        full_result = calculate_theoretical_entropy("aB3$kL9#mP")
        self.assertEqual(full_result["pool_size"], 95)
        self.assertTrue(full_result["has_lower"])
        self.assertTrue(full_result["has_upper"])
        self.assertTrue(full_result["has_digits"])
        self.assertTrue(full_result["has_symbols"])

    def test_pattern_detection(self):
        # Sequential numbers
        p1 = detect_patterns("mySecret1234")
        pattern_types = [p["type"] for p in p1]
        self.assertIn("sequential_numbers", pattern_types)

        # Sequential letters
        p2 = detect_patterns("abcdSafePass")
        pattern_types2 = [p["type"] for p in p2]
        self.assertIn("sequential_letters", pattern_types2)

        # Repeated characters
        p3 = detect_patterns("passsssword")
        pattern_types3 = [p["type"] for p in p3]
        self.assertIn("repeated_chars", pattern_types3)

        # Keyboard walk
        p4 = detect_patterns("myqwertyPass")
        pattern_types4 = [p["type"] for p in p4]
        self.assertIn("keyboard_sequence", pattern_types4)

        # Calendar year
        p5 = detect_patterns("SecurePass1995")
        pattern_types5 = [p["type"] for p in p5]
        self.assertIn("year_pattern", pattern_types5)

    def test_dictionary_and_leetspeak(self):
        # Direct common password hit
        res1 = check_dictionary("password")
        self.assertTrue(res1["is_exact_match"])

        # Leetspeak translation
        self.assertEqual(normalize_leetspeak("p@ssw0rd"), "password")
        res2 = check_dictionary("P@ssw0rd")
        self.assertTrue(res2["is_exact_match"] or res2["is_substring_match"])
        self.assertTrue(res2["is_leetspeak_match"])

        # Substring dictionary detection
        res3 = check_dictionary("MySecretDragon123")
        self.assertTrue(res3["is_substring_match"])
        self.assertIn("dragon", res3["substring_matches"])

    def test_overall_analysis_scores(self):
        # Extremely weak password
        weak = analyze_password("123456")
        self.assertLessEqual(weak["score"], 25)
        self.assertEqual(weak["category"], "Very Weak")

        # Strong high-entropy password
        strong = analyze_password("X9#mQ2$vL!8xP@wZ")
        self.assertGreaterEqual(strong["score"], 70)
        self.assertIn(strong["category"], ["Strong", "Very Strong"])
        self.assertGreater(strong["effective_entropy"], 60.0)

    def test_password_generator(self):
        pwd = generate_secure_password(length=20, use_upper=True, use_digits=True, use_symbols=True)
        self.assertEqual(len(pwd), 20)
        self.assertTrue(any(c.islower() for c in pwd))
        self.assertTrue(any(c.isupper() for c in pwd))
        self.assertTrue(any(c.isdigit() for c in pwd))
        self.assertTrue(any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd))

if __name__ == '__main__':
    unittest.main()
