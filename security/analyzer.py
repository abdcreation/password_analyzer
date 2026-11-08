"""
Password Strength Analyzer Module.
Provides mathematical Shannon entropy calculation, regex pattern detection,
dictionary-based checks, brute-force crack time estimation, and comprehensive scoring.
"""

import math
import re
import secrets
import string
from typing import Dict, Any, List
from .dictionary import check_dictionary

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890"
]

def calculate_shannon_entropy(password: str) -> float:
    """
    Calculates the Shannon Entropy based on character frequency distribution:
    H = - sum(p_i * log2(p_i))
    """
    if not password:
        return 0.0
    length = len(password)
    freq = {}
    for char in password:
        freq[char] = freq.get(char, 0) + 1
        
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
        
    return round(entropy, 2)

def calculate_theoretical_entropy(password: str) -> Dict[str, Any]:
    """
    Calculates the theoretical entropy based on character pool size:
    Bits = Length * log2(Pool Size)
    """
    if not password:
        return {"pool_size": 0, "entropy_bits": 0.0, "char_types": []}
        
    pool_size = 0
    char_types = []
    
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digits = bool(re.search(r'[0-9]', password))
    has_symbols = bool(re.search(r'[^a-zA-Z0-9\s]', password))
    has_spaces = bool(re.search(r'\s', password))
    
    if has_lower:
        pool_size += 26
        char_types.append("lowercase")
    if has_upper:
        pool_size += 26
        char_types.append("uppercase")
    if has_digits:
        pool_size += 10
        char_types.append("digits")
    if has_symbols:
        pool_size += 33
        char_types.append("symbols")
    if has_spaces:
        pool_size += 1
        char_types.append("spaces")
        
    if pool_size == 0:
        return {"pool_size": 0, "entropy_bits": 0.0, "char_types": []}
        
    bits = len(password) * math.log2(pool_size)
    return {
        "pool_size": pool_size,
        "entropy_bits": round(bits, 2),
        "char_types": char_types,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digits": has_digits,
        "has_symbols": has_symbols
    }

def detect_patterns(password: str) -> List[Dict[str, Any]]:
    """
    Detects security weaknesses, predictable sequences, repetitions,
    dates, keyboard walks, and structural patterns.
    """
    patterns = []
    pwd_lower = password.lower()
    
    # 1. Repetition patterns (3 or more consecutive identical characters)
    repeat_matches = re.findall(r'(.)\1{2,}', password)
    if repeat_matches:
        full_repeats = re.findall(r'((.)\2{2,})', password)
        repeat_strs = [match[0] for match in full_repeats]
        patterns.append({
            "type": "repeated_chars",
            "name": "Repeated Characters",
            "severity": "HIGH",
            "description": f"Consecutive repeated characters found: '{', '.join(repeat_strs)}'.",
            "penalty": 15
        })
        
    # 2. Sequential numbers (e.g. 123, 789, 4321)
    num_seq_found = []
    for i in range(len(pwd_lower) - 2):
        chunk = pwd_lower[i:i+3]
        if chunk.isdigit():
            d1, d2, d3 = int(chunk[0]), int(chunk[1]), int(chunk[2])
            if (d2 == d1 + 1 and d3 == d2 + 1) or (d2 == d1 - 1 and d3 == d2 - 1):
                num_seq_found.append(chunk)
    if num_seq_found:
        patterns.append({
            "type": "sequential_numbers",
            "name": "Sequential Numbers",
            "severity": "HIGH",
            "description": f"Predictable numerical sequence found: '{', '.join(set(num_seq_found))}'.",
            "penalty": 15
        })

    # 3. Sequential alphabet (e.g. abc, xyz, cba)
    alpha_seq_found = []
    for i in range(len(pwd_lower) - 2):
        chunk = pwd_lower[i:i+3]
        if chunk.isalpha():
            c1, c2, c3 = ord(chunk[0]), ord(chunk[1]), ord(chunk[2])
            if (c2 == c1 + 1 and c3 == c2 + 1) or (c2 == c1 - 1 and c3 == c2 - 1):
                alpha_seq_found.append(chunk)
    if alpha_seq_found:
        patterns.append({
            "type": "sequential_letters",
            "name": "Sequential Letters",
            "severity": "MEDIUM",
            "description": f"Predictable alphabetical sequence found: '{', '.join(set(alpha_seq_found))}'.",
            "penalty": 12
        })

    # 4. Keyboard walk / QWERTY row patterns
    keyboard_hits = []
    for row in KEYBOARD_ROWS:
        rev_row = row[::-1]
        for i in range(len(pwd_lower) - 2):
            sub = pwd_lower[i:i+3]
            if len(sub) == 3 and (sub in row or sub in rev_row):
                keyboard_hits.append(sub)
    if keyboard_hits:
        patterns.append({
            "type": "keyboard_sequence",
            "name": "Keyboard Layout Sequence",
            "severity": "HIGH",
            "description": f"Keyboard walk sequence detected (e.g., '{', '.join(set(keyboard_hits))}').",
            "penalty": 15
        })

    # 5. Date / Year detection (e.g. 1970 - 2035)
    year_match = re.search(r'(19\d{2}|20[0-3]\d)', password)
    if year_match:
        patterns.append({
            "type": "year_pattern",
            "name": "Calendar Year Detected",
            "severity": "MEDIUM",
            "description": f"Contains recognizable year '{year_match.group(0)}', a prime target for wordlist attacks.",
            "penalty": 10
        })

    # 6. Predictable corporate policy template (Capital + Letters + Numbers + Special)
    # e.g., 'Welcome1!' or 'Password2024#'
    if re.match(r'^[A-Z][a-z]+[0-9]+[^a-zA-Z0-9]?$', password):
        patterns.append({
            "type": "predictable_template",
            "name": "Predictable Formatting Structure",
            "severity": "MEDIUM",
            "description": "Matches common formulaic template: [Capital letter] + [lowercase word] + [number/symbol].",
            "penalty": 15
        })

    return patterns

def format_time_duration(seconds: float) -> str:
    """Converts seconds into human-readable duration."""
    if seconds < 0.001:
        return "Instant (< 1 millisecond)"
    elif seconds < 1:
        return "Instant (< 1 second)"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        mins = int(seconds / 60)
        return f"{mins} minute{'s' if mins > 1 else ''}"
    elif seconds < 86400:
        hrs = int(seconds / 3600)
        return f"{hrs} hour{'s' if hrs > 1 else ''}"
    elif seconds < 31536000:
        days = int(seconds / 86400)
        return f"{days} day{'s' if days > 1 else ''}"
    elif seconds < 31536000 * 100:
        years = int(seconds / 31536000)
        return f"{years:,} year{'s' if years > 1 else ''}"
    elif seconds < 31536000 * 1000000:
        centuries = int(seconds / (31536000 * 100))
        return f"{centuries:,} centuries"
    else:
        return "Millions of years"

def estimate_crack_times(effective_entropy: float) -> Dict[str, Dict[str, Any]]:
    """
    Calculates estimated crack times against various threat actors and attack types.
    Assumes average 50% search space exploration (2^(entropy - 1)).
    """
    total_combinations = 2 ** max(1.0, effective_entropy)
    half_space = total_combinations / 2.0
    
    # Attack speeds:
    # 1. Online Rate-Limited / Throttled: 100 attempts / hour (~0.028 attempts/sec)
    online_throttled_rate = 100.0 / 3600.0
    # 2. Online Unthrottled Web Attack: 1,000 attempts / sec
    online_unthrottled_rate = 1000.0
    # 3. Offline Slow Hash Attack (bcrypt cost 12 on multi-GPU rig): 10,000 attempts / sec
    offline_slow_hash_rate = 10000.0
    # 4. Offline Fast Hash Attack (MD5/SHA256 on GPU cluster): 100 Billion attempts / sec (10^11)
    offline_fast_hash_rate = 100000000000.0

    t_throttled = half_space / online_throttled_rate
    t_unthrottled = half_space / online_unthrottled_rate
    t_slow_hash = half_space / offline_slow_hash_rate
    t_fast_hash = half_space / offline_fast_hash_rate

    return {
        "online_throttled": {
            "name": "Online Attack (with lockout / rate limiting)",
            "rate": "100 attempts / hour",
            "time_seconds": t_throttled,
            "display": format_time_duration(t_throttled),
            "threat_level": "LOW" if t_throttled > 86400 * 30 else "HIGH"
        },
        "online_unthrottled": {
            "name": "Online Attack (no rate limiting)",
            "rate": "1,000 attempts / sec",
            "time_seconds": t_unthrottled,
            "display": format_time_duration(t_unthrottled),
            "threat_level": "LOW" if t_unthrottled > 86400 * 365 else "HIGH"
        },
        "offline_bcrypt": {
            "name": "Offline GPU Attack on Slow Hash (bcrypt cost 12)",
            "rate": "10,000 guesses / sec",
            "time_seconds": t_slow_hash,
            "display": format_time_duration(t_slow_hash),
            "threat_level": "LOW" if t_slow_hash > 31536000 else "HIGH"
        },
        "offline_fast_gpu": {
            "name": "Offline GPU Cluster Attack on Fast Hash (MD5 / SHA-256)",
            "rate": "100 Billion guesses / sec",
            "time_seconds": t_fast_hash,
            "display": format_time_duration(t_fast_hash),
            "threat_level": "LOW" if t_fast_hash > 31536000 else "HIGH"
        }
    }

def analyze_password(password: str) -> Dict[str, Any]:
    """
    Main evaluation pipeline:
    - Calculates character pool and theoretical bits
    - Calculates Shannon frequency entropy
    - Executes pattern matching
    - Runs dictionary & leetspeak checks
    - Computes effective entropy and normalized 0-100 score
    - Estimates crack times across multiple attack profiles
    - Generates actionable security recommendations
    """
    if not password:
        return {
            "password_length": 0,
            "score": 0,
            "category": "Very Weak",
            "color": "danger",
            "theoretical_entropy": 0.0,
            "shannon_entropy": 0.0,
            "effective_entropy": 0.0,
            "pool_size": 0,
            "crack_times": estimate_crack_times(0.0),
            "patterns": [],
            "dictionary_analysis": check_dictionary(""),
            "checklist": {
                "length_8": False,
                "length_12": False,
                "has_lower": False,
                "has_upper": False,
                "has_digits": False,
                "has_symbols": False,
                "no_dictionary_words": True,
                "no_patterns": True
            },
            "feedback": ["Password cannot be empty. Please enter a password to analyze."]
        }

    pwd_len = len(password)
    theor = calculate_theoretical_entropy(password)
    shannon_entropy = calculate_shannon_entropy(password)
    patterns = detect_patterns(password)
    dict_result = check_dictionary(password)
    
    # Base scoring breakdown
    score = 0
    feedback = []
    
    # 1. Length scoring (up to 30 points)
    if pwd_len >= 16:
        score += 30
    elif pwd_len >= 12:
        score += 24
    elif pwd_len >= 8:
        score += 15
    elif pwd_len >= 6:
        score += 8
    else:
        score += 2
        feedback.append("Increase length to at least 12–16 characters for robust security.")

    # 2. Diversity scoring (up to 25 points)
    types_count = len(theor["char_types"])
    score += types_count * 6  # max 24 (or 25 with 4-5 types)
    if types_count == 4 or types_count == 5:
        score += 1

    # 3. Entropy bits scoring (up to 25 points)
    # 60+ bits is strong, 80+ is very strong
    entropy_bits = theor["entropy_bits"]
    if entropy_bits >= 80:
        score += 25
    elif entropy_bits >= 60:
        score += 20
    elif entropy_bits >= 45:
        score += 14
    elif entropy_bits >= 30:
        score += 8
    else:
        score += 3

    # Bonus for high complexity
    if pwd_len >= 14 and types_count >= 4 and not patterns and not dict_result["is_substring_match"]:
        score += 15

    # 4. Deductions / Penalties
    total_penalty = 0
    for pat in patterns:
        total_penalty += pat["penalty"]
        feedback.append(pat["description"])

    if dict_result["is_exact_match"]:
        # Catastrophic weakness
        score = min(score, 5)
        total_penalty += 80
        feedback.append(f"CRITICAL: Password matches common weak password list ('{dict_result['matched_word']}').")
    elif dict_result["is_substring_match"]:
        matches_str = ", ".join(dict_result["substring_matches"])
        score -= 25
        total_penalty += 25
        feedback.append(f"Contains common dictionary word or leaked stem: '{matches_str}'.")
        if dict_result["is_leetspeak_match"]:
            feedback.append("Leetspeak substitution detected (e.g. '@' for 'a', '1' for 'i'). Attackers easily decode this!")

    # Calculate effective entropy: theoretical entropy penalized by patterns & dictionary matches
    # Each pattern/dictionary reduces the effective search space exponentially
    entropy_penalty = (total_penalty / 100.0) * theor["entropy_bits"]
    effective_entropy = max(5.0, round(theor["entropy_bits"] - entropy_penalty, 2))
    
    if dict_result["is_exact_match"]:
        effective_entropy = 5.0

    score = max(5, min(100, score - (total_penalty // 2)))

    # Determine qualitative strength category
    if score >= 85 and not dict_result["is_exact_match"]:
        category = "Very Strong"
        color = "success"
    elif score >= 70 and not dict_result["is_exact_match"]:
        category = "Strong"
        color = "primary"
    elif score >= 50 and not dict_result["is_exact_match"]:
        category = "Moderate"
        color = "warning"
    elif score >= 25 and not dict_result["is_exact_match"]:
        category = "Weak"
        color = "orange"
    else:
        category = "Very Weak"
        color = "danger"

    # Actionable suggestions if score < 85
    if not theor["has_symbols"]:
        feedback.append("Add special characters (e.g. ! @ # $ % ^ & *) to increase entropy pool.")
    if not theor["has_upper"]:
        feedback.append("Include uppercase letters distributed across the password.")
    if not theor["has_digits"]:
        feedback.append("Include numbers (avoid placing them only at the very end).")
    if pwd_len < 12:
        feedback.append("Aim for at least 12 to 16 characters to defeat modern GPU cracking rigs.")
    if not feedback:
        feedback.append("Excellent password! It demonstrates high entropy, diverse character sets, and no predictable patterns.")

    checklist = {
        "length_8": pwd_len >= 8,
        "length_12": pwd_len >= 12,
        "has_lower": theor["has_lower"],
        "has_upper": theor["has_upper"],
        "has_digits": theor["has_digits"],
        "has_symbols": theor["has_symbols"],
        "no_dictionary_words": not dict_result["is_substring_match"],
        "no_patterns": len(patterns) == 0
    }

    crack_times = estimate_crack_times(effective_entropy)

    return {
        "password_length": pwd_len,
        "score": score,
        "category": category,
        "color": color,
        "theoretical_entropy": theor["entropy_bits"],
        "shannon_entropy": shannon_entropy,
        "effective_entropy": effective_entropy,
        "pool_size": theor["pool_size"],
        "char_types": theor["char_types"],
        "crack_times": crack_times,
        "patterns": patterns,
        "dictionary_analysis": dict_result,
        "checklist": checklist,
        "feedback": feedback
    }


def generate_secure_password(length: int = 16, use_upper: bool = True, use_digits: bool = True, use_symbols: bool = True) -> str:
    """
    Generates a cryptographically strong random password guaranteed to contain
    characters from each requested character set.
    """
    length = max(8, min(64, length))
    
    chars = string.ascii_lowercase
    guaranteed = [secrets.choice(string.ascii_lowercase)]
    
    if use_upper:
        chars += string.ascii_uppercase
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        chars += string.digits
        guaranteed.append(secrets.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        chars += symbols
        guaranteed.append(secrets.choice(symbols))
        
    remaining_length = length - len(guaranteed)
    random_part = [secrets.choice(chars) for _ in range(remaining_length)]
    
    full_list = guaranteed + random_part
    # Cryptographically shuffle using secrets.randbelow
    for i in range(len(full_list) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        full_list[i], full_list[j] = full_list[j], full_list[i]
        
    return "".join(full_list)

