"""
Dictionary-based password blacklist and pattern check utilities.
Includes curated lists of common passwords, leaked passwords, and dictionary words,
along with leetspeak normalization for evasion detection.
"""

import re

# Comprehensive list of top common, compromised, and weak passwords
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345", "12345678", "qwerty", "1234567",
    "dragon", "pussycat", "baseball", "football", "letmein", "monkey", "sunshine",
    "master", "welcome", "shadow", "ashley", "bailey", "charlie", "superman",
    "michael", "jessica", "jordan", "killer", "robert", "thomas", "hockey",
    "rangers", "daniel", "starwars", "orange", "yellow", "matrix", "george",
    "assassin", "computer", "princess", "secret", "default", "system", "admin",
    "administrator", "root", "guest", "test", "testing", "login", "user",
    "trustno1", "mustang", "access", "iloveyou", "supersecret", "pass123",
    "password123", "admin123", "root123", "changeme", "hello123", "hunter2",
    "fuckyou", "whatever", "loveme", "cookie", "cheese", "flower", "pepper",
    "peanut", "merlin", "batman", "pokemon", "liverpool", "arsenal", "chelsea",
    "barcelona", "realmadrid", "freedom", "america", "london", "canada",
    "alaska", "security", "protect", "shield", "secure", "bullet", "wizard",
    "target", "target1", "qwertyuiop", "asdfghjkl", "zxcvbnm", "111111", "000000",
    "666666", "777777", "888888", "999999", "123321", "654321", "password1",
    "iloveyou1", "mydog", "family", "friends", "summer", "winter", "spring",
    "autumn", "december", "january", "november", "october", "september", "august",
    "summer2020", "summer2021", "summer2022", "summer2023", "summer2024",
    "winter2020", "winter2021", "winter2022", "winter2023", "winter2024",
    "welcome1", "welcome123", "company", "service", "support", "server",
    "database", "network", "firewall", "cyber", "hacker", "internet", "website",
    "portal", "client", "office", "workplace", "enterprise", "station"
}

# Common English words that appear frequently as password stems
DICTIONARY_WORDS = {
    "about", "after", "again", "air", "all", "along", "also", "an", "and", "another",
    "any", "are", "around", "as", "at", "away", "back", "be", "because", "been",
    "before", "below", "between", "both", "but", "by", "came", "can", "come",
    "could", "day", "did", "do", "does", "down", "each", "even", "every", "first",
    "for", "from", "get", "give", "go", "good", "great", "had", "has", "have",
    "he", "help", "her", "here", "him", "his", "home", "house", "how", "if",
    "in", "into", "is", "it", "its", "just", "know", "large", "last", "left",
    "life", "like", "line", "little", "live", "look", "made", "make", "man",
    "many", "may", "me", "men", "might", "more", "most", "much", "must", "my",
    "name", "never", "new", "next", "night", "no", "not", "now", "number", "of",
    "off", "often", "old", "on", "one", "only", "or", "other", "our", "out",
    "over", "own", "part", "people", "place", "point", "put", "read", "right",
    "said", "same", "saw", "say", "see", "she", "should", "show", "small", "so",
    "some", "something", "sound", "still", "such", "take", "tell", "than", "that",
    "the", "their", "them", "then", "there", "these", "they", "thing", "think",
    "this", "those", "thought", "three", "through", "time", "to", "together", "too",
    "two", "under", "up", "upon", "us", "use", "very", "want", "water", "way",
    "we", "well", "went", "were", "what", "when", "where", "which", "while", "white",
    "who", "why", "will", "with", "word", "work", "world", "would", "write", "year",
    "tiger", "angel", "golden", "shadow", "monkey", "coffee", "dragon", "silver",
    "doctor", "banana", "galaxy", "system", "matrix", "master", "legend", "hunter"
}

# Leetspeak substitution mapping for evasive pattern detection
LEET_MAP = {
    '@': 'a', '4': 'a',
    '8': 'b',
    '(': 'c', '<': 'c',
    '3': 'e',
    '9': 'g', '6': 'g',
    '#': 'h',
    '1': 'i', '!': 'i', '|': 'i',
    '0': 'o',
    '$': 's', '5': 's',
    '7': 't', '+': 't',
    'v': 'u',
    '%': 'x'
}

def normalize_leetspeak(text: str) -> str:
    """Translates leetspeak substitutions back to standard lowercase letters."""
    result = []
    for char in text.lower():
        result.append(LEET_MAP.get(char, char))
    return "".join(result)

def check_dictionary(password: str) -> dict:
    """
    Checks if a password or parts of it match common passwords, dictionary words,
    or leetspeak substitutions of those words.
    
    Returns a dict with:
      - is_exact_match (bool)
      - matched_word (str or None)
      - is_substring_match (bool)
      - substring_matches (list of str)
      - is_leetspeak_match (bool)
      - normalized_text (str)
    """
    if not password:
        return {
            "is_exact_match": False,
            "matched_word": None,
            "is_substring_match": False,
            "substring_matches": [],
            "is_leetspeak_match": False,
            "normalized_text": ""
        }
        
    pwd_clean = password.strip().lower()
    normalized = normalize_leetspeak(pwd_clean)
    
    # 1. Exact match against common passwords or dictionary
    if pwd_clean in COMMON_PASSWORDS or pwd_clean in DICTIONARY_WORDS:
        return {
            "is_exact_match": True,
            "matched_word": pwd_clean,
            "is_substring_match": True,
            "substring_matches": [pwd_clean],
            "is_leetspeak_match": False,
            "normalized_text": normalized
        }
        
    # Check normalized text exact match
    if normalized != pwd_clean and (normalized in COMMON_PASSWORDS or normalized in DICTIONARY_WORDS):
        return {
            "is_exact_match": True,
            "matched_word": normalized,
            "is_substring_match": True,
            "substring_matches": [normalized],
            "is_leetspeak_match": True,
            "normalized_text": normalized
        }
        
    # 2. Substring matching (checking words of length >= 4)
    found_substrings = set()
    is_leet = False
    
    # Check both raw and normalized
    candidates = [pwd_clean]
    if normalized != pwd_clean:
        candidates.append(normalized)
        
    for text in candidates:
        # Check against common passwords
        for word in COMMON_PASSWORDS:
            if len(word) >= 4 and word in text:
                found_substrings.add(word)
                if text == normalized and pwd_clean != normalized:
                    is_leet = True
                    
        # Check against dictionary words
        for word in DICTIONARY_WORDS:
            if len(word) >= 4 and word in text:
                found_substrings.add(word)
                if text == normalized and pwd_clean != normalized:
                    is_leet = True

    # Filter out redundant substrings (e.g., if 'pass' and 'password' both match, prefer longer)
    sorted_matches = sorted(list(found_substrings), key=len, reverse=True)
    filtered_matches = []
    for m in sorted_matches:
        if not any(m != other and m in other for other in filtered_matches):
            filtered_matches.append(m)

    return {
        "is_exact_match": False,
        "matched_word": filtered_matches[0] if filtered_matches else None,
        "is_substring_match": len(filtered_matches) > 0,
        "substring_matches": filtered_matches[:5],
        "is_leetspeak_match": is_leet,
        "normalized_text": normalized
    }
