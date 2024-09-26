# backend/password_health.py

import hashlib
import logging
import re
import time

import requests

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  # Adjust as needed
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)

# Constants
HIBP_API_URL = "https://api.pwnedpasswords.com/range/{}"
HEADERS = {"User-Agent": "Fortalice-PW-Checker/1.0"}
RETRY_LIMIT = 3
RETRY_DELAY = 2  # seconds


def check_password_pwned(password):
    """
    Check if the provided password has been compromised using the HIBP API.

    :param password: The plaintext password to check.
    :return: The number of times the password has been seen. Returns 0 if not found.
    :raises RuntimeError: If there's an issue fetching data from HIBP.
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    url = HIBP_API_URL.format(prefix)
    for attempt in range(RETRY_LIMIT):
        try:
            response = requests.get(url, headers=HEADERS, timeout=5)
            if response.status_code != 200:
                logger.error(f"HIBP API error: {response.status_code}")
                raise RuntimeError(f"Error fetching HIBP data: {response.status_code}")
            break
        except requests.RequestException as e:
            logger.warning(f"Attempt {attempt + 1} failed: {e}")
            if attempt < RETRY_LIMIT - 1:
                time.sleep(RETRY_DELAY)
            else:
                raise RuntimeError(
                    f"Failed to fetch HIBP data after {RETRY_LIMIT} attempts."
                ) from e

    hashes = (line.split(":") for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            logger.info(f"Password has been pwned {count} times.")
            return int(count)

    logger.info("Password not found in HIBP database.")
    return 0


def check_password_strength(password):
    """
    Evaluate the strength of a password based on predefined rules.

    :param password: The plaintext password to evaluate.
    :return: A tuple containing a boolean indicating if the password is strong and a dictionary of rule evaluations.
    """
    rules = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "special_char": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
    }

    is_strong = all(rules.values())
    logger.info(f'Password strength: {"Strong" if is_strong else "Weak"}')
    return is_strong, rules


def get_password_feedback(is_strong, rules):
    """
    Provide feedback based on password strength evaluation.

    :param is_strong: Boolean indicating if the password is strong.
    :param rules: Dictionary of rule evaluations.
    :return: A list of feedback messages.
    """
    feedback = []
    if is_strong:
        feedback.append("Your password is strong.")
    else:
        feedback.append("This password is weak. Consider the following improvements:")
        if not rules["length"]:
            feedback.append("- Use at least 8 characters.")
        if not rules["uppercase"]:
            feedback.append("- Include uppercase letters (A-Z).")
        if not rules["lowercase"]:
            feedback.append("- Include lowercase letters (a-z).")
        if not rules["digit"]:
            feedback.append("- Include numbers (0-9).")
        if not rules["special_char"]:
            feedback.append("- Include special characters (e.g., !@#$%^&*).")
    return feedback
