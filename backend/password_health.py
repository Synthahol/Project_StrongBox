import hashlib
import logging
import random
import re
import time

# Configure logging with rotation
from logging.handlers import RotatingFileHandler
from typing import List, Tuple

import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)  # Set logging level to WARNING for production

# Create handlers
if not logger.handlers:
    # Rotating file handler: 5MB per file, keep up to 5 backups
    file_handler = RotatingFileHandler(
        "password_checker.log", maxBytes=5 * 1024 * 1024, backupCount=5
    )
    file_handler.setLevel(logging.WARNING)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(formatter)

    # Stream handler for console output
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.WARNING)
    stream_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

# Constants
HIBP_API_URL = "https://api.pwnedpasswords.com/range/{}"
HEADERS = {"User-Agent": "Fortalice-PW-Checker/1.0"}
RETRY_LIMIT = 3
RETRY_DELAY = 2  # seconds (base delay for exponential backoff)
MAX_DELAY = 60  # seconds
TIMEOUT = 5  # seconds


class HIBPAPIError(Exception):
    """Custom exception for HIBP API related errors."""

    pass


def check_password_pwned(password: str) -> int:
    """
    Check if the provided password has been compromised using the HIBP API.

    :param password: The plaintext password to check.
    :return: The number of times the password has been seen. Returns 0 if not found.
    :raises HIBPAPIError: If there's an issue fetching data from HIBP.
    :raises ValueError: If the password is not a string.
    """
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")

    # Hash the password with SHA-1, required by HIBP API
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    url = HIBP_API_URL.format(prefix)

    # Attempt API request with retries and exponential backoff
    for attempt in range(1, RETRY_LIMIT + 1):
        try:
            response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

            # Check if the response is successful and has the correct content type
            if (
                response.status_code == 200
                and response.headers.get("Content-Type") == "text/plain"
            ):
                break
            else:
                logger.error(
                    f"HIBP API error: {response.status_code} - {response.text}"
                )
                raise HIBPAPIError(f"Error fetching HIBP data: {response.status_code}")
        except RequestException as e:
            logger.warning(f"Attempt {attempt} failed: {e}")
            if attempt < RETRY_LIMIT:
                delay = min(
                    RETRY_DELAY * (2 ** (attempt - 1)) + random.uniform(0, 1), MAX_DELAY
                )
                logger.info(f"Retrying after {delay:.2f} seconds...")
                time.sleep(delay)
            else:
                logger.error("Exceeded maximum retry attempts.")
                raise HIBPAPIError(
                    f"Failed to fetch HIBP data after {RETRY_LIMIT} attempts."
                ) from e

    # Process the response and check if the password suffix matches
    hashes = (line.split(":") for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            logger.warning(f"Password has been pwned {count} times.")
            return int(count)

    logger.info("Password not found in HIBP database.")
    return 0


def check_password_strength(password: str) -> Tuple[bool, dict]:
    """
    Evaluate the strength of a password based on predefined rules.

    :param password: The plaintext password to evaluate.
    :return: A tuple containing a boolean indicating if the password is strong and a dictionary of rule evaluations.
    :raises ValueError: If the password is not a string.
    """
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")

    # Define password strength rules
    rules = {
        "length": len(password) >= 12,  # Increased minimum length for better security
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "special_char": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
    }

    is_strong = all(rules.values())
    logger.debug(f'Password strength: {"Strong" if is_strong else "Weak"}')
    return is_strong, rules


def get_password_feedback(is_strong: bool, rules: dict) -> List[str]:
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
        feedback.append(
            "This password should be stronger. Consider the following improvements:"
        )
        if not rules.get("length", False):
            feedback.append("- Use at least 12 characters.")
        if not rules.get("uppercase", False):
            feedback.append("- Include uppercase letters (A-Z).")
        if not rules.get("lowercase", False):
            feedback.append("- Include lowercase letters (a-z).")
        if not rules.get("digit", False):
            feedback.append("- Include numbers (0-9).")
        if not rules.get("special_char", False):
            feedback.append("- Include special characters (e.g., !@#$%^&*).")
    return feedback


# Example Usage (comment out when running in production)
# if __name__ == "__main__":
#     test_password = "TestPassword123!"
#     try:
#         pwned_count = check_password_pwned(test_password)
#         is_strong, rule_evals = check_password_strength(test_password)
#         feedback = get_password_feedback(is_strong, rule_evals)
#         print(f"Password pwned {pwned_count} times.")
#         print("Feedback:")
#         for msg in feedback:
#             print(msg)
#     except Exception as e:
#         logger.error(f"An error occurred: {e}")
