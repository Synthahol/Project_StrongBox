# backend/password_generator.py

import logging
import math
import secrets
import string

# Configure logging
logger = logging.getLogger(__name__)


def generate_password(length: int, charset: str) -> str:
    """
    Generate a secure password with at least 256 bits of entropy.

    Args:
        length (int): The desired length of the password. Must be sufficient to achieve the required entropy.
        charset (str): A string of characters to use for generating the password.

    Returns:
        str: The generated password.

    Raises:
        ValueError: If the provided length is insufficient for the required entropy or if charset is empty.
    """
    if not charset:
        logger.error("Character set is empty.")
        raise ValueError("Character set must not be empty.")

    bits_per_char = math.log2(len(charset))
    required_entropy = 256
    actual_entropy = length * bits_per_char

    if actual_entropy < required_entropy:
        logger.error(
            f"Provided length {length} with charset size {len(charset)} "
            f"only provides {actual_entropy:.2f} bits of entropy, "
            f"which is less than the required {required_entropy} bits."
        )
        raise ValueError(
            f"Password length of {length} is insufficient for {required_entropy} bits of entropy with the given character set."
        )

    # Define character categories based on the charset
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special_characters = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"

    # Ensure the password contains at least one character from each category present in the charset
    password_characters = []
    if any(c in charset for c in lowercase):
        password_characters.append(secrets.choice(lowercase))
    if any(c in charset for c in uppercase):
        password_characters.append(secrets.choice(uppercase))
    if any(c in charset for c in digits):
        password_characters.append(secrets.choice(digits))
    if any(c in charset for c in special_characters):
        password_characters.append(secrets.choice(special_characters))

    # Fill the remaining length with random choices from all categories
    remaining_length = length - len(password_characters)
    if remaining_length > 0:
        password_characters += [secrets.choice(charset) for _ in range(remaining_length)]

    # Shuffle the characters to ensure randomness
    secrets.SystemRandom().shuffle(password_characters)

    # Join the characters to form the password
    secure_password = ''.join(password_characters)

    # Log the generated password details
    logger.info(
        f"Generated password of length {len(secure_password)} with {actual_entropy:.2f} bits of entropy."
    )

    return secure_password
