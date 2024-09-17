import logging
import math
import os
import secrets
import string

# Configure logging
logger = logging.getLogger(__name__)


def generate_password() -> str:
    """
    Generate a secure password with at least 256 bits of entropy.

    Returns:
        str: The generated password.
    """
    # Define the character pools
    lowercase = string.ascii_lowercase  # 26 characters
    uppercase = string.ascii_uppercase  # 26 characters
    digits = string.digits  # 10 characters
    special_characters = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"  # 28 characters

    # Combine all characters
    all_characters = lowercase + uppercase + digits + special_characters

    # Calculate entropy per character
    entropy_per_char = math.log2(
        len(all_characters)
    )  # Approximately 6.4919 bits per character

    # Minimum password length to achieve 256 bits of entropy
    min_length = math.ceil(256 / entropy_per_char)  # Calculated value is 40

    # Maximum password length (adjust as desired)
    max_length = 60

    # Choose a random length within the specified range
    length = secrets.choice(range(min_length, max_length + 1))

    # Ensure the password contains at least one character from each category
    password_characters = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special_characters),
    ]

    # Fill the rest of the password length with random choices from all categories
    remaining_length = length - len(password_characters)
    password_characters += [
        secrets.choice(all_characters) for _ in range(remaining_length)
    ]

    # Shuffle the characters to ensure randomness
    secrets.SystemRandom().shuffle(password_characters)

    # Join the characters to form the password
    secure_password = "".join(password_characters)

    # Log the generated password length and entropy
    total_entropy = length * entropy_per_char
    logger.info(
        f"Generated password of length {length} with approximately {total_entropy:.2f} bits of entropy."
    )

    return secure_password


def generate_passphrase(separator: str = "!") -> str:
    """
    Generate a secure passphrase using the Diceware method with at least 256 bits of entropy.
    Special characters are used as separators between words.

    Args:
        separator (str): The special character to use as a separator between words.

    Returns:
        str: The generated passphrase.
    """
    # Define the path to the Diceware wordlist
    wordlist_path = os.path.join(os.path.dirname(__file__), "diceware_wordlist.txt")

    # Load Diceware wordlist
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            wordlist = []
            for line in f:
                # Each line is in the format: '11111 word'
                parts = line.strip().split()
                if len(parts) == 2:
                    wordlist.append(parts[1])
                else:
                    logger.warning(f"Skipping malformed line: {line.strip()}")
    except FileNotFoundError:
        logger.error(f"Wordlist file not found at path: {wordlist_path}")
        raise FileNotFoundError(f"Wordlist file not found at path: {wordlist_path}")
    except Exception as e:
        logger.error(f"Failed to load Diceware wordlist: {e}")
        raise

    # Verify wordlist length
    wordlist_length = len(wordlist)  # Should be 7776 for standard Diceware
    if wordlist_length != 7776:
        logger.warning(
            f"Expected 7776 words, but found {wordlist_length} words in the wordlist."
        )

    # Calculate entropy per word
    entropy_per_word = math.log2(wordlist_length)  # ~12.92 bits

    # Number of words needed for 256 bits of entropy
    num_words = math.ceil(256 / entropy_per_word)  # 20 words

    # Generate passphrase
    words = [secrets.choice(wordlist) for _ in range(num_words)]
    passphrase = separator.join(words)

    # Log the generated passphrase details
    total_entropy = num_words * entropy_per_word
    logger.info(
        f"Generated passphrase with {num_words} words and approximately {total_entropy:.2f} bits of entropy."
    )

    return passphrase


def generate_hybrid() -> str:
    """
    Generate a hybrid passphrase combining words and special characters with at least 256 bits of entropy.

    Returns:
        str: The generated hybrid passphrase.
    """
    # Define the path to the Diceware wordlist
    wordlist_path = os.path.join(os.path.dirname(__file__), "diceware_wordlist.txt")

    # Load Diceware wordlist
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            wordlist = []
            for line in f:
                # Each line is in the format: '11111 word'
                parts = line.strip().split()
                if len(parts) == 2:
                    wordlist.append(parts[1])
                else:
                    logger.warning(f"Skipping malformed line: {line.strip()}")
    except FileNotFoundError:
        logger.error(f"Wordlist file not found at path: {wordlist_path}")
        raise FileNotFoundError(f"Wordlist file not found at path: {wordlist_path}")
    except Exception as e:
        logger.error(f"Failed to load Diceware wordlist: {e}")
        raise

    # Verify wordlist length
    wordlist_length = len(wordlist)  # Should be 7776 for standard Diceware
    if wordlist_length != 7776:
        logger.warning(
            f"Expected 7776 words, but found {wordlist_length} words in the wordlist."
        )

    # Calculate entropy per word
    entropy_per_word = math.log2(wordlist_length)  # ~12.92 bits

    # Number of words needed for 256 bits of entropy
    num_words = math.ceil(256 / entropy_per_word)  # 20 words

    # Define the special characters to interleave
    special_characters = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"

    # Calculate number of special characters needed (one less than number of words)
    num_separators = num_words - 1

    # Generate passphrase words
    words = [secrets.choice(wordlist) for _ in range(num_words)]

    # Generate separators
    separators = [secrets.choice(special_characters) for _ in range(num_separators)]

    # Interleave words and separators
    hybrid_passphrase = (
        "".join([word + sep for word, sep in zip(words, separators)]) + words[-1]
    )  # Append the last word without a separator

    # Log the generated hybrid passphrase details
    total_entropy = (
        num_words * entropy_per_word
        + math.log2(len(special_characters)) * num_separators
    )
    logger.info(
        f"Generated hybrid passphrase with {num_words} words and {num_separators} separators, totaling approximately {total_entropy:.2f} bits of entropy."
    )

    return hybrid_passphrase


# Usage example (to be removed or commented out in production):
if __name__ == "__main__":
    print("Generated Password:", generate_password())
    print("Generated Passphrase:", generate_passphrase())
    print("Generated Hybrid Passphrase:", generate_hybrid())
