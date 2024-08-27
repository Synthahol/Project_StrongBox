import logging
import secrets
import string

# Configure logging
logger = logging.getLogger(__name__)


def generate_password(strength: int = 32) -> str:
    try:
        if strength == 1:
            length = secrets.choice(range(16, 29))
        elif strength == 2:
            length = secrets.choice(range(29, 43))
        elif strength == 3:
            length = secrets.choice(range(43, 61))
        else:
            raise ValueError(
                "Invalid password strength. Choose strength level 1, 2, or 3."
            )

        characters = string.ascii_letters + string.digits + string.punctuation
        secure_password = "".join(secrets.choice(characters) for i in range(length))

        ### ENSURE PASSWORD HAS AT LEAST ONE OF EACH TYPE OF CHARACTER ###
        if (
            any(c.islower() for c in secure_password)
            and any(c.isupper() for c in secure_password)
            and any(c.isdigit() for c in secure_password)
            and any(c in string.punctuation for c in secure_password)
        ):
            logger.info(f"Generated password with strength {strength}.")
            return secure_password
        else:
            ### IF PASSWORD DOES NOT MEET CRITERIA, RECURSIVELY CALL THE FUNCTION ###
            return generate_password(strength)
    except Exception as e:
        logger.error(f"Error generating password: {e}")
        return None


# Usage example (to be removed or commented out in production):
if __name__ == "__main__":
    print("Generated Password:", generate_password(3))
