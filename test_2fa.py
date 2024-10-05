import logging
from backend.database import create_connection, initialize_db, store_2fa_secret, get_2fa_secret
from backend.two_factor_auth import TwoFactorAuthentication
from backend.exceptions import SecretAlreadyExistsError, SecretNotFoundError

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

def test_2fa():
    conn = create_connection()
    initialize_db(conn, "test_key_id")
    user = "test@example.com"
    two_fa = TwoFactorAuthentication(user, conn)
    try:
        secret = two_fa.generate_secret()
        logger.info(f"Secret generated: {secret}")
    except SecretAlreadyExistsError:
        logger.warning("Secret already exists.")
        secret = two_fa.get_secret()
        logger.info(f"Retrieved existing secret: {secret}")

    # Now retrieve the secret
    retrieved_secret = two_fa.get_secret()
    if retrieved_secret:
        logger.info(f"Retrieved secret: {retrieved_secret}")
    else:
        logger.error("Failed to retrieve secret.")

if __name__ == "__main__":
    test_2fa()
