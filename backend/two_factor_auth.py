# backend/two_factor_auth.py

import logging
from io import BytesIO
from typing import Optional

import pyotp
import qrcode

from .database import get_2fa_secret, store_2fa_secret
from .exceptions import (
    SecretAlreadyExistsError,
    SecretNotFoundError,
)  # Adjust import based on where exceptions are defined

logger = logging.getLogger(__name__)


class TwoFactorAuthentication:
    """Handles 2FA setup and verification."""

    def __init__(self, user_identifier: str, conn):
        """
        :param user_identifier: A unique identifier for the user (could be email or username)
        :param conn: SQLite connection object for database operations
        """
        self.user_identifier = user_identifier
        self.conn = conn

    def generate_secret(self) -> str:
        """Generates a new secret for the user and stores it."""
        existing_secret = self.get_secret()
        if existing_secret:
            logger.warning(
                "Attempted to generate a secret for a user who already has one."
            )
            raise SecretAlreadyExistsError("2FA is already set up for this user.")

        secret = pyotp.random_base32()
        logger.debug("Generated new secret, now storing it.")
        store_2fa_secret(self.conn, self.user_identifier, secret)
        logger.info("Generated and stored new 2FA secret for the user.")
        return secret

    def get_secret(self) -> Optional[str]:
        """Fetches the user's 2FA secret from the database."""
        secret = get_2fa_secret(self.conn, self.user_identifier)
        return secret

    def store_secret(self, secret: str) -> bool:
        """
        Stores the 2FA secret in the database.

        Args:
            secret (str): The 2FA secret to store.

        Returns:
            bool: True if storage was successful, False otherwise.
        """
        try:
            store_2fa_secret(self.conn, self.user_identifier, secret)
            logger.info(f"Stored 2FA secret for user: {self.user_identifier}")
            return True
        except Exception as e:
            logger.error(
                f"Failed to store 2FA secret for user {self.user_identifier}: {e}"
            )
            return False

    def generate_qr_code(self) -> bytes:
        """Generates a QR code for the user to scan with an authenticator app.

        :return: QR code image data in bytes.
        """
        secret = self.get_secret()
        if not secret:
            raise SecretNotFoundError(
                "2FA secret not found for user. Please set up 2FA first."
            )
        totp_uri = pyotp.TOTP(secret).provisioning_uri(
            self.user_identifier, issuer_name="Fortalice"
        )
        # Generate the QR code
        qr_img = qrcode.make(totp_uri)
        # Convert the QR code image to bytes
        buffer = BytesIO()
        qr_img.save(buffer, format="PNG")
        return buffer.getvalue()

    def verify_token(self, token: str) -> bool:
        """Verifies the provided TOTP token.

        :param token: The TOTP token provided by the user.
        :return: True if the token is valid, False otherwise.
        """
        secret = self.get_secret()
        if not secret:
            raise SecretNotFoundError("2FA secret not found for user.")
        totp = pyotp.TOTP(secret)
        is_valid = totp.verify(
            token, valid_window=1
        )  # Allows for slight time discrepancies
        if is_valid:
            logger.info("2FA token verification successful.")
        else:
            logger.warning("2FA token verification failed.")
        return is_valid
