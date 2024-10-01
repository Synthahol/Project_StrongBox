# exceptions.py (create this module if it doesn't exist)


class TwoFactorAuthError(Exception):
    """Base exception for 2FA errors."""


class SecretAlreadyExistsError(TwoFactorAuthError):
    """Raised when a 2FA secret already exists for the user."""


class SecretNotFoundError(TwoFactorAuthError):
    """Raised when a 2FA secret is not found for the user."""
