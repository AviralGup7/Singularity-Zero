"""Password hashing, verification, and strength validation."""

import re

from .models import PasswordHash


def hash_password(password: str, iterations: int = 600000) -> PasswordHash:
    """Create a new password hash from a plaintext password.

    Uses PBKDF2-HMAC-SHA256 with a random salt for secure password storage.

    Args:
        password: Plaintext password to hash.
        iterations: Number of PBKDF2 iterations (higher = more secure).

    Returns:
        PasswordHash instance with salt and hash.
    """
    return PasswordHash.create(password, iterations)


def verify_password(password: str, stored_hash: PasswordHash) -> bool:
    """Verify a plaintext password against a stored hash.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        password: Plaintext password to verify.
        stored_hash: PasswordHash instance to compare against.

    Returns:
        True if the password matches.
    """
    return stored_hash.verify(password)


def validate_password_strength(
    password: str,
    min_length: int = 8,
    require_uppercase: bool = True,
    require_lowercase: bool = True,
    require_digits: bool = True,
    require_special: bool = True,
) -> tuple[bool, list[str]]:
    """Validate password strength against security policies.

    Args:
        password: Plaintext password to validate.
        min_length: Minimum password length.
        require_uppercase: Require at least one uppercase letter.
        require_lowercase: Require at least one lowercase letter.
        require_digits: Require at least one digit.
        require_special: Require at least one special character.

    Returns:
        Tuple of (is_valid, list_of_error_messages).
    """
    errors: list[str] = []

    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters long")

    if require_uppercase and not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter")

    if require_lowercase and not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter")

    if require_digits and not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one digit")

    if require_special and not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\/~`]", password):
        errors.append("Password must contain at least one special character")

    return (len(errors) == 0, errors)
