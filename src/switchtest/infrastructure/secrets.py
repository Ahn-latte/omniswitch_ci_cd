import os

from switchtest.exceptions import ConfigurationError


def get_required_secret(env_name: str) -> str:
    value = os.getenv(env_name)
    if not value:
        raise ConfigurationError(f"Required environment variable is missing: {env_name}")
    return value


def get_optional_secret(env_name: str | None) -> str | None:
    if not env_name:
        return None
    return os.getenv(env_name)


def resolve_secret(inline: str | None, env_name: str | None, label: str) -> str:
    """A secret given either directly (lab config) or by environment variable.

    Inline wins: if the lab config carries the password, that is the one the
    operator just edited, and silently preferring a stale environment variable
    over it would be the more surprising of the two.
    """
    if inline:
        return inline
    if env_name:
        return get_required_secret(env_name)
    raise ConfigurationError(f"No password configured for {label}")


def resolve_optional_secret(inline: str | None, env_name: str | None) -> str | None:
    if inline:
        return inline
    return get_optional_secret(env_name)
