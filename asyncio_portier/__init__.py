"""Public API definitions for asyncio-portier."""
import pkg_resources

from .client import discover_keys, get_verified_email

# Module version, as defined in PEP-0396.
__version__ = pkg_resources.get_distribution('asyncio-portier').version

# Public API
__all__ = (
    'discover_keys',
    'get_verified_email',
)
