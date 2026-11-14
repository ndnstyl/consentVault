"""Consent confirmation messages (contracts/confirmations.md): send the person one message that repeats what they agreed to,
when, and how to stop; receive their replies; record every stop and START as evidence. See ``service.py`` for the seams."""

from .core import Reply
from .providers import ProviderError
from .service import ConfirmationService

__all__ = ["ConfirmationService", "ProviderError", "Reply"]
