"""The confirmation service: ``ConfirmationService(connect, token_key, custody, providers, dns, clock, jitter)``.

    connect     a runtime-role connection factory (the same one the admin app uses)
    token_key   the API's tenant token key; every unit of work mints its own short token for one organization
    custody     the key custody (``providers.keys.KeyProvider``): it wraps the provider credentials and opens contact keys
    providers   {"twilio": adapter, "ses": adapter, "postmark": adapter}; see ``providers.py`` for the shape
    dns         ``lookup(host, kind)`` for CNAME and TXT; a resolver over https when none is given
    clock       epoch seconds (a float): the ONE clock, the same callable the admin app is given, for quiet hours, windows and alarms
    jitter      a callable returning the fraction of extra delay (0 to 0.2) added to each retry offset; fixed at construction

Entry points: the admin routes call the functions of ``ConfigMixin`` and ``ReadsMixin`` with the request's context;
``handle_inbound`` and ``handle_public`` answer the provider and the person; ``run_sender``, ``recheck_link_hosts``,
``run_alarm_checks`` and ``purge`` are the periodic passes. Nothing here reads a reply with a model.
"""

from __future__ import annotations

from .config import ConfigMixin
from .core import Core
from .inbound import InboundMixin
from .jobs import JobsMixin
from .public import PublicMixin
from .reads import ReadsMixin
from .sender import SenderMixin


class ConfirmationService(SenderMixin, InboundMixin, PublicMixin, JobsMixin, ReadsMixin, ConfigMixin, Core):
    pass
