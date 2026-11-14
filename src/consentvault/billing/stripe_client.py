"""The vault's view of Stripe: a small interface the handlers take as an argument, and one HTTP implementation.

Handlers and routes never import this module's HTTP class; tests pass a fake. The HTTP implementation sends form
encoded requests with a bearer key, an Idempotency-Key on every POST, and a timeout on every call. Network faults,
timeouts, 429 and 5xx raise ``StripeUnavailableError`` (safe to retry); any other non-2xx raises
``StripeRejectedError`` with Stripe's own error message (never the key).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Protocol

from ..safelog import http_error_response
from .errors import StripeRejectedError, StripeUnavailableError
from ..urlguard import require_url, open_no_redirect

API_BASE = "https://api.stripe.com"
TIMEOUT_SECONDS = 20


class StripeClient(Protocol):
    def retrieve_checkout_session(self, session_id: str) -> dict[str, Any]: ...
    def retrieve_subscription(self, subscription_id: str) -> dict[str, Any]: ...
    def retrieve_invoice(self, invoice_id: str) -> dict[str, Any]: ...
    def retrieve_customer(self, customer_id: str) -> dict[str, Any]: ...
    def retrieve_price(self, price_id: str) -> dict[str, Any]: ...
    def list_subscriptions(self, customer: str) -> list[dict[str, Any]]: ...
    def list_open_checkout_sessions(self, customer: str) -> list[dict[str, Any]]: ...
    def expire_checkout_session(self, session_id: str) -> dict[str, Any]: ...
    def list_prices(self) -> list[dict[str, Any]]: ...
    def create_customer(self, *, org_id: str, idempotency_key: str) -> dict[str, Any]: ...
    def create_checkout_session(self, *, customer: str, line_items: list[dict[str, Any]], org_id: str,
                                success_url: str, cancel_url: str, idempotency_key: str) -> dict[str, Any]: ...
    def create_portal_session(self, *, customer: str, return_url: str) -> dict[str, Any]: ...
    def create_meter_event(self, *, event_name: str, customer: str, value: int, identifier: str,
                           timestamp: int) -> dict[str, Any]: ...


Transport = Callable[[str, str, bytes | None, dict[str, str]], tuple[int, bytes]]


def encode_form(params: dict[str, Any], prefix: str = "") -> list[tuple[str, str]]:
    """Stripe's nested form encoding: ``a[b][0][c]=v``. Booleans are ``true``/``false``; None is dropped."""
    pairs: list[tuple[str, str]] = []
    for key, value in params.items():
        name = f"{prefix}[{key}]" if prefix else str(key)
        if value is None:
            continue
        if isinstance(value, dict):
            pairs.extend(encode_form(value, name))
        elif isinstance(value, (list, tuple)):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    pairs.extend(encode_form(item, f"{name}[{i}]"))
                else:
                    pairs.append((f"{name}[{i}]", _scalar(item)))
        else:
            pairs.append((name, _scalar(value)))
    return pairs


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def urllib_transport(method: str, url: str, body: bytes | None, headers: dict[str, str]) -> tuple[int, bytes]:
    require_url(url, host_pattern=r"api\.stripe\.com")
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with open_no_redirect(req, timeout=TIMEOUT_SECONDS, host_pattern=r"api\.stripe\.com", loopback_http=False) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:  # the status code is the answer; the caller classifies it
        status, _headers, body = http_error_response(exc)
        return status, body
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise StripeUnavailableError(f"Stripe did not answer: {type(exc).__name__}") from exc


class HttpStripeClient:
    """Stripe over HTTPS. ``transport`` is replaceable so tests never touch the network."""

    def __init__(self, api_key: str, *, transport: Transport = urllib_transport, api_version: str | None = None):
        if not api_key:
            raise StripeRejectedError("no Stripe API key was given")
        self._key = api_key
        self._transport = transport
        self._version = api_version

    def __repr__(self) -> str:  # the key never reaches a log line
        return "HttpStripeClient(key=<hidden>)"

    def _call(self, method: str, path: str, params: dict[str, Any] | None = None,
              idempotency_key: str | None = None) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._key}", "Accept": "application/json"}
        if self._version:
            headers["Stripe-Version"] = self._version
        pairs = encode_form(params or {})
        url = API_BASE + path
        body: bytes | None = None
        if method == "GET":
            if pairs:
                url += "?" + urllib.parse.urlencode(pairs)
        else:
            body = urllib.parse.urlencode(pairs).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            if idempotency_key:
                headers["Idempotency-Key"] = idempotency_key
        status, raw = self._transport(method, url, body, headers)
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            raise StripeUnavailableError(f"Stripe answered {status} with a body that is not JSON") from None
        if 200 <= status < 300:
            return data
        message = ((data.get("error") or {}).get("message") if isinstance(data, dict) else None) or "no message"
        if status == 429 or status >= 500:
            raise StripeUnavailableError(f"Stripe answered {status}: {message}")
        raise StripeRejectedError(f"Stripe refused {method} {path} with {status}: {message}")

    def retrieve_checkout_session(self, session_id: str) -> dict[str, Any]:
        return self._call("GET", f"/v1/checkout/sessions/{urllib.parse.quote(session_id, safe='')}")

    def retrieve_subscription(self, subscription_id: str) -> dict[str, Any]:
        return self._call("GET", f"/v1/subscriptions/{urllib.parse.quote(subscription_id, safe='')}")

    def retrieve_invoice(self, invoice_id: str) -> dict[str, Any]:
        return self._call("GET", f"/v1/invoices/{urllib.parse.quote(invoice_id, safe='')}")

    def retrieve_customer(self, customer_id: str) -> dict[str, Any]:
        return self._call("GET", f"/v1/customers/{urllib.parse.quote(customer_id, safe='')}")

    def retrieve_price(self, price_id: str) -> dict[str, Any]:
        return self._call("GET", f"/v1/prices/{urllib.parse.quote(price_id, safe='')}", {"expand": ["product", "tiers"]})

    def list_subscriptions(self, customer: str) -> list[dict[str, Any]]:
        """The customer's subscriptions Stripe has not cancelled (Stripe's default list), walked to the end."""
        out: list[dict[str, Any]] = []
        params: dict[str, Any] = {"customer": customer, "limit": 100}
        for _ in range(20):
            page = self._call("GET", "/v1/subscriptions", params)
            out.extend(page.get("data") or [])
            if not page.get("has_more") or not page.get("data"):
                return out
            params = {**params, "starting_after": page["data"][-1]["id"]}
        raise StripeUnavailableError("Stripe subscription list did not end after 20 pages")

    def list_open_checkout_sessions(self, customer: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        params: dict[str, Any] = {"customer": customer, "status": "open", "limit": 100}
        for _ in range(20):
            page = self._call("GET", "/v1/checkout/sessions", params)
            out.extend(page.get("data") or [])
            if not page.get("has_more") or not page.get("data"):
                return out
            params = {**params, "starting_after": page["data"][-1]["id"]}
        raise StripeUnavailableError("Stripe checkout session list did not end after 20 pages")

    def expire_checkout_session(self, session_id: str) -> dict[str, Any]:
        return self._call("POST", f"/v1/checkout/sessions/{urllib.parse.quote(session_id, safe='')}/expire", {},
                          f"expire:{session_id}")

    def list_prices(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        params: dict[str, Any] = {"active": True, "limit": 100, "expand": ["data.product"]}
        for _ in range(20):  # a bounded walk: a runaway cursor is an error, not an endless loop
            page = self._call("GET", "/v1/prices", params)
            out.extend(page.get("data") or [])
            if not page.get("has_more") or not page.get("data"):
                return out
            params = {**params, "starting_after": page["data"][-1]["id"]}
        raise StripeUnavailableError("Stripe price list did not end after 20 pages")

    def create_customer(self, *, org_id: str, idempotency_key: str) -> dict[str, Any]:
        return self._call("POST", "/v1/customers", {"metadata": {"org_id": org_id}}, idempotency_key)

    def create_checkout_session(self, *, customer: str, line_items: list[dict[str, Any]], org_id: str,
                                success_url: str, cancel_url: str, idempotency_key: str) -> dict[str, Any]:
        params = {"mode": "subscription", "customer": customer, "line_items": line_items,
                  "client_reference_id": org_id, "success_url": success_url, "cancel_url": cancel_url,
                  "metadata": {"org_id": org_id}, "subscription_data": {"metadata": {"org_id": org_id}}}
        return self._call("POST", "/v1/checkout/sessions", params, idempotency_key)

    def create_portal_session(self, *, customer: str, return_url: str) -> dict[str, Any]:
        return self._call("POST", "/v1/billing_portal/sessions", {"customer": customer, "return_url": return_url})

    def create_meter_event(self, *, event_name: str, customer: str, value: int, identifier: str,
                           timestamp: int) -> dict[str, Any]:
        params = {"event_name": event_name, "identifier": identifier, "timestamp": timestamp,
                  "payload": {"stripe_customer_id": customer, "value": value}}
        return self._call("POST", "/v1/billing/meter_events", params, identifier)
