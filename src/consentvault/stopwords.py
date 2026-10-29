"""Classify an inbound message as ``stop``, ``start``, ``not_stop`` or ``needs_review``.

Word lists live in ``data/stopwords.json``. The classifier folds Unicode lookalikes (fullwidth,
Cyrillic, Greek, stylised letters), strips zero-width and combining characters, and drops
apostrophes before matching. When in doubt it asks a human (``needs_review``) instead of
guessing either way.

Order of evaluation:
1. mask near-misses ("bus stop", "can't stop", "stop by");
2. a negated stop word ("don't stop") is ``needs_review`` unless a real stop phrase remains;
3. a stop phrase ("don't text me", "remove me") is ``stop``;
4. a message that is only keywords and filler ("STOP", "please stop now") is ``stop``;
5. a keyword inside a longer message is ``needs_review``;
6. a message that is only a start word (START, UNSTOP, YES) and filler is ``start``: the sender controls the contact
   point and asks to be contacted again. It is checked after every stop signal, so "yes stop" is never a start;
7. anything else is ``not_stop``.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from .errors import ConfigError

STOP = "stop"
START = "start"
NOT_STOP = "not_stop"
NEEDS_REVIEW = "needs_review"
MAX_WRAPPED_TOKENS = 8


@dataclass(frozen=True)
class Classification:
    verdict: str
    reason: str
    matched: str = ""


@dataclass(frozen=True)
class _Lists:
    keywords: tuple[str, ...]
    sentence_keywords: tuple[str, ...]
    filler: frozenset[str]
    contact_words: frozenset[str]
    phrases: tuple[re.Pattern, ...]
    near_miss: tuple[re.Pattern, ...]
    negations: tuple[re.Pattern, ...]
    confusables: dict[int, str]
    keyword_sequence: re.Pattern
    start_sequence: re.Pattern
    sentence_re: re.Pattern


def _alt(words) -> str:
    return "|".join(re.escape(w) for w in sorted(words, key=len, reverse=True))


@lru_cache(maxsize=1)
def _load() -> _Lists:
    try:
        raw = json.loads(resources.files("consentvault").joinpath("data/stopwords.json").read_text(encoding="utf-8"))
        keywords = sorted({k for group in raw["keywords"].values() for k in group})
        exact_only = set(raw["exact_only"])
        sentence = [k for k in keywords if k not in exact_only]
        return _Lists(
            keywords=tuple(keywords),
            sentence_keywords=tuple(sentence),
            filler=frozenset(raw["filler"]),
            contact_words=frozenset(raw["contact_words"]),
            phrases=tuple(re.compile(p) for p in raw["phrases"]),
            near_miss=tuple(re.compile(p) for p in raw["near_miss"]),
            negations=tuple(re.compile(p) for p in raw["negations"]),
            confusables={ord(k): v for k, v in raw["confusables"].items()},
            keyword_sequence=re.compile(rf"(?:{_alt(keywords)})(?: (?:{_alt(keywords)}))*"),
            sentence_re=re.compile(rf"\b(?:{_alt(sentence)})\b"),
            start_sequence=re.compile(rf"(?:{_alt(raw['start_keywords'])})(?: (?:{_alt(raw['start_keywords'])}))*"),
        )
    except (OSError, KeyError, ValueError, re.error) as exc:
        raise ConfigError(f"stopwords.json is missing or malformed: {exc}") from exc


def fold(text: str) -> str:
    """Normalise a message: fold lookalikes, drop invisibles and accents, lowercase, strip punctuation."""
    lists = _load()
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    text = text.casefold().translate(lists.confusables)
    text = unicodedata.normalize("NFD", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    text = re.sub(r"['’ʼ`]", "", text)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return text.strip()


def _join_spaced_letters(folded: str) -> str:
    tokens = folded.split()
    if len(tokens) >= 3 and all(len(t) == 1 for t in tokens):
        return "".join(tokens)
    return folded


def _mask(patterns, text: str) -> tuple[str, list[str]]:
    hits: list[str] = []
    for pat in patterns:
        for m in pat.finditer(text):
            hits.append(m.group(0))
        text = pat.sub(" ", text)
    return re.sub(r" +", " ", text).strip(), hits


def classify(message: str) -> Classification:
    """Classify one inbound message. Never raises on odd text; raises ConfigError if the lists are broken."""
    if not isinstance(message, str) or not message.strip():
        return Classification(NOT_STOP, "empty_message")
    lists = _load()
    folded = _join_spaced_letters(fold(message))
    if not folded:
        return Classification(NOT_STOP, "no_letters")

    masked, near_hits = _mask(lists.near_miss, folded)
    near = bool(near_hits)
    tokens_all = set(folded.split())

    masked, neg_hits = _mask(lists.negations, masked)
    for pat in lists.phrases:
        m = pat.search(masked)
        if m:
            return Classification(STOP, "stop_phrase", m.group(0))
    if neg_hits:
        return Classification(NEEDS_REVIEW, "negated_stop_word", neg_hits[0])

    tokens = masked.split()
    core = [t for t in tokens if t not in lists.filler]
    if tokens and len(tokens) <= MAX_WRAPPED_TOKENS and core and lists.keyword_sequence.fullmatch(" ".join(core)):
        return Classification(STOP, "stop_keyword", " ".join(core))
    if tokens and len(tokens) <= MAX_WRAPPED_TOKENS and not core and not near and len(tokens) == len(
        [t for t in tokens if t in lists.keywords]
    ):
        return Classification(STOP, "stop_keyword", masked)

    m = lists.sentence_re.search(masked)
    if m:
        return Classification(NEEDS_REVIEW, "stop_word_in_longer_message", m.group(0))
    if near:
        if tokens_all & lists.contact_words:
            return Classification(NEEDS_REVIEW, "near_miss_with_contact_words", near_hits[0])
        return Classification(NOT_STOP, "near_miss", near_hits[0])
    if tokens and len(tokens) <= MAX_WRAPPED_TOKENS and core and lists.start_sequence.fullmatch(" ".join(core)):
        return Classification(START, "start_keyword", " ".join(core))
    return Classification(NOT_STOP, "no_stop_signal")
