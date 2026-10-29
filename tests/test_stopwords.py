import pytest

from consentvault.stopwords import NEEDS_REVIEW, NOT_STOP, START, STOP, classify, fold

STOPS = [
    "STOP", "stop", "Stop.", "stop!!", "STOPALL", "stop all", "UNSUBSCRIBE", "unsubscribe me", "CANCEL", "End",
    "QUIT", "REVOKE", "OPTOUT", "opt-out", "opt out", "please stop", "Stop now thanks", "pls stop",
    "don't text me", "Do not call me", "dont contact us", "never contact me again", "Never text me again",
    "remove me", "Please remove me from your list", "take me off your list", "stop texting me", "stop calling me",
    "stop sending me messages", "no more texts", "leave me alone", "opt me out", "I revoke my consent",
    "PARAR", "detener", "cancelar", "no me llames", "dejen de enviarme mensajes", "quitame de la lista",
    "no quiero mas mensajes", "ARRÊT", "arrete", "désabonner", "ne me contactez plus", "retirez moi de la liste",
    "je ne veux plus de messages", "ѕtop", "ЅТОР", "ΣΤΟΡ", "ｓｔｏｐ", "ＳＴＯＰ", "s t o p", "S.T.O.P", "st​op",
    "s‍t⁠o﻿p", "𝐒𝐓𝐎𝐏", "STÓP", "dοn't tехt me",
]

NOT_STOPS = [
    "stop by tomorrow", "I'll stop by at noon", "bus stop", "non-stop", "nonstop flights", "I can't stop laughing",
    "he won't stop talking", "full stop", "pit stop", "one stop shop", "stop sign ahead", "sans arrêt",
    "hello", "yes it is", "when does my order ship", "thanks", "", "   ", "the end", "call me tomorrow",
    "I'd like more info", "Sounds good",
]

REVIEWS = [
    "don't stop", "Do not stop", "please dont stop", "never stop", "Don't stop texting me",
    "can you cancel my order", "I want to unsubscribe from the newsletter but keep texts",
    "stop and let me think about it", "when will it end? stop is not what I meant",
    "I can't stop by, but call me later", "no cancel", "n'arrêtez pas",
]


@pytest.mark.parametrize("text", STOPS)
def test_stop(text):
    assert classify(text).verdict == STOP, classify(text)


@pytest.mark.parametrize("text", NOT_STOPS)
def test_not_stop(text):
    assert classify(text).verdict == NOT_STOP, classify(text)


@pytest.mark.parametrize("text", REVIEWS)
def test_needs_review(text):
    assert classify(text).verdict == NEEDS_REVIEW, classify(text)


def test_case_count():
    assert len(STOPS) + len(NOT_STOPS) + len(REVIEWS) >= 40


def test_never_a_false_stop_on_near_miss_family():
    for text in ["stop by", "Stop in for coffee", "bus stop", "non stop", "can't stop", "stoplight", "rest stop"]:
        assert classify(text).verdict != STOP, text


def test_fold_removes_invisibles_and_lookalikes():
    assert fold("ЅТО​Р") == "stop"
    assert fold("Ｓｔｏｐ") == "stop"


def test_non_string_is_not_stop():
    assert classify(None).verdict == NOT_STOP


def test_result_carries_reason():
    r = classify("remove me")
    assert r.reason == "stop_phrase" and r.matched


@pytest.mark.parametrize("text", ["START", "start", "Unstop", "YES", "yes please", "Please START now", "ＳＴＡＲＴ", "start.", "yes yes"])
def test_start(text):
    assert classify(text).verdict == START, classify(text)


@pytest.mark.parametrize("text", ["yes stop", "stop start", "do not start", "start texting me again tomorrow",
                                  "dont text me yes", "bus stop yes", "restart", "starting at noon"])
def test_a_start_word_next_to_anything_else_is_never_a_start(text):
    assert classify(text).verdict != START, classify(text)
