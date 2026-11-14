"""The time zone of a North American phone number, from its area code, and the hours a text may go out.

The table is owned by the vault and dated (``TABLE_VERSION``). It lists only area codes whose whole territory lies in one
zone. An area code that spans two zones, one that is not listed, a number outside +1 and a number that is not 12 characters
long all answer ``None``: the zone is unknown, and the caller skips the text. A zone is never guessed.

Texting hours (confirmations.md section 5, item 5): 9:00 AM to 8:00 PM Monday to Saturday, noon to 8:00 PM Sunday, local time;
each window includes its start and excludes its end.
"""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

TABLE_VERSION = "2026-10-31"  # 423 (Tennessee, split between Eastern and Central) removed

ET, CT, MT, PT = "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles"
AZ, HI, PR = "America/Phoenix", "Pacific/Honolulu", "America/Puerto_Rico"

_BY_ZONE: dict[str, str] = {
    ET: "203 475 860 959 302 202 771 239 305 321 352 386 407 561 645 689 727 728 754 772 786 813 863 904 941 954 "
        "229 404 470 478 678 706 762 770 912 943 260 317 463 502 859 207 240 301 410 443 667 339 351 413 508 617 774 781 "
        "857 978 231 248 269 313 517 586 616 679 734 810 947 989 603 201 551 609 640 732 848 856 862 908 973 212 315 332 "
        "347 516 518 585 607 631 646 680 716 718 838 845 914 917 929 934 252 336 704 743 828 910 919 980 984 216 220 234 "
        "330 380 419 440 513 567 614 740 937 215 223 267 272 412 445 484 570 610 717 724 814 835 878 401 803 839 843 854 "
        "864 802 276 434 540 571 703 757 804 686 948 304 681 865",
    CT: "205 251 256 334 659 938 479 501 870 217 224 309 312 331 464 618 630 708 773 779 815 847 872 319 515 563 641 712 "
        "316 913 225 318 337 504 985 218 320 507 612 651 763 952 228 601 662 769 314 417 573 636 660 816 557 402 531 405 "
        "539 572 918 210 214 254 281 325 346 361 409 469 512 682 713 726 737 817 830 832 903 936 940 945 956 972 979 262 "
        "274 414 534 608 715 920 615 629 731 901",
    MT: "303 719 720 970 983 406 505 575 385 435 801 307",
    PT: "209 213 279 310 323 341 408 415 424 442 510 530 559 562 619 626 628 650 657 661 669 707 714 747 760 805 818 820 "
        "831 858 909 916 925 949 951 702 725 503 971 206 253 360 425 509 564",
    AZ: "480 520 602 623",
    HI: "808",
    PR: "787 939",
}
AREA_ZONE: dict[str, str] = {code: zone for zone, codes in _BY_ZONE.items() for code in codes.split()}
assert len(AREA_ZONE) == sum(len(c.split()) for c in _BY_ZONE.values()), "an area code is listed under two zones"

LABEL = {ET: "ET", CT: "CT", MT: "MT", PT: "PT", AZ: "MST", HI: "HST", PR: "AST"}


def zone_for_phone(e164: str) -> str | None:
    """The IANA zone name of a +1 number whose area code lies wholly in one zone, else None."""
    if not isinstance(e164, str) or len(e164) != 12 or not e164.startswith("+1") or not e164[1:].isdigit():
        return None
    return AREA_ZONE.get(e164[2:5])


def local(now: datetime, zone: str) -> datetime:
    return now.astimezone(ZoneInfo(zone))


def text_window_open(local_time: datetime) -> bool:
    """Whether a text may go at this local time."""
    minutes = local_time.hour * 60 + local_time.minute  # seconds count: 8:00:00 PM is outside, 7:59:59 PM is inside
    if local_time.weekday() == 6:
        start = 12 * 60
    else:
        start = 9 * 60
    end = 20 * 60
    return start * 60 <= minutes * 60 + local_time.second < end * 60


def format_when(moment: datetime, zone: str | None) -> str:
    """``Oct 30, 2026 at 10:42 AM ET`` in the zone, or in UTC with ``UTC`` named when there is none."""
    if zone is None:
        moment, label = moment.astimezone(ZoneInfo("UTC")), "UTC"
    else:
        moment, label = local(moment, zone), LABEL.get(zone, zone)
    hour = moment.strftime("%I").lstrip("0") or "12"
    return f"{moment.strftime('%b')} {moment.day}, {moment.year} at {hour}:{moment.strftime('%M %p')} {label}"
