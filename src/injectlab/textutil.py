"""Unicode helpers shared by mutators, the canary detector and the mock models."""

from __future__ import annotations

import codecs
import re
import unicodedata

# Characters that render as nothing in most UIs.
ZERO_WIDTH: tuple[str, ...] = (
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
    "⁠",  # WORD JOINER
    "﻿",  # ZERO WIDTH NO-BREAK SPACE / BOM
    "᠎",  # MONGOLIAN VOWEL SEPARATOR
    "­",  # SOFT HYPHEN
)
_INVISIBLE_RE = re.compile("[" + "".join(ZERO_WIDTH) + "⁡-⁤‎‏‪-‮⁦-⁩]")

TAG_BASE = 0xE0000
_TAG_RE = re.compile("[\U000e0000-\U000e007f]+")

# Latin letter -> visually confusable code points (Cyrillic, Greek, Armenian, Latin extensions).
HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "a": ("а", "ɑ"),
    "c": ("с", "ϲ"),
    "d": ("ԁ",),
    "e": ("е", "ė"),
    "h": ("һ",),
    "i": ("і", "ι"),
    "j": ("ј",),
    "l": ("ӏ",),
    "o": ("о", "ο", "օ"),
    "p": ("р", "ρ"),
    "q": ("ԛ",),
    "s": ("ѕ",),
    "u": ("ս",),
    "v": ("ν",),
    "w": ("ѡ",),
    "x": ("х",),
    "y": ("у",),
    "A": ("А", "Α"),
    "B": ("В", "Β"),
    "C": ("С", "Ϲ"),
    "E": ("Е", "Ε"),
    "H": ("Н", "Η"),
    "I": ("І", "Ι"),
    "J": ("Ј",),
    "K": ("К", "Κ"),
    "M": ("М", "Μ"),
    "N": ("Ν",),
    "O": ("О", "Ο"),
    "P": ("Р", "Ρ"),
    "S": ("Ѕ",),
    "T": ("Т", "Τ"),
    "X": ("Х", "Χ"),
    "Y": ("Ү", "Υ"),
    "Z": ("Ζ",),
}
CONFUSABLE_TO_LATIN: dict[str, str] = {g: latin for latin, gs in HOMOGLYPHS.items() for g in gs}
# A few extra confusables seen in the wild that NFKC does not fold.
CONFUSABLE_TO_LATIN.update(
    {
        "в": "b",
        "к": "k",
        "м": "m",
        "н": "h",
        "т": "t",
        "г": "r",
        "ɡ": "g",
        "ǀ": "l",
        "‐": "-",
        "‑": "-",
        "‒": "-",
        "–": "-",
        "—": "-",
        "−": "-",
    }
)
_CONFUSABLE_TABLE = str.maketrans(CONFUSABLE_TO_LATIN)


def strip_invisible(text: str) -> str:
    """Remove zero-width / bidi-control characters and Unicode tag characters."""
    return _TAG_RE.sub("", _INVISIBLE_RE.sub("", text))


def fold_confusables(text: str) -> str:
    """NFKC-normalise (full-width, ligatures, math alphanumerics) then map homoglyphs to ASCII."""
    # Fold first: NFKC would otherwise turn some look-alikes (e.g. U+03F2 lunate sigma, which looks like
    # 'c') into a different letter (final sigma) that no longer maps back to Latin.
    return unicodedata.normalize("NFKC", text.translate(_CONFUSABLE_TABLE)).translate(_CONFUSABLE_TABLE)


def encode_tags(text: str) -> str:
    """Encode printable ASCII into the invisible Unicode tag block (U+E0020..U+E007E)."""
    out = []
    for ch in text:
        o = ord(ch)
        if 0x20 <= o <= 0x7E:
            out.append(chr(TAG_BASE + o))
        elif ch == "\n":
            out.append(chr(TAG_BASE + 0x20))
        else:
            out.append(ch)
    return "".join(out)


def decode_tags(text: str) -> str:
    """Reveal tag-smuggled ASCII: every tag character is mapped back to its ASCII twin."""
    return _TAG_RE.sub(lambda m: "".join(chr(ord(c) - TAG_BASE) for c in m.group(0)), text)


def has_tag_chars(text: str) -> bool:
    return bool(_TAG_RE.search(text))


def rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


def normalize_for_reading(text: str) -> str:
    """What a capable reader 'sees': tags revealed, invisibles dropped, homoglyphs folded."""
    return fold_confusables(strip_invisible(decode_tags(text)))


def skeleton(text: str) -> str:
    """Upper-cased alphanumeric-only projection used for separator-insensitive matching."""
    return re.sub(r"[^0-9A-Z]", "", normalize_for_reading(text).upper())
