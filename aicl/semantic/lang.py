"""Cheap "is this English?" check for detectors trained on English only (C-INJ-BASTION).

English-only classifiers (ProtectAI, Bastion) flag much ordinary non-English text as injection:
on the shipped example corpus ProtectAI flagged 55% of non-English benign examples vs 13% of
English ones. The classifier control uses this to skip or only escalate non-English text, which
the multilingual tiers (C-INJ-EMB, C-INJ-SEM) handle.

Heuristic, no dependency. Latin-script text counts as English unless it shows signs of another
language: more words that are function words of common European languages or carry their
diacritics (ą, ü, ñ, ç, ř, ğ, ...) than English function words. Mostly non-Latin script
(Cyrillic, CJK, Arabic, ...) is not English. Leaning to "English" keeps logs, tables and terse
text classified; a wrong guess either way costs one tier's opinion, never the other tiers.
On the example corpus plus scripts/stack_cases.yaml: 355/356 texts right.
"""

from __future__ import annotations

import re

_EN_WORDS = frozenset(
    "a about all also an and any are as at be been but by can could did do does for from had has have "
    "he her his how i if in into is it its just me more my new no not now of on one only or our out "
    "please she should so some than that the their them then there these they this to up us was we "
    "were what when where which who will with would you your".split()
)
# Function words of common European languages (pl, de, es, fr, it, pt, nl, cs, sv, tr); words
# that are also English are removed below.
_OTHER_WORDS = frozenset(
    """
    w z na nie się że jak co jest mi po od za czy ale tak dla tylko jeśli proszę mój moje mojej mnie
    der das und ist nicht ich du sie es mit zu den von für auf ein eine dem bitte wie was mir mein meine meiner
    el la los las y es en de que por para con una un del al lo como pero tu mis
    le les et est pas je il elle des du une pour avec qui dans sur ce mon ma mes
    lo gli è che di della come ma
    os é não um uma da em mas meu
    het een niet ik je dat voor met op te wat
    je se v že jak pro jsem
    och är det att som på för jag inte
    ve bir bu da için ile ne ben sen değil
    im wurde zusammen e quanto minha seu sua jako bez dla
    """.split()
) - _EN_WORDS - {"die", "men", "son", "dim", "ten", "pas", "con", "pro"}
_WORD_RE = re.compile(r"[^\W\d_]+")
_NON_ENGLISH_LATIN = re.compile(r"[ąćęłńśźżäöüßñáéíóúàèìòùçãõřěůšžčýğışåøæ]")


def is_english(text: str) -> bool:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return False
    if sum(ord(c) > 0x024F for c in letters) > 0.2 * len(letters):
        return False  # mostly Cyrillic, CJK, Arabic, ...
    lower = text.lower()
    words = _WORD_RE.findall(lower)
    en = sum(w in _EN_WORDS for w in words)
    # foreign function words + words with diacritics typical of other languages
    other = sum(w in _OTHER_WORDS or bool(_NON_ENGLISH_LATIN.search(w)) for w in words)
    return other <= en
