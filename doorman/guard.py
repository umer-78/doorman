"""Input classification: is a piece of untrusted text trying to instruct the agent?

Hand-written rules catch the phrasings attackers reach for first, and text disguised by
spacing its letters out (the benchmark's first run showed the model misses that). A linear model
over character n-grams, trained on injection attacks other people wrote (BIPIA and the
Tensor Trust game) against lines of real resumes, catches rewordings of them. It reads a
document a line and two lines at a time, the way a payload sits inside a resume.

Neither is the real control: text that fools a classifier can always be reworded once
more. This layer strips the cheap attacks and sends the documents it flags to a person.
"""
import base64
import binascii
import re
import unicodedata

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)
BASE64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
SPACED = re.compile(r"\b(?:\w ){4,}\w\b")      # "i g n o r e", written to dodge word matching
LETTER_SPACED = re.compile(r"(?:\b\w ){12,}")    # a long run of it is a disguise in itself
MIN_LINE = 25   # shorter lines ("About me", "Education") are only read together with a neighbour

RULES = {
    "ignore-instructions": r"\b(ignore|disregard|forget|override|ignorez|oubliez)\b.{0,40}\b(instructions?|rules|prompt|directions|consignes)\b",
    "addressed-to-an-ai": r"\b(note|message|instructions?)\s+(to|for)\s+(the\s+|any\s+)?(ai|llm|chatgpt|gpt|language model)\b",
    "role-override": r"\b(system prompt|you are now|new instructions|developer mode|jailbreak)\b",
    "decode-and-follow": r"\bdecode\b.{0,60}\b(follow|carry (it|them) out|execute|run|obey)\b",
}
COMPILED = {name: re.compile(p, re.I) for name, p in RULES.items()}


def normalize(text):
    """What the text says once the usual disguises are removed."""
    t = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)
    t = SPACED.sub(lambda m: m.group(0).replace(" ", ""), t)
    decoded = []
    for blob in BASE64.findall(re.sub(r"\s+", "", t)):
        try:
            plain = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if plain.isprintable():
            decoded.append(plain)
    return re.sub(r"\s+", " ", " ".join([t, *decoded])).strip().lower()


def windows(text, width=95):
    """The pieces the model reads: every line on its own, so a one-line payload is not
    diluted by its neighbour, and every pair of neighbouring lines, so a payload split
    across two lines is read whole. Long lines are cut to width first. A line shorter
    than MIN_LINE is only read in a pair: on its own, a heading like "About me" looks
    more like the attacks than like the resumes the model learned from."""
    lines = []
    for line in text.splitlines():
        line = line.strip()
        while len(line) > width:
            cut = line.rfind(" ", 0, width)
            cut = cut if cut > width // 2 else width
            lines.append(line[:cut])
            line = line[cut:].strip()
        if line:
            lines.append(line)
    return [x for x in lines if len(x) >= MIN_LINE] + [f"{a} {b}" for a, b in zip(lines, lines[1:])]


class Guard:
    def __init__(self, threshold=0.5):
        self.vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True, max_features=300_000)
        self.model = LogisticRegression(C=4.0, class_weight="balanced", max_iter=3000)
        self.threshold = threshold

    def fit(self, attacks, benign):
        """attacks and benign are texts; both are cut into the same two-line windows the guard reads."""
        pos = [w for t in attacks for w in windows(t)]
        neg = [w for t in benign for w in windows(t)]
        x = self.vec.fit_transform([normalize(t) for t in pos + neg])
        self.model.fit(x, np.r_[np.ones(len(pos)), np.zeros(len(neg))])
        return self

    def scores(self, texts):
        if not texts:
            return np.zeros(0)
        return self.model.predict_proba(self.vec.transform([normalize(t) for t in texts]))[:, 1]

    def max_score(self, text):
        s = self.scores(windows(text))
        return float(s.max()) if len(s) else 0.0

    def calibrate(self, benign_docs, max_rate):
        """Set the threshold so the model flags at most max_rate of these benign documents
        (resumes and portfolio pages, the two kinds of text the guard reads)."""
        s = np.sort([self.max_score(d) for d in benign_docs])
        self.threshold = float(s[min(len(s) - 1, int(np.ceil(len(s) * (1 - max_rate))))]) + 1e-9
        return self.threshold

    def rule(self, text):
        if m := LETTER_SPACED.search(unicodedata.normalize("NFKC", text)):
            return "letter-spacing", m.group(0)[:80]
        norm = normalize(text)
        for name, rx in COMPILED.items():
            if m := rx.search(norm):
                return name, m.group(0)[:80]
        return None

    def check(self, text):
        """(what fired, detail) for the first thing that fires, or None."""
        if hit := self.rule(text):
            return f"rule: {hit[0]}", hit[1]
        score = self.max_score(text)
        if score >= self.threshold:
            return "model", f"injection score {score:.2f}"
        return None
