"""The public data the benchmark runs on. Nothing is committed: each file is downloaded
on first use from a pinned commit, checked against its SHA-256, and cached in
DOORMAN_DATA (default ~/.cache/doorman).

- resumes: the resume corpus of Jiechieu and Tsopze (Neural Computing and Applications,
  2020), about 29,000 resumes collected from Indeed. The benign side: lines the guard
  learns from, and the applications false alarms are counted on.
- bipia_train, bipia_test: the text attacks of BIPIA, Microsoft's indirect prompt
  injection benchmark (MIT licence).
- tensor_trust: the hijacking attacks people wrote in the Tensor Trust game
  (Toyer et al., 2023).

Every split is decided by hashing an item's id, so it does not depend on file order.
"""
import hashlib
import html
import io
import json
import os
import re
import urllib.request
import zipfile
from functools import lru_cache
from pathlib import Path

SOURCES = {
    "resumes": ("https://raw.githubusercontent.com/florex/resume_corpus/24de39957d99caf2c89cf384ba2396bafe16050d/resume_samples.zip",
                "e49b0e7ee8752b51a4ac046f3fc07c2331749d136823e72c9a7bb5908ecf1beb"),
    "bipia_train": ("https://raw.githubusercontent.com/microsoft/BIPIA/a004b69ec0dd446e0afd461d98cb5e96e120a5d0/benchmark/text_attack_train.json",
                    "63f95d3e67eac4178cdabdbdaf192cd05f2b6ed0702b578f1d30d556e5155670"),
    "bipia_test": ("https://raw.githubusercontent.com/microsoft/BIPIA/a004b69ec0dd446e0afd461d98cb5e96e120a5d0/benchmark/text_attack_test.json",
                   "75750e7b4e8b34e8f9d88d89b357aeaaf02bd07f9e493ccd37eda74a0cd7c7f8"),
    "tensor_trust": ("https://raw.githubusercontent.com/HumanCompatibleAI/tensor-trust-data/747a75e096761ebc01bd3970158827326b4add23/benchmarks/hijacking-robustness/v1/hijacking_robustness_dataset.jsonl",
                     "2ad3c2343bbf43cb1924f3ec5d6f830864ce3c879e9832b01d93a991e7e2e680"),
}
# occupations close enough to the job that their resumes read like real applicants
IT_ROLES = re.compile(r"developer|engineer|programmer|administrator|architect|devops|analyst", re.I)


def cache_dir() -> Path:
    path = Path(os.environ.get("DOORMAN_DATA", Path.home() / ".cache" / "doorman"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def fetch(name) -> Path:
    url, sha = SOURCES[name]
    path = cache_dir() / url.rsplit("/", 1)[1]
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != sha:
        with urllib.request.urlopen(url, timeout=120) as response:
            body = response.read()
        got = hashlib.sha256(body).hexdigest()
        if got != sha:
            raise RuntimeError(f"{name}: expected sha256 {sha}, downloaded {got}")
        path.write_bytes(body)
    return path


def bucket(key, buckets=100):
    """A stable number in [0, buckets) for a string, used to split data."""
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % buckets


def split_of(key):
    b = bucket(key)
    return "train" if b < 60 else "validation" if b < 80 else "test"


def clean(text):
    text = html.unescape(re.sub(r"<[^>]+>", " ", text)).replace("�", " ")
    return re.sub(r"\s+", " ", text).strip()


def resume_lines(text, width=95):
    """A resume as the lines it would be printed in: sentence by sentence, wrapped at width."""
    out = []
    for sentence in re.split(r"(?<=[.;!?])\s+|\s+(?=[•▪●·])", text):
        words, line = sentence.split(), ""
        for w in words:
            if line and len(line) + 1 + len(w) > width:
                out.append(line)
                line = w
            else:
                line = f"{line} {w}".strip()
        if line:
            out.append(line)
    return out


@lru_cache(maxsize=1)
def resumes():
    """[(id, text)] for the IT resumes with enough text to be a real application, in file order."""
    out = []
    with zipfile.ZipFile(fetch("resumes")) as z, z.open("resume_samples.txt") as f:
        for raw in io.TextIOWrapper(f, encoding="utf-8", errors="replace"):
            parts = raw.rstrip("\n").split(":::")
            if len(parts) != 3 or not IT_ROLES.search(parts[1]):
                continue
            text = clean(parts[2])
            if 600 <= len(text) <= 6000:
                out.append((parts[0], text))
    return out


def resumes_in(split):
    return [(rid, text) for rid, text in resumes() if split_of(rid) == split]


def bipia(split):
    return [t.strip() for texts in json.loads(fetch(f"bipia_{split}").read_text()).values() for t in texts if t.strip()]


@lru_cache(maxsize=1)
def attacks():
    """{'train': [...], 'test': [...]}: injection texts written by other people, never by this project."""
    out = {"train": [], "test": []}
    for split in ("train", "test"):
        out[split].extend(bipia(split))
    for line in fetch("tensor_trust").read_text().splitlines():
        row = json.loads(line)
        text = row["attack"].strip()
        if 20 <= len(text) <= 3000:
            out["test" if bucket(str(row["sample_id"])) < 30 else "train"].append(text)
    return out
