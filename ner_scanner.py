import json
import os
import re

# ── NER detection data lives in ner_patterns.json (editable, persistent) ─────
# Same design as regex_patterns.json: no hardcoded vocabulary in code. A tiny
# built-in fallback keeps the scanner alive if the file is ever missing.
_HERE = os.path.dirname(os.path.abspath(__file__))
_NER_FALLBACK = {
    "ner_risk": {"PERSON": {"risk": "MEDIUM", "level": "standard",
                            "confidence": 0.82}},
    "min_entity_len": 3,
    "noise_keywords": ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE",
                       "DROP", "ALTER", "FROM", "WHERE", "JOIN"],
    "tech_terms": [],
    "fallback_patterns": [],
}


def _resolve_ner_file() -> str:
    env = os.environ.get("LOCALMASK_NER_FILE")
    if env and os.path.exists(env):
        return env
    for cand in (os.path.join(_HERE, "ner_patterns.json"),
                 os.path.join(_HERE, "localmask", "ner_patterns.json"),
                 os.path.join(os.getcwd(), "ner_patterns.json")):
        if os.path.exists(cand):
            return cand
    return os.path.join(_HERE, "ner_patterns.json")


def _load_ner_data() -> dict:
    global _NER_FILE
    _NER_FILE = _resolve_ner_file()
    try:
        with open(_NER_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        for k, v in _NER_FALLBACK.items():
            data.setdefault(k, v)
        return data
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[ner_scanner] WARNING: could not load {_NER_FILE}: {exc}")
        return dict(_NER_FALLBACK)


_NER_FILE = ""
_NER_DATA = _load_ner_data()

# NER entity types we care about and their risk mapping
NER_RISK = _NER_DATA["ner_risk"]

# Minimum token length to avoid flagging very short noise
MIN_ENTITY_LEN = _NER_DATA["min_entity_len"]

# Only filter out obvious non-entities (SQL keywords). Built from the data file.
_NOISE_FILTER = re.compile(
    r'^(?:' + "|".join(re.escape(k) for k in _NER_DATA["noise_keywords"])
    + r')\b', re.I
)

# Public tech vocabulary — vendor names, infra roles, architecture labels.
# An entity whose words ALL come from this set is never PII/ORG worth masking
# (e.g. "Datadog Agent", "Platform Team", "Redis Cache").
_TECH_TERMS = {t.lower() for t in _NER_DATA["tech_terms"]}

_WORD_SPLIT = re.compile(r"[\s/_\-.]+")


def reload_ner_data():
    """Re-read ner_patterns.json — pick up edits without restarting."""
    global _NER_DATA, NER_RISK, MIN_ENTITY_LEN, _NOISE_FILTER, _TECH_TERMS
    _NER_DATA = _load_ner_data()
    NER_RISK = _NER_DATA["ner_risk"]
    MIN_ENTITY_LEN = _NER_DATA["min_entity_len"]
    _NOISE_FILTER = re.compile(
        r'^(?:' + "|".join(re.escape(k) for k in _NER_DATA["noise_keywords"])
        + r')\b', re.I)
    _TECH_TERMS = {t.lower() for t in _NER_DATA["tech_terms"]}
    NERScanner._FALLBACK_PATTERNS = _NER_DATA["fallback_patterns"]
    return {"tech_terms": len(_TECH_TERMS),
            "fallback_patterns": len(_NER_DATA["fallback_patterns"])}


def add_tech_term(term: str, save: bool = True):
    """Add a public-tech word (never masked as PII) and persist it."""
    _TECH_TERMS.add(term.lower())
    if term.lower() not in [t.lower() for t in _NER_DATA["tech_terms"]]:
        _NER_DATA["tech_terms"].append(term.lower())
    if save:
        json.dump(_NER_DATA, open(_NER_FILE, "w"), indent=2)


def _is_tech_term(text: str) -> bool:
    """True when every word of the entity is public tech vocabulary."""
    words = [w for w in _WORD_SPLIT.split(text.lower()) if w]
    return bool(words) and all(w in _TECH_TERMS for w in words)


class NERScanner:
    """Named Entity Recognition scanner for free-text files.
    Uses SpaCy if available, falls back to regex heuristics.
    All candidates are passed to the LLM for final classification.
    """

    def __init__(self):
        self._nlp = None
        self._spacy_available = False
        self._try_load_spacy()

    def _try_load_spacy(self):
        try:
            import spacy
            try:
                self._nlp = spacy.load("en_core_web_sm")
                self._spacy_available = True
            except OSError:
                try:
                    from spacy.cli import download
                    download("en_core_web_sm")
                    self._nlp = spacy.load("en_core_web_sm")
                    self._spacy_available = True
                except Exception:
                    self._spacy_available = False
        except ImportError:
            self._spacy_available = False

    @property
    def backend(self) -> str:
        return "spacy" if self._spacy_available else "regex_fallback"

    def scan(self, content: str, file_path: str = "",
             sensitivity: str = "standard") -> list:
        if self._spacy_available:
            return self._scan_spacy(content, file_path, sensitivity)
        return self._scan_regex_fallback(content, file_path, sensitivity)

    # ── SpaCy path ────────────────────────────────────────────────────────

    def _scan_spacy(self, content: str, file_path: str,
                    sensitivity: str) -> list:
        CHUNK = 100_000
        results = []
        lines = content.split("\n")
        line_offsets = self._build_line_offsets(content)

        for start in range(0, len(content), CHUNK):
            chunk = content[start: start + CHUNK]
            doc = self._nlp(chunk)
            for ent in doc.ents:
                label = ent.label_
                if label not in NER_RISK:
                    continue
                meta = NER_RISK[label]
                if not self._passes_sensitivity(meta["level"], sensitivity):
                    continue
                text = ent.text.strip()
                if len(text) < MIN_ENTITY_LEN:
                    continue
                if _NOISE_FILTER.match(text):
                    continue
                if _is_tech_term(text):
                    continue

                abs_start = start + ent.start_char
                line_num = self._char_to_line(abs_start, line_offsets)
                context = lines[line_num - 1].strip()[:120] if line_num <= len(lines) else ""

                results.append({
                    "entity":         text,
                    "type":           f"ner_{label.lower()}",
                    "confidence":     meta["confidence"],
                    "level":          meta["level"],
                    "line":           line_num,
                    "context":        context,
                    "file_type":      "freetext",
                    "pattern_reason": f"NER entity: {label} (SpaCy)",
                    "ner_label":      label,
                })

        return self._deduplicate(results)

    # ── Regex fallback ───────────────────────────────────────────────────

    # Regex NER fallback patterns — loaded from ner_patterns.json (persistent,
    # editable), not hardcoded.
    _FALLBACK_PATTERNS = _NER_DATA["fallback_patterns"]

    def _scan_regex_fallback(self, content: str, file_path: str,
                              sensitivity: str) -> list:
        results = []
        lines = content.split("\n")
        for line_num, line in enumerate(lines, 1):
            if line.strip().startswith(("#", "//", "--", "<!--")):
                continue
            for pat in self._FALLBACK_PATTERNS:
                label = pat["label"]
                level = pat["level"]
                if not self._passes_sensitivity(level, sensitivity):
                    continue
                for m in re.finditer(pat["pattern"], line):
                    text = m.group(0).strip()
                    if len(text) < MIN_ENTITY_LEN:
                        continue
                    if _NOISE_FILTER.match(text):
                        continue
                    if _is_tech_term(text):
                        continue
                    results.append({
                        "entity":         text,
                        "type":           f"ner_{label.lower()}",
                        "confidence":     pat["confidence"],
                        "level":          level,
                        "line":           line_num,
                        "context":        line.strip()[:120],
                        "file_type":      "freetext",
                        "pattern_reason": pat["reason"],
                        "ner_label":      label,
                    })

        return self._deduplicate(results)

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _passes_sensitivity(pattern_level: str, scan_sensitivity: str) -> bool:
        order = {"minimal": 0, "standard": 1, "strict": 2}
        return order.get(pattern_level, 1) <= order.get(scan_sensitivity, 1)

    @staticmethod
    def _build_line_offsets(content: str) -> list:
        offsets = [0]
        for i, ch in enumerate(content):
            if ch == "\n":
                offsets.append(i + 1)
        return offsets

    @staticmethod
    def _char_to_line(char_pos: int, offsets: list) -> int:
        lo, hi = 0, len(offsets) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if offsets[mid] <= char_pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    @staticmethod
    def _deduplicate(results: list) -> list:
        seen = set()
        out = []
        for r in results:
            key = (r["entity"], r["line"], r["type"])
            if key not in seen:
                seen.add(key)
                out.append(r)
        return out
