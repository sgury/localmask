import re

# NER entity types we care about and their risk mapping
NER_RISK = {
    "PERSON":   {"risk": "MEDIUM", "level": "standard", "confidence": 0.82},
    "ORG":      {"risk": "MEDIUM", "level": "standard", "confidence": 0.78},
    "GPE":      {"risk": "LOW",    "level": "strict",   "confidence": 0.75},
    "LOC":      {"risk": "LOW",    "level": "strict",   "confidence": 0.75},
    "MONEY":    {"risk": "HIGH",   "level": "minimal",  "confidence": 0.88},
    "CARDINAL": {"risk": "LOW",    "level": "strict",   "confidence": 0.70},
    "DATE":     {"risk": "LOW",    "level": "strict",   "confidence": 0.70},
    "FAC":      {"risk": "MEDIUM", "level": "standard", "confidence": 0.78},
    "PRODUCT":  {"risk": "LOW",    "level": "strict",   "confidence": 0.72},
    "EVENT":    {"risk": "LOW",    "level": "strict",   "confidence": 0.70},
    "NORP":     {"risk": "LOW",    "level": "strict",   "confidence": 0.72},
}

# Minimum token length to avoid flagging very short noise
MIN_ENTITY_LEN = 3

# Only filter out obvious non-entities (single technical acronyms, SQL keywords)
# Everything else goes to the LLM for classification
_NOISE_FILTER = re.compile(
    r'^(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|FROM|WHERE|JOIN)\b', re.I
)

# Public tech vocabulary — vendor names, infra roles, architecture labels.
# An entity whose words ALL come from this set is never PII/ORG worth masking
# (e.g. "Datadog Agent", "Platform Team", "Redis Cache").
_TECH_TERMS = {
    # vendors / products (public names, not secrets)
    "datadog", "grafana", "prometheus", "kibana", "elastic", "elasticsearch",
    "kafka", "redis", "postgres", "postgresql", "mysql", "mongodb", "nginx",
    "docker", "kubernetes", "terraform", "ansible", "jenkins", "github",
    "gitlab", "bitbucket", "slack", "jira", "confluence", "sentry", "splunk",
    "pagerduty", "okta", "auth0", "stripe", "twilio", "sendgrid", "hubspot",
    "celery", "flask", "django", "spring", "react", "angular", "vue",
    "python", "java", "golang", "rabbitmq", "memcached", "haproxy", "consul",
    "vault", "airflow", "spark", "hadoop", "snowflake", "databricks",
    "fluentd", "logstash", "zookeeper", "cassandra", "dynamodb", "aurora",
    # infra / architecture labels
    "platform", "service", "services", "server", "servers", "gateway",
    "engine", "pipeline", "pipelines", "cluster", "database", "cache",
    "queue", "worker", "workers", "agent", "agents", "monitor",
    "monitoring", "dashboard", "logging", "alerting", "backup", "restore",
    "failover", "proxy", "balancer", "load", "primary", "replica", "shard",
    "node", "nodes", "pod", "pods", "deployment", "ingress", "storage",
    "network", "internal", "external", "core", "banking", "data", "web",
    "api", "rest", "graphql", "oauth", "jwt", "sdk", "cli", "devops",
    "backend", "frontend", "auth", "authentication", "authorization",
    "config", "configuration", "infrastructure", "architecture", "diagram",
    "overview", "schedule", "tier", "layer", "stack", "environment",
    "production", "staging", "development", "sandbox", "document", "store",
    "analytics", "metrics", "events", "stream", "batch", "compute",
    # org-structure words (role labels, not people)
    "team", "teams", "lead", "leads", "engineer", "engineering", "manager",
    "director", "senior", "junior", "staff", "principal", "contacts",
    "security", "compliance", "risk", "operations", "support",
}

_WORD_SPLIT = re.compile(r"[\s/_\-.]+")


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

    _FALLBACK_PATTERNS = [
        # Proper names: two or more capitalised words
        {
            "pattern": r'\b([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){1,3})\b',
            "label": "PERSON", "confidence": 0.68,
            "level": "standard",
            "reason": "Proper name (regex heuristic)",
        },
        # Money amounts
        {
            "pattern": r'\$\s*\d[\d,]*(?:\.\d{1,2})?(?:\s*(?:million|billion|thousand|k|M|B))?\b',
            "label": "MONEY", "confidence": 0.85,
            "level": "minimal",
            "reason": "Currency amount",
        },
        # Dates
        {
            "pattern": r'\b(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{2}[\/\-]\d{2})\b',
            "label": "DATE", "confidence": 0.72,
            "level": "strict",
            "reason": "Date (regex heuristic)",
        },
    ]

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
