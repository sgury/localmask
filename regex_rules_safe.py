import re
import os
import json

# Sensitivity levels — each pattern belongs to a level.
# "minimal"  = only undeniable secrets & hard PII
# "standard" = + infra topology + contributor identity
# "strict"   = + org identity + internal tracing IDs
LEVELS = ("minimal", "standard", "strict")



_HERE = os.path.dirname(os.path.abspath(__file__))


def _resolve_patterns_file() -> str:
    """Find regex_patterns.json. Env override wins; otherwise search next to
    this module, the localmask package dir, and the CWD — so it resolves for
    source runs, the Docker image, the tarball, and pip installs."""
    env = os.environ.get("LOCALMASK_PATTERNS_FILE")
    candidates = [env] if env else []
    candidates += [
        os.path.join(_HERE, "regex_patterns.json"),
        os.path.join(_HERE, "localmask", "regex_patterns.json"),
        os.path.join(os.getcwd(), "regex_patterns.json"),
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return os.path.join(_HERE, "regex_patterns.json")  # default (may warn)


_PATTERNS_FILE = _resolve_patterns_file()


def _load_pattern_data():
    """Detection patterns live in regex_patterns.json so they can be edited or
    added to WITHOUT changing code. Returns (universal, file_type_extra). Also
    stashes the full document in _PATTERN_META so tuning vocabularies
    (false_positive_values, public_url_domains) can be read from the same DB."""
    global _PATTERNS_FILE, _PATTERN_META
    _PATTERNS_FILE = _resolve_patterns_file()
    try:
        with open(_PATTERNS_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        _PATTERN_META = data
        universal = dict(data.get("universal", {}))
        # Language packs: same entry shape as universal, grouped per language
        # under "lang_packs" (Hebrew ת"ז / Russian паспорт / Spanish DNI …).
        # LOCALMASK_LANGS selects packs ("he,ru"); default none, "all" = all.
        # Default is none so users explicitly opt in to their language(s) —
        # avoids unexpected FPs from patterns for languages you don't use.
        packs = data.get("lang_packs", {}) or {}
        want = os.environ.get("LOCALMASK_LANGS", "").strip().lower()
        if not want:
            # persisted setting (Web UI / org policy); env var always wins
            try:
                from localmask.settings_store import get_setting, org_lock
                want = str(org_lock().get("langs")
                           or get_setting("langs", "")).strip().lower()
            except Exception:
                want = ""
        if want == "all":
            selected = [k for k in packs if not k.startswith("_")]
        elif want in ("none", "off", "0"):
            selected = []
        else:
            selected = [l.strip() for l in want.split(",") if l.strip()]
        for lang in selected:
            for name, body in (packs.get(lang) or {}).items():
                universal.setdefault(name, body)
        return universal, data.get("file_type_extra", {})
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[regex_rules_safe] WARNING: could not load {_PATTERNS_FILE}: {exc}")
        _PATTERN_META = {}
        return {}, {}


_PATTERN_META: dict = {}
_UNIVERSAL_DATA, _FILE_TYPE_EXTRA_DATA = _load_pattern_data()
_UNIVERSAL_META = _PATTERN_META


def _collect_direct_mask(universal: dict, file_type_extra: dict) -> set:
    """Subtypes whose value must be masked DIRECTLY (not via the key-position
    guard), read from the pattern DB (`"mask_mode": "direct"`). Used for dotted
    vendor tokens like hvs.<...> / SG.<...>.<...> that the guard mis-reads as
    identifiers and would leave unmasked. Data-driven — no hardcoded names."""
    names = set()
    for name, body in (universal or {}).items():
        if isinstance(body, dict) and body.get("mask_mode") == "direct":
            names.add(name)
    for _ft, pats in (file_type_extra or {}).items():
        for name, body in (pats or {}).items():
            if isinstance(body, dict) and body.get("mask_mode") == "direct":
                names.add(name)
    return names


class RegexRulesSafe:
    """Detection patterns with per-pattern sensitivity levels.
    Call scan_file(path, content, sensitivity="standard") to control depth."""

    UNIVERSAL = _UNIVERSAL_DATA

    FILE_TYPE_EXTRA = _FILE_TYPE_EXTRA_DATA

    # Subtypes flagged mask_mode=direct in regex_patterns.json (see above).
    DIRECT_MASK = _collect_direct_mask(_UNIVERSAL_DATA, _FILE_TYPE_EXTRA_DATA)

    NOTEBOOK_EXTS = {"ipynb"}
    BASENAME_MAP = {
        "dockerfile": "dockerfile",
        "makefile": "ini",
        ".env": "env",
        ".envrc": "env",
        "fastfile": "ruby",
        "gemfile": "ruby",
    }
    EXT_MAP = {
        "yml": "yaml", "yaml": "yaml",
        "sql": "sql",
        "py": "py", "pyw": "py",
        "env": "env",
        "sh": "env", "bash": "env", "zsh": "env",
        "json": "json",
        "tf": "tf", "tfvars": "tf", "hcl": "tf",
        "toml": "toml",
        "xml": "xml", "config": "xml", "csproj": "xml", "props": "xml",
        "plist": "xml",
        "js": "js", "ts": "js", "jsx": "js", "tsx": "js", "mjs": "js",
        "cs": "cs",
        "java": "java",
        "gradle": "gradle",
        "properties": "properties",
        "go": "go",
        "swift": "swift",
        "kt": "java", "kts": "java",
        "cls": "java", "trigger": "java", "apex": "java",
        "rb": "ruby",
        "dockerfile": "dockerfile",
        "ini": "ini", "cfg": "ini", "conf": "ini",
        "md": "freetext", "txt": "freetext", "rst": "freetext", "adoc": "freetext",
    }

    @classmethod
    def _detect_project_type(cls, file_path: str, content: str) -> str | None:
        """Return extra pattern-set key if a project type is detected from context."""
        p = file_path.replace("\\", "/").lower()
        if (p.endswith(".sql") or p.endswith(".yml") or p.endswith(".yaml")):
            if "{{ ref(" in content or "{{ source(" in content or "dbt_project" in p:
                return "dbt"
        return None

    @classmethod
    def _filter(cls, patterns: dict, sensitivity: str) -> dict:
        """Keep only patterns at or below the requested sensitivity level."""
        order = {l: i for i, l in enumerate(LEVELS)}
        max_i = order.get(sensitivity, 1)
        return {k: v for k, v in patterns.items()
                if order.get(v.get("level", "standard"), 1) <= max_i}

    @classmethod
    def scan_file(cls, file_path: str, content: str, sensitivity: str = "standard") -> list:
        ext = os.path.splitext(file_path)[1].lstrip(".").lower()
        basename = os.path.basename(file_path).lower()

        # Handle extension-less files by basename (e.g. Dockerfile, Makefile)
        if not ext:
            ext = cls.BASENAME_MAP.get(basename, "")

        # Handle .env.* variants (.env.development, .env.production, etc.)
        if basename.startswith(".env"):
            ext = "env"

        if ext in cls.NOTEBOOK_EXTS:
            return cls._scan_notebook(file_path, content, sensitivity)

        file_type = cls.EXT_MAP.get(ext, "")
        patterns = cls._filter({**cls.UNIVERSAL}, sensitivity)
        patterns.update(cls._filter(cls.FILE_TYPE_EXTRA.get(file_type, {}), sensitivity))

        # Layer on project-type-specific patterns detected from content/path
        project_type = cls._detect_project_type(file_path, content)
        if project_type:
            patterns.update(cls._filter(cls.FILE_TYPE_EXTRA.get(project_type, {}), sensitivity))

        return cls._scan_lines(content, patterns, file_type or ext)

    @classmethod
    def _scan_notebook(cls, file_path: str, raw: str, sensitivity: str) -> list:
        try:
            nb = json.loads(raw)
        except Exception:
            return cls._scan_lines(raw, cls._filter(cls.UNIVERSAL, sensitivity), "ipynb")

        results = []
        line_offset = 0
        patterns = cls._filter({**cls.UNIVERSAL, **cls.FILE_TYPE_EXTRA.get("py", {})}, sensitivity)

        for cell in nb.get("cells", []):
            source = cell.get("source", [])
            if isinstance(source, list):
                source = "".join(source)
            cell_results = cls._scan_lines(source, patterns, "py")
            for r in cell_results:
                r["line"] += line_offset
            results.extend(cell_results)
            line_offset += source.count("\n") + 1

        return results

    # Values that are almost never real secrets — structural/boilerplate.
    # Loaded from regex_patterns.json (editable/persistent); the literal below
    # is only a safety fallback if the data file omits the key.
    FALSE_POSITIVE_VALUES = set(_UNIVERSAL_META.get("false_positive_values") or {
        "utf-8", "utf8", "true", "false", "none", "null", "localhost",
        "127.0.0.1", "0.0.0.0", "example.com", "test", "changeme",
        "placeholder", "default", "example", "dummy", "secret",
    })

    # Generic key-value patterns prone to matching placeholders and config
    # noise — their values must survive the weak-value gate below.
    GENERIC_VALUE_PATTERNS = {
        "generic_api_key", "password_assignment", "password_unquoted",
        "unquoted_env_secret", "any_env_password", "any_env_secret",
        "any_env_token", "tf_hcl_secret", "java_properties_password",
        # Language hardcoded-secret matchers (secret|password|token|api_key =
        # "…") are equally prone to placeholders (YOUR_API_KEY_HERE, xxxx…,
        # your-secret-key) — gate their values too.
        "py_hardcoded_secret", "js_hardcoded_secret",
    }

    # Placeholder shapes: template vars, env references, "your-key-here"
    _PLACEHOLDER_RES = [
        re.compile(r"^\$\{[^}]*\}$"),              # ${VAR}
        re.compile(r"^\{\{[^}]*\}\}$"),            # {{ template }}
        re.compile(r"^<[^<>]*>$"),                  # <your-key>
        re.compile(r"^%\([^)]*\)s$"),               # %(var)s
        re.compile(r"^__\w+__$"),                   # __PLACEHOLDER__
        re.compile(r"^\$[A-Z_][A-Z0-9_]*$"),       # $ENV_VAR
        re.compile(r"(?i)^(?:your|my|the|an?)[-_]"),  # your_api_key
        re.compile(r"(?i)[-_](?:here|goes[-_]here)$"),  # key_goes_here
        re.compile(r"(?i)(?:changeme|change[-_]me|placeholder|xxxx"
                   r"|example|dummy|sample)"),
        # "replace-with-…", "replace_this", "insert-…-here", "fill[-_]in"
        re.compile(r"(?i)(?:replace|insert|enter|fill)[-_](?:me|this|with|in|your)"),
        re.compile(r"(?i)(?:os\.environ|process\.env|getenv|env\[)"),
    ]

    # Well-known public service hosts — a URL here carries no org-specific
    # info unless its path contains a token-like segment. Loaded from
    # regex_patterns.json (editable/persistent), with a small fallback.
    PUBLIC_URL_DOMAINS = tuple(_UNIVERSAL_META.get("public_url_domains") or (
        "google.com", "googleapis.com", "github.com", "microsoft.com",
        "apple.com", "python.org", "npmjs.com", "docker.io",
    ))

    _URL_HOST_RE = re.compile(r"^https?://([^/\s:]+)")
    _TOKENISH_PATH_RE = re.compile(r"[A-Za-z0-9_\-]{20,}")

    # Documentation / test credentials (AWS docs keys, *EXAMPLE suffixes)
    _TEST_CRED_RE = re.compile(r"(?i)(?:example|testing|sample)(?:key)?$")

    @classmethod
    def _is_public_service_url(cls, value: str) -> bool:
        m = cls._URL_HOST_RE.match(value)
        if not m:
            return False
        host = m.group(1).lower()
        if not any(host == d or host.endswith("." + d)
                   for d in cls.PUBLIC_URL_DOMAINS):
            return False
        rest = value[m.end():]
        # Keep URLs whose path/query embeds a token (webhooks, signed URLs)
        return not cls._TOKENISH_PATH_RE.search(rest)

    @classmethod
    def _is_weak_value(cls, pattern_name: str, value: str) -> bool:
        """Reject placeholder / low-entropy values for generic patterns."""
        if pattern_name not in cls.GENERIC_VALUE_PATTERNS:
            return False
        for pat in cls._PLACEHOLDER_RES:
            if pat.search(value):
                return True
        # generic_api_key: 20+ chars but no digit at all → almost never a key
        if pattern_name == "generic_api_key" and not any(
                c.isdigit() for c in value):
            return True
        # Pure dictionary-word-like values: all lowercase letters, low entropy
        if value.isalpha() and value.islower() and cls._entropy(value) < 3.0:
            return True
        # Extremely low entropy at any length (aaaaaa, 111111, abcabc)
        if len(value) >= 6 and cls._entropy(value) < 2.0:
            return True
        return False

    # Regex to detect email-like strings that are actually userinfo in URLs
    _EMAIL_IN_URL_RE = re.compile(
        r"(?:postgres|postgresql|mysql|mongodb|redis|mssql|amqp|mqtt|ftp|ssh|git)"
        r"(?:\+\w+)?://[^\s]*@"
    )

    # HTTP header lines / values — never secrets (Content-Type, X-Request-ID,
    # Stripe-Signature, Authorization schemes shown as examples, etc.)
    _HTTP_HEADER_RE = re.compile(
        r"^(?:Content-Type|Content-Length|Accept|Accept-Encoding|User-Agent"
        r"|X-[A-Za-z-]+|Cache-Control|Connection|Host|Referer|Origin"
        r"|Stripe-Signature|Set-Cookie|ETag|Location|Server|Date"
        r"|Access-Control-[A-Za-z-]+)\s*:\s*", re.IGNORECASE)

    # Connection strings whose host is localhost/loopback → dev/doc examples.
    _LOCAL_CONN_RE = re.compile(
        r"://[^\s]*@(?:localhost|127\.0\.0\.1|0\.0\.0\.0)\b", re.IGNORECASE)

    @classmethod
    def _is_noise_value(cls, value: str) -> bool:
        """Values that are structurally never secrets, regardless of pattern:
        HTTP header lines and localhost/loopback connection strings (examples)."""
        if not value:
            return True
        if cls._HTTP_HEADER_RE.match(value):
            return True
        if cls._LOCAL_CONN_RE.search(value):
            return True
        return False

    # Lines that are structural boilerplate — never contain secrets
    SKIP_LINE_PATTERNS = [
        re.compile(r'^\s*<\?xml\s'),           # <?xml version="1.0" ...?>
        re.compile(r'^\s*<!DOCTYPE\s'),          # <!DOCTYPE html>
        re.compile(r'^\s*xmlns[:=]'),            # xmlns declarations
        re.compile(r'^\s*<\?[a-z]+\s'),          # <?processing instructions?>
    ]

    @classmethod
    def _is_boilerplate_line(cls, line: str) -> bool:
        """Skip lines that are XML/HTML boilerplate."""
        for pat in cls.SKIP_LINE_PATTERNS:
            if pat.search(line):
                return True
        return False

    @classmethod
    def _scan_lines(cls, content: str, patterns: dict, file_type: str) -> list:
        results = []
        for line_num, line in enumerate(content.split("\n"), 1):
            if cls._is_commented(line):
                continue
            if cls._is_boilerplate_line(line):
                continue
            for pattern_name, pattern_info in patterns.items():
                try:
                    matches = re.finditer(pattern_info["pattern"], line,
                                         re.IGNORECASE | re.MULTILINE)
                except re.error:
                    continue
                for match in matches:
                    entity = (match.group(1)
                              if match.lastindex and match.lastindex >= 1
                              else match.group(0))
                    if len(entity) < 3 or entity.lower() in cls.FALSE_POSITIVE_VALUES:
                        continue
                    # <ANGLE-WRAPPED> values are placeholders/sentinels
                    # (<your-api-key-here>, <RST-VALIDATE-SYNTAX-CHECK>),
                    # never real secrets.
                    if entity.startswith("<") and entity.endswith(">"):
                        continue
                    if cls._is_noise_value(entity):
                        continue
                    if cls._is_weak_value(pattern_name, entity):
                        continue
                    # Docs/test creds only gate generic patterns — a value
                    # matching a high-precision pattern (AKIA..., sk_live_...)
                    # is flagged even if it looks like an example.
                    if (pattern_name in cls.GENERIC_VALUE_PATTERNS
                            and cls._TEST_CRED_RE.search(entity)):
                        continue
                    if cls._is_public_service_url(entity):
                        continue
                    # Prose heuristics must not fire on slugs INSIDE a URL —
                    # "…access-token-for-the-command-line/" is a help-page
                    # path, not a token. Skip when the match sits within a
                    # URL on the same line.
                    if pattern_name.startswith("prose_") and "://" in line:
                        if any(entity in u for u in
                               re.findall(r"https?://\S+", line)):
                            continue
                    # Skip email-like matches that are part of a connection URL
                    if pattern_name == "email" and "@" in entity:
                        if cls._EMAIL_IN_URL_RE.search(line):
                            continue
                    results.append({
                        "entity":         entity,
                        "type":           pattern_name,
                        "confidence":     pattern_info["confidence"],
                        "level":          pattern_info.get("level", "standard"),
                        "line":           line_num,
                        "context":        line.strip()[:120],
                        "file_type":      file_type,
                        "pattern_reason": pattern_info["reason"],
                    })
        return results

    @staticmethod
    def _entropy(s: str) -> float:
        """Shannon entropy of a string's characters."""
        from collections import Counter
        import math
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    @staticmethod
    def _is_commented(line: str) -> bool:
        # Don't skip comment lines — they often contain sensitive data
        # (server names in headers, passwords in TODOs, credentials in docs)
        return False

    # ── Runtime pattern management (data-driven, not hard-coded) ─────────

    @classmethod
    def reload_patterns(cls):
        """Re-read regex_patterns.json — pick up edits without restarting."""
        cls.UNIVERSAL, cls.FILE_TYPE_EXTRA = _load_pattern_data()
        cls.DIRECT_MASK = _collect_direct_mask(cls.UNIVERSAL, cls.FILE_TYPE_EXTRA)
        if _PATTERN_META.get("false_positive_values"):
            cls.FALSE_POSITIVE_VALUES = set(_PATTERN_META["false_positive_values"])
        if _PATTERN_META.get("public_url_domains"):
            cls.PUBLIC_URL_DOMAINS = tuple(_PATTERN_META["public_url_domains"])
        return {"universal": len(cls.UNIVERSAL),
                "file_types": len(cls.FILE_TYPE_EXTRA),
                "direct_mask": len(cls.DIRECT_MASK),
                "fp_values": len(cls.FALSE_POSITIVE_VALUES),
                "public_domains": len(cls.PUBLIC_URL_DOMAINS)}

    @classmethod
    def add_pattern(cls, name: str, pattern: str, reason: str,
                    confidence: float = 0.9, level: str = "standard",
                    file_type: str | None = None, save: bool = True):
        """Add or update a detection pattern and (optionally) persist it to
        regex_patterns.json. file_type=None puts it in the UNIVERSAL set."""
        re.compile(pattern)  # validate — raises on a bad regex
        entry = {"pattern": pattern, "confidence": confidence,
                 "level": level, "reason": reason}
        if file_type:
            cls.FILE_TYPE_EXTRA.setdefault(file_type, {})[name] = entry
        else:
            cls.UNIVERSAL[name] = entry
        if save:
            cls.save_patterns()
        return entry

    @classmethod
    def save_patterns(cls):
        """Write the current patterns back to regex_patterns.json."""
        data = {
            "_comment": "LocalMask detection patterns — editable without code "
                        "changes. Each entry: {pattern, confidence, level, reason}.",
            "universal": cls.UNIVERSAL,
            "file_type_extra": cls.FILE_TYPE_EXTRA,
        }
        with open(_PATTERNS_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        return _PATTERNS_FILE
