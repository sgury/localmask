"""The detection engine: regex + NER + entropy + LLM pipeline."""
import os
import re

from regex_rules_safe import RegexRulesSafe

from .gitops import _git_tracked_files
from .masking import _make_token, _context_aware_replace


SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox"}

# Files that contain only public/generated data — never scan these
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "Gemfile.lock", "poetry.lock",
    "Pipfile.lock", "go.sum", "cargo.lock",
    "packages.lock.json", "shrinkwrap.json",
}


TEXT_EXTS  = {".sql", ".py", ".yaml", ".yml", ".env", ".json", ".xml",
              ".config", ".conf", ".cfg", ".ini", ".sh", ".bat", ".ps1",
              ".tf", ".tfvars", ".hcl", ".toml", ".txt", ".md", ".js", ".ts",
              ".jsx", ".tsx", ".mjs", ".java", ".cs", ".go", ".rb", ".php",
              ".html", ".css", ".ipynb", ".r", ".scala",
              ".swift", ".kt", ".kts", ".gradle", ".properties", ".plist",
              ".rst", ".adoc", ".csproj", ".props", ".bash", ".zsh",
              ".cls", ".trigger", ".apex"}

# Basenames (no extension) that should be scanned
_TEXT_BASENAMES = {"dockerfile", "makefile", "fastfile", "gemfile",
                   "vagrantfile", "rakefile", "podfile", ".env",
                   ".envrc", ".gitconfig", ".npmrc", ".pypirc"}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _is_text(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in TEXT_EXTS:
        return True
    basename = os.path.basename(path).lower()
    if basename in _TEXT_BASENAMES:
        return True
    # Handle .env.* variants (.env.development, .env.production, etc.)
    if basename.startswith(".env"):
        return True
    return False




_WELL_KNOWN_IMAGES = {
    "postgres", "postgresql", "mysql", "mariadb", "redis", "mongodb", "mongo",
    "nginx", "apache", "httpd", "haproxy", "traefik",
    "elasticsearch", "kibana", "logstash", "grafana", "prometheus",
    "rabbitmq", "kafka", "zookeeper",
    "python", "node", "java", "golang", "ruby",
    "ubuntu", "debian", "alpine", "centos", "amazonlinux",
    "jenkins", "gitlab", "sonarqube", "vault", "consul",
}

_ENV_LABELS = {
    "production": "prod", "prod": "prod",
    "staging": "staging", "stage": "staging",
    "development": "dev", "dev": "dev",
    "test": "test", "testing": "test",
    "qa": "qa", "uat": "uat",
    "preprod": "preprod", "pre-prod": "preprod",
}


_VALUE_PREFIX_TYPES = [
    # (prefix, type) — checked in order, first match wins
    ("hvs.",            "vault_token"),
    ("sk_live_",        "stripe_secret_key"),
    ("sk_test_",        "stripe_test_key"),
    ("pk_live_",        "stripe_public_key"),
    ("pk_test_",        "stripe_public_key"),
    ("SG.",             "sendgrid_api_key"),
    ("AKIA",            "aws_access_key_id"),
    ("whsec_",          "stripe_webhook_secret"),
    ("xoxb-",           "slack_bot_token"),
    ("xoxp-",           "slack_user_token"),
    ("xoxa-",           "slack_app_token"),
    ("ghp_",            "github_personal_token"),
    ("ghs_",            "github_server_token"),
    ("gho_",            "github_oauth_token"),
    ("ghu_",            "github_user_token"),
    ("ghr_",            "github_refresh_token"),
    ("glpat-",          "gitlab_personal_token"),
    ("sk-ant-",         "anthropic_key"),
    ("mongodb://",      "mongodb_connection_string"),
    ("mongodb+srv://",  "mongodb_connection_string"),
    ("postgresql://",   "database_url"),
    ("postgres://",     "database_url"),
    ("mysql://",        "database_url"),
    ("redis://",        "redis_url"),
    ("rediss://",       "redis_url"),
    ("amqp://",         "amqp_connection_string"),
    ("amqps://",        "amqp_connection_string"),
]

# (key_regex, override_type) — applied to the context around the detected value
_CONTEXT_KEY_TYPES = [
    (re.compile(r"(?i)jwt[_.\s-]*(secret|sign|key)"),     "jwt_signing_key"),
    (re.compile(r"(?i)jwt[_.\s-]*refresh"),                "jwt_refresh_secret"),
    (re.compile(r"(?i)sentry[_.\s-]*dsn"),                 "sentry_dsn"),
    (re.compile(r"(?i)redis[_.\s-]*(pass|pw)"),            "redis_password"),
    (re.compile(r"(?i)(?:db|database)[_.\s-]*(pass|pw)"),  "database_password"),
    (re.compile(r"(?i)smtp[_.\s-]*(pass|pw)"),             "smtp_password"),
    (re.compile(r"(?i)oauth[_.\s-]*(secret|client_sec)"),  "oauth_client_secret"),
    (re.compile(r"(?i)rabbitmq[_.\s-]*(pass|pw)"),         "rabbitmq_password"),
    (re.compile(r"(?i)mongo[_.\s-]*(pass|pw)"),            "mongodb_password"),
    (re.compile(r"(?i)mysql[_.\s-]*(pass|pw)"),            "mysql_password"),
    (re.compile(r"(?i)postgres[_.\s-]*(pass|pw)"),         "postgres_password"),
    (re.compile(r"(?i)ldap[_.\s-]*(bind|pass|pw)"),        "ldap_bind_password"),
    (re.compile(r"(?i)grafana[_.\s-]*(token|key|secret)"), "grafana_service_token"),
    (re.compile(r"(?i)datadog[_.\s-]*(api|app)[_.\s-]*key"), "datadog_api_key"),
    (re.compile(r"(?i)newrelic[_.\s-]*(license|key)"),     "newrelic_license_key"),
    (re.compile(r"(?i)pagerduty[_.\s-]*(key|token)"),      "pagerduty_key"),
    (re.compile(r"(?i)twilio[_.\s-]*(auth|token)"),        "twilio_auth_token"),
    (re.compile(r"(?i)sendgrid[_.\s-]*(key|api)"),         "sendgrid_api_key"),
    (re.compile(r"(?i)slack[_.\s-]*(webhook|hook)"),       "slack_webhook_url"),
    (re.compile(r"(?i)vault[_.\s-]*(token|secret)"),       "vault_token"),
    (re.compile(r"(?i)consul[_.\s-]*(token|key)"),         "consul_token"),
    (re.compile(r"(?i)docker[_.\s-]*(password|pass)"),     "docker_hub_password"),
    (re.compile(r"(?i)stripe[_.\s-]*(secret|key)"),        "stripe_secret_key"),
    (re.compile(r"(?i)stripe[_.\s-]*webhook"),             "stripe_webhook_secret"),
    (re.compile(r"(?i)okta[_.\s-]*(token|key|secret)"),    "okta_api_token"),
    (re.compile(r"(?i)azure[_.\s-]*(secret|key|token)"),   "azure_secret"),
    (re.compile(r"(?i)gcp[_.\s-]*(key|secret|token)"),     "gcp_secret"),
    (re.compile(r"(?i)firebase[_.\s-]*(key|secret)"),      "firebase_api_key"),
    (re.compile(r"(?i)elasticsearch[_.\s-]*(pass|pw)"),    "elasticsearch_password"),
    (re.compile(r"(?i)ssl[_.\s-]*(passphrase|pass)"),      "ssl_passphrase"),
    (re.compile(r"(?i)encrypt[_.\s-]*(key|secret)"),       "encryption_key"),
    (re.compile(r"(?i)signing[_.\s-]*(key|secret)"),       "signing_key"),
    (re.compile(r"(?i)session[_.\s-]*(secret|key)"),       "session_secret"),
    (re.compile(r"(?i)django[_.\s-]*secret"),              "django_secret_key"),
    (re.compile(r"(?i)flask[_.\s-]*secret"),               "flask_secret_key"),
    (re.compile(r"(?i)erlang[_.\s-]*cookie"),              "erlang_cookie"),
    (re.compile(r"(?i)spring[_.\s-]*(pass|secret|key)"),   "spring_secret"),
]


def _semantic_subtype(pattern_type: str, value: str, context: str = "") -> str:
    """Enrich token label with semantic context from the matched value and
    surrounding line context (variable name / key)."""

    # ── Container images ────────────────────────────────────────────────
    if pattern_type in ("container_image_internal", "yaml_image"):
        image_name = value.split("/")[-1].split(":")[0].lower().replace("-", "_")
        if image_name in _WELL_KNOWN_IMAGES:
            return f"container_image_{image_name}"
        return "container_image_internal"

    if pattern_type == "k8s_namespace":
        label = _ENV_LABELS.get(value.lower().strip())
        return f"k8s_namespace_{label}" if label else "k8s_namespace"

    # ── URLs ────────────────────────────────────────────────────────────
    if pattern_type in ("url_in_assignment", "url_internal_ip", "git_remote_url"):
        v = value.lower()
        if any(k in v for k in ("/auth/", "/oauth/", "/login", "/token", "/sso/")):
            return "auth_url"
        if any(k in v for k in ("/webhook", "/hook/", "/callback", "/notify")):
            return "webhook_url"
        if any(k in v for k in ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/")):
            return "internal_api_url"
        if any(k in v for k in ("/health", "/ping", "/status", "/metrics", "/ready")):
            return "health_check_url"
        if pattern_type == "git_remote_url":
            return "git_remote_url"
        return "internal_url"

    # ── Value-prefix mapping (highest priority) ─────────────────────────
    for prefix, vtype in _VALUE_PREFIX_TYPES:
        if value.startswith(prefix):
            return vtype

    # ── Context-key mapping (variable/key name) ─────────────────────────
    # Extract just the key part (before = or : or the value itself) to avoid
    # matching neighboring variable names in multi-line context
    if context:
        # Find the key portion: everything before the value in the context
        val_pos = context.find(value[:20]) if len(value) >= 20 else context.find(value)
        key_part = context[:val_pos].strip() if val_pos > 0 else ""
        # Also try splitting on = or : to get the key name
        if not key_part:
            for sep in ("=", ":"):
                if sep in context:
                    key_part = context.split(sep)[0].strip()
                    break
        if key_part:
            for rx, ctype in _CONTEXT_KEY_TYPES:
                if rx.search(key_part):
                    return ctype

    # ── Sentry DSN by value pattern ─────────────────────────────────────
    if "ingest.sentry.io" in value or "sentry.io" in value:
        return "sentry_dsn"

    return pattern_type


def _engine_label(reason: str) -> str:
    if reason.startswith("custom:"):
        return "custom"
    if reason == "user_taught":
        return "lexicon"
    if "NER" in reason or "SpaCy" in reason:
        return "ner"
    return "regex"


def _llm_gate(bert, entity: str, context: str, file_type: str,
              ner_label: str = "") -> dict | None:
    """Ask the LLM classifier (Ollama) if this entity is sensitive.
    Returns the classification result, or None if classifier unavailable."""
    if not bert:
        return None
    try:
        return bert.classify(entity, context[:200], file_type, ner_label=ner_label)
    except Exception:
        return None


# ── Lazy-loaded detection engines ────────────────────────────────────────
_BERT_CLASSIFIER = None
_NER_SCANNER = None


def _get_bert():
    global _BERT_CLASSIFIER
    if _BERT_CLASSIFIER is None:
        # Free edition: no LLM classifier. The engine runs regex + NER +
        # entropy only (proven to detect + mask correctly). One-time notice
        # so users know the AI layer is a Pro upgrade, not a silent downgrade.
        from ._edition import has_capability, upgrade_notice
        if not has_capability("llm_classifier"):
            print(f"[LocalMask] {upgrade_notice('llm_classifier')}")
            _BERT_CLASSIFIER = False
            return None
        try:
            from sensitivity_classifier import SensitivityClassifier
            _BERT_CLASSIFIER = SensitivityClassifier()
        except Exception as e:
            print(f"[WARN] LLM classifier not available: {e}")
            _BERT_CLASSIFIER = False
    return _BERT_CLASSIFIER if _BERT_CLASSIFIER else None


def _get_ner():
    global _NER_SCANNER
    if _NER_SCANNER is None:
        try:
            from ner_scanner import NERScanner
            _NER_SCANNER = NERScanner()
            print(f"[INFO] NER scanner loaded (backend: {_NER_SCANNER.backend})")
        except Exception as e:
            print(f"[WARN] NER scanner not available: {e}")
            _NER_SCANNER = False
    return _NER_SCANNER if _NER_SCANNER else None


def _luhn_ok(value: str) -> bool:
    """Return True if digit string passes Luhn checksum (real credit cards do)."""
    digits = re.sub(r"\D", "", value)
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# Special characters that appear in generated passwords/keys but not in code
# identifiers, versions, datetimes, or dtype strings. Separators (- _ . / :)
# and '=' are deliberately excluded — '=' is an assignment operator and
# base64 padding, so it signals code (key=value), not a secret.
_SECRET_SPECIAL = re.compile(r"[!@#$%^&*~]")
# Brackets/quotes/pipes/backslashes mean the value is code or a data row;
# masking one would also corrupt the identical code elsewhere in the file.
_CODE_PUNCT = re.compile(r"""[()\[\]{}<>|\\'"`]""")
_SHELL_VAR = re.compile(r"\$\{|\$[A-Za-z_]{2,}")
_HASH_TEMPLATE = re.compile(r"#\w+#")
# Value shapes that are never secrets even next to an api_key/token variable:
# a bare domain/host (label.label.tld, incl. cloud suffixes) or a Firebase-
# style app-id (1:234567890123:web:abcdef…). Underscores excluded from the
# host form so leetspeak keys like acme_tw1l10_4uth_… are NOT swallowed.
_NONSECRET_VALUE = re.compile(
    r"(?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,}"          # domain / FQDN
    r"|\d+:\d+:[a-z]+:[0-9a-f]+", re.I)             # firebase appId
_HEX_TOKEN = re.compile(r"[0-9a-fA-F]{32,}")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                   r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _looks_generated(value: str) -> bool:
    """Decide whether a context-LESS 'secret' guess is trustworthy.

    When a nearby variable name already labelled the value (password=,
    API_KEY:, …) we trust that and never call this. This gate is only for the
    generic fallback — a value flagged purely because it "looks random." To
    survive it a value must actually look *generated*:
      - contiguous (no whitespace) and free of code/bracket punctuation, so
        it's a single opaque token and masking it can't corrupt code; and
      - carry real character diversity — all of upper/lower/digit, OR a
        special char plus two classes.
    Package names (scipy-openblas32), versions (2.1.0.dev0), datetimes
    (1959-10-13T12:34:56), dtype codes (GDFgdfQq?) and regex fragments all
    fail; passwords (P0stgr3s!Pr0d#2024) and API tokens (7xK2nM5pQ8rS…) pass.
    """
    if any(c.isspace() for c in value) or _CODE_PUNCT.search(value):
        return False
    # Shell/template variable references ($LLVM_PREFIX, ${VAR}, $env:…) are
    # unexpanded templates — the secret, if any, is the variable's value.
    if _SHELL_VAR.search(value):
        return False
    # `#name#` template markers (f2py rules) and a `*` glob/regex operator
    # never appear in generated keys.
    if "*" in value or _HASH_TEMPLATE.search(value):
        return False
    # `=` means an assignment or flag (TERM=…, -Dflag=1) — a real token only
    # carries `=` as trailing base64 padding, so allow it only at the end.
    if "=" in value.rstrip("="):
        return False
    # Pure hex tokens (≥32: MD5/SHA/Twilio-style) and UUIDs are generated
    # credential shapes even though hex is only two classes. The ≥32 floor
    # keeps short hex constants like "0123456789abcdef" out.
    if _HEX_TOKEN.fullmatch(value) or _UUID.fullmatch(value):
        return True
    classes = sum([any(c.isupper() for c in value),
                   any(c.islower() for c in value),
                   any(c.isdigit() for c in value)])
    if classes >= 3:
        return True
    return bool(_SECRET_SPECIAL.search(value)) and classes >= 2


_PAIRS = {"(": ")", "[": "]", "{": "}"}
_PAIRS_REV = {c: o for o, c in _PAIRS.items()}

# Inferred/prose/assignment patterns that tend to match code, not literals.
# High-precision vendor patterns are deliberately excluded.
_SOFT_VALUE_TYPES = {
    "password_unquoted", "unquoted_env_secret", "any_env_secret",
    "any_env_token", "email_credential", "prose_db_name",
    "prose_server_name", "prose_generic_key", "prose_token",
    "tf_hcl_username", "cli_mysql_password", "cli_password",
}
_CODE_CALL = re.compile(r"[A-Za-z_]\w*\s*\(")   # func call: foo(
_VERSION_CONSTRAINT = re.compile(r"[<>=!]=?\s*\d")  # >=2, <4, ==1.0


def _looks_like_code_value(v: str) -> bool:
    """True if a soft-pattern value is code/template/version rather than a
    literal secret: a function call, a version constraint, a {placeholder},
    or a fragment starting with a separator (`, default=…`). Kept narrow so
    real secrets (which never contain these) are untouched."""
    if _CODE_CALL.search(v) or _VERSION_CONSTRAINT.search(v):
        return True
    if "{" in v and "}" in v:            # {self.username}, f"{x}"
        return True
    if v[:1] in ",;":                    # leading-comma code fragment
        return True
    return False

def _trim_unbalanced(v: str) -> str:
    """Strip leading openers / trailing closers whose partner isn't inside
    the value. Masking half of a bracket pair corrupts the surrounding code."""
    while v and v[0] in _PAIRS and _PAIRS[v[0]] not in v:
        v = v[1:]
    while v and v[-1] in _PAIRS_REV and _PAIRS_REV[v[-1]] not in v:
        v = v[:-1]
    return v.strip()


_WORD_LIKE_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9_\-\.]{2,39}$')
_HAS_SPECIAL  = re.compile(r'[!@#$%^&*()\[\]{}|;:<>?,\\/\'"~`]')

def _is_word_like(value: str) -> bool:
    """True if value looks like a name/identifier rather than a real secret."""
    if _HAS_SPECIAL.search(value):
        return False
    if not _WORD_LIKE_RE.match(value):
        return False
    digit_ratio = sum(c.isdigit() for c in value) / max(len(value), 1)
    return digit_ratio < 0.4


def _is_dbt_model(rel_path: str, content: str) -> bool:
    p = rel_path.replace("\\", "/").lower()
    return (p.endswith(".sql") and
            ("models/" in p or "macros/" in p or "seeds/" in p) and
            ("{{ ref(" in content or "{{ source(" in content or "select" in content.lower()))


def _infer_secret_type(value: str, context_line: str) -> tuple[str, str]:
    """Infer the secret type from the value format and surrounding context.
    Returns (type_name, reason)."""
    vl = value.lower()
    cl = context_line.lower()

    # ── Value-based detection (what the string looks like) ───────────────
    # Connection strings
    if re.match(r"(?:postgres|postgresql|mysql|mongodb|redis|mssql|sqlite)"
                r"(?:\+\w+)?://", vl):
        return "db_connection_string", "Database connection string (auto-detected)"
    if re.match(r"amqps?://", vl):
        return "broker_url", "Message broker URL (auto-detected)"
    if re.match(r"redis://", vl):
        return "redis_url", "Redis connection URL (auto-detected)"
    # URLs
    if re.match(r"https?://", vl):
        return "internal_url", "Internal URL (auto-detected)"
    # JWT-shaped (three dot-separated base64 segments)
    if re.match(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.", value):
        return "jwt_token", "JWT token (auto-detected)"

    # ── Context-based detection (what the variable/key name says) ────────
    # Extract the variable/key name from the line
    # Patterns: VAR_NAME = "...",  "key_name": "...",  KEY: value
    var_match = re.search(
        r'(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["\']', context_line)
    if not var_match:
        var_match = re.search(
            r'["\']([A-Za-z_][A-Za-z0-9_]*?)["\']\s*:\s*["\']', context_line)
    if not var_match:
        var_match = re.search(
            r'(?:^|\s)([A-Za-z_][A-Za-z0-9_]*):\s', context_line)

    var_name = var_match.group(1).lower() if var_match else ""

    # Map variable name patterns to secret types
    # Order matters — more specific patterns first
    _VAR_TYPE_MAP = [
        (r"connect|conn|dsn|database_url|db_url|sqlalchemy", "db_connection_string",
         "Database connection (auto-detected from context)"),
        (r"jwt|json_web_token", "jwt_secret",
         "JWT secret (auto-detected from context)"),
        (r"api[_\s]?key|apikey|api[_\s]?secret", "api_key",
         "API key (auto-detected from context)"),
        (r"secret[_\s]?key|signing[_\s]?key|secret_access", "secret_key",
         "Secret key (auto-detected from context)"),
        (r"password|passwd|pwd", "password",
         "Password (auto-detected from context)"),
        (r"token|access_token|refresh_token|auth_token", "auth_token",
         "Auth token (auto-detected from context)"),
        (r"broker|celery|amqp|rabbit", "broker_url",
         "Message broker credential (auto-detected from context)"),
        (r"redis", "redis_credential",
         "Redis credential (auto-detected from context)"),
        (r"oauth|client_secret", "oauth_secret",
         "OAuth secret (auto-detected from context)"),
        (r"cookie|session", "session_secret",
         "Session/cookie secret (auto-detected from context)"),
        (r"encrypt|cipher|aes|hmac|hash|salt", "encryption_key",
         "Encryption key (auto-detected from context)"),
        (r"smtp|mail|email.*(?:pass|cred)", "email_credential",
         "Email credential (auto-detected from context)"),
        (r"aws|s3|iam|boto", "aws_credential",
         "AWS credential (auto-detected from context)"),
        (r"ssh|private_key|pem|rsa", "ssh_credential",
         "SSH/private key credential (auto-detected from context)"),
        (r"ldap|bind|active_directory", "ldap_credential",
         "LDAP credential (auto-detected from context)"),
        (r"(?:pagerduty|datadog|sentry|newrelic|grafana|slack|webhook)[_\s]?(?:key|token|secret)",
         "monitoring_key", "Monitoring/alerting service key (auto-detected from context)"),
        (r"_key$|_token$", "service_key",
         "Service key/token (auto-detected from context)"),
        (r"internal.*(?:key|api|auth)|service.*(?:key|auth)", "internal_api_key",
         "Internal API key (auto-detected from context)"),
    ]

    # ── Skip non-sensitive variable names ─────────────────────────────────
    _SAFE_VAR_NAMES = re.compile(
        r"^(organization|org|company|company_name|name|display_name|label"
        r"|title|description|comment|note|message|text|content|body"
        r"|version|type|kind|category|status|state|mode|format|level"
        r"|region|zone|location|country|city|address|timezone"
        r"|environment|env|stage|namespace|project|team|department"
        r"|author|owner|created_by|updated_by|reviewer"
        r"|filename|file_name|file_path|dir|directory|folder|path"
        r"|log|debug|info|warning|error|output|result|summary)$"
    )
    if var_name and _SAFE_VAR_NAMES.match(var_name):
        return "", ""  # Not a secret — caller should skip this detection

    # Check variable name ONLY — this is the most reliable signal
    for pattern, type_name, reason in _VAR_TYPE_MAP:
        if re.search(pattern, var_name):
            return type_name, reason

    # ── Value-shape heuristics (when var name is ambiguous) ─────────────
    # Looks like a hostname/FQDN
    if re.match(r"[a-z][a-z0-9\-]*\.[a-z0-9\-]+\.[a-z]{2,}", vl):
        return "server_hostname", "Server hostname (auto-detected from value)"
    # Looks like an IP:port
    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", vl):
        return "ip_address", "IP address (auto-detected from value)"
    # Looks like an S3/cloud path
    if re.match(r"[a-z][a-z0-9\-]*-(?:prod|staging|dev|raw|archive|landing)", vl):
        return "cloud_resource", "Cloud resource identifier (auto-detected from value)"
    # Looks like a file/folder path
    if re.match(r"[/\\]|[A-Z]:\\", value) or re.match(r"\w+[/\\]\w+", value):
        return "file_path", "File path (auto-detected from value)"

    # ── Context line search (ONLY var name, not full line) ──────────────
    # Don't search the full context line — it causes cross-contamination
    # (e.g. "password" on a nearby line making "server" look like a password)

    # Fallback: generic secret
    return "secret", "Secret value (auto-detected by entropy)"


# A base64 run long enough to hold a real credential. Bounded so we don't
# try to decode megabyte blobs. Standard and url-safe alphabets both covered
# by the charset; validated per-match.
_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{24,1024}={0,2})"
                      r"(?![A-Za-z0-9+/=_-])")
# Secret-naming context around a blob (used when the decoded plaintext has no
# regex hit of its own but the variable clearly holds a credential).
_B64_SECRET_CTX = re.compile(
    r"(?i)(secret|password|passwd|api[_-]?key|auth[_-]?token|access[_-]?token"
    r"|credential|private[_-]?key|encryption|signing[_-]?key|\.pem)")


def _scan_base64_secrets(content: str, file_ext: str,
                         already_found: set) -> list:
    """Decode base64 blobs and re-scan the plaintext. Flag the blob when the
    decoded text either matches a credential pattern (high precision — a real
    key was merely encoded) or sits in an unmistakable secret-naming context.
    Random/binary base64 (images, test vectors) fails to decode to text or
    yields no secret, so it is ignored."""
    import base64 as _b64
    from regex_rules_safe import RegexRulesSafe
    results = []
    lines = content.split("\n")
    for m in _B64_RUN.finditer(content):
        blob = m.group(1)
        if blob in already_found:
            continue
        core = len(blob) - (len(blob) - len(blob.rstrip("=")))
        if core % 4 and len(blob) % 4:      # not a whole base64 quantum
            continue
        std = blob.replace("-", "+").replace("_", "/")
        pad = "=" * (-len(std) % 4)
        try:
            raw = _b64.b64decode(std + pad, validate=True)
            decoded = raw.decode("utf-8")
        except Exception:
            continue                        # binary / not valid base64 text
        if not decoded.isprintable() and "\n" not in decoded:
            continue
        line_no = content[:m.start()].count("\n") + 1
        line = lines[line_no - 1] if line_no <= len(lines) else ""

        # (a) the plaintext itself carries a credential — highest precision.
        inner = RegexRulesSafe.scan_file("decoded." + file_ext, decoded,
                                         "standard")
        strong = [h for h in inner
                  if h.get("type") not in ("email", "ip_address_private",
                                           "phone_us", "credit_card")]
        # (b) or the blob sits in a secret-named field.
        ctx = _B64_SECRET_CTX.search(line)
        if not strong and not ctx:
            continue
        why = (f"base64 decodes to {strong[0].get('type')}" if strong
               else "base64 value in a secret field")
        results.append({
            "entity": blob, "type": "base64_encoded_secret",
            "confidence": 0.9 if strong else 0.8, "level": "standard",
            "line": line_no, "context": line.strip()[:120],
            "file_type": file_ext, "pattern_reason": why,
        })
        already_found.add(blob)
    return results


def _scan_entropy_strings(content: str, file_ext: str,
                          already_found: set) -> list:
    """
    Scan ALL quoted strings in code for high-entropy values that look like
    secrets/tokens/keys — regardless of the variable name or format.

    This catches things like:
        "fraud_service": "mfs-internal-fraud-7xK2nM5pQ8rS1tU4wY0zA"
    where the key name is generic but the VALUE is clearly a secret.

    Uses _infer_secret_type() to label each detection based on context.
    """
    import math
    from collections import Counter

    results = []
    # Match ALL quoted strings (any length, escapes respected) and length-
    # filter afterwards. A minimum length in the regex itself made short
    # strings invisible, so 'NaT'), np.datetime64('2038' matched from one
    # string's CLOSING quote to the next one's opener — capturing raw code
    # between strings and corrupting it at mask time.
    string_pat = re.compile(r"""(['"])((?:[^'"\\]|\\.)*)\1""")
    # Context keywords that boost confidence the string is a secret
    secret_context_re = re.compile(
        r"(?i)(key|secret|token|password|api|auth|credential|internal|private"
        r"|signing|encrypt|hmac|hash|salt)")
    # Context that means the string is NOT a secret
    safe_context_re = re.compile(
        r"(?i)(import|from|print|log|error|warning|info|debug|format|class\s"
        r"|def\s|#\s*TODO|#\s*FIXME|description|help|label|display|message"
        r"|comment|note|version|name.*=|__\w+__|\.com/|\.org/|http)")

    lines = content.split("\n")

    # Build a context window: for each line, also look at nearby lines
    # to find variable names (e.g. INTERNAL_API_KEYS = { ... })
    def _get_context_window(line_idx, window=5):
        start = max(0, line_idx - window)
        return "\n".join(lines[start:line_idx + 1])

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip pure comments and blank lines
        if stripped.startswith("#") and "key" not in stripped.lower() \
                and "secret" not in stripped.lower() \
                and "token" not in stripped.lower():
            continue

        for m in string_pat.finditer(line):
            value = m.group(2)
            if len(value) < 12:
                continue

            # Already detected by regex layer
            if value in already_found:
                continue

            # HTTP headers / localhost example connection strings are never
            # secrets (shared filter with the regex layer).
            if RegexRulesSafe._is_noise_value(value):
                continue

            # ── Filter 1: Length ──────────────────────────────────────────
            if len(value) < 16 or len(value) > 500:
                continue

            # ── Filter 2: Must have mixed charset ────────────────────────
            has_upper = any(c.isupper() for c in value)
            has_lower = any(c.islower() for c in value)
            has_digit = any(c.isdigit() for c in value)
            charset_mix = sum([has_upper, has_lower, has_digit])
            if charset_mix < 2:
                continue  # plain English or all-lowercase path

            # ── Filter 3: Entropy ────────────────────────────────────────
            counts = Counter(value)
            length = len(value)
            entropy = -sum(
                (c / length) * math.log2(c / length)
                for c in counts.values()
            )
            if entropy < 3.2:
                continue  # Low entropy = probably not a secret

            # ── Filter 4: Not a URL, file path, English phrase, or f-string ─
            if value.startswith(("/", "./")):
                continue
            if " " in value and value.count(" ") >= 2:
                continue  # Looks like natural language (3+ words)
            if " " in value and not has_digit:
                continue  # Two Title-Case words (CI step names, prose) — real
                          # secrets with spaces are rare and carry digits
            if value.count("/") > 3 and "://" not in value:
                continue  # Looks like a file path
            # ── Non-secret identifiers (verified 0 overlap with real secrets):
            #   AWS ARNs, internal hostnames, and dependency coordinates are
            #   infra/build metadata, not credentials. The entropy scanner is a
            #   last-resort net, so err toward precision here.
            if value.startswith(("arn:", "ldap://", "ldaps://")) \
                    and "@" not in value:
                continue  # ARN resource id / hostless LDAP URL
            if re.search(r"\.(?:internal|local|corp|svc|cluster)(?::\d+)?$",
                         value) and "@" not in value:
                continue  # internal hostname[:port], no embedded credentials
            if re.fullmatch(r"[a-z][\w.\-]*(?::[\w.\-]+){2}", value) \
                    and "://" not in value and "@" not in value:
                continue  # gradle/maven coordinate group:artifact:version
            # Skip f-string templates that reference variables, not literals
            if "{" in value and "}" in value:
                continue  # e.g. f"Bearer {API_KEY}" — the secret is the var, not the string

            # ── Filter 5: Safe context check ─────────────────────────────
            if safe_context_re.search(stripped) and not secret_context_re.search(stripped):
                continue

            # A value that is plainly a domain/host, cloud endpoint, or an
            # app-id triplet is not a secret no matter what the nearby
            # variable is called (Firebase config puts authDomain, appId and
            # storageBucket right next to apiKey). Veto by value shape before
            # trusting the context name.
            if _NONSECRET_VALUE.fullmatch(value):
                continue

            # ── Infer type from context ──────────────────────────────────
            context_window = _get_context_window(line_num - 1)
            inferred_type, reason = _infer_secret_type(value, context_window)
            if not inferred_type:
                continue  # Safe variable name — not a secret

            # ── Diversity gate for context-less guesses ──────────────────
            # A specific inferred_type means a nearby variable name identified
            # the secret — trust it. The generic "secret" fallback is a pure
            # "looks random" guess with no naming signal, and that's where all
            # the noise lands (regex sources, dtype codes, datetimes, package
            # names). Keep it only if the value actually looks generated. This
            # single positive rule replaces the old per-shape blocklist.
            if inferred_type == "secret" and not _looks_generated(value):
                continue

            # ── Confidence based on signals ──────────────────────────────
            confidence = 0.75
            if secret_context_re.search(stripped):
                confidence = 0.92
            if secret_context_re.search(context_window):
                confidence = max(confidence, 0.88)
            if entropy > 4.0:
                confidence = min(confidence + 0.1, 0.99)
            if charset_mix == 3:
                confidence = min(confidence + 0.05, 0.99)

            results.append({
                "entity":         value,
                "type":           inferred_type,
                "confidence":     round(confidence, 3),
                "level":          "minimal",
                "line":           line_num,
                "context":        stripped[:120],
                "file_type":      file_ext,
                "pattern_reason": reason,
            })
            already_found.add(value)

    return results


def _scan_file(session: dict, content: str, rel_path: str) -> dict:
    """Detect, mask, and return file dict.
    Layers:  1) Regex rules  2) NER (freetext)  3) BERT re-scoring
             4) Entropy scanner  5) Custom rules  6) User-taught values
    """
    sensitivity = session.get("sensitivity", "standard")
    file_ext = os.path.splitext(rel_path)[1].lstrip(".") or "txt"

    # ── Layer 1: Regex ───────────────────────────────────────────────────
    raw_detections = RegexRulesSafe.scan_file(rel_path, content, sensitivity)

    # ── Layer 2: NER (freetext files: .md, .txt, .rst, .adoc) ────────────
    ner = _get_ner()
    bert = _get_bert()
    freetext_exts = {"md", "txt", "rst", "adoc", "log", ""}
    if ner and file_ext in freetext_exts:
        ner_hits = ner.scan(content, rel_path, sensitivity)
        for hit in ner_hits:
            if any(d["entity"] == hit["entity"] for d in raw_detections):
                continue
            hit["pattern_reason"] = hit.get("pattern_reason", f"NER:{hit.get('ner_label','')}")
            raw_detections.append(hit)

    # ── Layer 3: Entropy-based secret scanner ─────────────────────────────
    # NB: the entropy scanner MUTATES the set it's given (adds each value it
    # flags). Give it a copy so `already_found` stays the clean regex+NER set
    # for the base64 layer below.
    already_found = {d["entity"] for d in raw_detections}
    _entropy_hits = _scan_entropy_strings(content, file_ext, set(already_found))
    raw_detections.extend(_entropy_hits)

    # ── Layer 3b: base64 decode-and-rescan ───────────────────────────────
    # A base64 blob that decodes to a live credential (e.g. a k8s Secret
    # `data:` value that is base64("sk_live_…"), or an encoded token) is
    # invisible to a surface scan. Decode each blob and re-run the regex
    # layer on the plaintext; flag the ORIGINAL blob when the plaintext
    # holds a real secret. Uses the clean regex+NER set (not entropy's) so a
    # weaker entropy claim doesn't suppress the stronger decoded verdict —
    # dedup merges any overlap.
    raw_detections.extend(_scan_base64_secrets(content, file_ext, already_found))

    # ── Layer 4: LLM gate — ask Ollama about ambiguous detections ────────
    # Obviously-sensitive types (credentials, keys, passwords, connections)
    # skip the LLM to save time. Only ambiguous ones (NER names, hostnames,
    # ports) go through the model.
    _SKIP_LLM_TYPES = {
        "api_key", "generic_api_key", "secret", "secret_key",
        "py_hardcoded_secret", "django_secret_key", "jwt_secret_var",
        "oauth_secret", "auth_token", "aws_access_key", "aws_account_id",
        "aws_arn", "aws_credential", "boto3_hardcoded_key",
        "boto3_hardcoded_secret", "s3_bucket_name", "password",
        "password_assignment", "django_db_password", "redis_credential",
        "db_connection_string", "db_connection_url", "flask_sqlalchemy_uri",
        "celery_broker_url", "ldap_credential", "internal_url",
        "prose_internal_url", "email", "ip_address_private",
        "internal_fqdn", "service_account",
        # Key-name patterns (PASSWORD=, SECRET=, TOKEN=) are strong signals;
        # weak/placeholder values are already rejected at the regex layer.
        "password_unquoted", "unquoted_env_secret", "any_env_password",
        "any_env_secret", "any_env_token", "tf_hcl_secret",
        "java_properties_password",
        # Already high-precision: FCM keys have a fixed shape, and a base64
        # blob we DECODED and re-scanned is verified — don't second-guess.
        "fcm_server_key", "base64_encoded_secret",
    }

    if bert and raw_detections and not session.get("skip_llm"):
        # Split: obvious secrets skip LLM, ambiguous ones get classified.
        # session["skip_llm"] forces regex+NER+entropy only — used by the AI
        # proxy hot path where per-request latency matters.
        needs_llm = []
        needs_llm_idx = []
        filtered = []

        for i, det in enumerate(raw_detections):
            det_type = det.get("type", det.get("subtype", ""))
            # Skip the LLM for named-secret patterns AND for any high-precision
            # regex hit (conf ≥ 0.9). A value that matched a vendor pattern like
            # whsec_… / AIza… / dd… / ghsecret_… IS that secret — letting the
            # classifier second-guess it only drops real credentials (this was
            # measured: the gate was dropping stripe-webhook/datadog/github/
            # google keys the regex layer had already nailed).
            _reason = str(det.get("pattern_reason", ""))
            is_regex = bool(_reason) and "auto-detected" not in _reason \
                and not _reason.startswith("NER:")   # exclude entropy + NER
            if det_type in _SKIP_LLM_TYPES or \
                    (is_regex and det.get("confidence", 0) >= 0.9):
                det["llm_decision"] = "SENSITIVE"
                det["llm_confidence"] = 0.95
                det["llm_reason"] = "High-confidence pattern"
                det["llm_source"] = "skip"
                filtered.append(det)
            else:
                needs_llm.append(det)
                needs_llm_idx.append(i)

        if needs_llm:
            batch_items = [
                {
                    "entity": det["entity"],
                    "context": det.get("context", "")[:200],
                    "file_type": det.get("file_type", file_ext),
                    "ner_label": det.get("ner_label", ""),
                }
                for det in needs_llm
            ]
            llm_results = bert.classify_batch(batch_items)

            for det, result in zip(needs_llm, llm_results):
                if result:
                    det["llm_decision"] = result["decision"]
                    det["llm_confidence"] = round(result.get("confidence", 0), 3)
                    det["llm_reason"] = result.get("reason", "")
                    det["llm_source"] = result.get("source", "")
                    if result["decision"] == "NOT_SENSITIVE":
                        continue  # LLM says skip
                    det["confidence"] = round(result.get("probability", 0.85), 3)
                filtered.append(det)

        raw_detections = filtered

    # ── Layer 5: Custom regex rules ──────────────────────────────────────
    for rule in session.get("custom_rules", []):
        try:
            for m in re.finditer(rule["pattern"], content):
                entity = m.group(1) if m.lastindex else m.group(0)
                if len(entity) < 3:
                    continue
                raw_detections.append({
                    "entity":         entity,
                    "type":           rule["name"],
                    "confidence":     0.90,
                    "line":           content[: m.start()].count("\n") + 1,
                    "context":        content[max(0, m.start()-40): m.end()+40].strip(),
                    "file_type":      file_ext,
                    "pattern_reason": f"custom:{rule['name']}",
                })
        except re.error:
            pass

    # ── Layer 6: User-taught values ──────────────────────────────────────
    for value, teach_info in session.get("taught", {}).items():
        # teach_info can be a string (subtype) for legacy, or a dict with context
        if isinstance(teach_info, str):
            subtype = teach_info
            context_pattern = None
        else:
            subtype = teach_info.get("subtype", "SECRET")
            context_pattern = teach_info.get("context_pattern")

        for m in re.finditer(re.escape(value), content):
            line_start = content.rfind("\n", 0, m.start()) + 1
            line_end = content.find("\n", m.end())
            if line_end == -1:
                line_end = len(content)
            full_line = content[line_start:line_end]

            # Context-aware: if a context pattern is set, only match in
            # lines that match the context pattern (e.g. port= but not phone)
            if context_pattern:
                try:
                    if not re.search(context_pattern, full_line, re.IGNORECASE):
                        continue
                except re.error:
                    pass

            raw_detections.append({
                "entity":         value,
                "type":           subtype,
                "confidence":     0.99,
                "line":           content[: m.start()].count("\n") + 1,
                "context":        content[max(0, m.start()-40): m.end()+40].strip(),
                "file_type":      "txt",
                "pattern_reason": "user_taught",
            })

    # ── Filter & dedupe ──────────────────────────────────────────────────
    allowed = session.get("allowed", set())
    # Patterns that are more specific get higher priority in dedup
    _SPECIFIC_PATTERNS = {
        "jwt_secret", "jwt_secret_var", "aws_access_key", "aws_secret_key",
        "github_token", "anthropic_key", "openai_key", "slack_token",
        "stripe_key", "google_api_key", "django_secret_key", "flask_secret_key",
        "boto3_hardcoded_key", "boto3_hardcoded_secret", "oauth2_client_secret",
        "django_db_password", "flask_sqlalchemy_uri", "celery_broker_url",
        # URL/connection credentials are a specific credential type — prefer
        # them over generic inferences (email, secret) for the same value.
        "url_embedded_password", "db_connection_url", "db_connection_string",
        "mongodb_connection_string", "jdbc_connection_string", "redis_url",
        # A decoded-and-verified base64 blob (or an FCM key) beats a generic
        # entropy claim on the same value — and masks directly (above).
        "base64_encoded_secret", "fcm_server_key",
    }
    # Inferred infra/PII types (from _infer_secret_type value heuristics) that
    # are not credentials — gated to 'strict' so standard scans stay low-noise.
    _STRICT_ONLY_INFERRED = {
        "internal_url", "server_hostname", "ip_address", "cloud_resource",
        "file_path",
    }
    seen: dict = {}
    for d in raw_detections:
        # Trim unbalanced brackets a regex may have swallowed (e.g. a phone-
        # like match on "seed(1301109903"). Masking an unpaired "(" breaks
        # the surrounding code — a token must never eat one side of a pair.
        v = _trim_unbalanced(d["entity"])
        if len(v) < 3:
            continue
        d["entity"] = v
        if v in allowed:
            continue
        # Unresolved templates are placeholders, not real values — e.g.
        # postgresql://{{ db_user }}:{{ db_password }}@host or ${DB_PASS}.
        # Skip any value carrying an interpolation marker.
        if ("{{" in v and "}}" in v) or "${" in v or "%(" in v \
                or "<%=" in v or "#{" in v:
            continue
        # Broad infra inferences (any http(s) URL → internal_url, generic
        # hostnames) are PII/infra, not credentials. Per the sensitivity model
        # they belong at 'strict'; drop them from standard scans to cut noise.
        if sensitivity != "strict" \
                and d.get("type", "") in _STRICT_ONLY_INFERRED:
            continue
        # NB: match on the pattern NAME ("type"), not pattern_reason — the
        # reason field carries prose ("Credit card number"), so comparing it
        # against names meant these filters never fired.
        dtype = d.get("type", "")
        if dtype in ("credit_card", "credit_card_grouped") and not _luhn_ok(v):
            continue
        if dtype in ("password_assignment", "declare_password", "any_env_password"):
            if _is_word_like(v):
                continue
        # Soft/inferred patterns (unquoted passwords, prose names, HCL/CLI
        # values) frequently match CODE rather than a literal secret — a
        # function call, a bare identifier, a {template}, or a version
        # constraint. Reject those. Named high-precision vendor patterns are
        # NOT in this set, so real keys are unaffected. (numpy/requests/flask
        # false positives: get_auth_from_url(proxy), {self.username},
        # charset_normalizer>=2,<4, default=5000.)
        if dtype in _SOFT_VALUE_TYPES and _looks_like_code_value(v):
            continue
        if v not in seen:
            seen[v] = d
        elif d.get("type", "") in _SPECIFIC_PATTERNS:
            # Prefer more specific pattern over generic one
            seen[v] = d

    # ── Mask & build findings ────────────────────────────────────────────
    # Sort by value length descending so longer matches (e.g. full ARN)
    # get masked before shorter substrings (e.g. account ID inside ARN)
    masked = content
    findings = []
    for value, det in sorted(seen.items(), key=lambda kv: -len(kv[0])):
        subtype = _semantic_subtype(det.get("type", "SECRET"), value,
                                    det.get("context", ""))
        token = _make_token(session, value, subtype)
        # Patterns flagged mask_mode=direct in regex_patterns.json (dotted
        # vendor tokens like hvs.<...> / SG.<...>.<...>) are wrongly protected
        # by the key-position guard in _context_aware_replace, which silently
        # drops them. Their shape proves they're the secret, so mask directly.
        # Data-driven: the set comes from the pattern DB, not hardcoded names.
        # base64 blobs and FCM keys are the whole value (never a key name), so
        # the key-position guard in _context_aware_replace would wrongly
        # protect them (leaving the token absent → finding silently dropped).
        # They're verified secrets — mask directly, like DIRECT_MASK patterns.
        if det.get("type", "") in RegexRulesSafe.DIRECT_MASK \
                or det.get("type", "") in ("base64_encoded_secret", "fcm_server_key"):
            masked = masked.replace(value, token)
        else:
            masked = _context_aware_replace(masked, value, token)
        base_engine = _engine_label(det.get("pattern_reason", ""))
        has_llm = bool(det.get("llm_decision"))
        if has_llm:
            llm_src = det.get("llm_source", "ollama")
            engine = f"{base_engine}+{llm_src}"  # "ner+ollama"
        else:
            engine = base_engine
        findings.append({
            "value":      value,
            "token":      token,
            "subtype":    subtype,
            "line":       det.get("line", 0),
            "confidence": det.get("confidence", 0.9),
            "source":     det.get("pattern_reason", "regex"),
            "engine":     engine,
            "llm_decision":    det.get("llm_decision", ""),
            "llm_confidence":  det.get("llm_confidence", 0),
            "llm_reason":      det.get("llm_reason", ""),
        })

    # Drop findings whose token never made it into the masked content
    # (protected by _context_aware_replace — key positions stay visible)
    kept_findings = []
    for f in findings:
        if f["token"] in masked:
            kept_findings.append(f)
        else:
            # Clean up vault — this value was never actually masked
            session["vault"].pop(f["value"], None)
            session["rev_vault"].pop(f["token"], None)
    findings = kept_findings

    status = "PENDING_REVIEW" if findings else "OK"
    return {"original": content, "masked": masked,
            "status": status, "findings": findings, "n": len(findings)}


def _scan_dir(session: dict, src_dir: str):
    """Walk directory and scan every text file.
    If inside a git repo, only scan git-tracked files (respects .gitignore)."""
    files: dict = {}
    tracked = _git_tracked_files(src_dir)

    if tracked is not None:
        # Git repo — only scan tracked + untracked-but-not-ignored files
        for rel in sorted(tracked):
            fname = os.path.basename(rel)
            if fname in SKIP_FILES:
                continue
            fpath = os.path.join(src_dir, rel)
            if not os.path.isfile(fpath) or not _is_text(fpath):
                continue
            try:
                if os.path.getsize(fpath) > 500_000:
                    continue
                content = open(fpath, errors="ignore").read()
            except Exception:
                continue
            files[rel] = _scan_file(session, content, rel)
    else:
        # Not a git repo — walk everything (skip standard dirs)
        for dirpath, dirnames, filenames in os.walk(src_dir):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in sorted(filenames):
                fpath = os.path.join(dirpath, fname)
                rel   = os.path.relpath(fpath, src_dir)
                if fname in SKIP_FILES or not _is_text(fpath):
                    continue
                try:
                    if os.path.getsize(fpath) > 500_000:
                        continue
                    content = open(fpath, errors="ignore").read()
                except Exception:
                    continue
                files[rel] = _scan_file(session, content, rel)
    session["files"] = files


def _remask(session: dict):
    """Re-run masking on all files (after teach / custom rule change)."""
    for rel, d in session["files"].items():
        updated = _scan_file(session, d["original"], rel)
        d.update(updated)


