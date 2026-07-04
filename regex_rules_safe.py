import re
import os
import json

# Sensitivity levels — each pattern belongs to a level.
# "minimal"  = only undeniable secrets & hard PII
# "standard" = + infra topology + contributor identity
# "strict"   = + org identity + internal tracing IDs
LEVELS = ("minimal", "standard", "strict")


class RegexRulesSafe:
    """Detection patterns with per-pattern sensitivity levels.
    Call scan_file(path, content, sensitivity="standard") to control depth."""

    UNIVERSAL = {
        # ── MINIMAL: clear credentials & hard PII ────────────────────────────
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "confidence": 0.99, "level": "minimal",
            "reason": "AWS access key ID"
        },
        "aws_secret_key": {
            "pattern": r"(?i)(?:aws.{0,20}secret|secret.{0,20}aws|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([a-zA-Z0-9/+]{40})['\"]?",
            "confidence": 0.99, "level": "minimal",
            "reason": "AWS secret access key"
        },
        "private_key_header": {
            "pattern": r"-----BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY",
            "confidence": 0.99, "level": "minimal",
            "reason": "Private key"
        },
        "github_token": {
            "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
            "confidence": 0.99, "level": "minimal",
            "reason": "GitHub token"
        },
        "anthropic_key": {
            "pattern": r"sk-ant-[a-zA-Z0-9\-_]{20,}",
            "confidence": 0.99, "level": "minimal",
            "reason": "Anthropic API key"
        },
        "openai_key": {
            "pattern": r"sk-[a-zA-Z0-9]{32,}",
            "confidence": 0.97, "level": "minimal",
            "reason": "OpenAI API key"
        },
        "google_api_key": {
            "pattern": r"AIza[0-9A-Za-z\-_]{35}",
            "confidence": 0.99, "level": "minimal",
            "reason": "Google API key"
        },
        "slack_token": {
            "pattern": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
            "confidence": 0.99, "level": "minimal",
            "reason": "Slack token"
        },
        "slack_webhook": {
            "pattern": r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+",
            "confidence": 0.99, "level": "minimal",
            "reason": "Slack webhook URL"
        },
        "telegram_bot_token": {
            "pattern": r"\b\d{8,12}:[A-Za-z0-9_-]{35,}\b",
            "confidence": 0.99, "level": "minimal",
            "reason": "Telegram bot token"
        },
        "stripe_key": {
            "pattern": r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}",
            "confidence": 0.99, "level": "minimal",
            "reason": "Stripe API key"
        },
        "jwt_token": {
            "pattern": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
            "confidence": 0.97, "level": "minimal",
            "reason": "JWT token"
        },
        "generic_api_key": {
            "pattern": r"(?i)(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\s*[:=]\s*['\"]([a-zA-Z0-9\-_.]{20,})['\"]",
            "confidence": 0.93, "level": "minimal",
            "reason": "API / secret key assignment"
        },
        "bearer_token": {
            "pattern": r"(?i)bearer\s+([a-zA-Z0-9\-_.]{30,})",
            "confidence": 0.95, "level": "minimal",
            "reason": "Bearer token"
        },
        "sendgrid_key": {
            "pattern": r"SG\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}",
            "confidence": 0.99, "level": "minimal",
            "reason": "SendGrid API key"
        },
        "stripe_webhook_secret": {
            "pattern": r"whsec_[a-zA-Z0-9]{20,}",
            "confidence": 0.99, "level": "minimal",
            "reason": "Stripe webhook signing secret"
        },
        "vault_token": {
            "pattern": r"hvs\.[a-zA-Z0-9_\-]{20,}",
            "confidence": 0.99, "level": "minimal",
            "reason": "HashiCorp Vault token"
        },
        "grafana_service_token": {
            "pattern": r"glsa_[a-zA-Z0-9_\-]{20,}",
            "confidence": 0.99, "level": "minimal",
            "reason": "Grafana service account token"
        },
        "sentry_dsn": {
            "pattern": r"https://[a-f0-9]{16,}@[a-z0-9.]+\.ingest\.sentry\.io/\d+",
            "confidence": 0.99, "level": "minimal",
            "reason": "Sentry DSN"
        },
        "twilio_auth_token": {
            "pattern": r"(?i)(?:twilio|auth_token)\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
            "confidence": 0.95, "level": "minimal",
            "reason": "Twilio auth token (32-char hex)"
        },
        "datadog_api_key": {
            "pattern": r"(?i)(?:dd[_-]?api[_-]?key|datadog[_-]?api[_-]?key)\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
            "confidence": 0.97, "level": "minimal",
            "reason": "Datadog API key"
        },
        "newrelic_license_key": {
            "pattern": r"(?i)(?:new_?relic|nr)[_-]?(?:license|api)[_-]?key\s*[=:]\s*['\"]?([a-zA-Z0-9]{32,})['\"]?",
            "confidence": 0.95, "level": "minimal",
            "reason": "New Relic license/API key"
        },
        "pagerduty_key": {
            "pattern": r"(?i)(?:pagerduty|pd)[_-]?(?:api|service|integration|routing)[_-]?key\s*[=:]\s*['\"]?([a-zA-Z0-9+/=\-_]{20,})['\"]?",
            "confidence": 0.95, "level": "minimal",
            "reason": "PagerDuty service/API key"
        },
        "azure_shared_access_key": {
            "pattern": r"(?i)SharedAccessKey\s*=\s*([A-Za-z0-9+/=]{20,})",
            "confidence": 0.97, "level": "minimal",
            "reason": "Azure shared access key"
        },
        "consul_gossip_key": {
            "pattern": r'(?i)encrypt\s*=\s*["\']?([A-Za-z0-9+/=]{20,})["\']?',
            "confidence": 0.95, "level": "minimal",
            "reason": "Consul gossip encryption key"
        },
        "mongodb_connection_string": {
            "pattern": r"mongodb(?:\+srv)?://[^:/@\s]+:[^@\s'\"]{6,}@[^\s'\"]+",
            "confidence": 0.97, "level": "minimal",
            "reason": "MongoDB connection string with credentials"
        },
        "jdbc_connection_string": {
            "pattern": r"jdbc:[a-z]+://[^\s'\"]{10,}",
            "confidence": 0.90, "level": "minimal",
            "reason": "JDBC connection string"
        },
        "azure_sas_token": {
            "pattern": r"\?sv=\d{4}-\d{2}-\d{2}&[^\s'\"]{20,}sig=[^\s'\"]+",
            "confidence": 0.95, "level": "minimal",
            "reason": "Azure SAS token"
        },
        "azure_sql_connection": {
            "pattern": r"(?i)Server=tcp:[^;]+;.*Password=[^;'\"]+",
            "confidence": 0.95, "level": "minimal",
            "reason": "Azure SQL connection string with password"
        },
        "url_embedded_password": {
            "pattern": r"://[^:/@\s]+:([^@\s'\"]{6,})@",
            "confidence": 0.95, "level": "minimal",
            "reason": "Password embedded in connection URL"
        },
        "cli_mysql_password": {
            "pattern": r"-p['\"]([^'\"]{6,})['\"]",
            "confidence": 0.93, "level": "minimal",
            "reason": "MySQL CLI -p password flag"
        },
        "cli_redis_password": {
            "pattern": r"(?i)-a\s+['\"]([^'\"]{6,})['\"]",
            "confidence": 0.93, "level": "minimal",
            "reason": "Redis CLI -a password flag"
        },
        "sql_identified_by": {
            "pattern": r"(?i)IDENTIFIED\s+BY\s+['\"]([^'\"]{6,})['\"]",
            "confidence": 0.95, "level": "minimal",
            "reason": "SQL IDENTIFIED BY password"
        },
        "json_camelcase_secret": {
            "pattern": r"""(?i)["'](?:signing[Kk]ey|passphrase|refresh[Tt]oken[Ss]ecret|master[Kk]ey|encryption[Kk]ey|auth[Ss]ecret|app[Ss]ecret|webhook[Ss]ecret|session[Ss]ecret|hmac[Ss]ecret)["']\s*:\s*["']([^"']{6,})["']""",
            "confidence": 0.95, "level": "minimal",
            "reason": "Secret in JSON camelCase key"
        },
        "json_camelcase_token": {
            "pattern": r"""(?i)["'](?:service[Tt]oken|api[Tt]oken|auth[Tt]oken|access[Tt]oken|bearer[Tt]oken|refresh[Tt]oken)["']\s*:\s*["']([^"']{8,})["']""",
            "confidence": 0.93, "level": "minimal",
            "reason": "Token in JSON camelCase key"
        },
        "json_camelcase_apikey": {
            "pattern": r"""(?i)["'](?:api[Kk]ey|apiKey|secret[Kk]ey|datadogApi[Kk]ey|sentryDsn|stripe[Kk]ey|sendgrid[Kk]ey)["']\s*:\s*["']([^"']{8,})["']""",
            "confidence": 0.93, "level": "minimal",
            "reason": "API key in JSON camelCase key"
        },
        "curl_auth_header": {
            "pattern": r"""(?i)-H\s+["'](?:Authorization|X-API-Key|DD-API-KEY|DD-APPLICATION-KEY)\s*:\s*(?:Bearer\s+)?([^\s"']{8,})["']""",
            "confidence": 0.93, "level": "minimal",
            "reason": "Secret in curl -H header"
        },
        "datadog_prefixed_key": {
            "pattern": r"\bdd[_-](?:api|app)[_-][a-f0-9]{20,}\b",
            "confidence": 0.95, "level": "minimal",
            "reason": "Datadog API/app key with dd_ prefix"
        },
        "newrelic_key_pattern": {
            "pattern": r"\b[a-z0-9]{32,40}NRAL\b",
            "confidence": 0.95, "level": "minimal",
            "reason": "New Relic license key (NRAL suffix)"
        },
        "commented_env_secret": {
            "pattern": r"#\s*\w*(?:PASSWORD|SECRET|TOKEN|KEY)\w*\s*=\s*['\"]([^'\"]{6,})['\"]",
            "confidence": 0.88, "level": "minimal",
            "reason": "Commented-out secret in code"
        },
        "password_assignment": {
            "pattern": r"(?i)\w*(?:password|passwd|pwd)\w*\s*[:=]\s*['\"]([^'\"]{6,})['\"]",
            "confidence": 0.95, "level": "minimal",
            "reason": "Password assignment"
        },
        "password_unquoted": {
            "pattern": r"(?i)\w*(?:password|passwd|pwd|secret_key|master_key|encryption_key)\w*\s*[:=]\s*([^\s'\"#]{6,})$",
            "confidence": 0.88, "level": "minimal",
            "reason": "Password/secret assignment (unquoted)"
        },
        "login_password": {
            "pattern": r"(?i)\.login\s*\([^)]*,\s*['\"]([^'\"]{6,})['\"]",
            "confidence": 0.95, "level": "minimal",
            "reason": "Login function password argument"
        },
        "unquoted_env_secret": {
            "pattern": r"(?m)^(?:export\s+)?[A-Z_]*(?:SECRET|PASSWORD|TOKEN|KEY|APIKEY|API_KEY)[A-Z_]*\s*=\s*([^\s#'\"]{8,})",
            "confidence": 0.95, "level": "minimal",
            "reason": "Secret env var (unquoted)"
        },
        "tf_hcl_secret": {
            "pattern": r"(?i)(?:secret_key|access_key|private_key|db_password|master_password|admin_password)\s*=\s*['\"]([^'\"]{6,})['\"]",
            "confidence": 0.97, "level": "minimal",
            "reason": "Terraform secret field"
        },
        "db_connection_url": {
            "pattern": r"(?:postgres|postgresql|mysql|mongodb|redis|mssql)://[^\s'\"<>]{8,}",
            "confidence": 0.97, "level": "minimal",
            "reason": "Database connection URL with credentials"
        },
        "us_ssn": {
            "pattern": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
            "confidence": 0.97, "level": "minimal",
            "reason": "US Social Security Number"
        },
        "credit_card": {
            "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
            "confidence": 0.96, "level": "minimal",
            "reason": "Credit card number"
        },
        "email": {
            "pattern": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            "confidence": 0.92, "level": "minimal",
            "reason": "Email address"
        },

        # ── STANDARD: infrastructure topology + contributor identity ──────────
        "network_port": {
            "pattern": r"(?i)(?:port|listen|expose|bind)\s*[:=]\s*['\"]?(\d{2,5})['\"]?",
            "confidence": 0.82, "level": "standard",
            "reason": "Network port number in config"
        },
        "port_in_url": {
            "pattern": r"(?i)(?:://[a-zA-Z0-9.\-]+):(\d{2,5})(?:[/\s'\"]|$)",
            "confidence": 0.80, "level": "standard",
            "reason": "Port number in URL/connection string"
        },
        "ip_address_private": {
            "pattern": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
            "confidence": 0.85, "level": "standard",
            "reason": "Private / internal IP address"
        },
        "internal_hostname": {
            "pattern": r"(?i)(?:host|hostname|endpoint|server|fqdn)\s*=\s*['\"]([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9\-]+)+)['\"]",
            "confidence": 0.87, "level": "standard",
            "reason": "Internal hostname / endpoint"
        },
        "phone_us": {
            "pattern": r"\b(\+1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b(?!:)",
            "confidence": 0.82, "level": "standard",
            "reason": "US phone number"
        },
        "git_modifier_user": {
            "pattern": r"(?i)git_(?:last_modified_by|modifiers)\s*=\s*['\"]([^'\"]{2,})['\"]",
            "confidence": 0.93, "level": "standard",
            "reason": "Git contributor username"
        },
        "git_config_username": {
            "pattern": r"git\s+config\s+(?:--\S+\s+)*user\.name\s+['\"]([^'\"]+)['\"]",
            "confidence": 0.95, "level": "standard",
            "reason": "Git config committer name"
        },
        "git_config_email": {
            "pattern": r"git\s+config\s+(?:--\S+\s+)*user\.email\s+['\"]([^'\"]+)['\"]",
            "confidence": 0.95, "level": "standard",
            "reason": "Git config committer email"
        },
        "tf_hcl_username": {
            "pattern": r"(?i)(?:username|db_username|master_username|admin_user)\s*=\s*['\"]([^'\"]{3,})['\"]",
            "confidence": 0.88, "level": "standard",
            "reason": "Terraform username field"
        },

        "service_account": {
            "pattern": r"\b(svc_[a-zA-Z0-9_]{3,})\b",
            "confidence": 0.90, "level": "standard",
            "reason": "Service account name (svc_ prefix)"
        },
        "unc_path": {
            "pattern": r"\\\\[a-zA-Z0-9\-_.]+(?:\\[a-zA-Z0-9\-_. ]+)+",
            "confidence": 0.88, "level": "standard",
            "reason": "UNC network path"
        },
        "internal_fqdn": {
            "pattern": r"\b[A-Z][A-Z0-9\-]{2,}(?:\.[a-zA-Z0-9\-]+)*\.(?:local|internal|corp|intranet|lan|private)\b",
            "confidence": 0.88, "level": "standard",
            "reason": "Internal FQDN (.local/.internal/.corp)"
        },
        "server_hostname": {
            "pattern": r"\b(PRD[A-Z0-9\-]{3,}|STG[A-Z0-9\-]{3,}|DEV[A-Z0-9\-]{3,})\b",
            "confidence": 0.85, "level": "standard",
            "reason": "Server hostname (PRD/STG/DEV prefix)"
        },
        "connstr_password_inline": {
            "pattern": r"(?i)Password\s*=\s*([^;\s'\"<>]{6,})\s*;",
            "confidence": 0.97, "level": "minimal",
            "reason": "Password in semicolon-delimited connection string"
        },
        "connstr_userid_inline": {
            "pattern": r"(?i)User\s+ID\s*=\s*([^;\s'\"<>]{3,})\s*;",
            "confidence": 0.90, "level": "standard",
            "reason": "User ID in semicolon-delimited connection string"
        },

        # ── STRICT: org identity + internal tracing + infra details ──────────
        "uuid": {
            "pattern": r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            "confidence": 0.88, "level": "strict",
            "reason": "UUID / internal trace ID"
        },
        "git_commit_hash": {
            "pattern": r"(?i)git_commit\s*=\s*['\"]([0-9a-f]{40})['\"]",
            "confidence": 0.95, "level": "strict",
            "reason": "Git commit hash"
        },
        "git_org_name": {
            "pattern": r"(?i)git_org\s*=\s*['\"]([^'\"]{2,})['\"]",
            "confidence": 0.90, "level": "strict",
            "reason": "Git organization name"
        },
        "git_repo_name": {
            "pattern": r"(?i)git_repo\s*=\s*['\"]([^'\"]{2,})['\"]",
            "confidence": 0.90, "level": "strict",
            "reason": "Git repository name"
        },
        "git_file_path": {
            "pattern": r"(?i)git_file\s*=\s*['\"]([^'\"]{2,})['\"]",
            "confidence": 0.90, "level": "strict",
            "reason": "Git file path in tag"
        },
        "git_modified_at": {
            "pattern": r"(?i)git_last_modified_at\s*=\s*['\"]([^'\"]+)['\"]",
            "confidence": 0.88, "level": "strict",
            "reason": "Git last-modified timestamp"
        },
        "system_path_unix": {
            "pattern": r"(?<![a-zA-Z0-9_])((?:/(?:var|etc|home|usr|opt|dev|srv|tmp|root|proc|sys|run|mnt|media)[/\w.\-]*)+)",
            "confidence": 0.88, "level": "strict",
            "reason": "Unix system / server path"
        },
        "system_path_windows": {
            "pattern": r"[A-Za-z]:\\(?:Users|Windows|Program Files|ProgramData|System32)[\\.\w\-\s]*",
            "confidence": 0.90, "level": "strict",
            "reason": "Windows system path"
        },
        "aws_region": {
            "pattern": r"\b(us-east-[12]|us-west-[12]|eu-west-[123]|eu-central-1|eu-north-1|ap-southeast-[123]|ap-northeast-[123]|ap-south-1|sa-east-1|ca-central-1|af-south-1|me-south-1)\b",
            "confidence": 0.92, "level": "strict",
            "reason": "AWS region (reveals deployment geography)"
        },
        "aws_arn": {
            "pattern": r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s'\"]+",
            "confidence": 0.98, "level": "standard",
            "reason": "AWS ARN (contains account ID)"
        },
        "aws_account_id": {
            "pattern": r"(?i)(?:account[_-]?id|account[_-]?number)\s*[=:]\s*['\"]?(\d{12})['\"]?",
            "confidence": 0.97, "level": "standard",
            "reason": "AWS account ID"
        },
        "cidr_block": {
            "pattern": r"\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b",
            "confidence": 0.85, "level": "strict",
            "reason": "Internal network CIDR block"
        },
        # URLs — assigned to config keys (guaranteed internal/private)
        "url_in_assignment": {
            "pattern": r"(?i)(?:url|endpoint|base_url|api_url|service_url|webhook|callback_url|redirect_url|origin|host_url|server_url)\s*[=:]\s*['\"]?(https?://[^\s'\"<>{}\[\]]{8,})['\"]?",
            "confidence": 0.88, "level": "strict",
            "reason": "URL assigned to a config/env key"
        },
        # Bare URLs that are clearly non-public (private-range IPs or internal hostnames)
        "url_internal_ip": {
            "pattern": r"\bhttps?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|localhost)[:/][^\s'\"<>{}]{0,200}",
            "confidence": 0.95, "level": "strict",
            "reason": "URL pointing to a private IP address"
        },
        "git_remote_url": {
            "pattern": r"(?:git@|https?://)(?:github\.com|gitlab\.com|bitbucket\.org|dev\.azure\.com|ssh\.dev\.azure\.com)[:/]([a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+?)(?:\.git)?(?=[\s\"'#]|$)|(?:git@[\w.\-]+\.[\w]{2,}:[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+?)(?:\.git)?(?=[\s\"']|$)|https?://[\w.\-]+\.[\w]{2,}/([a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+?)\.git(?=[\s\"'#]|$)",
            "confidence": 0.93, "level": "strict",
            "reason": "Git remote URL (exposes org/repo name)"
        },
        "s3_bucket_name": {
            "pattern": r"(?i)(?:s3://|(?:bucket|s3_bucket)\s*[=:]\s*['\"])([a-z0-9][a-z0-9\-\.]{2,61}[a-z0-9])",
            "confidence": 0.90, "level": "standard",
            "reason": "S3 bucket name (globally unique, enumerable)"
        },
        "container_image_internal": {
            "pattern": r"(?i)(?:^|\s)(?:image|from)[\s:=]+['\"]?([a-zA-Z0-9_.\-]+\.[a-zA-Z]{2,}/[a-zA-Z0-9_.\-/]+(?::[a-zA-Z0-9_.\-]+)?)['\"]?",
            "confidence": 0.85, "level": "strict",
            "reason": "Internal container registry image URI"
        },
        "k8s_namespace": {
            "pattern": r"(?i)(?:^|\s)namespace:\s*([a-z][a-z0-9\-]{1,62})\b",
            "confidence": 0.85, "level": "strict",
            "reason": "Kubernetes namespace name"
        },
        "tf_resource_label": {
            "pattern": r'resource\s+["\'][a-z][a-z0-9_]+["\']\s+["\']([a-zA-Z0-9_\-]{3,})["\']',
            "confidence": 0.82, "level": "strict",
            "reason": "Terraform resource name label"
        },
    }

    FILE_TYPE_EXTRA = {
        "dbt": {
            # dbt Jinja references — expose internal model/source/table names
            "dbt_ref": {
                "pattern": r"\{\{\s*ref\s*\(\s*['\"]([^'\"]+)['\"]\s*\)\s*\}\}",
                "confidence": 0.97, "level": "strict",
                "reason": "dbt {{ ref() }} — internal model name"
            },
            "dbt_source_name": {
                "pattern": r"\{\{\s*source\s*\(\s*['\"]([^'\"]+)['\"]",
                "confidence": 0.97, "level": "strict",
                "reason": "dbt {{ source() }} — source name"
            },
            "dbt_source_table": {
                "pattern": r"\{\{\s*source\s*\([^,]+,\s*['\"]([^'\"]+)['\"]\s*\)\s*\}\}",
                "confidence": 0.97, "level": "strict",
                "reason": "dbt {{ source() }} — table name"
            },
            "dbt_var": {
                "pattern": r"\{\{\s*var\s*\(\s*['\"]([^'\"]+)['\"]\s*\)\s*\}\}",
                "confidence": 0.88, "level": "strict",
                "reason": "dbt {{ var() }} — variable name"
            },
            "sql_schema_table": {
                "pattern": r"(?i)(?:from|join)\s+([a-zA-Z][a-zA-Z0-9_]{1,63}\.[a-zA-Z][a-zA-Z0-9_]{1,63})\b",
                "confidence": 0.82, "level": "strict",
                "reason": "schema-qualified table name in SQL"
            },
        },
        "sql": {
            "server_in_connection": {
                "pattern": r"server\s*=\s*['\"]?([a-zA-Z0-9\-_.]+)['\"]?(?=;|$)",
                "confidence": 0.95, "level": "standard",
                "reason": "server= in connection string"
            },
            "uid_in_connection": {
                "pattern": r"uid\s*=\s*['\"]([a-zA-Z0-9_\-@.]{3,})['\"]",
                "confidence": 0.98, "level": "standard",
                "reason": "uid= SQL Server syntax"
            },
            "initial_catalog": {
                "pattern": r"Initial Catalog\s*=\s*['\"]?([a-zA-Z0-9_\-]+)['\"]?",
                "confidence": 0.99, "level": "standard",
                "reason": "Initial Catalog (database name)"
            },
            "declare_password": {
                "pattern": r"@\w*[Pp]ass\w*\s+\w[\w()]*\s*=\s*['\"]([^'\"]{6,})['\"]",
                "confidence": 0.97, "level": "minimal",
                "reason": "SQL DECLARE @Password"
            },
            "declare_api_key": {
                "pattern": r"@\w*[Aa]pi[Kk]ey\w*\s+\w[\w()]*\s*=\s*['\"]([a-zA-Z0-9\-_]{20,})['\"]",
                "confidence": 0.95, "level": "minimal",
                "reason": "SQL DECLARE @ApiKey"
            },
        },
        "yaml": {
            "yaml_password": {
                "pattern": r"(?i)^\s*\w*(?:password|passwd|pwd|secret_?key|client[_-]?secret|master[_-]?key|encryption[_-]?key|become[_-]?pass|smtp[_-]?password|auth[_-]?password|db[_-]?password|redis[_-]?password|rabbitmq[_-]?password|mongo[_-]?password):\s*['\"]?([^\s'\"#]{6,})['\"]?\s*(?:#.*)?$",
                "confidence": 0.95, "level": "minimal",
                "reason": "Password/secret field in YAML (quoted or unquoted)"
            },
            "yaml_api_key": {
                "pattern": r"(?i)^\s*\w*(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token|api[_-]?token|api[_-]?secret|service[_-]?key|license[_-]?key|integration[_-]?key|app[_-]?key):\s*['\"]?([^\s'\"#]{8,})['\"]?\s*(?:#.*)?$",
                "confidence": 0.93, "level": "minimal",
                "reason": "API key/token field in YAML"
            },
            "yaml_token": {
                "pattern": r"(?i)^\s*\w*(?:token|access_token|auth_token|bearer_token|session_token):\s*['\"]?([^\s'\"#]{10,})['\"]?\s*(?:#.*)?$",
                "confidence": 0.93, "level": "minimal",
                "reason": "Token field in YAML"
            },
            "yaml_connection_string": {
                "pattern": r"(?i)^\s*(?:connection[_-]?string|connstr|dsn|database[_-]?url|db[_-]?url|jdbc[_-]?url|broker[_-]?url):\s*['\"]?([^\s'\"#]{10,})['\"]?\s*(?:#.*)?$",
                "confidence": 0.97, "level": "minimal",
                "reason": "Connection string in YAML"
            },
            "database_url": {
                "pattern": r"^\s*database[_-]?url:\s*['\"]([^'\"]+)['\"]",
                "confidence": 0.99, "level": "minimal",
                "reason": "database_url: in YAML"
            },
            "host": {
                "pattern": r"^\s*host:\s*([a-zA-Z0-9\-_.]+)$",
                "confidence": 0.85, "level": "standard",
                "reason": "host: in YAML"
            },
            "yaml_database_name": {
                "pattern": r"^\s*(?:dbname|database|db):\s*['\"]?([a-zA-Z0-9_\-]{2,})['\"]?$",
                "confidence": 0.88, "level": "strict",
                "reason": "database name in YAML config"
            },
            "yaml_schema_name": {
                "pattern": r"^\s*schema:\s*['\"]?([a-zA-Z0-9_\-]{2,})['\"]?$",
                "confidence": 0.85, "level": "strict",
                "reason": "schema name in YAML config"
            },
            "yaml_repository": {
                "pattern": r"^\s*repository:\s*['\"]?([a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+)['\"]?",
                "confidence": 0.90, "level": "strict",
                "reason": "repository: org/repo reference in YAML"
            },
            "yaml_image": {
                "pattern": r"^\s*image:\s*['\"]?([a-zA-Z0-9_.\-]+(?:/[a-zA-Z0-9_.\-]+)+(?::[a-zA-Z0-9_.\-]+)?)['\"]?",
                "confidence": 0.85, "level": "strict",
                "reason": "image: in Docker Compose / K8s YAML"
            },
        },
        "env": {
            "any_env_password": {
                "pattern": r"^[A-Z_]*PASSWORD[A-Z_]*\s*=\s*(.+)$",
                "confidence": 0.97, "level": "minimal",
                "reason": "PASSWORD= env var"
            },
            "any_env_secret": {
                "pattern": r"^[A-Z_]*SECRET[A-Z_]*\s*=\s*(.{6,})$",
                "confidence": 0.95, "level": "minimal",
                "reason": "SECRET= env var"
            },
            "any_env_token": {
                "pattern": r"^[A-Z_]*TOKEN[A-Z_]*\s*=\s*([a-zA-Z0-9\-_.]{20,})$",
                "confidence": 0.95, "level": "minimal",
                "reason": "TOKEN= env var"
            },
        },
        "py": {
            # ── existing ──────────────────────────────────────────────────────
            "db_connection_string": {
                "pattern": r"(?:mssql|mysql|postgresql|sqlite)[+\w]*://[^\s'\"]+:[^\s'\"@]+@([^\s'\"/:]+)",
                "confidence": 0.97, "level": "minimal",
                "reason": "SQLAlchemy connection string"
            },
            "py_hardcoded_secret": {
                "pattern": r"(?i)(?:secret|password|passwd|token|api_key|apikey)\s*=\s*['\"]([^'\"]{8,})['\"]",
                "confidence": 0.93, "level": "minimal",
                "reason": "Hardcoded secret/password variable in Python"
            },
            "py_os_environ_secret": {
                "pattern": r"os\.environ(?:\.get)?\(['\"]([A-Z_]*(?:SECRET|PASSWORD|TOKEN|KEY|API_KEY)[A-Z_]*)['\"]",
                "confidence": 0.88, "level": "standard",
                "reason": "os.environ access to secret env var name"
            },
            "py_requests_auth": {
                "pattern": r"(?i)auth\s*=\s*\(\s*['\"]([^'\"]{3,})['\"],\s*['\"]([^'\"]{6,})['\"]",
                "confidence": 0.92, "level": "minimal",
                "reason": "requests auth tuple with credentials"
            },

            # ── Django ────────────────────────────────────────────────────────
            "django_secret_key": {
                "pattern": r"SECRET_KEY\s*=\s*['\"]([^'\"]{8,})['\"]",
                "confidence": 0.99, "level": "minimal",
                "reason": "Django SECRET_KEY setting"
            },
            "django_db_password": {
                "pattern": r"(?i)['\"]PASSWORD['\"]\s*:\s*['\"]([^'\"]{4,})['\"]",
                "confidence": 0.93, "level": "minimal",
                "reason": "Django DATABASES PASSWORD entry"
            },
            "django_db_host": {
                "pattern": r"(?i)['\"]HOST['\"]\s*:\s*['\"]([a-zA-Z0-9\-_.]{4,})['\"]",
                "confidence": 0.85, "level": "standard",
                "reason": "Django DATABASES HOST entry"
            },
            "django_db_name": {
                "pattern": r"(?i)['\"]NAME['\"]\s*:\s*['\"]([a-zA-Z0-9_\-]{2,})['\"]",
                "confidence": 0.82, "level": "strict",
                "reason": "Django DATABASES NAME entry"
            },
            "django_allowed_hosts": {
                "pattern": r"ALLOWED_HOSTS\s*=\s*\[([^\]]{4,})\]",
                "confidence": 0.80, "level": "strict",
                "reason": "Django ALLOWED_HOSTS (exposes internal hostnames)"
            },
            "django_email_creds": {
                "pattern": r"(?i)EMAIL_HOST_(?:PASSWORD|USER)\s*=\s*['\"]([^'\"]{4,})['\"]",
                "confidence": 0.96, "level": "minimal",
                "reason": "Django email backend credentials"
            },

            # ── Flask ─────────────────────────────────────────────────────────
            "flask_secret_key": {
                "pattern": r"(?i)app\.(?:secret_key|config\[[\'\"]SECRET_KEY[\'\"]\])\s*=\s*['\"]([^'\"]{8,})['\"]",
                "confidence": 0.98, "level": "minimal",
                "reason": "Flask app.secret_key or config SECRET_KEY"
            },
            "flask_config_secret": {
                "pattern": r"(?i)app\.config\[['\"]([A-Z_]*(?:SECRET|PASSWORD|TOKEN|KEY|API_KEY)[A-Z_]*)['\"]]\s*=\s*['\"]([^'\"]{6,})['\"]",
                "confidence": 0.95, "level": "minimal",
                "reason": "Flask app.config secret value"
            },
            "flask_sqlalchemy_uri": {
                "pattern": r"(?i)SQLALCHEMY_DATABASE_URI\s*=\s*['\"]([^'\"]{10,})['\"]",
                "confidence": 0.97, "level": "minimal",
                "reason": "Flask-SQLAlchemy database URI"
            },

            # ── boto3 / AWS SDK ───────────────────────────────────────────────
            "boto3_hardcoded_key": {
                "pattern": r"aws_access_key_id\s*=\s*['\"]([A-Z0-9]{16,})['\"]",
                "confidence": 0.99, "level": "minimal",
                "reason": "boto3 hardcoded AWS access key ID"
            },
            "boto3_hardcoded_secret": {
                "pattern": r"aws_secret_access_key\s*=\s*['\"]([a-zA-Z0-9/+=]{20,})['\"]",
                "confidence": 0.99, "level": "minimal",
                "reason": "boto3 hardcoded AWS secret access key"
            },
            "boto3_hardcoded_token": {
                "pattern": r"aws_session_token\s*=\s*['\"]([a-zA-Z0-9/+=]{20,})['\"]",
                "confidence": 0.99, "level": "minimal",
                "reason": "boto3 hardcoded AWS session token"
            },
            "boto3_region": {
                "pattern": r"region_name\s*=\s*['\"]([a-z]{2}-[a-z]+-\d)['\"]",
                "confidence": 0.88, "level": "strict",
                "reason": "boto3 hardcoded AWS region"
            },

            # ── SSH / Paramiko ────────────────────────────────────────────────
            "paramiko_password": {
                "pattern": r"\.connect\s*\([^)]*password\s*=\s*['\"]([^'\"]{4,})['\"]",
                "confidence": 0.97, "level": "minimal",
                "reason": "Paramiko SSH connect() with hardcoded password"
            },
            "paramiko_hostname": {
                "pattern": r"\.connect\s*\(\s*['\"]([a-zA-Z0-9\-_.]{4,})['\"]",
                "confidence": 0.85, "level": "standard",
                "reason": "Paramiko SSH connect() hostname"
            },
            "paramiko_pkey_path": {
                "pattern": r"(?i)(?:RSAKey|DSSKey|ECDSAKey|Ed25519Key)\.from_private_key_file\s*\(\s*['\"]([^'\"]{4,})['\"]",
                "confidence": 0.90, "level": "standard",
                "reason": "Paramiko private key file path"
            },

            # ── smtplib / email ───────────────────────────────────────────────
            "smtp_login": {
                "pattern": r"\.login\s*\(\s*['\"]([^'\"]{3,})['\"],\s*['\"]([^'\"]{4,})['\"]",
                "confidence": 0.96, "level": "minimal",
                "reason": "smtplib login() with hardcoded credentials"
            },
            "smtp_host": {
                "pattern": r"(?:smtplib\.SMTP|SMTP_SSL)\s*\(\s*['\"]([a-zA-Z0-9\-_.]{4,})['\"]",
                "confidence": 0.88, "level": "standard",
                "reason": "smtplib hardcoded SMTP server host"
            },

            # ── Celery / Redis / message brokers ─────────────────────────────
            "celery_broker_url": {
                "pattern": r"(?i)(?:CELERY_BROKER_URL|broker_url|BROKER_URL)\s*=\s*['\"]([^'\"]{8,})['\"]",
                "confidence": 0.97, "level": "minimal",
                "reason": "Celery broker URL (may contain credentials)"
            },
            "celery_result_backend": {
                "pattern": r"(?i)(?:CELERY_RESULT_BACKEND|result_backend)\s*=\s*['\"]([^'\"]{8,})['\"]",
                "confidence": 0.90, "level": "minimal",
                "reason": "Celery result backend URL"
            },
            "redis_url": {
                "pattern": r"redis://[^\s'\"<>]{6,}",
                "confidence": 0.93, "level": "minimal",
                "reason": "Redis connection URL (may contain password)"
            },
            "amqp_url": {
                "pattern": r"amqps?://[^\s'\"<>]{6,}",
                "confidence": 0.95, "level": "minimal",
                "reason": "AMQP/RabbitMQ URL (may contain credentials)"
            },

            # ── JWT ───────────────────────────────────────────────────────────
            "jwt_secret": {
                "pattern": r"(?i)jwt\.(?:encode|decode)\s*\([^,)]+,\s*['\"]([^'\"]{6,})['\"]",
                "confidence": 0.97, "level": "minimal",
                "reason": "Hardcoded JWT secret in jwt.encode/decode"
            },
            "jwt_secret_var": {
                "pattern": r"(?i)(?:JWT_SECRET|JWT_SECRET_KEY|jwt_secret|jwt_key)\s*=\s*['\"]([^'\"]{6,})['\"]",
                "confidence": 0.97, "level": "minimal",
                "reason": "JWT secret key variable assignment"
            },

            # ── OAuth2 / social auth ──────────────────────────────────────────
            "oauth2_client_secret": {
                "pattern": r"(?i)client_secret\s*=\s*['\"]([a-zA-Z0-9\-_.~]{8,})['\"]",
                "confidence": 0.97, "level": "minimal",
                "reason": "OAuth2 client_secret hardcoded"
            },
            "oauth2_client_id": {
                "pattern": r"(?i)client_id\s*=\s*['\"]([a-zA-Z0-9\-_.]{8,})['\"]",
                "confidence": 0.88, "level": "standard",
                "reason": "OAuth2 client_id hardcoded"
            },
            "oauth2_refresh_token": {
                "pattern": r"(?i)refresh_token\s*=\s*['\"]([a-zA-Z0-9\-_.]{20,})['\"]",
                "confidence": 0.95, "level": "minimal",
                "reason": "OAuth2 refresh token hardcoded"
            },

            # ── subprocess with secrets ───────────────────────────────────────
            "subprocess_password_flag": {
                "pattern": r"(?i)subprocess\.(?:run|call|Popen)\s*\(\s*\[.*?['\"]--?(?:password|passwd|secret|token)['\"],\s*['\"]([^'\"]{4,})['\"]",
                "confidence": 0.94, "level": "minimal",
                "reason": "Password/secret passed as CLI flag to subprocess"
            },
            "subprocess_env_secret": {
                "pattern": r"(?i)subprocess\.(?:run|call|Popen)\s*\(.*env\s*=\s*\{[^}]*['\"](?:PASSWORD|SECRET|TOKEN|API_KEY)['\"]:\s*['\"]([^'\"]{4,})['\"]",
                "confidence": 0.93, "level": "minimal",
                "reason": "Secret injected into subprocess env dict"
            },

            # ── hashlib / crypto ──────────────────────────────────────────────
            "hardcoded_salt": {
                "pattern": r"(?i)(?:pbkdf2_hmac|scrypt|bcrypt\.hashpw)\s*\([^,]+,\s*b['\"]([^'\"]{4,})['\"]",
                "confidence": 0.90, "level": "minimal",
                "reason": "Hardcoded cryptographic salt"
            },
            "hardcoded_iv_key": {
                "pattern": r"(?i)(?:AES|DES|Fernet|Cipher)\s*\.\s*new\s*\([^,)]*,\s*(?:key\s*=\s*)?b['\"]([a-fA-F0-9]{16,})['\"]",
                "confidence": 0.93, "level": "minimal",
                "reason": "Hardcoded encryption key/IV"
            },

            # ── Azure SDK ────────────────────────────────────────────────────
            "azure_connection_string": {
                "pattern": r"(?i)(?:DefaultEndpointsProtocol|AccountName|AccountKey)=[^;\"'\s]{4,}",
                "confidence": 0.97, "level": "minimal",
                "reason": "Azure storage connection string component"
            },
            "azure_client_secret": {
                "pattern": r"(?i)ClientSecretCredential\s*\([^)]*['\"]([a-zA-Z0-9\-_.~]{8,})['\"]",
                "confidence": 0.97, "level": "minimal",
                "reason": "Azure SDK ClientSecretCredential hardcoded"
            },
            "azure_subscription_id": {
                "pattern": r"(?i)subscription_id\s*=\s*['\"]([0-9a-f\-]{36})['\"]",
                "confidence": 0.92, "level": "strict",
                "reason": "Azure subscription ID"
            },

            # ── GCP SDK ──────────────────────────────────────────────────────
            "gcp_credentials_file": {
                "pattern": r"(?i)(?:service_account\.Credentials|google\.oauth2)\.from_service_account_file\s*\(\s*['\"]([^'\"]{4,})['\"]",
                "confidence": 0.93, "level": "standard",
                "reason": "GCP service account credentials file path"
            },
            "gcp_project_id": {
                "pattern": r"(?i)project(?:_id)?\s*=\s*['\"]([a-z][a-z0-9\-]{4,28}[a-z0-9])['\"]",
                "confidence": 0.80, "level": "strict",
                "reason": "GCP project ID"
            },

            # ── configparser ─────────────────────────────────────────────────
            "configparser_set_secret": {
                "pattern": r"(?i)config\.set\s*\([^,]+,\s*['\"][^'\"]*(?:password|secret|token|key)[^'\"]*['\"],\s*['\"]([^'\"]{4,})['\"]",
                "confidence": 0.93, "level": "minimal",
                "reason": "configparser.set() with secret value"
            },

            # ── pytest fixtures ───────────────────────────────────────────────
            "pytest_hardcoded_cred": {
                "pattern": r"(?i)@pytest\.fixture[^#\n]*\n(?:[^\n]*\n){0,5}[^\n]*(?:password|secret|token|api_key)\s*=\s*['\"]([^'\"]{6,})['\"]",
                "confidence": 0.88, "level": "minimal",
                "reason": "Hardcoded credential in pytest fixture"
            },

            # ── internal service hostnames ────────────────────────────────────
            "py_hardcoded_host": {
                "pattern": r"(?i)(?:host|hostname|server|endpoint)\s*=\s*['\"]([a-zA-Z0-9][a-zA-Z0-9\-_.]{3,}(?:\.[a-zA-Z]{2,})+)['\"]",
                "confidence": 0.83, "level": "standard",
                "reason": "Hardcoded hostname/server in Python"
            },
            "py_hardcoded_port_host": {
                "pattern": r"(?i)(?:host|server)\s*=\s*['\"](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})['\"]",
                "confidence": 0.90, "level": "standard",
                "reason": "Hardcoded IP address as host in Python"
            },
        },

        # ── JSON ─────────────────────────────────────────────────────────────
        "json": {
            "json_password": {
                "pattern": r'(?i)["\'](?:password|passwd)["\'\s]*:\s*["\']([^"\']{6,})["\']',
                "confidence": 0.95, "level": "minimal",
                "reason": "Password field in JSON"
            },
            "json_api_key": {
                "pattern": r'(?i)["\'](?:api_key|apikey|access_token)["\'\s]*:\s*["\']([^"\']{6,})["\']',
                "confidence": 0.95, "level": "minimal",
                "reason": "API key/token field in JSON"
            },
            "json_secret": {
                "pattern": r'(?i)["\'](?:secret|secret_key|private_key|secret_access_key)["\'\s]*:\s*["\']([^"\']{6,})["\']',
                "confidence": 0.95, "level": "minimal",
                "reason": "Secret/private key field in JSON"
            },
            "json_connection_string": {
                "pattern": r'(?i)["\'](?:connectionString|connection_string|connStr|DatabaseUrl)["\'\s]*:\s*["\']([^"\']{10,})["\']',
                "confidence": 0.97, "level": "minimal",
                "reason": "Connection string field in JSON"
            },
            "json_db_host": {
                "pattern": r'(?i)["\'](?:host|hostname|server|endpoint)["\'\s]*:\s*["\']([a-zA-Z0-9\-_.]{4,})["\']',
                "confidence": 0.85, "level": "standard",
                "reason": "Database host/server field in JSON"
            },
            "json_database_name": {
                "pattern": r'(?i)["\'](?:database|dbname|db_name|catalog)["\'\s]*:\s*["\']([a-zA-Z0-9_\-]{2,})["\']',
                "confidence": 0.85, "level": "strict",
                "reason": "Database name field in JSON"
            },
            "json_client_id": {
                "pattern": r'(?i)["\'](?:client_id|clientId|app_id|appId)["\'\s]*:\s*["\']([a-zA-Z0-9\-_.]{8,})["\']',
                "confidence": 0.88, "level": "standard",
                "reason": "OAuth client ID in JSON"
            },
            "json_client_secret": {
                "pattern": r'(?i)["\'](?:client_secret|clientSecret)["\'\s]*:\s*["\']([a-zA-Z0-9\-_.~]{8,})["\']',
                "confidence": 0.97, "level": "minimal",
                "reason": "OAuth client secret in JSON"
            },
        },

        # ── Terraform (.tf / .tfvars) ─────────────────────────────────────────
        "tf": {
            "tf_db_password": {
                "pattern": r'(?i)(?:db_password|database_password|master_password|admin_password|root_password)\s*=\s*["\']([^"\']{6,})["\']',
                "confidence": 0.98, "level": "minimal",
                "reason": "Terraform database password variable"
            },
            "tf_access_key": {
                "pattern": r'(?i)(?:access_key|access_key_id|aws_access_key)\s*=\s*["\']([A-Z0-9]{16,})["\']',
                "confidence": 0.97, "level": "minimal",
                "reason": "Terraform AWS access key"
            },
            "tf_secret_key": {
                "pattern": r'(?i)(?:secret_key|aws_secret_key|secret_access_key)\s*=\s*["\']([a-zA-Z0-9/+=]{20,})["\']',
                "confidence": 0.97, "level": "minimal",
                "reason": "Terraform AWS secret key"
            },
            "tf_token": {
                "pattern": r'(?i)(?:token|auth_token|api_token)\s*=\s*["\']([a-zA-Z0-9\-_.]{20,})["\']',
                "confidence": 0.93, "level": "minimal",
                "reason": "Terraform token field"
            },
            "tf_bucket": {
                "pattern": r'(?i)bucket\s*=\s*["\']([a-z0-9][a-z0-9\-.]{2,61}[a-z0-9])["\']',
                "confidence": 0.88, "level": "strict",
                "reason": "Terraform S3 bucket name"
            },
            "tf_region": {
                "pattern": r'(?i)region\s*=\s*["\']([a-z]{2}-[a-z]+-\d)["\']',
                "confidence": 0.90, "level": "strict",
                "reason": "Terraform cloud region"
            },
            "tf_account_id": {
                "pattern": r'(?i)account_id\s*=\s*["\'](\d{12})["\']',
                "confidence": 0.97, "level": "strict",
                "reason": "Terraform AWS account ID"
            },
            "tf_private_ip": {
                "pattern": r'(?i)(?:private_ip|internal_ip|ip_address)\s*=\s*["\'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})["\']',
                "confidence": 0.90, "level": "standard",
                "reason": "Terraform private IP assignment"
            },
            "tf_password_default": {
                "pattern": r'(?i)default\s*=\s*["\']([^"\']{6,})["\']',
                "confidence": 0.80, "level": "minimal",
                "reason": "Terraform variable default value (potential secret)"
            },
            "tf_connection_password": {
                "pattern": r'(?i)(?:password|secret|token|auth)\s*=\s*["\']([^"\']{6,})["\']',
                "confidence": 0.93, "level": "minimal",
                "reason": "HCL password/secret/token field"
            },
            "tf_acl_token": {
                "pattern": r'(?i)(?:acl[_-]?token|initial_management|master_token|agent_token)\s*=\s*["\']([^"\']{6,})["\']',
                "confidence": 0.95, "level": "minimal",
                "reason": "Consul/Nomad ACL token in HCL"
            },
        },

        # ── TOML (.toml) ──────────────────────────────────────────────────────
        "toml": {
            "toml_password": {
                "pattern": r'(?i)(?:password|passwd|secret|token)\s*=\s*["\']([^"\']{6,})["\']',
                "confidence": 0.95, "level": "minimal",
                "reason": "Password/secret in TOML config"
            },
            "toml_db_url": {
                "pattern": r'(?i)(?:url|database_url|db_url|connection)\s*=\s*["\']([^"\']{10,}://[^"\']+)["\']',
                "confidence": 0.97, "level": "minimal",
                "reason": "Database URL in TOML config"
            },
            "toml_api_key": {
                "pattern": r'(?i)(?:api_key|apikey|api_token)\s*=\s*["\']([a-zA-Z0-9\-_.]{16,})["\']',
                "confidence": 0.93, "level": "minimal",
                "reason": "API key in TOML config"
            },
            "toml_host": {
                "pattern": r'(?i)(?:host|hostname|server)\s*=\s*["\']([a-zA-Z0-9\-_.]{4,})["\']',
                "confidence": 0.85, "level": "standard",
                "reason": "Host/server in TOML config"
            },
            "toml_database_name": {
                "pattern": r'(?i)(?:database|dbname|db)\s*=\s*["\']([a-zA-Z0-9_\-]{2,})["\']',
                "confidence": 0.85, "level": "strict",
                "reason": "Database name in TOML config"
            },
        },

        # ── XML / .config (app.config, web.config, MSBuild) ──────────────────
        "xml": {
            "xml_password_attr": {
                "pattern": r'(?i)(?:password|pwd|passwd)\s*=\s*["\']([^"\']{4,})["\']',
                "confidence": 0.95, "level": "minimal",
                "reason": "password= attribute in XML"
            },
            "xml_user_attr": {
                "pattern": r'(?i)(?:user\s*id|uid|username)\s*=\s*["\']([a-zA-Z0-9_\-@.]{3,})["\']',
                "confidence": 0.90, "level": "standard",
                "reason": "user/uid= attribute in XML connection string"
            },
            "xml_server_attr": {
                "pattern": r'(?i)(?:server|data\s+source|datasource)\s*=\s*["\']?([a-zA-Z0-9\-_.\\]+)["\']?(?=;|["\'])',
                "confidence": 0.92, "level": "standard",
                "reason": "server/Data Source in XML connection string"
            },
            "xml_appkey": {
                "pattern": r'(?i)<add\s+key\s*=\s*["\'][^"\']*(?:key|secret|token|password)[^"\']*["\']\s+value\s*=\s*["\']([^"\']{6,})["\']',
                "confidence": 0.95, "level": "minimal",
                "reason": "appSettings key with secret value in XML"
            },
            "xml_encrypt_key": {
                "pattern": r'(?i)(?:encryptionKey|machineKey|validationKey|decryptionKey)\s*=\s*["\']([a-fA-F0-9]{16,})["\']',
                "confidence": 0.98, "level": "minimal",
                "reason": "Encryption/machine key in XML"
            },
            "xml_connstr_password": {
                "pattern": r'(?i)Password\s*=\s*([^;"\'<>\s]{4,})\s*;',
                "confidence": 0.97, "level": "minimal",
                "reason": "Password in semicolon-delimited connection string"
            },
            "xml_connstr_userid": {
                "pattern": r'(?i)User\s+ID\s*=\s*([^;"\'<>\s]{3,})\s*;',
                "confidence": 0.90, "level": "standard",
                "reason": "User ID in semicolon-delimited connection string"
            },
        },

        # ── JavaScript / TypeScript ───────────────────────────────────────────
        "js": {
            "js_hardcoded_secret": {
                "pattern": r"(?i)(?:const|let|var)\s+\w*(?:secret|password|passwd|token|api_?key)\w*\s*=\s*['\"`]([^'\"`]{8,})['\"`]",
                "confidence": 0.93, "level": "minimal",
                "reason": "Hardcoded secret/password variable in JS/TS"
            },
            "js_process_env_secret": {
                "pattern": r"process\.env(?:\[|\.)([A-Z_]*(?:SECRET|PASSWORD|TOKEN|KEY|API_KEY)[A-Z_]*)",
                "confidence": 0.88, "level": "standard",
                "reason": "process.env access to secret variable name"
            },
            "js_fetch_auth_header": {
                "pattern": r"(?i)['\"]Authorization['\"]\s*:\s*['\"`](?:Bearer|Basic)\s+([a-zA-Z0-9\-_.+/=]{20,})",
                "confidence": 0.95, "level": "minimal",
                "reason": "Hardcoded Authorization header value"
            },
            "js_db_uri": {
                "pattern": r"(?:mongodb|postgres|postgresql|mysql|redis)\+?://[^\s'\"`;]{10,}",
                "confidence": 0.97, "level": "minimal",
                "reason": "Database URI in JS/TS source"
            },
            "js_private_key_string": {
                "pattern": r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
                "confidence": 0.99, "level": "minimal",
                "reason": "Private key embedded in JS/TS string"
            },
            "js_internal_url": {
                "pattern": r"(?i)(?:baseUrl|apiUrl|serviceUrl|backendUrl|endpoint)\s*[:=]\s*['\"`](https?://[^\s'\"`;]{8,})['\"`]",
                "confidence": 0.87, "level": "strict",
                "reason": "Internal service URL assigned in JS/TS"
            },
        },

        # ── C# (.cs) ─────────────────────────────────────────────────────────
        "cs": {
            "cs_connection_string": {
                "pattern": r'(?i)(?:connectionString|ConnectionString)\s*=\s*["\']([^"\']{10,})["\']',
                "confidence": 0.97, "level": "minimal",
                "reason": "Connection string in C# code"
            },
            "cs_hardcoded_secret": {
                "pattern": r'(?i)(?:string|var|const)\s+\w*(?:password|secret|token|apiKey|api_key)\w*\s*=\s*["\']([^"\']{6,})["\']',
                "confidence": 0.94, "level": "minimal",
                "reason": "Hardcoded secret/password in C#"
            },
            "cs_config_manager": {
                "pattern": r'ConfigurationManager\.(?:AppSettings|ConnectionStrings)\[["\']([^"\']+)["\']\]',
                "confidence": 0.85, "level": "standard",
                "reason": "ConfigurationManager key lookup in C#"
            },
            "cs_smtp_credentials": {
                "pattern": r'(?i)new\s+NetworkCredential\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']',
                "confidence": 0.97, "level": "minimal",
                "reason": "SMTP/network credentials hardcoded in C#"
            },
            "cs_sql_server_name": {
                "pattern": r'(?i)(?:Data\s+Source|Server)\s*=\s*([a-zA-Z0-9\-_.\\]+)\s*;',
                "confidence": 0.90, "level": "standard",
                "reason": "SQL Server name in C# connection string"
            },
        },

        # ── Java (.java) ─────────────────────────────────────────────────────
        "java": {
            "java_hardcoded_secret": {
                "pattern": r'(?i)(?:String|private|public|final)\s+\w*(?:password|secret|token|apiKey|api_key)\w*\s*=\s*["\']([^"\']{6,})["\']',
                "confidence": 0.94, "level": "minimal",
                "reason": "Hardcoded secret/password in Java"
            },
            "java_jdbc_url": {
                "pattern": r'jdbc:[a-z]+://([^\s"\']{8,})',
                "confidence": 0.97, "level": "minimal",
                "reason": "JDBC connection URL in Java"
            },
            "java_properties_password": {
                "pattern": r'(?i)(?:password|passwd|secret)\s*=\s*([^\s#]{6,})',
                "confidence": 0.90, "level": "minimal",
                "reason": "Password in Java .properties file"
            },
            "java_spring_datasource": {
                "pattern": r'(?i)spring\.datasource\.(?:password|username|url)\s*=\s*(.+)',
                "confidence": 0.95, "level": "minimal",
                "reason": "Spring datasource credential in properties"
            },
            "java_aws_sdk_key": {
                "pattern": r'(?i)(?:withCredentials|BasicAWSCredentials)\s*\(\s*["\']([A-Z0-9]{16,})["\']',
                "confidence": 0.97, "level": "minimal",
                "reason": "AWS SDK credential in Java"
            },
        },

        # ── Go (.go) ─────────────────────────────────────────────────────────
        "go": {
            "go_hardcoded_secret": {
                "pattern": r'(?i)(?:password|secret|token|apiKey|api_key)\s*(?::=|=)\s*["`]([^"`]{6,})["`]',
                "confidence": 0.93, "level": "minimal",
                "reason": "Hardcoded secret/password in Go"
            },
            "go_db_open": {
                "pattern": r'sql\.Open\s*\(\s*["\'][^"\']+["\']\s*,\s*["\']([^"\']{10,})["\']',
                "confidence": 0.97, "level": "minimal",
                "reason": "sql.Open() connection string in Go"
            },
            "go_os_getenv_secret": {
                "pattern": r'os\.Getenv\s*\(\s*["\']([A-Z_]*(?:SECRET|PASSWORD|TOKEN|KEY|API_KEY)[A-Z_]*)["\']',
                "confidence": 0.87, "level": "standard",
                "reason": "os.Getenv access to secret variable name in Go"
            },
            "go_struct_secret": {
                "pattern": r'(?i)(?:Password|Secret|Token|ApiKey)\s*:\s*["`]([^"`]{6,})["`]',
                "confidence": 0.93, "level": "minimal",
                "reason": "Secret field in Go struct literal"
            },
            "go_internal_service": {
                "pattern": r'(?i)(?:baseURL|serviceURL|endpoint|host)\s*(?::=|=)\s*["`](https?://[^\s"`]{8,})["`]',
                "confidence": 0.87, "level": "strict",
                "reason": "Internal service URL in Go"
            },
        },

        # ── Dockerfile ───────────────────────────────────────────────────────
        "dockerfile": {
            "dockerfile_env_secret": {
                "pattern": r'(?i)^(?:ENV|ARG)\s+[A-Z_]*(?:SECRET|PASSWORD|TOKEN|KEY|API_KEY)[A-Z_]*[=\s]+([^\s#]{6,})',
                "confidence": 0.95, "level": "minimal",
                "reason": "Secret baked into Dockerfile ENV/ARG"
            },
            "dockerfile_run_password": {
                "pattern": r'(?i)RUN\s+.*(?:password|passwd|secret|token)\s*[=:]\s*([^\s\\&|;]{6,})',
                "confidence": 0.93, "level": "minimal",
                "reason": "Secret passed to RUN command in Dockerfile"
            },
            "dockerfile_from_registry": {
                "pattern": r'(?i)^FROM\s+([a-zA-Z0-9_.\-]+\.[a-zA-Z]{2,}/[a-zA-Z0-9_.\-/]+(?::[a-zA-Z0-9_.\-]+)?)',
                "confidence": 0.85, "level": "strict",
                "reason": "Internal registry image in FROM instruction"
            },
            "dockerfile_label_secret": {
                "pattern": r'(?i)LABEL\s+[^=]*(?:secret|token|password|key)\s*=\s*["\']?([^\s"\']{6,})["\']?',
                "confidence": 0.90, "level": "minimal",
                "reason": "Secret value in Dockerfile LABEL"
            },
            "dockerfile_internal_host": {
                "pattern": r'(?i)(?:ENV|ARG)\s+[A-Z_]*(?:HOST|SERVER|ENDPOINT|URL)[A-Z_]*[=\s]+([a-zA-Z0-9\-_.]{6,})',
                "confidence": 0.83, "level": "standard",
                "reason": "Internal host/server baked into Dockerfile"
            },
        },

        # ── Gradle (.gradle) ─────────────────────────────────────────────────
        "gradle": {
            "gradle_keystore_password": {
                "pattern": r'(?i)(?:storePassword|keyPassword|keystorePassword)\s*[=:]\s*["\']([^"\']{4,})["\']',
                "confidence": 0.97, "level": "minimal",
                "reason": "Keystore/signing password in Gradle"
            },
            "gradle_signing_key": {
                "pattern": r'(?i)(?:signingKey|signing_key)\s*[=:]\s*["\']([^"\']{8,})["\']',
                "confidence": 0.95, "level": "minimal",
                "reason": "Signing key in Gradle"
            },
            "gradle_api_key": {
                "pattern": r'(?i)(?:apiKey|api_key|API_KEY)\s*[=:,]\s*["\']([^"\']{8,})["\']',
                "confidence": 0.93, "level": "minimal",
                "reason": "API key in Gradle build file"
            },
            "gradle_manifest_placeholder": {
                "pattern": r'(?i)manifestPlaceholders\s*[=:]\s*\[[^\]]*["\']([A-Za-z0-9\-_]{20,})["\']',
                "confidence": 0.90, "level": "minimal",
                "reason": "Secret in Gradle manifestPlaceholders"
            },
            "gradle_password": {
                "pattern": r'(?i)(?:password|passwd|secret)\s*[=:]\s*["\']([^"\']{6,})["\']',
                "confidence": 0.95, "level": "minimal",
                "reason": "Password/secret in Gradle build"
            },
            "gradle_buildconfig": {
                "pattern": r'(?i)buildConfigField\s+["\']String["\']\s*,\s*["\'][^"\']*(?:KEY|SECRET|TOKEN|PASSWORD)[^"\']*["\']\s*,\s*["\']\\?"([^"\'\\]{6,})\\?"["\']',
                "confidence": 0.95, "level": "minimal",
                "reason": "Secret in Gradle buildConfigField"
            },
        },

        # ── Swift (.swift) ───────────────────────────────────────────────────
        "swift": {
            "swift_api_key": {
                "pattern": r'(?i)(?:apiKey|api_key|secretKey|secret_key|authToken|accessToken)\s*[=:]\s*"([^"]{8,})"',
                "confidence": 0.93, "level": "minimal",
                "reason": "API key/secret in Swift"
            },
            "swift_provide_api_key": {
                "pattern": r'(?i)(?:provideAPIKey|withAPIKey|configure)\s*\(\s*"([^"]{8,})"\s*\)',
                "confidence": 0.95, "level": "minimal",
                "reason": "SDK API key configuration in Swift"
            },
            "swift_password": {
                "pattern": r'(?i)(?:password|passwd|secret|credential)\s*[=:]\s*"([^"]{6,})"',
                "confidence": 0.95, "level": "minimal",
                "reason": "Password/credential in Swift"
            },
            "swift_firebase_options": {
                "pattern": r'(?i)(?:API_KEY|GCM_SENDER_ID|CLIENT_ID|GOOGLE_APP_ID)\s*[=:]\s*"([^"]{8,})"',
                "confidence": 0.90, "level": "minimal",
                "reason": "Firebase configuration in Swift"
            },
            "swift_url_secret": {
                "pattern": r'(?i)(?:baseURL|apiURL|serviceURL|endpoint)\s*[=:]\s*"(https?://[^"]{8,})"',
                "confidence": 0.87, "level": "strict",
                "reason": "Internal URL in Swift"
            },
        },

        # ── Ruby (.rb, Fastfile) ─────────────────────────────────────────────
        "ruby": {
            "ruby_env_secret": {
                "pattern": r'(?i)ENV\[[\"\']([A-Z_]*(?:SECRET|PASSWORD|TOKEN|KEY|API_KEY)[A-Z_]*)[\"\']\]\s*=\s*["\']([^"\']{6,})["\']',
                "confidence": 0.95, "level": "minimal",
                "reason": "Secret assigned via ENV[] in Ruby/Fastfile"
            },
            "ruby_password": {
                "pattern": r'(?i)(?:password|secret|token|api_key)\s*[=:]\s*["\']([^"\']{6,})["\']',
                "confidence": 0.93, "level": "minimal",
                "reason": "Password/secret in Ruby/Fastfile"
            },
            "ruby_credential": {
                "pattern": r'(?i)(?:match_password|app_store_connect_api_key|certificate_password)\s*[=(]\s*["\']([^"\']{6,})["\']',
                "confidence": 0.95, "level": "minimal",
                "reason": "CI/CD credential in Fastlane"
            },
        },

        # ── Java .properties ─────────────────────────────────────────────────
        "properties": {
            "props_password": {
                "pattern": r'(?i)(?:password|passwd|secret|credentials?)\s*=\s*(.{6,})$',
                "confidence": 0.95, "level": "minimal",
                "reason": "Password in .properties file"
            },
            "props_url": {
                "pattern": r'(?i)(?:url|jdbc\.url|connection\.url)\s*=\s*(.{10,})$',
                "confidence": 0.95, "level": "minimal",
                "reason": "Connection URL in .properties file"
            },
            "props_api_key": {
                "pattern": r'(?i)(?:api[._]key|apikey|api[._]token|access[._]key)\s*=\s*([^\s#]{8,})$',
                "confidence": 0.93, "level": "minimal",
                "reason": "API key in .properties file"
            },
            "props_host": {
                "pattern": r'(?i)(?:host|hostname|server)\s*=\s*([a-zA-Z0-9\-_.]{4,})$',
                "confidence": 0.83, "level": "standard",
                "reason": "Host in .properties file"
            },
            "spring_datasource": {
                "pattern": r'(?i)spring\.datasource\.(?:password|username|url)\s*=\s*(.+)$',
                "confidence": 0.97, "level": "minimal",
                "reason": "Spring datasource config"
            },
            "spring_secret": {
                "pattern": r'(?i)spring\.[\w.]*(?:password|secret|key|token|credentials?)\s*=\s*([^\s#]{6,})$',
                "confidence": 0.95, "level": "minimal",
                "reason": "Spring property secret"
            },
        },

        # ── INI / CFG ────────────────────────────────────────────────────────
        # ── Free text (.md / .txt / .rst) ────────────────────────────────────
        # Patterns written for prose — no key=value structure assumed.
        "freetext": {
            "prose_password": {
                "pattern": r'(?i)\bpassword\s*(?:is|was|:)\s*["\']?([^\s"\',.()]{6,})["\']?',
                "confidence": 0.88, "level": "minimal",
                "reason": "Password mentioned in prose"
            },
            "prose_credential": {
                "pattern": r'(?i)\b(?:credentials?|passphrase|secret)\s*[:\-–]\s*["\']?([^\s"\',.]{6,})["\']?',
                "confidence": 0.87, "level": "minimal",
                "reason": "Credential value in prose"
            },
            "prose_api_key": {
                "pattern": r'(?i)\bapi\s+key\s*[:\-–is]+\s*["\']?([a-zA-Z0-9\-_.]{16,})["\']?',
                "confidence": 0.88, "level": "minimal",
                "reason": "API key value in prose"
            },
            "prose_token": {
                "pattern": r'(?i)\btoken\s*[:\-–is]+\s*["\']?([a-zA-Z0-9\-_.]{20,})["\']?',
                "confidence": 0.86, "level": "minimal",
                "reason": "Token value in prose"
            },
            "prose_server_name": {
                "pattern": r'(?i)\b(?:server|host|hostname|endpoint)\s+(?:is|at|called|named|:)\s+["\']?([a-zA-Z0-9][a-zA-Z0-9\-_.]{3,})["\']?',
                "confidence": 0.82, "level": "standard",
                "reason": "Server/host name mentioned in prose"
            },
            "prose_db_name": {
                "pattern": r'(?i)\b(?:database|db|schema)\s+(?:is|called|named|:)\s+["\']?([a-zA-Z0-9_\-]{2,})["\']?',
                "confidence": 0.80, "level": "standard",
                "reason": "Database name mentioned in prose"
            },
            "prose_internal_url": {
                "pattern": r'https?://(?!(?:www\.|github\.com|stackoverflow|docs\.|example\.com))[a-zA-Z0-9\-_.]+(?:\.[a-zA-Z]{2,})+(?:/[^\s"\'<>)]*)?',
                "confidence": 0.80, "level": "standard",
                "reason": "Internal URL in free text"
            },
            "prose_ip_address": {
                "pattern": r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b',
                "confidence": 0.88, "level": "standard",
                "reason": "Private IP address in prose"
            },
            "prose_connection_string": {
                "pattern": r'(?:postgres|postgresql|mysql|mongodb|redis|mssql)://[^\s"\'<>)]{8,}',
                "confidence": 0.97, "level": "minimal",
                "reason": "Database connection URL in prose"
            },
            "prose_aws_key": {
                "pattern": r'AKIA[0-9A-Z]{16}',
                "confidence": 0.99, "level": "minimal",
                "reason": "AWS access key in prose"
            },
            "prose_generic_key": {
                "pattern": r'(?i)\b(?:key|secret)\s*[:\-–=]\s*["\']?([a-zA-Z0-9\-_/+]{20,})["\']?',
                "confidence": 0.82, "level": "minimal",
                "reason": "Generic key/secret value in prose"
            },
            "prose_salary": {
                "pattern": r'(?i)\b(?:salary|compensation|pay|wage|bonus)\s+(?:of|is|was|:)\s+\$?\s*[\d,]+(?:\.\d{2})?(?:\s*(?:k|K|million|M))?\b',
                "confidence": 0.85, "level": "minimal",
                "reason": "Salary/compensation figure in prose"
            },
            "prose_employee_id": {
                "pattern": r'(?i)\b(?:employee\s+id|emp\s+id|staff\s+id|worker\s+id)\s*[:\-#]\s*([A-Z0-9\-]{3,})\b',
                "confidence": 0.88, "level": "minimal",
                "reason": "Employee ID in prose"
            },
            "prose_aws_account_id": {
                "pattern": r'(?i)(?:account\s*(?:id|number|#)?|acct)\s*[:\-=]\s*(\d{12})\b',
                "confidence": 0.92, "level": "standard",
                "reason": "AWS Account ID in prose"
            },
            "prose_aws_arn": {
                "pattern": r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s"\'<>]+',
                "confidence": 0.95, "level": "standard",
                "reason": "AWS ARN in prose"
            },
            "prose_s3_bucket": {
                "pattern": r'(?i)\b([a-z0-9][a-z0-9\-]{2,61}(?:-\d{4,}))\b',
                "confidence": 0.82, "level": "standard",
                "reason": "S3 bucket name (with account suffix) in prose"
            },
            "prose_s3_uri": {
                "pattern": r's3://[a-z0-9][a-z0-9\-./]{3,}',
                "confidence": 0.95, "level": "standard",
                "reason": "S3 URI in prose"
            },
            "prose_sftp_user": {
                "pattern": r'(?i)(?:sftp|ftp|ssh)\s+(?:user(?:name)?|login)\s*[:\-=]\s*["\']?([^\s"\',.]{3,})["\']?',
                "confidence": 0.88, "level": "minimal",
                "reason": "SFTP/FTP username in prose"
            },
            "prose_user_line": {
                "pattern": r'(?i)^\s*-?\s*(?:User|Username|Login)\s*:\s*([a-zA-Z0-9_\-.@]{4,})\s*$',
                "confidence": 0.85, "level": "standard",
                "reason": "Username on its own line in prose"
            },
            "prose_sftp_password": {
                "pattern": r'(?i)(?:sftp|ftp|ssh)\s+(?:password|pass|pwd)\s*[:\-=]\s*["\']?([^\s"\',.()]{6,})["\']?',
                "confidence": 0.92, "level": "minimal",
                "reason": "SFTP/FTP password in prose"
            },
        },

        "ini": {
            "ini_password": {
                "pattern": r'(?i)^(?:password|passwd|pwd|secret)\s*=\s*(.{6,})$',
                "confidence": 0.95, "level": "minimal",
                "reason": "password= in INI/CFG file"
            },
            "ini_api_key": {
                "pattern": r'(?i)^(?:api_key|apikey|api_token|access_key)\s*=\s*([a-zA-Z0-9\-_.]{16,})$',
                "confidence": 0.93, "level": "minimal",
                "reason": "API key in INI/CFG file"
            },
            "ini_connection_string": {
                "pattern": r'(?i)^(?:connection_string|connstr|dsn)\s*=\s*(.{10,})$',
                "confidence": 0.95, "level": "minimal",
                "reason": "Connection string in INI/CFG file"
            },
            "ini_host": {
                "pattern": r'(?i)^(?:host|hostname|server|endpoint)\s*=\s*([a-zA-Z0-9\-_.]{4,})$',
                "confidence": 0.83, "level": "standard",
                "reason": "Host/server in INI/CFG file"
            },
            "ini_database": {
                "pattern": r'(?i)^(?:database|dbname|db_name|catalog)\s*=\s*([a-zA-Z0-9_\-]{2,})$',
                "confidence": 0.83, "level": "strict",
                "reason": "Database name in INI/CFG file"
            },
            "ini_username": {
                "pattern": r'(?i)^(?:username|user|uid)\s*=\s*([a-zA-Z0-9_\-@.]{3,})$',
                "confidence": 0.85, "level": "standard",
                "reason": "Username in INI/CFG file"
            },
            "ini_space_delimited_secret": {
                "pattern": r'(?i)[\w.]+\.(?:secret|password|key|token)\s+([^\s#]{8,})',
                "confidence": 0.90, "level": "minimal",
                "reason": "Space-delimited secret in conf (Spark/Hadoop style)"
            },
            "ini_jaas_password": {
                "pattern": r'(?i)password\s*=\s*["\']([^"\']{6,})["\']',
                "confidence": 0.93, "level": "minimal",
                "reason": "Password in JAAS/inline config"
            },
            "ini_connection_password": {
                "pattern": r'(?i)Connection(?:Password|Secret)\s+([^\s#]{6,})',
                "confidence": 0.93, "level": "minimal",
                "reason": "ConnectionPassword in space-delimited conf"
            },
        },
    }

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

    # Values that are almost never real secrets — structural/boilerplate
    FALSE_POSITIVE_VALUES = {
        "utf-8", "utf8", "utf-16", "true", "false", "yes", "no", "none",
        "null", "nil", "undefined", "localhost", "127.0.0.1", "0.0.0.0",
        "example.com", "test", "testing", "password", "changeme",
        "change_me", "change-me", "changeit", "your_password_here",
        "todo", "fixme", "placeholder", "default", "example", "sample",
        "dummy", "secret", "redacted", "masked", "notset", "not_set",
        "disabled", "enabled", "required", "optional", "unknown",
        # log levels / common config values
        "debug", "info", "warning", "warn", "error", "critical", "trace",
        "development", "production", "staging",
    }

    # Generic key-value patterns prone to matching placeholders and config
    # noise — their values must survive the weak-value gate below.
    GENERIC_VALUE_PATTERNS = {
        "generic_api_key", "password_assignment", "password_unquoted",
        "unquoted_env_secret", "any_env_password", "any_env_secret",
        "any_env_token", "tf_hcl_secret", "java_properties_password",
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
        re.compile(r"(?i)(?:os\.environ|process\.env|getenv|env\[)"),
    ]

    # Well-known public service hosts — a URL here carries no org-specific
    # info unless its path contains a token-like segment.
    PUBLIC_URL_DOMAINS = (
        "google.com", "googleapis.com", "googleusercontent.com",
        "github.com", "githubusercontent.com", "microsoft.com",
        "microsoftonline.com", "apple.com", "salesforce.com",
        "stackoverflow.com", "python.org", "npmjs.com", "docker.com",
        "docker.io", "readthedocs.io", "wikipedia.org",
    )

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
