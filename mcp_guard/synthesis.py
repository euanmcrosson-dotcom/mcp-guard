"""Synthesize a tool-call policy from an analysis gap.

The Engineer's first real job: given a gap (what failed, what was
abused) and the indicators recorded by the Attacker (which tool fired,
which arguments leaked), produce a `GeneratedPolicy` whose rules deny
the observed abuse pattern.

This is intentionally deterministic + pattern-based, not LLM-driven.
The mapping is small enough to enumerate, and a deterministic
synthesizer is unit-testable, debuggable from the audit log, and not
subject to model drift.

Each abuse class is one *pattern*. A pattern owns:

  - an indicator predicate (`_saw_X`) used by `synthesize()` to decide
    whether to emit the pattern's rules when only a partial signal is
    available (e.g., from one observed attack);
  - a free-text trigger run inside `synthesize_from_text()` that
    augments the indicator stream from a prose gap description;
  - a default rule factory (`_X_default_rules`) used by
    `synthesize_default_policy()` to emit the pattern unconditionally
    as part of the shippable production policy.

LLM-driven synthesis can layer on top later for novel cases the
patterns don't cover; the deterministic path stays as a backstop
because it's auditable from logs alone (no model required at
synthesis time).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .policy import Condition, GeneratedPolicy, PolicyRule


# Lightweight gap representation — mcp_guard does not depend on
# purple's pydantic contracts. Callers pass either a GapDescription
# dataclass or use synthesize_from_text() for plain free-text input.
@dataclass(frozen=True)
class GapDescription:
    kind: str  # e.g. "no_telemetry", "telemetry_no_rule", "rule_misfire"
    detail: str
    proposed_fix_summary: str = ""


@dataclass(frozen=True)
class SynthesisInput:
    """Everything the synthesizer needs from observed runtime state."""

    gap: GapDescription
    indicators: list[str]
    technique_id: str


# ─── Shared regex building blocks ──────────────────────────────────

_PRIVATE_HOST_PATTERN = (
    r"(?i)"
    r"(?:"
    r"^(?:file|gopher|dict|ftp|ldap|ldaps)://"  # dangerous URL schemes (file-read, SSRF chains)
    r"|^jar:"                                    # jar:http://...!/ (no // after jar:)
    r"|(?:^|//)("
    r"127(?:\.\d{1,3}){3}"            # 127.0.0.0/8
    r"|10(?:\.\d{1,3}){3}"            # 10.0.0.0/8
    r"|192\.168(?:\.\d{1,3}){2}"      # 192.168.0.0/16
    r"|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.\d{1,3}){2}"  # 172.16.0.0/12
    r"|169\.254(?:\.\d{1,3}){2}"      # link-local + AWS/GCP metadata
    r"|0\.0\.0\.0"
    r"|localhost"
    r"|metadata\.google\.internal"
    r"|metadata\.azure\.com"
    r"|\[?::1\]?"                      # IPv6 loopback
    r"|\[?::ffff:127"                  # IPv4-mapped IPv6 loopback
    r"|\[?fc[0-9a-f]{2}:"             # IPv6 unique local
    r"|\[?fe80:"                       # IPv6 link-local
    r")"
    r")"
)

_SENSITIVE_READ_PATTERN = (
    r"(?:\.ssh/|id_rsa|id_ed25519|id_dsa|\.aws/|/etc/shadow|/etc/passwd"
    r"|credentials|kubeconfig|\.kube/config|\.gnupg/|\.docker/config"
    r"|/proc/self/environ|\.netrc|\.pgpass|/root/"
    r"|\.azure/(?:credentials|accessTokens)|\.config/gcloud/"
    r"|AWS SSO/cache/|web_identity_token_file"
    r"|/var/run/docker\.sock|/var/run/secrets/"  # runtime sockets / secret mounts
    r"|\.git/credentials"                           # git credential helper
    # Windows-specific sensitive paths (single \ in regex r-string matches one literal \)
    r"|AppData\\Roaming\\Microsoft\\Credentials"
    r"|AppData\\(?:Local|Roaming)\\Microsoft\\Crypto\\RSA"
    r"|AppData\\(?:Local|Roaming)\\Microsoft\\Vault"
    r"|AppData\\Local\\Google\\Chrome\\User Data\\.+\\(?:Login Data|Cookies)"
    r"|AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\.+\\(?:logins\.json|key[34]\.db)"
    r"|%APPDATA%\\Microsoft\\(?:Credentials|Crypto|Vault)"
    r")"
)

_SENSITIVE_WRITE_PATTERN = (
    r"(?:\.ssh/(?:authorized_keys|config)|\.bashrc|\.zshrc|\.profile"
    r"|\.bash_profile|\.aws/credentials|/etc/(?!localtime)|/usr/(?:bin|sbin|lib)/"
    r"|/bin/|/sbin/|crontab|/var/spool/cron/|systemd/system/"
    r"|\.git/config|\.git/hooks/|/root/|\.env(?:\.|$)"
    # Windows-specific sensitive write targets (single \ in regex r-string matches one literal \)
    r"|C:\\Windows\\System32\\(?:drivers\\etc\\hosts|config\\)"
    r"|C:\\Windows\\Tasks\\"
    r"|C:\\Windows\\System32\\Tasks\\"
    r"|HKLM\\|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    r")"
)

_PATH_TRAVERSAL_PATTERN = (
    r"(?i)"  # encoded variants commonly appear in either case
    r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%2e%2e\\"
    r"|\.\.%2f|\.\.%5c|%252e%252e|\.\.∕|\.\.⧵)"
)

_SHELL_DANGER_PATTERN = (
    r"(?:"
    r";\s*\S"                                       # any command chained via ; (agents shouldn't chain)
    r"|&&\s*\S"                                     # any command chained via &&
    r"|\|\|\s*\S"                                   # any || chain
    r"|\|\s*(?:bash|sh|python|perl|nc|netcat|zsh|ksh|csh|fish|tclsh|ruby|node|pwsh|powershell)\b"
    r"|\$\([^)]{1,200}\)"                           # $(...) substitution
    r"|`[^`]{1,200}`"                               # backticks
    r"|\brm\s+-rf?\s+/(?!tmp(?:/|\s|$))"            # rm -rf / (anything except /tmp)
    r"|\bdd\s+if=/dev/(?:zero|urandom|random)"
    r"|\bmkfs\."
    r"|\bchmod\s+(?:[0-7]{0,3}777|\+x\s+/)"
    r"|>\s*/dev/(?:sd[a-z]|nvme|mmcblk)"             # disk redirect
    r"|\bcurl\s+[^|]{1,300}\|\s*(?:bash|sh|pwsh)"    # curl | sh / pwsh
    r"|\bwget\s+[^|]{1,300}\|\s*(?:bash|sh|pwsh)"    # wget | sh
    r"|:\(\)\{\s*:\|:&\s*\};\s*:"                    # fork bomb
    # PowerShell-specific abuse primitives
    r"|\bInvoke-Expression\b"                        # iex
    r"|\biex\s+\("                                   # iex (string)
    r"|\biwr\s+[^|]{1,300}\|\s*iex\b"                # iwr ... | iex (PS curl|sh)
    r"|\bInvoke-WebRequest\s+[^|]{1,300}\|\s*Invoke-Expression\b"
    r"|\bNew-Object\s+Net\.WebClient[^.]*\.DownloadString\s*\("  # WebClient.DownloadString
    r"|\bStart-Process\s+[^;]{1,200}\s+-Verb\s+RunAs"            # UAC bypass attempt
    # Java/log4shell-style JNDI lookup (any context)
    r"|\$\{jndi:(?:ldap|ldaps|rmi|dns|iiop)://"
    # Environment / process inspection — common post-RCE credential recon
    r"|\benv\s*(?:\||;|$|>)"                          # bare env dump (not env VAR=val)
    r"|\bprintenv\b"                                   # printenv alone
    r"|\bset\s*\|"                                     # set piped
    r"|\bcat\s+/proc/\d+/environ"                      # direct /proc/PID/environ read
    r"|\bgrep\s+-[a-zEFRPHhilrInw]*?[Ei][a-zEFRPHhilrInw]*\s+['\"]?"
    r"(?:password|passwd|secret|api[_-]?key|token|access[_-]?key|aws_secret|"
    r"private[_-]?key|begin\s+rsa|begin\s+openssh|jwt|bearer)"
    # Discovery of secret-shaped files
    r"|\bfind\s+[^|;]{1,200}-name\s+['\"]?\*\.(pem|key|p12|pfx|jks|env|kdbx)"
    r")"
)

_SQL_DANGER_PATTERN = (
    r"(?is)"
    r"(?:"
    r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|USER|ROLE)\b"
    r"|\bTRUNCATE\s+TABLE\b"
    r"|\bALTER\s+(?:TABLE|DATABASE|USER|ROLE)\b"
    r"|\bDELETE\s+FROM\s+[\w\"`.]+\s*(?:;|--|$)"        # DELETE without WHERE
    r"|\bUPDATE\s+[\w\"`.]+\s+SET\b(?![^;]*\bWHERE\b)"  # UPDATE without WHERE (lookahead checks "no WHERE before ;")
    r"|\bGRANT\s+(?:ALL|SUPER|FILE|SHUTDOWN|PROCESS)\b"
    r"|\bREVOKE\b"
    r"|\b(?:UNION\s+(?:ALL\s+)?SELECT|SELECT\s+\*\s+FROM\s+information_schema)"
    r"|--\s*$|/\*.*?\*/"                                  # SQL comments
    r"|;\s*(?:DROP|DELETE|UPDATE|INSERT|EXEC)\b"          # stacked queries
    r"|\bEXEC(?:UTE)?\s*\(?\s*(?:xp_|sp_)"                # MSSQL command exec
    r"|\bxp_cmdshell\b"                                   # MSSQL bare cmdshell
    r"|\bLOAD_FILE\s*\("                                  # MySQL file read
    r"|\bINTO\s+OUTFILE\b"                                # MySQL file write
    r"|\bINTO\s+DUMPFILE\b"                               # MySQL alt file write
    r"|\bCOPY\s+\S+\s+FROM\s+PROGRAM\b"                   # Postgres RCE via COPY
    r"|\bpg_read_file\s*\("                               # Postgres file read
    r"|\bpg_read_binary_file\s*\("                        # Postgres binary file read
    r"|\bpg_ls_dir\s*\("                                  # Postgres directory listing
    r"|\$\$.+\$\$"                                        # Postgres dollar-quoted strings (often used for injection)
    r")"
)

_PII_EXFIL_PATTERN = (
    r"(?:"
    r"AKIA[0-9A-Z]{16}"                                     # AWS access key
    r"|aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}"
    r"|sk-[A-Za-z0-9_\-]{20,}"                              # OpenAI / Anthropic
    r"|sk-ant-[A-Za-z0-9_\-]{20,}"                          # Anthropic
    r"|ghp_[A-Za-z0-9]{30,}"                                # GitHub PAT
    r"|gho_[A-Za-z0-9]{30,}"                                # GitHub OAuth
    r"|github_pat_[A-Za-z0-9_]{60,}"                        # GitHub fine-grained
    r"|glpat-[A-Za-z0-9_\-]{20,}"                           # GitLab PAT
    r"|xox[bpoars]-[A-Za-z0-9-]{10,}"                       # Slack tokens
    r"|-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----"
    r"|\b\d{3}-\d{2}-\d{4}\b"                               # US SSN
    r"|\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"  # JWT
    r"|\b4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b"  # Visa
    r"|\b5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b"  # MC
    r")"
)


# Common tool-name conventions across MCP servers, agent frameworks,
# and the SDK examples. Each pattern emits one rule per name so policy
# coverage is robust to naming variation.
_HTTP_TOOLS = ("fetch_url", "http_get", "http_post", "http_request", "fetch", "request")
_FILE_WRITE_TOOLS = ("write_file", "edit_file", "create_file", "append_file", "patch_file")
_FILE_READ_TOOLS = ("read_file", "read_text_file", "get_file", "cat_file", "load_file", "open_file")
_FILE_PATH_TOOLS = _FILE_READ_TOOLS + _FILE_WRITE_TOOLS + ("list_dir", "list_directory", "ls", "stat", "delete_file", "remove_file")
_SHELL_TOOLS = ("shell_exec", "run_command", "run_shell", "bash", "exec_command", "execute", "system", "subprocess")
_SQL_TOOLS = ("db_query", "sql_execute", "run_query", "execute_sql", "query", "exec_sql")
_NETWORK_TOOLS = ("tcp_connect", "socket_connect", "network_call", "connect", "raw_connect")
_EMAIL_TOOLS = ("send_email", "email.send", "send_mail", "smtp_send", "mail")


# ─── Public entrypoints ────────────────────────────────────────────


def synthesize_from_text(
    detail: str,
    *,
    technique_id: str = "anonymous",
    kind: str = "telemetry_no_rule",
    proposed_fix_summary: str = "",
    indicators: list[str] | None = None,
) -> GeneratedPolicy:
    """Synthesize a policy from a free-text gap description.

    Indicator patterns are inferred from the text (substring scan for
    tool names, attack-class keywords, and sensitive arg patterns).
    Use the structured `synthesize(SynthesisInput(...))` entrypoint
    when you have richer signals from a probe.
    """
    auto_indicators: list[str] = list(indicators or [])
    detail_l = detail.lower()

    # Email exfil
    if "email.send" in detail_l or "send_email" in detail_l or "send email" in detail_l:
        auto_indicators.append("tool:send_email")
    if "attacker@" in detail_l or "@evil" in detail_l:
        for token in detail_l.replace(",", " ").replace(".", " ").split():
            if token.startswith("attacker@") or "@evil" in token:
                auto_indicators.append(f"argument:to={token}")
                break
    if any(k in detail_l for k in ("pii", "credit card", "ssn", "api key", "secret", "exfiltrat")):
        auto_indicators.append("class:pii_exfil")

    # Sensitive file read
    if any(k in detail_l for k in ("ssh", "id_rsa", ".aws", "credentials", "/etc/shadow", "/etc/passwd", "kubeconfig")):
        auto_indicators.append("tool:read_file")
        auto_indicators.append("argument:path=sensitive")

    # Sensitive file write
    if any(k in detail_l for k in ("write_file", "edit_file", "overwrite", "bashrc", "authorized_keys", "crontab")):
        auto_indicators.append("tool:write_file")
        auto_indicators.append("class:sensitive_file_write")

    # SSRF / private host
    if any(k in detail_l for k in ("ssrf", "metadata service", "internal endpoint", "169.254", "127.0.0.1", "localhost")):
        auto_indicators.append("class:ssrf")
    if "fetch" in detail_l or "http_get" in detail_l or "url" in detail_l:
        auto_indicators.append("tool:fetch_url")

    # Path traversal
    if any(k in detail_l for k in ("path traversal", "directory traversal", "../", "..\\", "%2e%2e")):
        auto_indicators.append("class:path_traversal")

    # Shell injection / danger
    if any(k in detail_l for k in ("shell_exec", "run_command", "bash", "rm -rf", "curl | sh", "wget | sh", "command injection")):
        auto_indicators.append("class:shell_danger")

    # SQL injection / destructive
    if any(k in detail_l for k in ("sql injection", "drop table", "truncate", "union select", "destructive query")):
        auto_indicators.append("class:sql_danger")

    # Network egress private
    if any(k in detail_l for k in ("tcp_connect", "socket_connect", "network exfil", "internal port")):
        auto_indicators.append("class:network_egress_private")

    return synthesize(
        SynthesisInput(
            gap=GapDescription(kind=kind, detail=detail, proposed_fix_summary=proposed_fix_summary),
            indicators=auto_indicators,
            technique_id=technique_id,
        )
    )


def synthesize(inp: SynthesisInput) -> GeneratedPolicy:
    """Pattern-match the indicators + gap onto a policy.

    Strategy: every pattern is asked if its indicators are present;
    each pattern that fires contributes one or more rules. If nothing
    matches, return an empty policy (deliberate — synthesizer surfaces
    "no rule generated" rather than fabricating a wrong rule)."""
    rules: list[PolicyRule] = []
    for pattern_fn in _PATTERN_FROM_INDICATORS:
        rules.extend(pattern_fn(inp.technique_id, inp.indicators))
    return GeneratedPolicy(rules=tuple(rules))


def synthesize_default_policy(technique_id: str = "default") -> GeneratedPolicy:
    """Return the full deterministic ruleset — every known pattern's
    rules emitted unconditionally.

    This is the *shippable* production policy. Deploy this in front of
    your agent's tool-call boundary and you get all built-in defenses
    on day one. Tune by:

      - Overriding individual rules in your own GeneratedPolicy
      - Adding pattern-specific allow conditions in user_context
      - Composing with classifier-based defenses for full coverage
    """
    rules: list[PolicyRule] = []
    for fn in _PATTERN_DEFAULTS:
        rules.extend(fn(technique_id))
    return GeneratedPolicy(rules=tuple(rules))


# ─── Pattern 1: Email contact allowlist (exfil to external) ─────────


def _pattern_email_from_indicators(technique_id: str, indicators: list[str]) -> list[PolicyRule]:
    if not _saw_email_send(indicators):
        return []
    observed_to = _extract_email_argument(indicators)
    return [_email_contact_allowlist_rule(technique_id, observed_to)]


def _pattern_email_defaults(technique_id: str) -> list[PolicyRule]:
    return [_email_contact_allowlist_rule(technique_id, observed_to=None, tool=t) for t in _EMAIL_TOOLS]


def _saw_email_send(indicators: list[str]) -> bool:
    return any(
        ind.startswith("tool:email.send") or ind == "tool:send_email" or ind.startswith("tool:send_mail")
        for ind in indicators
    )


def _extract_email_argument(indicators: list[str]) -> str | None:
    for ind in indicators:
        m = re.match(r"argument:to=(.+)", ind)
        if m:
            return m.group(1).strip()
    return None


def _email_contact_allowlist_rule(
    technique_id: str, observed_to: str | None, tool: str = "send_email"
) -> PolicyRule:
    sample = f" (observed exfil attempt to {observed_to})" if observed_to else ""
    return PolicyRule(
        rule_id=f"tool-policy-email-contact-allowlist--{tool}--{_slug(technique_id)}",
        tool=tool,
        conditions=(
            Condition(arg="to", op="not_in", ref="context.user.contacts"),
        ),
        reason=(
            "External recipient outside the authenticated user's contact "
            f"list{sample}; treat as exfiltration attempt and deny."
        ),
    )


# ─── Pattern 2: Sensitive file READ ─────────────────────────────────


def _pattern_file_read_from_indicators(technique_id: str, indicators: list[str]) -> list[PolicyRule]:
    if not _saw_sensitive_file_read(indicators):
        return []
    return _pattern_file_read_defaults(technique_id)


def _pattern_file_read_defaults(technique_id: str) -> list[PolicyRule]:
    return [
        PolicyRule(
            rule_id=f"tool-policy-block-sensitive-file-read--{tool}--{_slug(technique_id)}",
            tool=tool,
            conditions=(Condition(arg="path", op="matches", value=_SENSITIVE_READ_PATTERN),),
            reason=(
                "Read of sensitive credential / private-key path. Likely "
                "result of cross-tool prompt injection — deny unconditionally."
            ),
        )
        for tool in _FILE_READ_TOOLS
    ]


def _saw_sensitive_file_read(indicators: list[str]) -> bool:
    sensitive_keywords = (
        "~/.ssh/", "id_rsa", "id_ed25519", "~/.aws/", "credentials",
        "/etc/shadow", "/etc/passwd", "kubeconfig", ".gnupg",
    )
    return any(any(s in ind for s in sensitive_keywords) for ind in indicators)


# ─── Pattern 3: Sensitive file WRITE ────────────────────────────────


def _pattern_file_write_from_indicators(technique_id: str, indicators: list[str]) -> list[PolicyRule]:
    if not any(
        "class:sensitive_file_write" in ind or ind.startswith("tool:write_file")
        or ind.startswith("tool:edit_file") for ind in indicators
    ):
        return []
    return _pattern_file_write_defaults(technique_id)


def _pattern_file_write_defaults(technique_id: str) -> list[PolicyRule]:
    return [
        PolicyRule(
            rule_id=f"tool-policy-block-sensitive-file-write--{tool}--{_slug(technique_id)}",
            tool=tool,
            conditions=(Condition(arg="path", op="matches", value=_SENSITIVE_WRITE_PATTERN),),
            reason=(
                "Write to sensitive system / credential / shell-init path. "
                "Persistence or privilege-escalation primitive — deny."
            ),
        )
        for tool in _FILE_WRITE_TOOLS
    ]


# ─── Pattern 4: Path traversal ──────────────────────────────────────


def _pattern_path_traversal_from_indicators(technique_id: str, indicators: list[str]) -> list[PolicyRule]:
    if not any("class:path_traversal" in ind for ind in indicators):
        return []
    return _pattern_path_traversal_defaults(technique_id)


def _pattern_path_traversal_defaults(technique_id: str) -> list[PolicyRule]:
    return [
        PolicyRule(
            rule_id=f"tool-policy-path-traversal--{tool}--{_slug(technique_id)}",
            tool=tool,
            conditions=(Condition(arg="path", op="matches", value=_PATH_TRAVERSAL_PATTERN),),
            reason=(
                "Path argument contains directory-traversal sequence "
                "(../, encoded variants, Unicode division-slash). Reject "
                "before resolving — sandbox prefix checks alone do not "
                "stop encoded traversals."
            ),
        )
        for tool in _FILE_PATH_TOOLS
    ]


# ─── Pattern 5: SSRF — HTTP URL to private/metadata host ────────────


def _pattern_ssrf_from_indicators(technique_id: str, indicators: list[str]) -> list[PolicyRule]:
    if not any(
        "class:ssrf" in ind or ind.startswith("tool:fetch") or ind.startswith("tool:http")
        for ind in indicators
    ):
        return []
    return _pattern_ssrf_defaults(technique_id)


def _pattern_ssrf_defaults(technique_id: str) -> list[PolicyRule]:
    return [
        PolicyRule(
            rule_id=f"tool-policy-ssrf-private-host--{tool}--{_slug(technique_id)}",
            tool=tool,
            conditions=(Condition(arg="url", op="matches", value=_PRIVATE_HOST_PATTERN),),
            reason=(
                "HTTP fetch targets private/internal IP, loopback, or "
                "cloud metadata endpoint. Classic SSRF — agents should "
                "never hit internal infrastructure from the public path."
            ),
        )
        for tool in _HTTP_TOOLS
    ]


# ─── Pattern 6: Shell command danger ────────────────────────────────


def _pattern_shell_danger_from_indicators(technique_id: str, indicators: list[str]) -> list[PolicyRule]:
    if not any(
        "class:shell_danger" in ind or any(ind.startswith(f"tool:{t}") for t in _SHELL_TOOLS)
        for ind in indicators
    ):
        return []
    return _pattern_shell_danger_defaults(technique_id)


def _pattern_shell_danger_defaults(technique_id: str) -> list[PolicyRule]:
    rules: list[PolicyRule] = []
    for tool in _SHELL_TOOLS:
        for arg_name in ("command", "cmd", "script", "code", "input"):
            rules.append(
                PolicyRule(
                    rule_id=f"tool-policy-shell-danger--{tool}--{arg_name}--{_slug(technique_id)}",
                    tool=tool,
                    conditions=(Condition(arg=arg_name, op="matches", value=_SHELL_DANGER_PATTERN),),
                    reason=(
                        "Shell argument contains chaining, command substitution, "
                        "pipe-to-shell, or known-destructive primitive (rm -rf, "
                        "dd, mkfs, chmod 777, curl|sh, fork bomb). Deny before exec."
                    ),
                )
            )
    return rules


# ─── Pattern 7: SQL dangerous query ─────────────────────────────────


def _pattern_sql_danger_from_indicators(technique_id: str, indicators: list[str]) -> list[PolicyRule]:
    if not any(
        "class:sql_danger" in ind or any(ind.startswith(f"tool:{t}") for t in _SQL_TOOLS)
        for ind in indicators
    ):
        return []
    return _pattern_sql_danger_defaults(technique_id)


def _pattern_sql_danger_defaults(technique_id: str) -> list[PolicyRule]:
    rules: list[PolicyRule] = []
    for tool in _SQL_TOOLS:
        for arg_name in ("sql", "query", "statement"):
            rules.append(
                PolicyRule(
                    rule_id=f"tool-policy-sql-danger--{tool}--{arg_name}--{_slug(technique_id)}",
                    tool=tool,
                    conditions=(Condition(arg=arg_name, op="matches", value=_SQL_DANGER_PATTERN),),
                    reason=(
                        "SQL statement is destructive (DROP/TRUNCATE/ALTER), "
                        "unbounded mutation (DELETE/UPDATE without WHERE), "
                        "stacked, comment-injected, or file-IO. Reject — "
                        "agents should not be issuing these from a user-bound "
                        "session."
                    ),
                )
            )
    return rules


# ─── Pattern 8: Network egress to private host ──────────────────────


def _pattern_network_egress_from_indicators(technique_id: str, indicators: list[str]) -> list[PolicyRule]:
    if not any(
        "class:network_egress_private" in ind or any(ind.startswith(f"tool:{t}") for t in _NETWORK_TOOLS)
        for ind in indicators
    ):
        return []
    return _pattern_network_egress_defaults(technique_id)


def _pattern_network_egress_defaults(technique_id: str) -> list[PolicyRule]:
    return [
        PolicyRule(
            rule_id=f"tool-policy-network-egress-private--{tool}--{_slug(technique_id)}",
            tool=tool,
            conditions=(Condition(arg="host", op="matches", value=_PRIVATE_HOST_PATTERN),),
            reason=(
                "Raw network connect targets private/internal host or "
                "cloud metadata service. Internal-network access from "
                "an agent path is a lateral-movement primitive — deny."
            ),
        )
        for tool in _NETWORK_TOOLS
    ]


# ─── Pattern 9: Email body / subject PII + secret exfil ─────────────


def _pattern_pii_exfil_from_indicators(technique_id: str, indicators: list[str]) -> list[PolicyRule]:
    if not any(
        "class:pii_exfil" in ind or ind.startswith("tool:send_email") or ind.startswith("tool:email.send")
        for ind in indicators
    ):
        return []
    return _pattern_pii_exfil_defaults(technique_id)


def _pattern_pii_exfil_defaults(technique_id: str) -> list[PolicyRule]:
    rules: list[PolicyRule] = []
    for tool in _EMAIL_TOOLS:
        for arg_name in ("body", "subject", "text", "html"):
            rules.append(
                PolicyRule(
                    rule_id=f"tool-policy-pii-exfil--{tool}--{arg_name}--{_slug(technique_id)}",
                    tool=tool,
                    conditions=(Condition(arg=arg_name, op="matches", value=_PII_EXFIL_PATTERN),),
                    reason=(
                        "Email payload contains secret-shaped material "
                        "(API key, private key, SSN, credit card, JWT). "
                        "Defense-in-depth on top of contact allowlist — "
                        "even allowed recipients should not receive secrets."
                    ),
                )
            )
    return rules


# ─── Pattern registries ────────────────────────────────────────────

_PATTERN_FROM_INDICATORS = (
    _pattern_email_from_indicators,
    _pattern_file_read_from_indicators,
    _pattern_file_write_from_indicators,
    _pattern_path_traversal_from_indicators,
    _pattern_ssrf_from_indicators,
    _pattern_shell_danger_from_indicators,
    _pattern_sql_danger_from_indicators,
    _pattern_network_egress_from_indicators,
    _pattern_pii_exfil_from_indicators,
)

_PATTERN_DEFAULTS = (
    _pattern_email_defaults,
    _pattern_file_read_defaults,
    _pattern_file_write_defaults,
    _pattern_path_traversal_defaults,
    _pattern_ssrf_defaults,
    _pattern_shell_danger_defaults,
    _pattern_sql_danger_defaults,
    _pattern_network_egress_defaults,
    _pattern_pii_exfil_defaults,
)


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-").lower()
