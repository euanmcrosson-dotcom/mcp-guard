# Case Study — Agent SSRF chain to AWS IMDS credential exfil

> Realistic synthetic finding modelling a well-known pattern: an agent
> with an HTTP-fetching tool follows attacker-controlled URLs into
> the AWS Instance Metadata Service (IMDS), retrieves the IAM role
> credentials of the host, and exfiltrates them. This case study
> walks the gap → synthesised policy → backtest cycle for the SSRF
> pattern in mcp-guard.

## The setup

The vulnerable agent runs on an EC2 instance (or any IMDS-equipped
cloud host). It has a tool with this shape:

```python
{
    "name": "fetch_url",
    "description": "Fetch the contents of a URL and return the body.",
    "args_schema": {"url": "string"},
}
```

Plausible legitimate uses: documentation lookup, fetching public
datasets, calling a partner API. The agent has no notion that some
URLs are dangerous.

The attack flow:

1. **User input contains a poisoned URL.** Could be a customer-
   submitted ticket linking to "documentation," a malicious search
   result the agent follows, or a referenced URL in a PDF the agent
   summarises.
2. **The URL targets the IMDS endpoint** at `169.254.169.254`. On
   AWS EC2, this is the metadata service. With **IMDSv1** enabled
   (still common in legacy deployments), GET-without-token returns
   IAM credentials for the role attached to the instance.
3. **The agent calls `fetch_url`** with the IMDS URL because the
   tool description doesn't preclude it.
4. **The credentials come back** in the HTTP response body. The
   agent may then quote them in chat output, write them to a log
   tool, or fetch attacker-controlled exfil URLs with them.

The IMDS variant is one of dozens. The same attack class also
works against:

- **GCP metadata**: `metadata.google.internal/computeMetadata/v1/`
- **Azure IMDS**: `169.254.169.254/metadata/identity/oauth2/token`
- **Kubernetes metadata**: `kubernetes.default.svc.cluster.local`
- **Internal admin APIs**: any private-IP endpoint
- **`file://` scheme**: reads local files via HTTP-style URL parsing
- **`gopher://` / `dict://`**: protocol smuggling for Redis / memcached / SMTP

## The gap, in `mcp-guard`'s format

```python
from mcp_guard import synthesize_from_text

gap = (
    "Agent invoked fetch_url with URL http://169.254.169.254/latest/"
    "meta-data/iam/security-credentials/ after following a poisoned "
    "link in user-supplied content. The response body contained "
    "AWS IAM role credentials which the agent then echoed in its "
    "next turn. Classic SSRF to the cloud metadata service "
    "via the AWS IMDSv1 endpoint."
)

policy = synthesize_from_text(gap, technique_id="aws-imds-ssrf-2026-05-15")
```

The synthesiser pattern-matches `fetch_url` + `169.254` + `metadata
service` keywords → fires the SSRF pattern across all 6 HTTP tool
names.

## The defended dispatch

```python
from mcp_guard import evaluate

decision = evaluate(
    policy,
    tool_name="fetch_url",
    args={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
    user_context={"user": {"id": "u-123"}},
)
# Decision(allowed=False,
#          denying_rule_id='tool-policy-ssrf-private-host--fetch_url--aws-imds-ssrf-2026-05-15',
#          reason="HTTP fetch targets private/internal IP...")
```

Every variant in the corpus is denied:

| Variant | Tool / URL | Denied by |
|---|---|---|
| AWS IMDS | `fetch_url http://169.254.169.254/...` | `ssrf-private-host--fetch_url` |
| GCP metadata | `http_get http://metadata.google.internal/...` | `ssrf-private-host--http_get` |
| Loopback admin | `fetch_url http://127.0.0.1:8080/admin` | `ssrf-private-host--fetch_url` |
| Private IP | `http_get http://10.0.0.1/internal-api/users` | `ssrf-private-host--http_get` |
| IPv4-mapped IPv6 | `fetch_url http://[::ffff:127.0.0.1]/admin` | `ssrf-private-host--fetch_url` (v0.3.0+) |
| `file://` scheme | `fetch_url file:///etc/passwd` | `ssrf-private-host--fetch_url` (v0.3.0+) |
| `gopher://` smuggling | `fetch_url gopher://127.0.0.1:6379/_FLUSHALL` | `ssrf-private-host--fetch_url` (v0.3.0+) |
| `ldap://` (JNDI-adjacent) | `fetch_url ldap://attacker.example/...` | `ssrf-private-host--fetch_url` (v0.3.0+) |

## Why this rule alone isn't enough — and what to layer with it

The mcp-guard SSRF rule is a **structural** defense. It denies the
call when the *URL itself* matches a private-host or dangerous-scheme
pattern. That handles 95% of agent SSRF where the agent passes the
URL through unchanged.

Two attack shapes that bypass the rule (and what to do about them):

1. **DNS rebinding.** Attacker controls a domain like
   `rebind.example.com` whose A record resolves to a public IP for
   the first lookup (passing any pre-check) and a private IP for
   the second lookup (when the HTTP library actually connects). The
   URL string `http://rebind.example.com/` doesn't match our regex.
   - **Mitigation:** use an HTTP client that pins the resolved IP at
     URL-parse time and refuses to reconnect on a different IP. Most
     modern HTTP libraries support this (`requests` with `urllib3`'s
     custom poolmanager, or `httpx` with a custom transport).
2. **302 redirect chains.** Attacker hosts a public URL that returns
   `Location: http://169.254.169.254/...`. Our regex sees the safe
   public URL; the HTTP library quietly follows the redirect to
   IMDS.
   - **Mitigation:** disable redirects in your fetcher, OR re-evaluate
     each hop through mcp-guard. The `MCPGuard.check()` wrapper makes
     this ~5 lines of code in your HTTP middleware.

The deterministic policy is the floor, not the ceiling. Layer with
HTTP-client-level pinning, redirect re-checks, and (for AWS) **enable
IMDSv2 with `aws ec2 modify-instance-metadata-options
--http-tokens required`** so the credential endpoint requires a
session token IMDSv1 can't issue.

## Reproduce

```bash
python case_studies/aws-metadata-ssrf/reproduce.py
```

Generates `synthesised_policy.yaml` (the targeted policy) and
`backtest.json` (TPR/FPR for both targeted and default policies
against the v0.3.x default corpus).

## Related

- [echoleak-gpt4o](../echoleak-gpt4o/) — direct content injection
  (email exfil), the original SSRF-adjacent attack
- [tool-description-poisoning](../tool-description-poisoning/) —
  cross-tool hijack via poisoned MCP tool catalog
- [capnagent](https://github.com/euanmcrosson-dotcom/capnagent) —
  capability tokens that scope agents at the authority level so
  SSRF is also an authority-violation, not just a policy-violation
- [mcp-recon](https://github.com/euanmcrosson-dotcom/mcp-recon) —
  audit MCP servers' tool descriptions for `http_get` / `fetch_url`
  surfaces before integrating
