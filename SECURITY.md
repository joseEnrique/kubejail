# Security policy

## What counts as a vulnerability

kubejail promises that processes started inside a session have one direct
network route: the API server chosen when the session started. Please report
anything that breaks that promise, for example:

- reaching any other host, port or Unix socket from inside the jail;
- making the host forwarder connect anywhere other than the pinned endpoint;
- reading host credentials or files outside the documented allowlist;
- affecting the host after the session ends (terminal injection, surviving
  processes with network access, leftover session files).

Not vulnerabilities: anything done *through* the chosen API server
(`kubectl exec`, `port-forward`, `proxy`, `debug`). Those are governed by the
cluster's network policy and RBAC, as documented in the README. The macOS
backend also has known, documented limitations.

## How to report

Use GitHub's private reporting:
<https://github.com/joseEnrique/kubejail/security/advisories/new>

Please include your OS and kernel version, the kubejail version and the steps
to reproduce. Do not open a public issue for an escape until a fix is out.
