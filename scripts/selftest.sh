#!/bin/bash
# Checks kubejail's isolation on this machine using only the binary: no Rust,
# Docker or cluster needed. A local TCP responder plays the API server.
#
#   scripts/selftest.sh [path/to/kubejail] [real-context]
#
# With a real context it also runs `kubectl get namespaces` through the jail.
set -u

KUBEJAIL=${1:-kubejail}
CONTEXT=${2:-}
command -v "$KUBEJAIL" >/dev/null || { echo "kubejail binary not found: $KUBEJAIL"; exit 2; }
command -v perl >/dev/null || { echo "perl is required"; exit 2; }

WORK=$(mktemp -d)
mkdir "$WORK/run"
PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# responder TAG: prints its port, then answers every connection with "TAG:<line>".
responder() {
  perl -MIO::Socket::INET -e '
    my $s = IO::Socket::INET->new(Listen => 16, LocalAddr => "127.0.0.1", LocalPort => 0, ReuseAddr => 1) or die $!;
    open(my $f, ">", $ARGV[1]) or die $!; print $f $s->sockport; close $f;
    while (my $c = $s->accept) { my $l = <$c>; print $c "$ARGV[0]:$l" if defined $l; close $c; }
  ' "$1" "$WORK/$1.port" &
  PIDS+=($!)
  for _ in $(seq 50); do [ -s "$WORK/$1.port" ] && break; sleep 0.1; done
}
responder api
responder other
API=$(cat "$WORK/api.port")
OTHER=$(cat "$WORK/other.port")

CERT=LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg==
cat > "$WORK/config.yaml" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: fake
  cluster: {server: "https://127.0.0.1:$API", certificate-authority-data: $CERT}
users:
- name: op
  user: {client-certificate-data: $CERT, client-key-data: $CERT}
contexts:
- name: selftest
  context: {cluster: fake, user: op}
EOF
SECRET_FILE="$HOME/.kubejail-selftest-$$"
echo secret > "$SECRET_FILE"

read -r -d '' SCRIPT <<EOF
port=\$(sed -n 's/.*127\.0\.0\.1:\([0-9]*\).*/\1/p' "\$KUBECONFIG")
try() { (exec 4<>"/dev/tcp/\$1/\$2") 2>/dev/null && echo open || echo closed; }
exec 3<>/dev/tcp/127.0.0.1/\$port && echo ping >&3 && read -r reply <&3; exec 3>&-
echo "forward=\${reply:-none}"
echo "other_port=\$(try 127.0.0.1 $OTHER)"
echo "direct_port=\$(try 127.0.0.1 $API)"
echo "internet=\$(try 1.1.1.1 443)"
echo "host_env=\${HOST_SECRET:-unset}"
cat '$SECRET_FILE' >/dev/null 2>&1 && echo home_file=readable || echo home_file=hidden
touch /tmp/kubejail-selftest-escape 2>/dev/null; echo done > /dev/null
touch "\$HOME/scratch" 2>/dev/null && echo jail_home=writable || echo jail_home=readonly
command -v kubectl >/dev/null && echo kubectl=found || echo kubectl=missing
EOF

OUT=$(XDG_RUNTIME_DIR="$WORK/run" TMPDIR="$WORK/run" HOST_SECRET=leak \
  "$KUBEJAIL" enter selftest --kubeconfig "$WORK/config.yaml" -- /bin/bash -c "$SCRIPT" 2>"$WORK/stderr")
STATUS=$?
rm -f "$SECRET_FILE"

FAILED=0
check() { # check NAME EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1 (expected '$2', got '$3')"; FAILED=1; fi
}
value() { echo "$OUT" | sed -n "s/^$1=//p"; }

check "session starts and exits cleanly" 0 "$STATUS"
check "selected endpoint reachable through the forwarder" "api:ping" "$(value forward)"
check "another local port is unreachable" closed "$(value other_port)"
check "endpoint not reachable around the forwarder" closed "$(value direct_port)"
check "internet is unreachable" closed "$(value internet)"
check "host environment is not inherited" unset "$(value host_env)"
check "files in the operator's HOME are hidden" hidden "$(value home_file)"
check "session HOME is writable" writable "$(value jail_home)"
check "kubectl is available inside" found "$(value kubectl)"
# The Linux jail has its own /tmp; on macOS /tmp must be read-only.
[ -e /tmp/kubejail-selftest-escape ] && { rm -f /tmp/kubejail-selftest-escape; ESC=yes; } || ESC=no
check "host /tmp is not writable from the jail" no "$ESC"
check "session files are removed" "" "$(ls -A "$WORK/run")"

if [ -n "$CONTEXT" ]; then
  if "$KUBEJAIL" enter "$CONTEXT" -- kubectl get namespaces >/dev/null 2>"$WORK/real"; then
    echo "PASS  kubectl works against context $CONTEXT"
  else
    echo "FAIL  kubectl against context $CONTEXT"; cat "$WORK/real"; FAILED=1
  fi
fi

if [ "$FAILED" != 0 ]; then
  echo; echo "--- kubejail stderr"; cat "$WORK/stderr"; echo "--- jail output"; echo "$OUT"
  exit 1
fi
echo "All checks passed."
