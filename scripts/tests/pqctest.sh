#!/usr/bin/env bash
set -euo pipefail
# Defaults: the historical /opt/qai build tree when present, otherwise the
# system OpenSSL configuration (empty OPENSSL_CONF). Explicit environment
# always wins. (Wave 2 fix: the old defaults made the script unrunnable
# anywhere but one machine.)
if [[ -z "${OPENSSL_CONF+x}" && -f /opt/qai/qompassl/ssl/openssl.cnf ]]; then
    OPENSSL_CONF=/opt/qai/qompassl/ssl/openssl.cnf
fi
if [[ -z "${OPENSSL_MODULES+x}" && -d /opt/qai/qompassl/lib64/ossl-modules ]]; then
    OPENSSL_MODULES=/opt/qai/qompassl/lib64/ossl-modules
fi
export OPENSSL_CONF="${OPENSSL_CONF:-}" OPENSSL_MODULES="${OPENSSL_MODULES:-}"
PROVIDERS=(-provider default)
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
REPORT="$WORKDIR/report.md"
printf "| Algorithm | Key-gen | Sign | Verify | Notes |\n" >"$REPORT"
printf "|-----------|--------|------|--------|-------|\n" >>"$REPORT"
# Fail loudly if openssl cannot enumerate algorithms (e.g. a malformed
# OPENSSL_CONF). The old process-substitution form swallowed this failure
# and reported an empty table with exit 0. (Wave 2 fix.)
ALG_LIST=$(openssl list -signature-algorithms "${PROVIDERS[@]}") || {
    echo "error: openssl list -signature-algorithms failed" >&2
    exit 1
}
# `openssl list -signature-algorithms` prints entries like
#   { 2.16.840.1.101.3.4.3.17, id-ml-dsa-44, ML-DSA-44, MLDSA44 } @ default
# The canonical key-algorithm name is the LAST name inside the braces (or
# the bare token). The old extraction fed the whole "{ oid, names }" blob
# to genpkey, so every row failed. (Wave 2 fix.)
mapfile -t ALGS < <(
    printf '%s\n' "$ALG_LIST" |
        awk -F '@' '{print $1}' |
        sed 's/[{}]//g' |
        awk -F ',' '{print $NF}' |
        sed 's/^ *//;s/ *$//' |
        grep -v '^$' |
        sort -u
)
if [[ ${#ALGS[@]} -eq 0 ]]; then
    echo "error: no signature algorithms reported by openssl" >&2
    exit 1
fi
for ALG in "${ALGS[@]}"; do
    KEY="$WORKDIR/${ALG// /_}.key"
    PUB="$WORKDIR/${ALG// /_}.pub"
    SIG="$WORKDIR/${ALG// /_}.sig"
    MSG="$WORKDIR/msg.txt"
    printf "testing %-30s ... " "$ALG"
    echo "Quantum-test" >"$MSG"
    keygen_status="FAIL"
    sign_status="FAIL"
    verify_status="FAIL"
    notes=""
    if openssl genpkey -algorithm "$ALG" -out "$KEY" "${PROVIDERS[@]}" 2>/dev/null; then
        keygen_status="OK"
        if openssl pkeyutl -sign -inkey "$KEY" -in "$MSG" -out "$SIG" \
            "${PROVIDERS[@]}" 2>/dev/null; then
            sign_status="OK"
            openssl pkey -in "$KEY" -pubout -out "$PUB" "${PROVIDERS[@]}" 2>/dev/null
            if openssl pkeyutl -verify -pubin -inkey "$PUB" -in "$MSG" \
                -sigfile "$SIG" "${PROVIDERS[@]}" 2>/dev/null; then
                verify_status="OK"
            fi
        fi
    fi
    if [[ $keygen_status != "OK" ]]; then
        notes="❌ Key-gen failed → algorithm not enabled or provider missing"
    elif [[ $sign_status != "OK" ]]; then
        notes="❌ Sign failed → ${ALG} may be KEM-only (no signing)"
    elif [[ $verify_status != "OK" ]]; then
        notes="❌ Verify failed → probable provider mismatch"
    else
        notes="✅ All good"
    fi
    printf "| \`%s\` | %s | %s | %s | %s |\n" \
        "$ALG" "$keygen_status" "$sign_status" "$verify_status" "$notes" >>"$REPORT"
    echo "done"
done
cat "$REPORT"
