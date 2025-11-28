#!/usr/bin/env bash

exec > pq_report.txt 2>&1

set -uo pipefail

echo "Debug: Script started"
echo "Debug: Arguments: $@"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <script_file>"
    exit 1
fi

TARGET_FILE="$1"
echo "Debug: Target file set to $TARGET_FILE"

if [ ! -f "$TARGET_FILE" ]; then
    CURRENT_DIR=$(pwd)
    if [ -f "$CURRENT_DIR/$TARGET_FILE" ]; then
        TARGET_FILE="$CURRENT_DIR/$TARGET_FILE"
        echo "Debug: Updated target file to $TARGET_FILE"
    else
        echo "Error: File '$TARGET_FILE' not found."
        exit 1
    fi
fi

echo "Running PQ check on: $TARGET_FILE"
echo "Debug: File size: $(wc -c < "$TARGET_FILE") bytes"

ALGORITHMS=(
    bikel1 p256_bikel1 x25519_bikel1 bikel3 p384_bikel3 x448_bikel3 bikel5 p521_bikel5
    frodo640aes p256_frodo640aes x25519_frodo640aes frodo640shake p256_frodo640shake x25519_frodo640shake
    frodo976aes p384_frodo976aes x448_frodo976aes frodo976shake p384_frodo976shake x448_frodo976shake
    frodo1344aes p521_frodo1344aes frodo1344shake p521_frodo1344shake
    hqc128 p256_hqc128 x25519_hqc128 hqc192 p384_hqc192 x448_hqc192 hqc256 p521_hqc256
    mlkem512 p256_mlkem512 x25519_mlkem512 mlkem768 p384_mlkem768 x448_mlkem768 X25519MLKEM768 SecP256r1MLKEM768
    mlkem1024 p521_mlkem1024 SecP384r1MLKEM1024
    mldsa44 p256_mldsa44 rsa3072_mldsa44 mldsa44_pss2048 mldsa44_rsa2048 mldsa44_ed25519 mldsa44_p256 mldsa44_bp256
    mldsa65 p384_mldsa65 mldsa65_pss3072 mldsa65_rsa3072 mldsa65_p256 mldsa65_bp256 mldsa65_ed25519
    mldsa87 p521_mldsa87 mldsa87_p384 mldsa87_bp384 mldsa87_ed448
    falcon512 p256_falcon512 rsa3072_falcon512 falconpadded512 p256_falconpadded512 rsa3072_falconpadded512
    falcon1024 p521_falcon1024 falconpadded1024 p521_falconpadded1024
    sphincssha2128fsimple p256_sphincssha2128fsimple rsa3072_sphincssha2128fsimple sphincssha2128ssimple
    p256_sphincssha2128ssimple rsa3072_sphincssha2128ssimple sphincssha2192fsimple p384_sphincssha2192fsimple
    sphincssha2192ssimple p384_sphincssha2192ssimple sphincssha2256fsimple p521_sphincssha2256fsimple
    sphincssha2256ssimple p521_sphincssha2256ssimple
    sphincsshake128fsimple p256_sphincsshake128fsimple rsa3072_sphincsshake128fsimple sphincsshake128ssimple
    p256_sphincsshake128ssimple rsa3072_sphincsshake128ssimple sphincsshake192fsimple p384_sphincsshake192fsimple
    sphincsshake192ssimple p384_sphincsshake192ssimple sphincsshake256fsimple p521_sphincsshake256fsimple
    sphincsshake256ssimple p521_sphincsshake256ssimple
    mayo1 p256_mayo1 mayo2 p256_mayo2 mayo3 p384_mayo3 mayo5 p521_mayo5
    CROSSrsdp128balanced CROSSrsdp128fast CROSSrsdp128small CROSSrsdp192balanced CROSSrsdp192fast CROSSrsdp192small
    CROSSrsdp256small CROSSrsdpg128balanced CROSSrsdpg128fast CROSSrsdpg128small CROSSrsdpg192balanced
    CROSSrsdpg192fast CROSSrsdpg192small CROSSrsdpg256balanced CROSSrsdpg256fast CROSSrsdpg256small
    OV_Is p256_OV_Is OV_Ip p256_OV_Ip OV_III p384_OV_III OV_V p521_OV_V
    OV_Is_pkc p256_OV_Is_pkc OV_Ip_pkc p256_OV_Ip_pkc OV_III_pkc p384_OV_III_pkc OV_V_pkc p521_OV_V_pkc
    OV_Is_pkc_skc p256_OV_Is_pkc_skc OV_Ip_pkc_skc p256_OV_Ip_pkc_skc OV_III_pkc_skc p384_OV_III_pkc_skc
    OV_V_pkc_skc p521_OV_V_pkc_skc
)

echo "Debug: Algorithms loaded"
echo "Debug: Number of algorithms: ${#ALGORITHMS[@]}"

# Initialize associative arrays
declare -A found count
echo "Debug: Initialized associative arrays"

for alg in "${ALGORITHMS[@]}"; do
    count["$alg"]=0
done
echo "Debug: Populated count array"

echo "Debug: About to process file"
normalized=$(tr -cs '[:alnum:]_' '\n' < "$TARGET_FILE")
echo "Debug: File normalized"

# Count algorithm occurrences
while read -r word; do
    if [[ -v "count[$word]" ]]; then
        ((count["$word"]++))
    fi
done <<< "$normalized"
echo "Debug: Counted algorithm occurrences"

echo -e "\n🔍 Post-Quantum Algorithm Report for $TARGET_FILE"
echo "=============================================="

# Generate report
for alg in "${ALGORITHMS[@]}"; do
    if [[ ${count["$alg"]} -eq 0 ]]; then
        echo -e "❌ MISSING: $alg"
    elif [[ ${count["$alg"]} -eq 1 ]]; then
        echo -e "✅ Present: $alg"
        found["$alg"]=1
    else
        echo -e "⚠️ DUPLICATE (${count["$alg"]}): $alg"
        found["$alg"]=1
    fi
done
echo "Debug: Generated algorithm status report"

echo "=============================================="

# Calculate statistics
missing=0
for alg in "${ALGORITHMS[@]}"; do
    if [[ -z "${found["$alg"]+set}" ]]; then
        ((missing++))
    fi
done

echo "✅ Total Present: ${#found[@]}"
echo "❌ Total Missing: $missing"

total_occurrences=0
for alg in "${ALGORITHMS[@]}"; do
    total_occurrences=$((total_occurrences + count["$alg"]))
done
duplicates=$((total_occurrences - ${#found[@]}))


OQS_IDS_FILE="$(dirname "$0")/oqs_id.sh"

if [[ ! -f "$OQS_IDS_FILE" ]]; then
    echo "❌ Could not find oqs_id.sh at $OQS_IDS_FILE"
    exit 1
fi

declare -A oids_seen
errors=0

echo "🔍 Validating OQS OID variables from: $OQS_IDS_FILE"

# shellcheck disable=SC1090
source "$OQS_IDS_FILE"

for var in $(grep -oP '^export\s+OQS_OID_[A-Z0-9_]+(?==)' "$OQS_IDS_FILE"); do
    oid="${!var:-}"

    if [[ -z "$oid" ]]; then
        echo "⚠️  [MISSING] $var is unset or empty"
        ((errors++))
        continue
    fi

    if ! [[ "$oid" =~ ^([0-9]+)(\.[0-9]+)*$ ]]; then
        echo "❌ [INVALID] $var has malformed OID: $oid"
        ((errors++))
    fi

    if [[ -n "${oids_seen["$oid"]+found}" ]]; then
        echo "❌ [DUPLICATE] $var has duplicate OID: $oid (already used by ${oids_seen["$oid"]})"
        ((errors++))
    fi

    oids_seen["$oid"]="$var"
done

if [[ $errors -eq 0 ]]; then
    echo "✅ All OQS_OID_* variables passed validation."
else
    echo "❌ Validation failed with $errors issue(s)."
    exit 1
fi

echo "⚠️ Total Duplicates: $duplicates"
echo "Debug: Script completed successfully"

