#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./pipeline.sh -s scope.txt -t target-name [-o output-dir]

Environment toggles:
  ENABLE_AMASS=1
  ENABLE_KATANA=1
  ENABLE_NUCLEI=1
  SKIP_CRTSH=1

This script expects tools like subfinder, assetfinder, httpx, gau, waybackurls,
katana, and nuclei to already be installed if you want those stages.
EOF
}

have() {
  command -v "$1" >/dev/null 2>&1
}

slugify_url() {
  local input="$1"
  printf '%s' "$input" | tr -c '[:alnum:]._-' '_'
}

SCOPE_FILE=""
TARGET_NAME=""
OUTPUT_ROOT="output"

while getopts ":s:t:o:h" opt; do
  case "$opt" in
    s) SCOPE_FILE="$OPTARG" ;;
    t) TARGET_NAME="$OPTARG" ;;
    o) OUTPUT_ROOT="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if [[ -z "$SCOPE_FILE" || -z "$TARGET_NAME" ]]; then
  usage
  exit 1
fi

if [[ ! -f "$SCOPE_FILE" ]]; then
  echo "Scope file not found: $SCOPE_FILE" >&2
  exit 1
fi

TARGET_ROOT="$OUTPUT_ROOT/$TARGET_NAME"
RUN_DIR="$TARGET_ROOT/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR"

PREVIOUS_RUN="$(find "$TARGET_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1 || true)"
if [[ "$PREVIOUS_RUN" == "$RUN_DIR" ]]; then
  PREVIOUS_RUN=""
fi

grep -v '^[[:space:]]*#' "$SCOPE_FILE" | sed '/^[[:space:]]*$/d' | sort -u > "$RUN_DIR/scope.txt"
cp "$RUN_DIR/scope.txt" "$RUN_DIR/subdomains.txt"

while IFS= read -r root; do
  base="${root#*.}"
  exact="${root#\*.}"

  if have subfinder; then
    subfinder -d "$exact" -silent >> "$RUN_DIR/subdomains.txt" || true
  fi

  if have assetfinder; then
    assetfinder --subs-only "$exact" >> "$RUN_DIR/subdomains.txt" || true
  fi

  if [[ "${ENABLE_AMASS:-0}" == "1" ]] && have amass; then
    amass enum -passive -norecursive -d "$exact" >> "$RUN_DIR/subdomains.txt" || true
  fi

  if [[ "${SKIP_CRTSH:-0}" != "1" ]] && have curl && have jq; then
    curl -fsSL "https://crt.sh/?q=%25.${exact}&output=json" \
      | jq -r '.[].name_value' 2>/dev/null \
      | tr '\n' '\n' \
      | sed 's/^\*\.//' >> "$RUN_DIR/subdomains.txt" || true
  fi
done < "$RUN_DIR/scope.txt"

sort -u "$RUN_DIR/subdomains.txt" -o "$RUN_DIR/subdomains.txt"

if have httpx; then
  httpx -silent -json < "$RUN_DIR/subdomains.txt" > "$RUN_DIR/live_hosts.jsonl" || true
  jq -r '.url // empty' "$RUN_DIR/live_hosts.jsonl" 2>/dev/null | sort -u > "$RUN_DIR/live_hosts.txt" || true
else
  : > "$RUN_DIR/live_hosts.jsonl"
  : > "$RUN_DIR/live_hosts.txt"
fi

: > "$RUN_DIR/urls.txt"
while IFS= read -r host; do
  domain="$(printf '%s' "$host" | awk -F/ '{print $3}')"
  if have gau; then
    gau --subs "$domain" >> "$RUN_DIR/urls.txt" || true
  fi
  if have waybackurls; then
    waybackurls "$domain" >> "$RUN_DIR/urls.txt" || true
  fi
  if [[ "${ENABLE_KATANA:-0}" == "1" ]] && have katana; then
    katana -u "$host" -silent >> "$RUN_DIR/urls.txt" || true
  fi
done < "$RUN_DIR/live_hosts.txt"

cat "$RUN_DIR/live_hosts.txt" >> "$RUN_DIR/urls.txt"
sort -u "$RUN_DIR/urls.txt" -o "$RUN_DIR/urls.txt"

awk -F'?' 'NF > 1 { print $2 }' "$RUN_DIR/urls.txt" \
  | tr '&' '\n' \
  | cut -d= -f1 \
  | sed '/^[[:space:]]*$/d;s/$/=/' \
  | sort -u > "$RUN_DIR/parameters.txt"

grep -Eiv '\.(png|jpg|jpeg|gif|svg|webp|css|woff2?|ttf|eot|ico|mp4|mp3|avi|mov|pdf|zip)(\?|$)' "$RUN_DIR/urls.txt" \
  | grep -Ei '(/api/|/admin|/auth|/login|/oauth|/callback|/redirect|/upload|/file|/debug|/internal|\?)' \
  | sort -u > "$RUN_DIR/priority_endpoints.txt" || true

if [[ "${ENABLE_NUCLEI:-0}" == "1" ]] && have nuclei; then
  nuclei -silent -no-color < "$RUN_DIR/priority_endpoints.txt" > "$RUN_DIR/nuclei.txt" || true
fi

if [[ -n "$PREVIOUS_RUN" ]]; then
  for artifact in subdomains live_hosts parameters priority_endpoints; do
    prev="$PREVIOUS_RUN/${artifact}.txt"
    curr="$RUN_DIR/${artifact}.txt"
    if [[ -f "$prev" && -f "$curr" ]]; then
      comm -13 <(sort "$prev") <(sort "$curr") > "$RUN_DIR/diff_${artifact}_added.txt" || true
      comm -23 <(sort "$prev") <(sort "$curr") > "$RUN_DIR/diff_${artifact}_removed.txt" || true
    fi
  done
fi

cat > "$RUN_DIR/run_summary.txt" <<EOF
target_name=$TARGET_NAME
run_dir=$RUN_DIR
previous_run=$PREVIOUS_RUN
subdomains=$(wc -l < "$RUN_DIR/subdomains.txt" | tr -d ' ')
live_hosts=$(wc -l < "$RUN_DIR/live_hosts.txt" | tr -d ' ')
urls=$(wc -l < "$RUN_DIR/urls.txt" | tr -d ' ')
parameters=$(wc -l < "$RUN_DIR/parameters.txt" | tr -d ' ')
priority_endpoints=$(wc -l < "$RUN_DIR/priority_endpoints.txt" | tr -d ' ')
EOF

echo "Artifacts written to: $RUN_DIR"
