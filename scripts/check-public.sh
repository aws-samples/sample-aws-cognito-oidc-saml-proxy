#!/usr/bin/env bash
#
# check-public.sh — fail if the repository contains content that must not be
# published to the public repository: internal-only hostnames and tool names,
# real AWS account IDs, local state and scan output, or private identifiers.
#
# Usage:
#   scripts/check-public.sh                 scan tracked files in the working tree
#   scripts/check-public.sh --cached        scan the index (what the next commit holds)
#   scripts/check-public.sh --tree <rev>    scan the tree of a commit
#   scripts/check-public.sh --range <a..b>  also scan the commit messages in a range
#   scripts/check-public.sh --message <f>   scan only a commit message file
#
# Checks:
#   1. Forbidden paths    agent/IDE state, scan output, Terraform state and plans,
#                         env files, keys, decks, real per-env tfvars/backends,
#                         and files that are kept out of this repository
#                         (.gitlab-ci.yml, sync/).
#                         *.example is allowed.
#   2. Internal names     internal-only hostnames and tool names.
#   3. Account IDs        12-digit IDs in ARNs or ECR hosts, other than the
#                         documentation placeholders in ALLOWED_ACCOUNTS.
#   4. Private patterns   extra extended regexes that are themselves private
#                         (aliases, personal domains, real account IDs), so they
#                         are never committed. Read from:
#                           $PUBLIC_CHECK_PATTERNS        newline-separated
#                           $PUBLIC_CHECK_PATTERNS_FILE   a file, one per line
#                                                         (default: .public-check-patterns,
#                                                         gitignored; # comments allowed)
#
# Exit codes: 0 clean, 1 findings, 2 usage or git error.

set -euo pipefail

usage() { sed -n '3,/^# Exit codes/p' "$0" | sed 's/^# \{0,1\}//'; }

MODE="worktree"
TREE=""
RANGE=""
MESSAGE_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --cached) MODE="cached"; shift ;;
    --tree)
      [ $# -ge 2 ] || { echo "check-public: --tree needs a revision" >&2; exit 2; }
      MODE="tree"; TREE="$2"; shift 2 ;;
    --range)
      [ $# -ge 2 ] || { echo "check-public: --range needs a revision range" >&2; exit 2; }
      RANGE="$2"; shift 2 ;;
    --message)
      [ $# -ge 2 ] || { echo "check-public: --message needs a file" >&2; exit 2; }
      MODE="message"; MESSAGE_FILE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "check-public: unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
done

cd "$(git rev-parse --show-toplevel)"

# --- Patterns ----------------------------------------------------------------

FORBIDDEN_PATHS='(^|/)(\.gitlab-ci\.yml|\.kiro/|\.claude/|\.ash/|scan-results/|deploy-state/)|\.tfstate(\.|$)|\.tfplan$|(^|/)\.env(\.[^/]*)?$|\.pem$|\.pptx$|^docs/threat-model\.md$|^infra/env/[^/]+\.(tfvars|backend\.hcl)$|^sync/'

# Matched case-insensitively. Holmes is matched as a whole word only.
INTERNAL_NAMES='gitlab\.aws\.dev|\.aws\.dev|code\.amazon\.com|(^|[^[:alnum:].-])w\.amazon\.com|\.a2z\.com|corp\.amazon\.com|\.amazon\.dev|quip-amazon\.com|phonetool|issues\.amazon\.com|sim\.amazon\.com|ant\.amazon\.com|isengard|(^|[^[:alnum:]_])midway([^[:alnum:]_]|$)|Probe/Holmes|(^|[^[:alnum:]_])Holmes([^[:alnum:]_]|$)'

ACCOUNT_REFS='arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}:|[0-9]{12}\.dkr\.ecr\.'

# Placeholder account IDs used by the docs and tests.
ALLOWED_ACCOUNTS="123456789012 111122223333 444455556666 777788889999 999988887777 111111111111 222222222222"

# Lockfiles carry hashes that can look like anything; this script names the
# patterns it looks for; .gitleaksignore lists historical fingerprints.
EXCLUDES=(
  ':(exclude,glob)**/go.sum'
  ':(exclude,glob)**/package-lock.json'
  ':(exclude).gitleaksignore'
  ':(exclude)scripts/check-public.sh'
)

PRIVATE_FILE="${PUBLIC_CHECK_PATTERNS_FILE:-.public-check-patterns}"
PRIVATE_ARGS=()
add_private_patterns() {
  local p
  while IFS= read -r p || [ -n "$p" ]; do
    p="${p%$'\r'}"
    case "$p" in ''|'#'*) continue ;; esac
    PRIVATE_ARGS+=(-e "$p")
  done
}
if [ -f "$PRIVATE_FILE" ]; then
  add_private_patterns < "$PRIVATE_FILE"
elif [ -n "${PUBLIC_CHECK_PATTERNS_FILE:-}" ]; then
  echo "check-public: PUBLIC_CHECK_PATTERNS_FILE=$PRIVATE_FILE does not exist" >&2
  exit 2
fi
if [ -n "${PUBLIC_CHECK_PATTERNS:-}" ]; then
  add_private_patterns <<< "$PUBLIC_CHECK_PATTERNS"
fi
PRIVATE_COUNT=$(( ${#PRIVATE_ARGS[@]} / 2 ))

# --- Helpers -----------------------------------------------------------------

FINDINGS=0
report() { # report <title> <lines>
  [ -n "$2" ] || return 0
  local n
  n=$(printf '%s\n' "$2" | wc -l | tr -d ' ')
  FINDINGS=$((FINDINGS + n))
  printf '\n✗ %s (%s)\n' "$1" "$n"
  printf '%s\n' "$2" | cut -c1-200 | sed 's/^/    /'
}

# git grep over the selected source. Exit 1 (no match) is not an error.
grep_source() {
  local rc=0
  case "$MODE" in
    worktree) git grep --no-color -I -n -E "$@" -- . "${EXCLUDES[@]}" || rc=$? ;;
    cached)   git grep --no-color -I -n -E --cached "$@" -- . "${EXCLUDES[@]}" || rc=$? ;;
    tree)     git grep --no-color -I -n -E "$@" "$TREE" -- . "${EXCLUDES[@]}" || rc=$? ;;
  esac
  if [ "$rc" -gt 1 ]; then
    echo "check-public: git grep failed (exit $rc)" >&2
    return 2
  fi
}

list_paths() {
  case "$MODE" in
    worktree|cached) git ls-files ;;
    tree) git ls-tree -r --name-only "$TREE" ;;
  esac
}

# Scan text on stdin; prints "<prefix><line>" for each hit.
scan_text() { # scan_text <prefix>
  local rc=0 out
  out="$(grep -n -i -E -e "$INTERNAL_NAMES" ${PRIVATE_ARGS[@]+"${PRIVATE_ARGS[@]}"})" || rc=$?
  [ "$rc" -le 1 ] || { echo "check-public: grep failed (exit $rc)" >&2; return 2; }
  [ -z "$out" ] || printf '%s\n' "$out" | sed "s|^|$1|"
}

# --- Checks ------------------------------------------------------------------

# Each result is assigned before it is reported so that a git or grep failure
# inside the command substitution stops the script (set -e) instead of being
# read as "no findings".

if [ "$MODE" = "message" ]; then
  [ -f "$MESSAGE_FILE" ] || { echo "check-public: no such file: $MESSAGE_FILE" >&2; exit 2; }
  # Skip the comment lines git adds to the editor template.
  out="$(grep -v '^#' "$MESSAGE_FILE" | scan_text "message:")"
  report "Commit message contains internal or private references" "$out"
else
  if [ "$MODE" = "tree" ]; then
    git rev-parse --verify --quiet "$TREE^{tree}" >/dev/null ||
      { echo "check-public: not a revision: $TREE" >&2; exit 2; }
  fi

  paths="$(list_paths)"
  out="$(printf '%s\n' "$paths" | grep -E "$FORBIDDEN_PATHS" | grep -vE '\.example$' || true)"
  report "Forbidden paths are tracked" "$out"

  out="$(grep_source -i -e "$INTERNAL_NAMES")"
  report "Internal hostnames or tool names" "$out"

  refs="$(grep_source -o -e "$ACCOUNT_REFS")"
  out=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    id="$(printf '%s\n' "$line" | grep -oE '[0-9]{12}(:|\.dkr\.ecr\.)$' | grep -oE '^[0-9]{12}' || true)"
    case " $ALLOWED_ACCOUNTS " in *" $id "*) continue ;; esac
    out="${out:+$out
}$line"
  done <<< "$refs"
  report "AWS account IDs that are not documentation placeholders" "$out"

  if [ "$PRIVATE_COUNT" -gt 0 ]; then
    out="$(grep_source -i "${PRIVATE_ARGS[@]}")"
    report "Private patterns" "$out"
  fi
fi

if [ -n "$RANGE" ]; then
  commits="$(git rev-list "$RANGE")" ||
    { echo "check-public: bad revision range: $RANGE" >&2; exit 2; }
  out=""
  for c in $commits; do
    hits="$(git log -1 --format=%B "$c" | scan_text "$(git rev-parse --short "$c"):")"
    [ -z "$hits" ] || out="${out:+$out
}$hits"
  done
  report "Commit messages in $RANGE contain internal or private references" "$out"
fi

# --- Result ------------------------------------------------------------------

scope="$MODE${TREE:+ $TREE}${RANGE:+, messages in $RANGE}"
if [ "$FINDINGS" -gt 0 ]; then
  printf '\ncheck-public: %s finding(s) in %s. Remove them before publishing.\n' "$FINDINGS" "$scope" >&2
  exit 1
fi
printf 'check-public: clean (%s; %s private pattern(s) loaded)\n' "$scope" "$PRIVATE_COUNT"
