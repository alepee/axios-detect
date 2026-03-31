#!/usr/bin/env bash
# detect-axios.sh — Scan local filesystem for compromised axios versions
#
# Usage: ./detect-axios.sh [root_path]
#   root_path: directory to scan (default: /)
#
# Detects:
#   - axios@1.14.1 and axios@0.30.4 in lockfiles and installed node_modules
#   - plain-crypto-js dependency (the malicious dropper package)
#   - Related campaign packages (@shadanai/openclaw, @qqbrowser/openclaw-qbot)
#   - RAT payload files at known paths (persist after dropper self-cleanup)
#   - Running RAT processes and active C2 connections (domain + IP)
#   - C2 traces in system logs, DNS cache, proxy logs (incl. fake IE8 User-Agent)
#   - Malicious tarballs in npm cache

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

COMPROMISED_VERSION="1.14.1"
COMPROMISED_VERSION_0X="0.30.4"
MALICIOUS_DEP="plain-crypto-js"
# Related campaign packages (same attacker infrastructure)
RELATED_PKGS=("@shadanai/openclaw" "@qqbrowser/openclaw-qbot")
C2_DOMAIN="sfrclak.com"
C2_IP="142.11.206.73"
C2_PORT="8000"
# Known RAT payload paths (persist after dropper self-cleanup)
RAT_PATHS_DARWIN=("/Library/Caches/com.apple.act.mond")
RAT_PATHS_LINUX=("/tmp/ld.py")
# Known dropper temp file names (self-delete, but check anyway)
DROPPER_NAMES=("6202033.vbs" "6202033.ps1" "ld.py")
# Fake User-Agent used by the RAT for C2 beaconing
RAT_USER_AGENT="mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)"

ROOT="${1:-/}"
FOUND=0
SEVERITY="CLEAN"  # CLEAN → LATENT → INSTALLED → CONFIRMED

# Prune expression for find: skip virtual/network filesystems and system dirs
# that cannot contain node_modules or JS lockfiles.
FIND_PRUNE=(
  \( -fstype proc -o -fstype sysfs -o -fstype devtmpfs -o -fstype devpts
     -o -fstype tmpfs -o -fstype cgroup -o -fstype cgroup2
     -o -fstype fuse -o -fstype fuse.gvfsd-fuse
     -o -fstype nfs -o -fstype nfs4 -o -fstype cifs
     -o -path /etc -o -path /boot -o -path /lost+found
     -o -path /bin -o -path /sbin -o -path /usr/bin -o -path /usr/sbin
  \) -prune
)

escalate_severity() {
  local new="$1"
  case "$SEVERITY" in
    CLEAN)     SEVERITY="$new" ;;
    LATENT)    [[ "$new" != "LATENT" ]] && SEVERITY="$new" ;;
    INSTALLED) [[ "$new" == "CONFIRMED" ]] && SEVERITY="$new" ;;
  esac
}

log_alert() {
  echo -e "${RED}[ALERT]${RESET} $1"
  FOUND=$((FOUND + 1))
}

log_warn() {
  echo -e "${YELLOW}[WARN]${RESET} $1"
}

log_info() {
  echo -e "${GREEN}[OK]${RESET} $1"
}

echo -e "${BOLD}=== Axios Supply Chain Scanner (local) ===${RESET}"
echo "Scanning: ${ROOT}"
echo "Looking for: axios@${COMPROMISED_VERSION} / axios@${COMPROMISED_VERSION_0X} / ${MALICIOUS_DEP}"
echo "Also checking: related campaign packages, RAT payloads, C2 traces, npm cache"
echo ""

# --- 1. Scan installed node_modules/axios/package.json ---
echo -e "${BOLD}[1/6] Scanning installed axios packages in node_modules...${RESET}"

while IFS= read -r pkg_json; do
  version=$(grep -o '"version"\s*:\s*"[^"]*"' "$pkg_json" 2>/dev/null | head -1 | grep -o '[0-9][^"]*' || true)
  if [[ "$version" == "$COMPROMISED_VERSION" || "$version" == "$COMPROMISED_VERSION_0X" ]]; then
    log_alert "Compromised axios@${version} installed at: ${pkg_json}"
    # LATENT, not INSTALLED: the presence of axios itself doesn't mean plain-crypto-js
    # was installed and its postinstall executed. Step 3 checks for that specifically.
    escalate_severity "LATENT"
  fi

  # Check if plain-crypto-js is a dependency
  if grep -q "$MALICIOUS_DEP" "$pkg_json" 2>/dev/null; then
    log_alert "Malicious dependency '${MALICIOUS_DEP}' found in: ${pkg_json}"
    escalate_severity "LATENT"
  fi
done < <(find "$ROOT" \
  "${FIND_PRUNE[@]}" \
  -o -path '*/node_modules/axios/package.json' \
     -not -path '*/node_modules/*/node_modules/axios/package.json' \
     -print \
  2>/dev/null || true)

# --- 2. Scan lockfiles ---
echo -e "${BOLD}[2/6] Scanning lockfiles...${RESET}"

scan_lockfile() {
  local file="$1"
  local basename
  basename=$(basename "$file")
  local hit=0

  case "$basename" in
    package-lock.json)
      # JSON format: use Python for precise parsing
      if grep -q "axios" "$file" 2>/dev/null; then
        # Exit codes: 0=clean, 1=axios only, 2=malicious dep only, 3=both
        if python3 -c "
import json, sys
file_path, versions, malicious_dep = sys.argv[1], sys.argv[2].split(','), sys.argv[3]
rc = 0
try:
    with open(file_path) as f:
        lock = json.load(f)
    pkgs = lock.get('packages', lock.get('dependencies', {}))
    for key, val in pkgs.items():
        if 'axios' in key and val.get('version') in versions:
            rc |= 1
        if malicious_dep in key:
            rc |= 2
except Exception:
    pass
sys.exit(rc)
" "$file" "${COMPROMISED_VERSION},${COMPROMISED_VERSION_0X}" "$MALICIOUS_DEP" 2>/dev/null; then
          : # clean
        else
          local rc=$?
          if (( rc & 1 )); then
            log_alert "Compromised axios version in lockfile: ${file}"
            hit=1
          fi
          if (( rc & 2 )); then
            log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
            hit=1
          fi
        fi
      fi
      ;;

    yarn.lock)
      if grep -qE "^\"?axios@" "$file" 2>/dev/null; then
        if grep -A5 "^\"*axios@" "$file" 2>/dev/null | grep -qE "version:?\s+\"?(${COMPROMISED_VERSION}|${COMPROMISED_VERSION_0X})\"?"; then
          log_alert "Compromised axios version in lockfile: ${file}"
          hit=1
        fi
      fi
      if grep -q "$MALICIOUS_DEP" "$file" 2>/dev/null; then
        log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
        hit=1
      fi
      ;;

    pnpm-lock.yaml)
      # pnpm format: '/axios/1.14.1' or 'axios: 1.14.1'
      if grep -qE "['\"]/axios/(${COMPROMISED_VERSION}|${COMPROMISED_VERSION_0X})['\"]|axios:\s+(${COMPROMISED_VERSION}|${COMPROMISED_VERSION_0X})" "$file" 2>/dev/null; then
        log_alert "Compromised axios version in lockfile: ${file}"
        hit=1
      fi
      if grep -q "$MALICIOUS_DEP" "$file" 2>/dev/null; then
        log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
        hit=1
      fi
      ;;

    bun.lock)
      # bun.lock is JSONC — use JSON-aware pattern
      if grep -qE "\"axios\"[^}]*\"(${COMPROMISED_VERSION}|${COMPROMISED_VERSION_0X})\"" "$file" 2>/dev/null; then
        log_alert "Compromised axios version in lockfile: ${file}"
        hit=1
      fi
      if grep -q "$MALICIOUS_DEP" "$file" 2>/dev/null; then
        log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
        hit=1
      fi
      ;;

    bun.lockb)
      # bun.lockb is binary — strings are stored separately, not as JSON
      # Check that both "axios" and the compromised version appear in the file
      if grep -qa "axios" "$file" 2>/dev/null && \
         grep -qaE "(${COMPROMISED_VERSION}|${COMPROMISED_VERSION_0X})" "$file" 2>/dev/null; then
        log_alert "Compromised axios version in lockfile: ${file}"
        hit=1
      fi
      if grep -qa "$MALICIOUS_DEP" "$file" 2>/dev/null; then
        log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
        hit=1
      fi
      ;;
  esac

  if [[ $hit -eq 1 ]]; then
    escalate_severity "LATENT"
  fi

  return $hit
}

while IFS= read -r lockfile; do
  scan_lockfile "$lockfile" || true
done < <(find "$ROOT" \
  "${FIND_PRUNE[@]}" \
  -o \( -name 'package-lock.json' \
        -o -name 'yarn.lock' \
        -o -name 'pnpm-lock.yaml' \
        -o -name 'bun.lock' \
        -o -name 'bun.lockb' \) \
     -not -path '*/node_modules/*' \
     -print \
  2>/dev/null || true)

# --- 3. Check for malicious package installation ---
echo -e "${BOLD}[3/6] Scanning for malicious packages in node_modules...${RESET}"

while IFS= read -r mal_pkg; do
  log_alert "Malicious package installed: ${mal_pkg}"
  escalate_severity "INSTALLED"
done < <(find "$ROOT" \
  "${FIND_PRUNE[@]}" \
  -o -path "*node_modules/${MALICIOUS_DEP}/package.json" -print \
  2>/dev/null || true)

# Also check for related campaign packages
for related_pkg in "${RELATED_PKGS[@]}"; do
  while IFS= read -r rel_pkg; do
    log_alert "Related campaign package installed: ${rel_pkg}"
    escalate_severity "INSTALLED"
  done < <(find "$ROOT" \
    "${FIND_PRUNE[@]}" \
    -o -path "*node_modules/${related_pkg}/package.json" -print \
    2>/dev/null || true)
done

# --- 4. Scan for RAT payload files (persist after dropper self-cleanup) ---
echo -e "${BOLD}[4/6] Scanning for RAT payload files...${RESET}"

ARTIFACT_FOUND=false
OS_TYPE="$(uname)"

# 4a. Check known RAT binary/script paths by platform
if [[ "$OS_TYPE" == "Darwin" ]]; then
  for rat_path in "${RAT_PATHS_DARWIN[@]}"; do
    if [[ -f "$rat_path" ]]; then
      log_alert "RAT payload found: ${rat_path}"
      ARTIFACT_FOUND=true
      # Verify it's not legitimately signed by Apple
      if command -v codesign &>/dev/null; then
        if ! codesign -v "$rat_path" 2>/dev/null; then
          log_alert "  File is NOT signed by Apple (expected for RAT)"
        fi
      fi
    fi
  done
elif [[ "$OS_TYPE" == "Linux" ]]; then
  for rat_path in "${RAT_PATHS_LINUX[@]}"; do
    if [[ -f "$rat_path" ]]; then
      log_alert "RAT payload found: ${rat_path}"
      ARTIFACT_FOUND=true
    fi
  done
fi

# 4b. Check for Windows payload paths (when running under WSL)
if [[ "$OS_TYPE" == "Linux" ]] && [[ -d /mnt/c/ProgramData ]]; then
  if [[ -f /mnt/c/ProgramData/wt.exe ]]; then
    log_alert "RAT payload found: /mnt/c/ProgramData/wt.exe (Windows via WSL)"
    ARTIFACT_FOUND=true
  fi
fi

# 4c. Check temp directories for known dropper file names
TEMP_DIRS=("/tmp" "/var/tmp")
[[ -n "${TMPDIR:-}" ]] && TEMP_DIRS+=("$TMPDIR")

if [[ "$OS_TYPE" == "Darwin" ]]; then
  user_tmp=$(getconf DARWIN_USER_TEMP_DIR 2>/dev/null || true)
  [[ -n "$user_tmp" ]] && TEMP_DIRS+=("$user_tmp")
fi

for tmp_dir in "${TEMP_DIRS[@]}"; do
  [[ -d "$tmp_dir" ]] || continue
  # Check for exact known dropper filenames
  for dropper_name in "${DROPPER_NAMES[@]}"; do
    while IFS= read -r dropper_file; do
      log_alert "Dropper artifact found: ${dropper_file}"
      ARTIFACT_FOUND=true
    done < <(find "$tmp_dir" -maxdepth 2 -name "$dropper_name" -type f 2>/dev/null || true)
  done
  # Also check for the generic patterns (catch variants)
  while IFS= read -r suspicious_file; do
    log_alert "Suspicious recent file in temp directory: ${suspicious_file}"
    ARTIFACT_FOUND=true
  done < <(find "$tmp_dir" -maxdepth 2 -type f \
    \( -name "*.sh" -o -name "*.bat" -o -name "*.cmd" -o -name "*.ps1" -o -perm /111 \) \
    -mtime -2 \
    2>/dev/null | grep -iE "crypto|axios|plain|payload|dropper" || true)
done

# --- 5. Scan for network/process/log artifacts ---
echo -e "${BOLD}[5/6] Scanning for C2 network traces and suspicious processes...${RESET}"

# 5a. Check for running RAT processes
if command -v pgrep &>/dev/null; then
  # macOS: RAT runs from /Library/Caches/com.apple.act.mond
  if pgrep -f "com.apple.act.mond" &>/dev/null; then
    log_alert "Running process matches RAT: com.apple.act.mond"
    ARTIFACT_FOUND=true
  fi
  # Linux: python3 /tmp/ld.py orphaned to PID 1
  if pgrep -f "/tmp/ld.py" &>/dev/null; then
    log_alert "Running process matches RAT: python3 /tmp/ld.py"
    ARTIFACT_FOUND=true
  fi
  # Windows payload name via WSL
  if pgrep -f "wt.exe" &>/dev/null; then
    log_warn "Process 'wt.exe' is running (may be Windows Terminal or the RAT — verify manually)"
  fi
fi

# 5b. Check for active network connections to C2 (domain and IP)
if command -v ss &>/dev/null; then
  if ss -tnp 2>/dev/null | grep -qE "${C2_IP}|:${C2_PORT}" 2>/dev/null; then
    log_alert "Active connection to C2 IP ${C2_IP} or port ${C2_PORT} detected (ss)"
    ARTIFACT_FOUND=true
  fi
elif command -v lsof &>/dev/null; then
  if lsof -i "@${C2_IP}" 2>/dev/null | grep -q . 2>/dev/null; then
    log_alert "Active connection to C2 IP ${C2_IP} detected (lsof)"
    ARTIFACT_FOUND=true
  fi
  if lsof -i ":${C2_PORT}" 2>/dev/null | grep -qE "${C2_DOMAIN}|${C2_IP}" 2>/dev/null; then
    log_alert "Active connection to C2 server on port ${C2_PORT} detected (lsof)"
    ARTIFACT_FOUND=true
  fi
fi

# 5c. Check for C2 domain/IP in DNS cache and system logs
if [[ "$OS_TYPE" == "Darwin" ]] && command -v log &>/dev/null; then
  echo "  Checking macOS unified log for C2 traces (this may take a moment)..."
  if timeout 30 log show --predicate "processImagePath contains 'mDNSResponder'" --last 48h 2>/dev/null \
    | grep -qE "${C2_DOMAIN}|${C2_IP}" 2>/dev/null; then
    log_alert "C2 indicator found in macOS DNS logs (${C2_DOMAIN} or ${C2_IP})"
    ARTIFACT_FOUND=true
  fi
else
  # Check common Linux log locations
  for logfile in /var/log/syslog /var/log/messages /var/log/kern.log; do
    if [[ -f "$logfile" ]]; then
      if grep -qE "${C2_DOMAIN}|${C2_IP}" "$logfile" 2>/dev/null; then
        log_alert "C2 indicator found in ${logfile}"
        ARTIFACT_FOUND=true
      fi
    fi
  done
  # Check journald if available
  if command -v journalctl &>/dev/null; then
    if journalctl --since "48 hours ago" --no-pager -q 2>/dev/null \
      | grep -qE "${C2_DOMAIN}|${C2_IP}" 2>/dev/null; then
      log_alert "C2 indicator found in journald logs"
      ARTIFACT_FOUND=true
    fi
  fi
fi

# 5d. Check for the RAT's fake User-Agent in proxy/access logs (if readable)
for access_log in /var/log/squid/access.log /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log; do
  if [[ -f "$access_log" ]] && [[ -r "$access_log" ]]; then
    if grep -qi "msie 8.0.*windows nt 5.1.*trident/4.0" "$access_log" 2>/dev/null; then
      log_alert "RAT User-Agent signature found in ${access_log}"
      ARTIFACT_FOUND=true
    fi
  fi
done

# --- 6. Check npm cache for malicious tarballs ---
echo -e "${BOLD}[6/6] Scanning npm cache for compromised packages...${RESET}"

NPM_CACHE_DIR=""
if command -v npm &>/dev/null; then
  NPM_CACHE_DIR=$(npm config get cache 2>/dev/null || true)
fi
[[ -z "$NPM_CACHE_DIR" ]] && NPM_CACHE_DIR="${HOME}/.npm"

if [[ -d "$NPM_CACHE_DIR" ]]; then
  # Check _cacache content for plain-crypto-js references
  if grep -rq "${MALICIOUS_DEP}" "${NPM_CACHE_DIR}/_cacache/" 2>/dev/null; then
    log_alert "Malicious package '${MALICIOUS_DEP}' found in npm cache: ${NPM_CACHE_DIR}"
    log_warn "  Run 'npm cache clean --force' after investigation to remove cached malicious tarballs"
    escalate_severity "INSTALLED"
  fi
  # Check for related campaign packages in cache
  for related_pkg in "${RELATED_PKGS[@]}"; do
    if grep -rq "${related_pkg}" "${NPM_CACHE_DIR}/_cacache/" 2>/dev/null; then
      log_alert "Related campaign package '${related_pkg}' found in npm cache"
      escalate_severity "INSTALLED"
    fi
  done
else
  log_warn "npm cache directory not found at ${NPM_CACHE_DIR} — skipping cache check"
fi

if [[ "$ARTIFACT_FOUND" == true ]]; then
  escalate_severity "CONFIRMED"
fi

# --- Summary & Guidance ---
echo ""
echo -e "${BOLD}=== Scan Complete ===${RESET}"
echo -e "Findings: ${FOUND} indicator(s) | Severity: ${BOLD}${SEVERITY}${RESET}"
echo ""

case "$SEVERITY" in
  CLEAN)
    log_info "No compromised axios versions or malicious dependencies detected."
    echo ""
    echo -e " ${BOLD}Best practice:${RESET} pin exact dependency versions in package.json to prevent"
    echo "  supply chain attacks from silently upgrading to compromised versions."
    exit 0
    ;;

  LATENT)
    echo -e "${YELLOW}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${YELLOW}${BOLD} SEVERITY: LATENT — Compromised version in lockfile, not yet installed${RESET}"
    echo -e "${YELLOW}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e " ${BOLD}TL;DR:${RESET} The compromised axios version is referenced in your lockfile but has"
    echo "  not been installed yet. Clean the lockfile and pin axios to a safe version"
    echo "  before running any install command."
    echo ""
    echo -e " ${BOLD}Step-by-step remediation:${RESET}"
    echo ""
    echo "  1. Pin axios to a safe version in package.json (1.14.0 for 1.x, 0.30.3 for 0.x)"
    echo "     → This prevents the compromised version from being resolved on next install."
    echo ""
    echo "  2. Delete the compromised lockfile"
    echo "     → The lockfile pins the malicious version; it must be regenerated clean."
    echo ""
    echo "  3. Delete node_modules/ directory"
    echo "     → Ensures no cached resolution of the compromised dependency tree."
    echo ""
    echo "  4. Run a fresh install (npm install / bun install / yarn / pnpm install)"
    echo "     → Regenerates a clean lockfile with the safe version."
    echo ""
    echo "  5. Verify: search the new lockfile for \"plain-crypto-js\""
    echo "     → It should NOT appear. If it does, the version pin did not take effect."
    echo ""
    echo "  6. Commit the cleaned lockfile."
    echo ""
    echo -e " ${BOLD}Best practice:${RESET} pin exact dependency versions in package.json to prevent"
    echo "  future supply chain attacks from silently upgrading to compromised versions."
    exit 1
    ;;

  INSTALLED)
    echo -e "${RED}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${RED}${BOLD} SEVERITY: INSTALLED — Malicious package was installed (infection probable)${RESET}"
    echo -e "${RED}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e " ${BOLD}TL;DR:${RESET} The malicious package plain-crypto-js was found in node_modules."
    echo "  The postinstall dropper has likely executed. Treat this as an active infection."
    echo -e "  ${RED}Rotate ALL secrets immediately and alert your security team.${RESET}"
    echo ""
    echo -e " ${YELLOW}⚠ WARNING:${RESET} The malware deletes its own artifacts after execution."
    echo "  Absence of OS-level traces does NOT mean the system is clean."
    echo ""
    echo -e " ${BOLD}Step-by-step remediation:${RESET}"
    echo ""
    echo "  1. DO NOT delete node_modules yet"
    echo "     → Preserve evidence for forensic analysis if needed."
    echo ""
    echo "  2. Manually inspect temp directories for dropper artifacts:"
    echo "     - macOS/Linux: /tmp, \$TMPDIR, /var/tmp"
    echo "     - Windows: C:\\ProgramData"
    echo "     → Look for recently created executables or scripts you don't recognize."
    echo ""
    echo "  3. Check for network connections to the C2 server:"
    echo "     - Search logs/connections for: ${C2_DOMAIN} or port 8000"
    echo "     → Confirms whether the RAT payload was able to phone home."
    echo ""
    echo "  4. Rotate ALL secrets and credentials accessible from this environment:"
    echo "     - .env files, CI/CD tokens, API keys, SSH keys, cloud credentials"
    echo "     → The RAT had potential access to everything on this machine."
    echo ""
    echo "  5. Alert your security team and the rest of the organization."
    echo "     → Other machines/environments may also be affected."
    echo ""
    echo "  6. Clean the npm cache:"
    echo "     - Run: npm cache clean --force"
    echo "     → Removes cached malicious tarballs that would re-infect on reinstall."
    echo ""
    echo "  7. Clean the lockfile:"
    echo "     - Pin axios to a safe version (1.14.0 / 0.30.3)"
    echo "     - Delete lockfile and node_modules/, reinstall, verify no plain-crypto-js"
    echo ""
    echo "  8. Consider the machine compromised until proven otherwise."
    echo "     → Audit access logs for services this machine connected to."
    echo ""
    echo -e " ${BOLD}Best practice:${RESET} pin exact dependency versions in package.json to prevent"
    echo "  future supply chain attacks from silently upgrading to compromised versions."
    exit 1
    ;;

  CONFIRMED)
    echo -e "${RED}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${RED}${BOLD} SEVERITY: CONFIRMED — Malware execution artifacts detected${RESET}"
    echo -e "${RED}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e " ${BOLD}TL;DR:${RESET} The RAT payload was deployed on this machine. This system is"
    echo -e "  compromised. ${RED}Rotate ALL secrets NOW and alert your security team immediately.${RESET}"
    echo ""
    echo -e " ${BOLD}Step-by-step remediation:${RESET}"
    echo ""
    echo "  1. Disconnect the machine from the network if possible."
    echo "     → Prevents further data exfiltration via the C2 channel."
    echo ""
    echo "  2. DO NOT delete node_modules or artifacts yet."
    echo "     → Preserve all evidence for forensic analysis."
    echo ""
    echo "  3. Rotate ALL secrets and credentials — not just on this machine:"
    echo "     - .env files, CI/CD tokens, API keys, SSH keys, GPG keys, cloud credentials"
    echo "     - Any service this machine had access to (AWS, GCP, GitHub, etc.)"
    echo "     → The RAT had full access to the local environment."
    echo ""
    echo "  4. Alert your security team and the rest of the organization IMMEDIATELY."
    echo "     → This is a confirmed breach, not a potential one."
    echo ""
    echo "  5. Audit recent activity:"
    echo "     - Review git commits made from this machine (the attacker may have had"
    echo "       access to SSH/GPG keys)"
    echo "     - Check access logs of cloud services, CI/CD platforms, internal tools"
    echo "     → Determine the blast radius of the compromise."
    echo ""
    echo "  6. Evaluate a full machine wipe and rebuild."
    echo "     → The safest remediation for a confirmed RAT infection."
    echo ""
    echo "  7. After rebuild: clean npm cache and lockfile:"
    echo "     - Run: npm cache clean --force"
    echo "     - Pin axios to a safe version (1.14.0 / 0.30.3)"
    echo "     - Delete lockfile and node_modules/, reinstall, verify no plain-crypto-js"
    echo ""
    echo -e " ${BOLD}Best practice:${RESET} pin exact dependency versions in package.json to prevent"
    echo "  future supply chain attacks from silently upgrading to compromised versions."
    exit 1
    ;;
esac
