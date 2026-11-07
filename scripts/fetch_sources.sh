#!/usr/bin/env bash
# Shallow checkouts of the public wordlists this dataset is built from.
# A failed source is reported and skipped so one outage does not stop the sync.
set -u
cd "$(dirname "$0")/.."
mkdir -p _sources
export GIT_TERMINAL_PROMPT=0

clone_full() {
  local url="$1" dest="$2"
  echo "== clone $dest =="
  if git clone --depth 1 "$url" "$dest"; then
    return 0
  fi
  echo "WARN: could not clone $url"
  rm -rf "$dest"
}

clone_sparse() {
  local url="$1" dest="$2"
  shift 2
  echo "== sparse $dest =="
  if git clone --depth 1 --filter=blob:none --sparse "$url" "$dest" \
    && git -C "$dest" sparse-checkout set "$@"; then
    return 0
  fi
  echo "WARN: could not sparse-checkout $url"
  rm -rf "$dest"
}

clone_full "https://github.com/swisskyrepo/PayloadsAllTheThings.git" "_sources/PayloadsAllTheThings"
clone_sparse "https://github.com/danielmiessler/SecLists.git" "_sources/SecLists" \
  Fuzzing Passwords/Common-Credentials Passwords/Default-Credentials
clone_sparse "https://github.com/projectdiscovery/nuclei-templates.git" "_sources/nuclei-templates" \
  http/vulnerabilities http/misconfiguration http/exposures http/cves http/default-logins http/fuzzing dast
clone_full "https://github.com/payload-box/xss-payload-list.git" "_sources/xss-payload-list"
clone_full "https://github.com/D35m0nd142/LFISuite.git" "_sources/LFISuite"
clone_full "https://github.com/minimaxir/big-list-of-naughty-strings.git" "_sources/naughty-strings"
clone_sparse "https://github.com/commixproject/commix.git" "_sources/commix" \
  src/core/eval/payloads src/core/techniques data/txt
clone_sparse "https://github.com/sqlmapproject/sqlmap.git" "_sources/sqlmap" \
  data/xml data/txt
clone_sparse "https://github.com/fuzzdb-project/fuzzdb.git" "_sources/fuzzdb" \
  attack
clone_sparse "https://gitlab.com/exploit-database/exploitdb.git" "_sources/exploitdb" \
  exploits/php/webapps exploits/aspx exploits/jsp exploits/cfm

echo "Source checkouts ready."
