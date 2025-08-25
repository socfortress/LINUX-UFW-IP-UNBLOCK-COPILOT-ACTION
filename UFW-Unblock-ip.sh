#!/bin/bash
set -eu

ScriptName="Unblock-IP"
LOG="/var/ossec/active-response/active-responses.log"
LogPath="/tmp/${ScriptName}.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
RunStart=$(date +%s)

WriteLog() {
  local level="$1"
  local message="$2"
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$ts][$level] $message" >&2
  echo "[$ts][$level] $message" >> "$LogPath"
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  local size_kb
  size_kb=$(du -k "$LogPath" | awk '{print $1}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  local i=$((LogKeep - 1))
  while [ $i -ge 0 ]; do
    [ -f "$LogPath.$i" ] && mv -f "$LogPath.$i" "$LogPath.$((i+1))"
    i=$((i - 1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

RotateLog
WriteLog "INFO" "=== SCRIPT START : $ScriptName ==="

# Prefer ARG1 from Velociraptor, fallback to positional $1
IP="${ARG1:-${1:-}}"

Status="error"
Reason="No IP provided"

if [ -z "${IP:-}" ]; then
  WriteLog "ERROR" "No IP address provided, exiting."
else
  if ! command -v ufw >/dev/null 2>&1; then
    WriteLog "ERROR" "ufw not installed or not in PATH"
    Status="failed"
    Reason="ufw not installed"
  else
    WriteLog "INFO" "Unblocking IP address: $IP"
    if ufw status | grep -qw "$IP"; then
      if ufw delete deny from "$IP" >/dev/null 2>&1; then
        WriteLog "INFO" "Unblocked IP $IP successfully"
        Status="unblocked"
        Reason="IP unblocked successfully"
      else
        WriteLog "ERROR" "Failed to unblock IP $IP"
        Status="failed"
        Reason="ufw command failed"
      fi
    else
      WriteLog "INFO" "IP $IP is not currently blocked"
      Status="not_blocked"
      Reason="IP was not blocked"
    fi
  fi
fi

# Build one-line NDJSON entry
Timestamp=$(date --iso-8601=seconds 2>/dev/null || date -Iseconds)
final_json=$(jq -n \
  --arg timestamp "$Timestamp" \
  --arg host "$HostName" \
  --arg action "$ScriptName" \
  --arg ip "$IP" \
  --arg status "$Status" \
  --arg reason "$Reason" \
  --argjson copilot_action true \
  '{timestamp:$timestamp,host:$host,action:$action,ip:$ip,status:$status,reason:$reason,copilot_action:$copilot_action}')

# Atomic overwrite with .new fallback
tmpfile=$(mktemp)
echo "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$LOG" 2>/dev/null; then
  mv -f "$tmpfile" "$LOG.new"
fi

Duration=$(( $(date +%s) - RunStart ))
WriteLog "INFO" "=== SCRIPT END : duration ${Duration}s ==="
