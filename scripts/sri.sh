#!/bin/sh
# Print the Subresource Integrity hash for a CDN file. Usage: scripts/sri.sh <url>
[ -n "$1" ] || { echo "usage: scripts/sri.sh <url>" >&2; exit 1; }
printf 'sha384-%s\n' "$(curl -sfL "$1" | openssl dgst -sha384 -binary | openssl base64 -A)"
