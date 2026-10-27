#!/bin/sh
# Creates the NATS KV buckets libredesk binds to at startup. libredesk never creates
# buckets itself, so run this (or provision the same buckets elsewhere) before starting it.
#
# Each bucket's max age only reclaims storage: libredesk enforces expiry itself, but refuses
# to start if a bucket's max age is shorter than the values it keeps there. Raise the
# sessions max age if app.server.session_lifetime is longer than 24h.
#
# Usage: NATS_URL=nats://localhost:4222 REPLICAS=1 ./scripts/nats-kv-buckets.sh
# Needs the nats CLI (e.g. the natsio/nats-box image).
set -eu

REPLICAS="${REPLICAS:-1}"

bucket() {
	if nats kv info "$1" >/dev/null 2>&1; then
		echo "bucket $1 exists"
		return
	fi
	nats kv add "$1" --ttl "$2" --history 1 --replicas "$REPLICAS" --storage file
}

bucket libredesk_sessions 24h
bucket libredesk_widget_sessions 4320h
bucket libredesk_hc_cache 30m
bucket libredesk_hc_feedback 24h
bucket libredesk_oauth_state 15m
bucket libredesk_page_visits 24h
bucket libredesk_otp_pending 10m
bucket libredesk_otp_state 30m
bucket libredesk_ratelimit 2m
