#!/bin/sh
# The public live demo in one container: four provider receivers (Aurora also runs its network edge
# and serves the pirate site to its subscribers in reverse-proxy form), the licensed platform
# broadcasting $VIDEO (or a synthetic match), the pirate restreaming it, and Strack on a standalone
# match. Nothing is scripted: streams are loaded by hand in Cargar sitios.
#
# Environment: PIRATE_HOST (public name of the pirate site), PIRATE_URL (its public address),
# VIDEO (a recording mounted read-only), MATCH_NAME, END_MIN, INTAKE_TOKEN, STAFF_PASSWORD.
set -eu

PIRATE_HOST="${PIRATE_HOST:-pirata.example.com}"
PIRATE_URL="${PIRATE_URL:-https://$PIRATE_HOST}"
INTAKE_TOKEN="${INTAKE_TOKEN:-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
export STRACK_DEMO_STAFF_PASSWORD="${STAFF_PASSWORD:-$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
mkdir -p /data/logs
# Every start is a fresh demo: no orders, suspended accounts or cases from the previous run.
rm -rf /data/provider-*.json /data/subscribers.json /data/var

KICKOFF=$(python3 live-config.py)
echo "match kicked off at $KICKOFF"

start() {
  name="$1"; shift
  "$@" >"/data/logs/$name.log" 2>&1 &
}

start isp-aurora strack provider --id aurora --name "Conectividad Aurora" --listen 127.0.0.1:9101 \
  --kickoff "$KICKOFF" --accepts ip,dominio --data /data/provider-aurora.json \
  --gateway 0.0.0.0:19180 --gateway-site "$PIRATE_HOST=http://127.0.0.1:18200"
start isp-andina strack provider --id andina --name "Red Andina Telecom" --listen 127.0.0.1:9102 \
  --kickoff "$KICKOFF" --accepts ip,dominio --data /data/provider-andina.json
start isp-valle strack provider --id valle --name "FibraValle" --listen 127.0.0.1:9103 \
  --kickoff "$KICKOFF" --accepts dominio --data /data/provider-valle.json
start isp-cumbre strack provider --id cumbre --name "Cooperativa Cumbre Conecta" --listen 127.0.0.1:9104 \
  --kickoff "$KICKOFF" --accepts ip,dominio --data /data/provider-cumbre.json

if [ -n "${VIDEO:-}" ] && [ -f "$VIDEO" ]; then
  start platform strack demo platform --listen 0.0.0.0:18100 --data /data/subscribers.json --video "$VIDEO" --loop
else
  start platform strack demo platform --listen 0.0.0.0:18100 --data /data/subscribers.json
fi
start pirate strack demo pirate --listen 0.0.0.0:18200 --platform http://127.0.0.1:18100 \
  --site "$PIRATE_HOST" --public-url "$PIRATE_URL"

# The reader stays on public addresses: the pirate is loaded through its public name.
exec strack serve --config /data/match.json --state-dir /data/var --accounts /data/accounts.json \
  --platforms /data/platforms.json --intake-token "$INTAKE_TOKEN" --listen 0.0.0.0:13000 --secure-cookies
