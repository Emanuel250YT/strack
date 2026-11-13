"""Writes the public live demo's configuration into /data: the match (kicked off now, or as far back as
the recording starts), the accounts without the administrator, and the platform registry.

Environment: MATCH_NAME, END_MIN, KICKOFF_OFFSET_S, PIRATE_HOST. Run by live-demo.sh."""
import datetime
import json
import os
import re

DATA = "/data"
os.makedirs(DATA, exist_ok=True)

with open("config/match.example.json", encoding="utf-8") as f:
    text = re.sub(r" \(ficticio\)", "", f.read())
config = json.loads(text)

end_min = int(os.environ.get("END_MIN", "600"))
offset = int(os.environ.get("KICKOFF_OFFSET_S", "60"))
kickoff = datetime.datetime.now(datetime.timezone.utc).astimezone() - datetime.timedelta(seconds=offset)
config["partido"]["inicio_iso"] = kickoff.isoformat(timespec="seconds")
config["partido"]["fin_min"] = end_min
if os.environ.get("MATCH_NAME"):
    config["partido"]["nombre"] = os.environ["MATCH_NAME"]
# A public demo stays live for the day: the first judge covers the first half of it.
half = end_min // 2
for shift in config["juzgados"]["turnos"]:
    if shift["desde_min"] < 0:
        shift["hasta_min"] = half
    else:
        shift["desde_min"] = half
        shift["hasta_min"] = end_min + 240

with open(os.path.join(DATA, "match.json"), "w", encoding="utf-8") as f:
    json.dump(config, f, ensure_ascii=False, indent=2)

# No administrator on a public deployment: the demo passwords are published.
with open("config/accounts.json", encoding="utf-8") as f:
    accounts = json.load(f)
accounts["accounts"] = [a for a in accounts["accounts"] if a.get("role") != "admin"]
with open(os.path.join(DATA, "accounts.json"), "w", encoding="utf-8") as f:
    json.dump(accounts, f, ensure_ascii=False, indent=2)

with open("config/platforms.json", encoding="utf-8") as f:
    platforms = json.load(f)
for p in platforms["platforms"]:
    if p["id"] == "tvf":
        p["api_url"] = "http://127.0.0.1:18100"
        p["api_url_from_platform"] = False
with open(os.path.join(DATA, "platforms.json"), "w", encoding="utf-8") as f:
    json.dump(platforms, f, ensure_ascii=False, indent=2)

print(config["partido"]["inicio_iso"])
