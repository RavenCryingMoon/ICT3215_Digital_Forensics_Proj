#!/usr/bin/env bash
# collect_collide.sh — the hash-collision test: recover a 64-key map whose keys
# share buckets, check every entry byte-for-byte, and count the chain lengths.
# Results go to ~/DF_proj/evidence_collide/.
#
# BEFORE YOU RUN
# 1. Terminal 1 (in ~/DF_proj):
#       gcc -static -O2 -o plant_collide plant_collide.c
#       sudo ./plant_collide | tee ~/DF_proj/truth_collide.txt
# 2. Terminal 2, while it is still running:
#       sudo ~/DF_proj/lemon/lemon.core.x86_64 -d ~/DF_proj/collide.lime
#       sudo chown kali:kali ~/DF_proj/collide.lime
# 3. Ctrl+C in terminal 1.
# 4. Copy chain_stats.py into the plugin folder, then run this script:
#       cp ~/DF_proj/chain_stats.py ~/DF_proj/vol3-pinned/volatility3/framework/plugins/linux/
#       cd ~/DF_proj/vol3-pinned && bash ~/DF_proj/collect_collide.sh

set -uo pipefail
DF=~/DF_proj
IMG=$DF/collide.lime
SYM=$DF/symbols
PY=~/cart-venv/bin/python
EV=$DF/evidence_collide

fail() { echo "STOPPED: $*" >&2; exit 1; }
[ -f vol.py ] || fail "run this from ~/DF_proj/vol3-pinned"
[ -r "$IMG" ] || fail "can't read $IMG (missing, or run: sudo chown kali:kali $IMG)"
[ -s "$DF/truth_collide.txt" ] || fail "truth file missing: $DF/truth_collide.txt"
[ -f volatility3/framework/plugins/linux/chain_stats.py ] || fail "copy chain_stats.py into volatility3/framework/plugins/linux/ first"

rm -rf "$EV"; mkdir -p "$EV/raw"
find . -name __pycache__ -type d -prune -exec rm -rf {} +

echo "== listing + raw dump"
SECONDS=0
"$PY" vol.py -q -s "$SYM" -f "$IMG" -o "$EV/raw" linux.bpf_listmaps.MapList --dump --raw > "$EV/maplist.txt" 2> "$EV/log_maplist.txt"
echo "maplist: ${SECONDS} s" > "$EV/TIMINGS.txt"
off=$(awk -F'\t' '$4=="cart_collide"{print $1}' "$EV/maplist.txt")
[ -n "$off" ] || fail "cart_collide not in the map list — was plant_collide running during capture?"

echo "== byte check"
python3 "$DF/tests/verify.py" "$DF/truth_collide.txt" "$EV/raw" > "$EV/verify.txt" 2>&1

echo "== chain lengths (independent of the recovery code)"
"$PY" vol.py -q -s "$SYM" -f "$IMG" linux.chain_stats.ChainStats --map "$off" > "$EV/chain_stats.txt" 2> "$EV/log_chain_stats.txt"

{
  echo "COLLISION TEST — $(date -Is)"
  echo "image sha256: $(sha256sum "$IMG" | cut -d' ' -f1)"
  echo; grep -E "OFFSET|cart_collide" "$EV/maplist.txt"
  echo; cat "$EV/verify.txt"
  echo; cat "$EV/chain_stats.txt"
  echo; cat "$EV/TIMINGS.txt"
} > "$EV/SUMMARY.txt"
cat "$EV/SUMMARY.txt"
