#!/usr/bin/env bash
# collect_evidence.sh — runs every experiment in the report on ONE fresh image
# and saves all output (for the figures, Table I, Table II and run times) in
# ~/DF_proj/evidence/.
#
# ---------------------------------------------------------------- BEFORE YOU RUN
# 1. Open four terminals in ~/DF_proj and start the four loaders. Leave them
#    running (each prints PLANTED-OK and then waits):
#       sudo ./plant_maps       | tee ~/DF_proj/truth_plant.txt
#       sudo ./cart_btf_loader  | tee ~/DF_proj/truth_btf.txt
#       sudo ./hide_loader      | tee ~/DF_proj/truth_hide.txt
#       sudo ./plant_lru_pcpu   | tee ~/DF_proj/truth_lru_pcpu.txt
# 2. In a fifth terminal, take ONE image while all four are still running:
#       sudo ~/DF_proj/lemon/lemon.core.x86_64 -d ~/DF_proj/final.lime
#       sudo chown kali:kali ~/DF_proj/final.lime
# 3. Only now press Ctrl+C in the four loader terminals.
# 4. Save this file as ~/DF_proj/collect_evidence.sh, then run it on the SAME
#    Kali VM that took the image (it reads that VM's possible-CPU list):
#       cd ~/DF_proj/vol3-pinned
#       bash ~/DF_proj/collect_evidence.sh
#
# It takes a while (the scanner reads the whole image). It makes ONE temporary
# copy of the image at a time and deletes it afterwards, so you need free disk
# space of about one image size.
# --------------------------------------------------------------------------------

set -uo pipefail

# ---- settings (change only if your paths differ) -------------------------------
DF=~/DF_proj
IMG=$DF/final.lime                 # the fresh image from step 2
SYM=$DF/symbols                    # btf2json symbol profile folder
PY=~/cart-venv/bin/python
VERIFY=$DF/tests/verify.py
TRUTHS=("$DF/truth_plant.txt" "$DF/truth_btf.txt" "$DF/truth_hide.txt" "$DF/truth_lru_pcpu.txt")
BPFVOL3_DIR=${BPFVOL3_DIR:-$DF/BPFVol3}   # your clone of upstream BPFVol3, if you have one
CORRUPT_MAP=${CORRUPT_MAP:-cart_hash_np}  # map whose chain gets corrupted for Fig. 4
EV=$DF/evidence
COPY=$DF/ev_copy.lime              # the temporary image copy
# --------------------------------------------------------------------------------

fail() { echo "STOPPED: $*" >&2; exit 1; }

[ -f vol.py ]   || fail "run this from ~/DF_proj/vol3-pinned (the folder with vol.py)"
[ -f "$IMG" ]   || fail "image not found: $IMG"
[ -r "$IMG" ]   || fail "can't read $IMG — run: sudo chown kali:kali $IMG"
for t in "${TRUTHS[@]}"; do [ -s "$t" ] || fail "truth file missing or empty: $t"; done

need=$(stat -c %s "$IMG"); free=$(df --output=avail -B1 "$DF" | tail -1)
[ "$free" -gt $((need + 1073741824)) ] || fail "not enough free disk: need about $((need/1073741824 + 1)) GB for the temporary copy"

rm -rf "$EV"; mkdir -p "$EV"
find . -name __pycache__ -type d -prune -exec rm -rf {} +    # avoid stale plugin code

# run <label> <image> <stdout-file> <vol arguments...>
# Saves the plugin output, its log, and the run time + peak memory.
run() {
  local label=$1 img=$2 out=$3; shift 3
  echo "== $label"
  if [ -x /usr/bin/time ]; then
    /usr/bin/time -f "$label: %e s, %M KB peak memory" -a -o "$EV/TIMINGS.txt" \
      "$PY" vol.py -q -s "$SYM" -f "$img" "$@" > "$out" 2> "$EV/log_$label.txt"
  else
    local t0=$SECONDS
    "$PY" vol.py -q -s "$SYM" -f "$img" "$@" > "$out" 2> "$EV/log_$label.txt"
    echo "$label: $((SECONDS - t0)) s (peak memory not measured: /usr/bin/time missing)" >> "$EV/TIMINGS.txt"
  fi
  [ -s "$out" ] || fail "$label produced no output — see $EV/log_$label.txt"
}

# field <csv-file> <map-name> <column-keyword>  -> prints that column for that map
field() {
  python3 - "$1" "$2" "$3" <<'PY'
import csv, sys
path, name, key = sys.argv[1], sys.argv[2], sys.argv[3].upper()
rows = list(csv.reader(open(path)))
for i, hdr in enumerate(rows):
    up = [h.strip().upper() for h in hdr]
    if "NAME" in up and any(h.startswith("OFFSET") for h in up):
        n = up.index("NAME")
        k = next(j for j, h in enumerate(up) if h.startswith(key))
        for r in rows[i + 1:]:
            if len(r) > n and r[n].strip() == name:
                print(r[k].strip()); sys.exit(0)
        break
sys.exit(1)
PY
}

# ---- 0. environment (fills the [fill in] commits in refs [4] and [6]) ----------
echo "== environment"
{
  echo "date:            $(date -Is)"
  echo "kernel:          $(uname -r)"
  echo "possible CPUs:   $(cat /sys/devices/system/cpu/possible)   <- check against the 128 per-CPU slots"
  echo "nproc --all:     $(nproc --all)"
  echo "volatility3 git: $(git rev-parse HEAD 2>/dev/null || echo 'not a git checkout')"
  if [ -d "$BPFVOL3_DIR/.git" ]; then
    echo "BPFVol3 git:     $(git -C "$BPFVOL3_DIR" rev-parse HEAD)"
  else
    echo "BPFVol3 git:     clone not found at $BPFVOL3_DIR (set BPFVOL3_DIR=... and rerun)"
  fi
  echo "python:          $("$PY" --version 2>&1)"
  echo "image:           $IMG ($(du -h "$IMG" | cut -f1))"
  echo "image sha256:    $(sha256sum "$IMG" | cut -d' ' -f1)"
} > "$EV/00_environment.txt"

# ---- 1. listing + raw dump + byte check  ->  Fig. 2 and Table I ----------------
mkdir -p "$EV/raw"
run 01_maplist_raw "$IMG" "$EV/01_maplist.txt" -o "$EV/raw" linux.bpf_listmaps.MapList --dump --raw
run 01_maplist_csv "$IMG" "$EV/01_maplist.csv" -r csv linux.bpf_listmaps.MapList
for t in "${TRUTHS[@]}"; do
  python3 "$VERIFY" "$t" "$EV/raw" > "$EV/01_verify_$(basename "$t" .txt).txt" 2>&1
done

# ---- 2. decoded dump  ->  Fig. 3 (same cart_btf value, raw vs decoded) ---------
mkdir -p "$EV/decoded"
run 02_maplist_decoded "$IMG" "$EV/02_maplist_decoded.txt" -o "$EV/decoded" linux.bpf_listmaps.MapList --dump
id=$(field "$EV/01_maplist.csv" cart_btf ID) || fail "cart_btf not in the map list — was cart_btf_loader running during capture?"
{
  echo "--- cart_btf (id $id), raw (--raw):";  cat "$EV"/raw/.map_*_"$id"
  echo; echo "--- cart_btf (id $id), decoded:"; cat "$EV"/decoded/.map_*_"$id"
} > "$EV/02_cart_btf_raw_vs_decoded.txt"

# ---- 3. corrupted chain  ->  Fig. 4 (traversed in 01, partial here) ------------
off=$(field "$EV/01_maplist.csv" "$CORRUPT_MAP" OFFSET) || fail "$CORRUPT_MAP not in the map list; set CORRUPT_MAP=<another hash map name>"
echo "== copying image for the corruption test"
cp "$IMG" "$COPY"
run 03_find_next "$IMG" "$EV/03_find_next.txt" linux.find_next.FindNext --htab "$off" --outfile "$COPY"
mkdir -p "$EV/corrupt"
run 03_maplist_corrupted "$COPY" "$EV/03_maplist_corrupted.txt" -o "$EV/corrupt" linux.bpf_listmaps.MapList --dump --raw
rm -f "$COPY"

# ---- 4. unlink hide_rules AND cart_btf from map_idr  ->  Fig. 5, Fig. 6, Table II
hide_off=$(field "$EV/01_maplist.csv" hide_rules OFFSET) || fail "hide_rules not in the map list"
cart_off=$(field "$EV/01_maplist.csv" cart_btf OFFSET)   || fail "cart_btf not in the map list"
echo "== copying image for the unlink test"
cp "$IMG" "$COPY"
run 04_unlink_hide "$IMG" "$EV/04_unlink_hide.txt" linux.unlink_map.UnlinkMap --map "$hide_off" --outfile "$COPY"
run 04_unlink_cart "$IMG" "$EV/04_unlink_cart.txt" linux.unlink_map.UnlinkMap --map "$cart_off" --outfile "$COPY"
mkdir -p "$EV/unlinked_raw" "$EV/unlinked_decoded" "$EV/scan"
# Fig. 5: hide_rules now SOURCE=prog;  Fig. 6 left: cart_btf is gone from this list
run 04_maplist_unlinked "$COPY" "$EV/04_maplist_unlinked.txt" -o "$EV/unlinked_decoded" linux.bpf_listmaps.MapList --dump
run 04_maplist_unlinked_raw "$COPY" "$EV/04_maplist_unlinked_raw.txt" -o "$EV/unlinked_raw" linux.bpf_listmaps.MapList --dump --raw
python3 "$VERIFY" "$DF/truth_hide.txt" "$EV/unlinked_raw" > "$EV/04_verify_hide_after_unlink.txt" 2>&1
# Fig. 6 right + Table II: the scanner finds cart_btf anyway
run 04_scanmaps "$COPY" "$EV/04_scanmaps.txt" -o "$EV/scan" linux.bpf_scanmaps.ScanMaps --dump
rm -f "$COPY"

# ---- 5. BTF code: upstream BPFVol3 vs ours (for Section III wording) ------------
if [ -d "$BPFVOL3_DIR" ]; then
  up=$(find "$BPFVOL3_DIR" -path '*utility*' -name btf.py | head -1)
  if [ -n "$up" ]; then
    diff -u --strip-trailing-cr "$up" volatility3/utility/btf.py > "$EV/05_btf_vs_upstream.diff"
    echo "upstream btf.py: $(wc -l < "$up") lines; ours: $(wc -l < volatility3/utility/btf.py) lines; lines added: $(grep -c "^+[^+]" "$EV/05_btf_vs_upstream.diff"); lines removed: $(grep -c "^-[^-]" "$EV/05_btf_vs_upstream.diff")" \
      > "$EV/05_btf_summary.txt"
  fi
fi

# ---- summary --------------------------------------------------------------------
{
  echo "CARTOGRAPHER EVIDENCE — $(date -Is)"
  echo; cat "$EV/00_environment.txt"
  echo; echo "### Table I — byte check per truth file (original image)"; cat "$EV"/01_verify_*.txt
  echo; echo "### hide_rules byte check after unlinking from map_idr"; cat "$EV/04_verify_hide_after_unlink.txt"
  echo; echo "### Fig. 4 — STATUS of $CORRUPT_MAP: before / after corruption"
  grep -w "$CORRUPT_MAP" "$EV/01_maplist.txt"; grep -w "$CORRUPT_MAP" "$EV/03_maplist_corrupted.txt"
  echo; echo "### Fig. 5 / 6 — hide_rules and cart_btf after unlinking (cart_btf should be absent)"
  grep -w hide_rules "$EV/04_maplist_unlinked.txt" || echo "hide_rules: NOT FOUND (unexpected)"
  grep -w cart_btf "$EV/04_maplist_unlinked.txt" || echo "cart_btf: absent from the list (expected)"
  echo; echo "### Table II — scanner results"; cat "$EV/04_scanmaps.txt"
  echo; echo "### Run times";  cat "$EV/TIMINGS.txt"
  [ -f "$EV/05_btf_summary.txt" ] && { echo; echo "### BTF code vs upstream"; cat "$EV/05_btf_summary.txt"; }
} > "$EV/SUMMARY.txt"

echo
echo "Done. Everything is in $EV — start with $EV/SUMMARY.txt"
