#!/usr/bin/env bash
#
# Cut the Splunkbase listing screenshots out of the full-page dashboard
# captures in docs/screenshots/.
#
# Splunkbase requires PNG at exactly 623x350. Everything here is a REDUCTION of
# a 1600px-wide capture, never an enlargement, so text stays legible. A region
# 1600x899 is exactly 623:350, so it reduces with nothing cropped off the sides;
# a taller region is fitted and padded with the dashboard's own background
# rather than being squashed, because a distorted chart misrepresents the data
# it is drawn from.
#
#   tools/make_listing_shots.sh
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# The FULL-PAGE captures, not the gallery's. The crops below reach thousands of
# pixels down a scrolled page, and docs/screenshots holds one viewport per page.
# Pointing this at those silently produced blank 348-byte images for every crop
# below y=1000. Refresh them with tools/capture_full_pages.js.
SRC="${RK_SHOT_SRC:-$ROOT/docs/screenshots-full}"
[ -d "$SRC" ] || { echo "no full-page captures in $SRC; run tools/capture_full_pages.js first" >&2; exit 1; }
# Gitignored: these are listing assets for the Splunkbase admin flow, not
# repository content. They are transferred out of band.
OUT="${RK_LISTING_OUT:-$ROOT/docs/splunkbase}"
mkdir -p "$OUT"

command -v magick >/dev/null || { echo "ImageMagick (magick) is required" >&2; exit 1; }

# Sampled from a dashboard gutter so padding is invisible against the page.
BG="srgb(23,29,33)"

# name                     source                y     height
SHOTS="
01-priority-matrix         exposure              320   899
02-fleet-overview          fleet-overview        60    899
03-findings                findings              120   899
04-exposure-chain          exposure              1470  899
05-attack-matrix           mitre-attack          285   1010
06-weakness-to-technique   mitre-attack          2500  899
07-coverage                coverage              640   899
08-hosts                   hosts                 180   899
09-containers              exposure              2800  899
10-feed-administration     feed-administration   70    899
"

fail=0
while read -r name src y h; do
  [ -n "${name:-}" ] || continue
  f="$SRC/$src.png"
  if [ ! -f "$f" ]; then
    echo "  MISSING $f - recapture the dashboards first" >&2; fail=1; continue
  fi
  # A region running past the bottom of the page yields a short crop, which
  # then pads instead of showing what was intended. Catch it here rather than
  # shipping a listing image that is half background.
  ph=$(magick identify -format '%h' "$f")
  if [ $((y + h)) -gt "$ph" ]; then
    echo "  FAIL $name: wants ${y}+${h} but $src is only ${ph}px tall; recapture it" >&2
    fail=1
    continue
  fi
  magick "$f" -crop "1600x${h}+0+${y}" +repage \
    -resize 623x350 -background "$BG" -gravity center -extent 623x350 \
    "$OUT/$name.png"
  printf '  %-26s %s\n' "$name" "$(magick identify -format '%wx%h' "$OUT/$name.png")"
done <<< "$SHOTS"

# The upload form defaults to this name; keep a copy so nobody has to rename.
cp "$OUT/01-priority-matrix.png" "$OUT/listing-screenshot.png"
echo "  listing-screenshot.png     (copy of 01-priority-matrix)"
exit $fail
