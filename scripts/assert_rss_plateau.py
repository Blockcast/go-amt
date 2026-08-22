#!/usr/bin/env python3
"""Assert the receiver's RSS plateaued rather than growing with unique shreds.

The criterion is stated in the same shape as shred/retention_test.go:207-211,
which is what this is the process-level counterpart to: linear growth would put
the 3N measurement at ~3x the N one, so requiring 3N <= 2x N catches a linear
leak while leaving generous headroom for allocator noise.

Three guards run before the ratio, because each one has a failure mode that
would otherwise let a meaningless run report a pass:

  unparsed == 0        A framing mismatch means the receiver rejected the feed
                       and scored nothing. RSS would be flat because the process
                       was idle, not because memory is bounded.
  unique == ingress    Every datagram the driver sends carries an identity it
                       has never sent before. If the receipt's unique count fell
                       below accepted ingress, identities were repeating and the
                       retention map was absorbing them as dedup hits -- the
                       false negative in defect 3 on BLO-29547.
  3N >= 1,500,000      The acceptance criterion needs N >= 500,000, so the run
                       has to have reached three times that.
"""

import csv
import json
import re
import sys

# Acceptance criterion: RSS at 3N must not exceed this multiple of RSS at N.
PLATEAU_RATIO = 2.0
# The criterion is stated for N >= 500,000 unique shreds.
MIN_N = 500_000


def die(message):
    print(f"::error::{message}")
    sys.exit(1)


def read_series(path):
    with open(path, newline="") as handle:
        rows = [
            (int(row["elapsed_s"]), int(row["unique_shreds"]), int(row["rss_kb"]))
            for row in csv.DictReader(handle)
        ]
    if not rows:
        die(f"{path} carries no samples; the sampler never ran or the receiver died at startup")
    return rows


def metric(text, name):
    # Capture the exponent too. Prometheus renders a counter past ~1e6 in
    # scientific notation (1.57357e+06), and a \d+(\.\d+)? pattern captures
    # "1.57357" and silently yields 1 -- which then reads as "the receiver only
    # ever saw one packet" rather than as a parse bug.
    match = re.search(rf"^bcast_shred_gw_{name}\S*\s+([0-9.eE+-]+)", text, re.M)
    return None if match is None else int(float(match.group(1)))


def rss_at(rows, target):
    """RSS at the first sample by which `target` unique shreds had arrived."""
    for _, shreds, rss in rows:
        if shreds >= target:
            return rss, shreds
    die(f"no sample reached {target:,} unique shreds; the run was too short")


def main():
    series_path, metrics_path, receipt_path = sys.argv[1:4]
    rows = read_series(series_path)
    metrics_text = open(metrics_path).read()
    receipt = json.load(open(receipt_path))

    unparsed = metric(metrics_text, "shreds_unparsed_total")
    ingress = metric(metrics_text, "ingress_packets_total")
    unique = receipt.get("unique_shreds_total")

    if unparsed is None or ingress is None or unique is None:
        die(f"missing counters: unparsed={unparsed} ingress={ingress} unique={unique}")
    if unparsed != 0:
        die(
            f"{unparsed:,} datagrams were unparsed: the receiver rejected the feed's framing, "
            "so a flat RSS would mean the process was idle rather than bounded"
        )
    if unique != ingress:
        die(
            f"unique_shreds_total ({unique:,}) != accepted ingress ({ingress:,}): identities repeated, "
            "so held state absorbed them as dedup hits and this run cannot show growth even if it exists"
        )

    peak = max(shreds for _, shreds, _ in rows)
    n = peak // 3
    if n < MIN_N:
        die(
            f"peak was {peak:,} unique shreds, so N = {n:,}; the criterion needs N >= {MIN_N:,} "
            f"(i.e. at least {MIN_N * 3:,} total)"
        )

    rss_n, at_n = rss_at(rows, n)
    rss_3n, at_3n = rss_at(rows, 3 * n)
    ratio = rss_3n / rss_n

    duration = rows[-1][0]
    print(f"samples          {len(rows)} over {duration}s")
    print(f"unique shreds    {unique:,} accepted, {unparsed} unparsed")
    print(f"sets             {receipt['union']['sets_total']:,} total, "
          f"{receipt['union']['sets_erased']:,} erased")
    print(f"RSS at N         {rss_n:,} kB at {at_n:,} unique shreds (N = {n:,})")
    print(f"RSS at 3N        {rss_3n:,} kB at {at_3n:,} unique shreds (3N = {3 * n:,})")
    print(f"ratio            {ratio:.2f}x (must be <= {PLATEAU_RATIO}x)")
    print(f"absolute growth  {rss_3n - rss_n:+,} kB")

    if ratio > PLATEAU_RATIO:
        die(
            f"RSS grew {ratio:.2f}x from {rss_n:,} kB at {n:,} unique shreds to {rss_3n:,} kB at "
            f"{3 * n:,} -- that is growth with cumulative unique shreds, not a plateau. "
            "Name the responsible allocation and file it against go-amt (BLO-29547)."
        )
    print(f"\nPLATEAU HELD: {ratio:.2f}x <= {PLATEAU_RATIO}x across a 3x increase in unique shreds.")


if __name__ == "__main__":
    main()
