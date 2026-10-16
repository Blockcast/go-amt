# 2026-10-16 W7.5 re-baseline (post-G2)

**Transcribed, not verbatim.** The verbatim receipt is on the devbox at
`receipts/2026-10-16/w75-rebaseline/` (`receipt.txt` sha256 `2b35890b…`,
`score.txt` `9533e2c7…`). The figures below are copied from the run's record
on BLO-45889 (comment of 2026-10-16T13:22Z). Replace this file with the
verbatim `receipt.txt` when it is copied off the devbox.

- Window: 2026-10-16 13:18:31–13:21:32Z, 180.3 s. The G2 roll landed at
  12:06:50Z (rev 425), so the run starts 1 h 12 m after it.
- Receiver: the devbox `69.25.95.32`, sfo12, native join on `eth0`,
  receive-only, go-amt `1b36ebd`.
- Arms, named as in that run: `listener=ssm://69.25.95.197@232.0.0.1:5001`
  (the same source as the `prod` arm in the 2026-10-13 receipts) and
  `merged=ssm://69.25.95.57@232.0.0.2:5001` (the same source as `union`).

| | listener | merged | union of both |
|---|---:|---:|---:|
| FEC sets | 16,469 | 16,469 | 16,469 |
| erased | 310 = 1.882% | 18 = 0.109% | 17 = 0.103% |

- `rescued_sets` 293: sets erased on the listener alone and complete once
  merged was added. 293/16,469 = 1.779% of sets.
- Host drops: `tap110i0` on pve2 dropped 70 of 2,018,370 (0.003%). The
  receiver's own two sockets dropped 0 of 1,943,665. Host-wide
  `UdpRcvbufErrors` +0.
- Clamp warnings 0, `erasure_frontier_resyncs_total` 0,
  `completions_above_ceiling` 0, exit 0.
- Devbox 1-min load was 58.9 at start and 31.1 at end, from other tooling on
  the host.
