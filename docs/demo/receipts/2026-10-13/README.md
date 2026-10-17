# 2026-10-13 re-rehearsal receipts (pre-G2)

Receiver: the devbox `69.25.95.32` in sfo12, joining natively on `eth0`,
receive-only. The `prod` arm is `ssm://69.25.95.197@232.0.0.1:5001`, the
`union` arm is `ssm://69.25.95.57@232.0.0.2:5001`. These runs predate the G2
roll of 2026-10-16, so the `prod` figures describe a feed that has since been
fixed. Archived verbatim on BLO-27267 (comment of 2026-10-13T16:57Z); the
devbox copy is `demo-bench/breakpoint-2026/receipts/2026-10-13/`.

All four runs are here, not only the best one.

| Run (UTC) | File | Arms, duration | Receive buffer | union arm erased | prod arm erased | both arms erased | Host nstat bracket |
|---|---|---|---|---:|---:|---:|---|
| 02:20–02:22Z | [`receipt-2arm.txt`](receipt-2arm.txt) | prod + union, 150 s | kernel default (`rmem_max` 212,992) | 339/14,260 = 2.38% | 4,675/14,260 = 32.8% | 134/14,260 = 0.94% | UdpInDatagrams +1,427,648, UdpRcvbufErrors +54,026 |
| 02:29–02:31Z | [`receipt-twoarm.txt`](receipt-twoarm.txt) | prod + union, 150 s | forced 8 MiB, reads back 16,777,216 | 45/15,842 = 0.28% | 5,359/15,842 = 33.8% | 38/15,842 = 0.24% | UdpInDatagrams +1,594,709, UdpRcvbufErrors +1,331 |
| 02:32–02:33Z | [`receipt-union.txt`](receipt-union.txt) | union only, 60 s | forced 8 MiB, reads back 16,777,216 | 96/6,536 = 1.47% | — | — | UdpInDatagrams +341,591, UdpRcvbufErrors +3,307 |
| 03:38–03:39Z | [`g3-receipt.txt`](g3-receipt.txt) | union only, `--rcvbuf` 8 MiB default | **clamped**: allocated 425,984 | 21/2,410 = 0.87% | — | — | none taken |

Caveats:

- nstat counters are host-wide, so other sockets on the devbox count too.
- A 60 s union-only run at 02:22–02:23Z had its receipt overwritten by the
  02:32Z run, which wrote the same file name. Only its bracket survives:
  UdpInDatagrams +302,922, UdpRcvbufErrors +7,702. It is not scored here.
- The 03:38Z run covered only 2,410 sets. Treat it as a hint, not a result.

[`selftest.txt`](selftest.txt) is the offline control, run first.
[`rehearse.sh`](rehearse.sh) produced the 02:20Z run;
[`rehearse2.sh`](rehearse2.sh) produced the 02:29Z and 02:32Z runs. The 03:38Z
run was the G3 PR's live check with the `union` feed alone.
