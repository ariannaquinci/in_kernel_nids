## Hook points overview (UDP vs TCP)

This project uses different hook points for UDP and TCP to match their
semantics. UDP is packet-oriented, while TCP is a byte stream with
reordering and per-socket receive queues. The hooks are split to avoid
cross-impact and to keep each path aligned with the protocol behavior.

## UDP hook points

UDP handling is built around netfilter, where packets are inspected and
can be dropped before delivery to user space.

Key hooks:

- **Netfilter ingress hook (UDP)**  
  Implemented in `netfilter_hook_udp.c`. This receives each UDP packet,
  builds a flow key, and correlates with XDP metadata when needed.

- **NFQUEUE-style gating**  
  UDP packets can be queued for deferred analysis and re-injected later.
  This is used to emulate a “hold until verdict” policy at the packet
  level without reordering issues.

Why it works for UDP:

- UDP has no stream ordering requirements at the socket layer.
- Dropping a packet at netfilter is semantically valid.

## TCP hook points

TCP handling is post-reordering and stream-oriented, so we do not act
on raw packets. We instead hook where the kernel has already ordered
data for the receive queue.

Key hooks:

- **`tcp_data_queue` (post-reordering)**  
  Implemented in `tcp_stream_hook.c` with a kretprobe. This runs after
  the kernel has validated and re-ordered segments. We enqueue a stream
  chunk for deferred analysis using `dw_tcp_enqueue_stream()`.

- **`tcp_recvmsg` (read path clamp)**  
  Implemented in `tcp_stream_hook.c` with a kprobe. We clamp the length
  passed to `tcp_recvmsg` to the current `approved_seq` (PASS boundary)
  via `dw_tcp_approved_len()`. This is a best-effort guard to reduce
  exposure of unanalyzed bytes.

Why this is different from UDP:

- TCP reordering and ACKs are handled by the kernel. We rely on the
  receive queue’s contiguous stream state, not on packet order.
- A verdict arriving after data is already in the receive queue cannot
  “un-deliver” bytes already copied to user space. We can only restrict
  delivery before copying or terminate the connection.

## Deferred analysis

Deferred work runs in `deferred_analysis_tcp.c` and `deferred_analysis_udp.c`.
For TCP it scans contiguous stream chunks and maintains:

- `approved_seq`: last PASS boundary (contiguous only).
- `drop_armed`: signal to abort the connection and purge receive data.

For UDP it evaluates packet payloads and decides PASS/DROP, using the
existing queue + reinject mechanism.

## Practical implications

- **UDP** can be fully blocked at packet level before delivery.
- **TCP** can be gated only at the stream boundary. Bytes already copied
  to user space cannot be revoked.

This is why the design keeps UDP and TCP hook points separated and only
shares XDP interception logic.
