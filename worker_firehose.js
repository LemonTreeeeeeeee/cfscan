// Firehose Worker — ground-truth target for the WS-sustained probe.
// On WebSocket upgrade it streams 64 KB binary frames as fast as
// backpressure allows for ~30 s. This isolates the WS-flow-shaping axis
// E63 found (no VLESS / no fetch() confound): if the censor chokes
// sustained WS downlink on the path to a given CF edge IP, this firehose
// will exhibit the burst-then-zero signature; if the edge is "clean" it
// streams steadily.
//
// Deploy (dashboard): Workers & Pages -> Create -> paste this -> Deploy.
//   Note the *.workers.dev host (e.g. firehose.you.workers.dev).
// Deploy (wrangler):  wrangler deploy   (with a minimal wrangler.toml:
//   name = "firehose"; main = "worker_firehose.js"; compatibility_date = "2024-01-01")
//
// The probe connects with SNI = this host and WS-upgrades to "/".

export default {
  async fetch(req) {
    const upgrade = (req.headers.get("Upgrade") || "").toLowerCase();

    // -mode=get path: chunked HTTP download stream (XHTTP/SplitHTTP
    // downlink shape, NO WebSocket Upgrade). E71 uses this to test
    // whether the censor's WS-flow choke is specific to the Upgrade
    // handshake or applies to any long worker stream.
    if (upgrade !== "websocket") {
      const url = new URL(req.url);
      if (url.pathname === "/stream") {
        const chunk = new Uint8Array(64 * 1024).fill(120);
        const body = new ReadableStream({
          async pull(controller) {
            const deadline = Date.now() + 30000;
            while (Date.now() < deadline) {
              controller.enqueue(chunk);
              await new Promise((r) => setTimeout(r, 15));
            }
            controller.close();
          },
        });
        return new Response(body, {
          status: 200,
          headers: { "content-type": "application/octet-stream", "cache-control": "no-store" },
        });
      }
      return new Response("e70 firehose: WS at / or chunked stream at /stream\n", { status: 426 });
    }
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();

    const chunk = new Uint8Array(64 * 1024).fill(120); // 'x'
    let stop = false;
    server.addEventListener("close", () => { stop = true; });
    server.addEventListener("error", () => { stop = true; });

    // Throttled send: 64 KB every 15 ms ≈ 4 MB/s target. This is well
    // above the probe's "clean" threshold yet keeps per-tick CPU tiny so
    // WALL time (not CPU) dominates — a tight send loop blows the Worker
    // CPU budget and the isolate gets killed, producing a FALSE
    // burst-then-zero choke on every IP. Do not remove the delay.
    (async () => {
      const deadline = Date.now() + 30000;
      while (!stop && Date.now() < deadline) {
        try {
          server.send(chunk);
        } catch (e) {
          break;
        }
        await new Promise((r) => setTimeout(r, 15));
      }
      try { server.close(1000, "done"); } catch (e) {}
    })();

    return new Response(null, { status: 101, webSocket: client });
  },
};
