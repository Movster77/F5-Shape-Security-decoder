
f5 shape's sensor on idp.movistar.com.ar. pins the bundle through mitmproxy,
runs it in a headless chrome, scoops the chacha20 state out of the vm at
runtime, then decrypts "-a" and the other five headers inside the login payload, -d seems to be the second most important one.
ya gotta run mitmdump first to pin the relevant files to the page

"r.json" ends up with the bundle constants up top (sigma, key, counter,
alphabet) and a "sensor.decoded" object with each header broken out. "-a"
becomes a list of tlv records. "-d"'s 22-byte signal descriptor gets a bit
dump because that's where the probe flags live, even if the
bit-to-probe-name table is mostly missing.

some stuff to know if you'll try to reverse shape
shape rotates the served bundle on every fetch and at least one of
{sigma, counter} is per-rotation. the bundle in "pin/" is one snapshot.
re-pinning a fresh fetch means re-running the patcher that adds the
dispatcher tracer, which isn't in this repo

about thirty of the records inside "-a" are opaque hash digests written
by individual fingerprint probes. the bytes are deterministic but
figuring out what each probe is actually hashing means lifting its
encoder out of the bundle bytecode. didn't get there.

serverside checks (bundle-content hash, replay window, scoring) live on
f5's side, so nothing here gets you a sensor that passes validation. it
just reads them.
