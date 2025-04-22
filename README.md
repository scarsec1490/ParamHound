ParamHound is SCARSEC’s open‑source utility for red‑teamers who want speed without the bloat. Point it at a URL (or let it recurse the whole domain) and it will:

Crawl up to 10 levels deep using plain requests—no headless browsers.

Detect both GET parameters and HTML forms, printing them in color.

Highlight parameters that matter (id, q, search, …) while ignoring noise like CSRF tokens and timestamps.

Rotate User‑Agents or accept a custom header to blend into traffic.

Save results to disk so you can feed them straight into your favourite fuzzer or proxy.

Why use ParamHound?

Lightweight – ships as a single Python script, installs three tiny libs.

Noise‑free output – surfaces high‑value inputs, trims false positives.

Portable – works on Linux, macOS, Windows, even a barebones Docker alpine.

SCARSEC built ParamHound to scratch our own itch during web assessments; now it’s yours to fork, extend, and improve. Happy hunting!
