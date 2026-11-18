# 📝 Phase 2: XSS & Client-Side – Study Notes

Theory, DOM-execution model, and "why/when" from the INE tutorials, OWASP WSTG 4.2 (`WSTG-INPV-01`, `WSTG-INPV-02`, `WSTG-CLNT-01`) and the PortSwigger XSS labs. Commands for the exam live in [🧭 phase-walkthrough.md](<./🧭 phase-walkthrough.md>). Variants and the payload bank live in [📜 cheatsheet.md](<./📜 cheatsheet.md>). This file explains *why* and *when*.

Placeholders: `<MARKER>`, `<CONTEXT>`, `<PAYLOAD>`, `<LISTENER_IP>`/`<LISTENER_PORT>`.

---

## Quick Decision Table

| Question during the exam | Do | Type |
|---|---|---|
| Does this input come back at all? | Marker sweep, grep the response for the marker | Manual |
| Where does it land, and what filters it? | Character probe (`'"<>` etc.), read what survives | Manual |
| What payload fires here? | Match the context (body/attribute/JS string/URL/comment) to the payload table | Manual |
| The exact payload is stripped or blocked | Allow-list enumeration, then encoding tricks | Manual |
| Does this survive a reload or a different role? | Two sessions, read the render page, not the submit page | Manual |
| The input never touches the server at all | Grep JS for a source reaching a sink | Manual (DevTools) |
| A question asks for an exact stolen value | A listener plus the confirmed payload | Manual |
| WordPress, a named plugin/theme | `wpscan`, then `searchsploit` for that exact version | Automated lookup |

---

## 1. Methodology (WSTG)

- **Scope is three WSTG IDs.** Reflected and stored XSS sit under `WSTG-INPV-01`/`02`; DOM XSS is `WSTG-CLNT-01`. The eWPTv2 maps the rest of the client-side `CLNT` range (CORS, clickjacking, WebSockets, client storage) to this same phase folder, but this file and the walkthrough focus on the XSS IDs — the others get their own triggered checks when a question names them.
- **This phase attacks entry points, it does not discover them.** Every parameter, form field, header, cookie and `.js` file comes from Phase 1's Burp Site map and parameter discovery (block J). A parameter never found in Phase 1 is a parameter never tested here either.
- **Self-XSS does not count**, and CSRF-via-XSS or a full cookie-theft chain is built only when a question explicitly asks for impact — otherwise a confirmed `alert(document.domain)` plus the request/response is the finding.

---

## 2. XSS types

| Type | Where the payload lives | What confirms it |
|---|---|---|
| Reflected | Echoed back in the same response that carried it | Fires immediately, on this one request |
| Stored | Saved once, rendered on a different request/page/role | Fires on reload, or when a second account/role views the page |
| DOM-based | Never leaves the browser — a client-side source reaches a client-side sink | Fires with no corresponding server request in Burp's HTTP history (except for the source itself, if it was a URL parameter) |

**Why the distinction matters operationally:** reflected and stored both need the server to echo input into HTML, so a WAF or backend filter applies to both. DOM XSS reaches the dangerous operation entirely in JavaScript, so the exact same filter is irrelevant — the only thing that can stop it is client-side sanitisation (`DOMPurify`, a regex strip) sitting between the source and the sink.

---

## 3. JavaScript execution model (why source → sink thinking works)

- **Sandboxed, low-privilege, segregated** from other browser processes — this is why DOM XSS is scoped to "what this one page's JS can do" (read cookies without `HttpOnly`, make same-origin requests, rewrite the DOM) rather than anything OS-level.
- **Execution is sequential, top to bottom.** A source read early and a sink called later in the same script, or in a script loaded after it, is still a valid chain — the trace does not require them to be adjacent lines.
- **Practical consequence:** grepping a `.js` file for a source and a sink in the same file is a *candidate*, not a confirmed chain — open the file and read the actual data flow between the two matches (block G of the walkthrough) before spending a URL-bar payload on it.

---

## 4. Finding reflected XSS manually

- **Query-string parameters are the first suspect**, but Burp's Site map and parameter discovery (Phase 1 block J) can show a parameter the browser's own UI never exposes directly — a hidden field, a tracking parameter appended by JS, a value only visible in the POST body.
- **The filter acts on specific characters, not on "the idea of a script tag."** `<` and `>` are what most filters escape first; a payload that also closes an attribute or a JS string first (`">`, `';`, `--></script>`) survives a filter tuned only for bare angle brackets.
- **URL-encode whenever the parameter travels in the query string** — the same rule as every other phase. Ctrl+U in Burp, or `--data-urlencode` in curl.

---

## 5. Cookie stealing and exploit chains

- **Out-of-band exfiltration needs your own listener**, never an external OAST/Collaborator domain — Kali has no internet during the exam, and Burp Community has no Collaborator client either.
- **`new Image().src=...` is the minimal exfil primitive:** it fires a GET request with no page navigation and no CORS preflight, which is why it is the standard cookie-theft payload across every walkthrough and lab.
- **`HttpOnly` makes this specific demo fail by design** — that is not a dead end, it is the expected result, and the real-impact follow-up is a forged request using the victim's session (CSRF-via-XSS) rather than reading the cookie value directly.

---

## 6. Stored XSS

- **The write and the read are often two different places.** A field can be safely encoded on its own submit-confirmation page and still render unencoded on an admin's review page, a moderation queue, or another user's inbox — always check a second role, not just a second reload of the same page.
- **A known CMS plugin/theme is a searchsploit lookup before it is a manual hunt.** Read the finding's description for the exact vulnerable field and parameter name rather than re-discovering the injection from scratch — this is the single fastest path to a stored XSS finding on a fingerprinted CMS.
- **Lab pattern:** identify the plugin/theme and version (Phase 1 block D/L), `searchsploit` the exact name, read the PoC's field and payload, then store it through the real form.

---

## 7. DOM-based XSS

- **Source and sink are the whole model.** A *source* is anywhere untrusted data enters the page's JavaScript (`location.search`, `location.hash`, `document.referrer`, `document.URL`, `window.name`, `postMessage` data). A *sink* is a dangerous operation that can turn a string into executing code or markup (`innerHTML`, `document.write`, `eval`, a jQuery `.html()`/`.attr('href', ...)`, a bare `location` assignment).
- **Naming both is most of the work.** Once the exact source and the exact sink are named, the payload almost writes itself — it needs to be whatever that specific sink executes (an event handler for `innerHTML`, since `innerHTML` never runs a bare `<script>` tag by spec; a `javascript:` URI for an `href`/`location` sink).
- **`location.hash` never reaches the server.** A hash-fragment payload shows up only in the browser's URL bar and DevTools, never in Burp's HTTP history — this is expected, not a sign the payload failed to send.

---

## 8. Tools

- **wpscan:** the one automated tool worth planning around for CMS-flavoured XSS — confirms the plugin/theme version so `searchsploit` can find a matching pre-written PoC instead of rebuilding one by hand.
- **XSSer, dalfox, kxss, XSStrike:** automated XSS scanners and payload generators. Useful to know about, but none are confirmed preinstalled on the exam image, and the eWPTv2's manual-methodology expectation means the marker sweep, context probe and payload tables (walkthrough blocks B–E) cover the same ground with tools that are definitely there. Treat them the same way Phase 1 treats Metasploit: a lab/practice accelerator, not an exam-day default.
- **DOM Invader** (Burp's built-in DOM XSS helper, if present in the exam's Burp build): a faster version of the source/sink grep, not a replacement for reading the trace by hand — it still needs a human to confirm the finding.

---

## 9. Lab Patterns (INE / PortSwigger)

These repeat across the labs, and the exam is expected to be similar:

- **Reflected XSS, context-driven:** a parameter reflects → probe the exact characters the server escapes → match the surviving context (body, attribute, JS string) to a payload built for it, rather than reusing one generic `<script>` payload everywhere.
- **CMS plugin XSS (e.g. a named WordPress plugin):** go straight to the CVE/exploit-db description for the exact vulnerable page and parameter, then replay the documented payload — this is faster than a blind marker sweep across the whole admin area.
- **Stored XSS via a comment/post field (e.g. a PHP microblog or forum app):** `searchsploit` the product name first, read which field is vulnerable, then submit the payload through that real form and confirm it fires on the page that renders the post/comment back.
- **Cookie-theft demo:** a netcat listener plus the `new Image().src` primitive is the whole lab pattern — nothing more elaborate is expected unless a question asks for a full account-takeover chain.

---

## 10. Scenario → Commands

| Scenario | Start with | Then |
|---|---|---|
| A parameter reflects in the page | Marker sweep (block B) | Context probe (C), then the matching payload (D) |
| The exact payload is stripped | — | Allow-list enumeration, encoding tricks (E) |
| A comment/profile/ticket field | Mark the write surface (block F) | Reload as a second role, not just a second request |
| `document.write`, `innerHTML`, `location.hash` mentioned | Grep JS for sources and sinks (block G) | Trigger it from the URL/hash in the browser |
| WordPress, a named plugin/theme | `wpscan` | `searchsploit` the exact version, replay the documented payload |
| A question asks for an exact stolen value | Start the listener early (block A) | Deliver the confirmed payload, read the listener (block H) |

Exact commands for each row are in the walkthrough, with the full payload bank and tool fallbacks in the cheatsheet.

