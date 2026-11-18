## FAQ

Block letters (A–K) refer to [🧭 phase-walkthrough.md](<./🧭 phase-walkthrough.md>); *cheatsheet* means [📜 cheatsheet.md](<./📜 cheatsheet.md>). No doubts were logged for this phase yet — these are the points most likely to cause confusion, written ahead of the drill so the first run starts from answers instead of guesses.

---

**1. The ground rules say "never run sqlmap with `T` (time-based)", but block H has time-based payloads. Isn't that a contradiction?**

> No — block H is identification, not extraction. A single, by-hand `SLEEP(5)`/`WAITFOR DELAY` request confirms a timing oracle exists; that is one request, not a campaign. The ban is specifically on `sqlmap --technique=...T...`, which fires one sleep-delayed request *per character guessed*, repeated for a whole value or table — that repeated load on a shared exam network is the stability risk. Confirming with one slow request and then handing extraction to sqlmap's safe `BEUSQ` set is the whole point of the block.
>
> If boolean and error both genuinely give nothing and timing is the *only* oracle, `BEUSQ` cannot extract at all (it excludes `T` by design). That is the one case where the cheatsheet's bounded, by-hand time-based script is worth running — aimed only at the single value the question needs, never a full table.

---

**2. Burp Community can't save a project file. How do I actually get a request into a file for `sqlmap -r`?**

> Copy/paste, not export. In Repeater, open the confirmed request, click the **Raw** tab, select all (Ctrl+A), copy (Ctrl+C), then paste into a text editor on Kali (`mousepad recon/req-login.txt &`, or `nano`/`vim` if no GUI editor) and save. Do this the moment a candidate confirms in block B — it is one less thing to rebuild from memory later, and it is what the exam's "paste text only" input rule expects anyway (no file upload needed, you are typing/pasting directly on Kali).

---

**3. `ORDER BY` and counting `NULL`s in a UNION gave me different column counts. Which one is right?**

> Trust `ORDER BY`. It queries the real table directly, so the point where it breaks is the exact column count. A `UNION SELECT NULL,NULL,...` test can still return `200` with *fewer* columns than the real count on some engines/configurations (the extra columns in the real query just don't get compared against anything), which makes it look right when it isn't. Use `UNION` only to *confirm* the number `ORDER BY` already gave you, not to discover it from scratch.

---

**4. The union row renders, but the column I'm writing to never shows my data.**

> That column is almost certainly numeric-only, so a string value in it silently fails or errors. Walk every position one at a time: replace each `NULL` with a literal (`'x'`) and see which one survives — that is your only text-capable column. If none survive, some engines let you cast around it (`CAST('x' AS CHAR)`/`CONVERT(varchar,'x')`), which belongs in the cheatsheet's union bank, not the main walkthrough payload.

---

**5. How do I know when to stop extracting and just answer the question?**

> Read the question's exact wording before you query (ground rule 1). "What is the database name" needs one value — stop at `database()`/`current-db`. "What is the password for user X" needs one row, one column — scope sqlmap with `-D <DB> -T <TABLE> -C <COLUMN> --dump` instead of a bare `--dump`. Only a "how many" or "list every" question genuinely needs the full table. Dumping everything by default is the fastest way to burn minutes a scenario+question exam doesn't reward.

---

**6. sqlmap confirms nothing on a parameter I'm fairly sure is injectable. What next?**

> First, re-confirm the break manually (block B) on the exact same field and value format sqlmap is sending — sqlmap cannot find what a hand-sent quote also fails to break. If the manual probe *does* break it but sqlmap misses it, the saved request might be missing a header (content-type, a second cookie, an auth token) that the app needs to even reach that code path — compare the saved `<REQ_FILE>` against the live Repeater request. If both come up empty, one retry at `--level=3 --risk=2` (walkthrough block I) is the only escalation worth the time; beyond that, the parameter is not the one the question is about.

---

**7. What's the practical difference between `--level` and `--risk` in sqlmap?**

> `--level` (1–5) controls *where* sqlmap looks and *how many payload variants* it tries per place — higher levels also test cookies, headers like `Referer`/`User-Agent`, and more entry points inside a single request. `--risk` (1–3) controls *how aggressive* the payloads are — higher risk adds heavier, sometimes data-altering tests (OR-based, stacked queries that write). The walkthrough's one allowed escalation step (`--level=3 --risk=2`) raises coverage first and aggressiveness only one notch, rather than jumping straight to the riskiest setting.

---

**8. Should I run the NoSQL payloads on every target, just in case the backend isn't SQL?**

> No — guideline §2 and §8 both explicitly exclude it from the default sweep. Block B's syntax probe only costs a handful of requests; spend that budget there first. Move to block J only when something concrete already points away from SQL: a MongoDB-style error, a JSON-only API with no visible SQL anywhere, or a parameter the app clearly treats as an array/object instead of a scalar. Testing NoSQL by default on every parameter is exactly the kind of speculative sweep the exam's time budget cannot afford.

---

**9. My quote gets blocked or rewritten — a WAF or filter is clearly in front. What now?**

> This phase stays in its lane: note the block and move to Phase 1 block M (WAF detection/fingerprint) and Phase 8 (encoding and filter bypass) rather than trying to out-guess the filter here. Once Phase 8's encoding tricks get a payload through, come back and resume at whichever block the now-unblocked response points to (block D if it errors, block G if only a diff shows).

---

**10. The login bypass in block C worked, but the question still asks for a specific value (a flag, a password hash). What now?**

> A successful bypass only proves the field is injectable — it is not itself an answer unless the question literally asks "can you log in as admin". Keep the same field and continue at block D (fingerprint the engine) exactly as if the bypass had never happened; the OR-based payload and a proper extraction payload are the same injection, just built for a different goal.

---

**11. How much time should detection (block B) and fingerprinting (block D) realistically cost per parameter?**

> A handful of requests each — the probe is four curl calls, the fingerprint is one or two more. If a parameter is genuinely going to be the answer, this confirms within a couple of minutes. The time sink this phase warns about is never detection, it's manual data extraction after detection (blind, character-by-character) — that's what sqlmap exists to absorb, not the probing itself.

---

**12. When do I use error-based (block F) instead of union-based (block E)?**

> They answer two different symptoms, not a preference: union needs a visible extra row rendering somewhere in the page, which only happens when the query's own output has a spot for it. Error-based needs the opposite — no visible row, but the server still prints SQL errors (a `500`, a stack trace, a verbose message) that a forced type-mismatch can be made to carry your value inside. If neither symptom is present (no row, no error, but the page still differs on true/false), that's block G, not a weaker version of E or F.

---

**13. A field I injected earlier (a profile name, a comment) doesn't break anything there, but a question implies SQLi happened somewhere downstream — e.g. in an admin report. What is this?**

> Second-order injection: the payload is stored safely from the first field's point of view, then concatenated unsafely into a *different* query later (an export, a report, an admin search over stored data). Treat it as block B applied to the second location, not the first — probe the page/report that actually *reads* the stored value, using a marker value first (store a recognisable string, then check where and how it gets queried back) before committing a real payload there.
