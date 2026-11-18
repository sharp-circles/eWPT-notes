## FAQ

Block letters (A–N) refer to [🧭 phase-walkthrough.md](<./🧭 phase-walkthrough.md>); *cheatsheet* means [📜 cheatsheet.md](<./📜 cheatsheet.md>).

---

**1. How to act against the different http codes?**

> Follow the status table in the walkthrough (Conventions → *HTTP status codes in recon*):
>
> | Code | Do |
> |---|---|
> | `200` | Open it in Burp so it lands in the Site map |
> | `301` / `302` | Follow it and note the target (it can reveal a new hostname) |
> | `401` | Note it, test credentials later |
> | `403` | Exists but blocked: log it and try verb tampering (block H) |
> | `405` / `415` | Probably an API: retry with other verbs and `Content-Type` (block I) |
> | `500` | Read the body, it may leak a stack trace or version |
> | `404` | Ignore |
>
> The *Discovery → next step* table at the end of the walkthrough has the same map.

---

**2. Does nmap work with application paths, such as http://meta2/mutillidae or root only? Does it work with subnets, such as 172.20.0.0/16?**

> **Paths:** no. nmap scans hosts and ports, it does not take URLs. Give it `meta2` (or the IP), never `http://meta2/mutillidae`. The path only matters to NSE HTTP scripts, which take it as an argument: `--script http-enum --script-args http-enum.basepath=/mutillidae/` or `http-methods.url-path=/mutillidae/`. For paths, use ffuf or Burp instead.
>
> **Subnets:** yes, CIDR notation works (`nmap -sn 172.20.0.0/16`). A `/16` is 65,536 addresses, so run host discovery first (block B, `-sn`), keep the live hosts in `recon/live_hosts.txt`, and only then run the full port scan against those.

---

**3. Metasploitable could be good for certain actions done in the pentest, but might not be so for the overall. Which app/tool can I really use in order to practice in an environment like the eWPTv2?**

> Metasploitable2 is only a practice range for the commands and the notes workflow, not a proxy for the exam ([exam_doubts_faq.md](<../../3. EXAM STRATEGY/exam_doubts_faq.md>) §2.6). The exam is several separate web apps on an internal network, with a large share of web services/APIs and CMS. To get closer to it:
>
> - **PortSwigger Web Security Academy:** already mapped in this vault, closest to the exam question style.
> - **Your own Docker lab:** DVWA, OWASP Juice Shop, a WordPress install (for wpscan) and an intentionally vulnerable API (crAPI, VAmPI), each on its own port or vhost.
> - **INE's own labs** for the course, and VulnHub/HTB-style web boxes for volume.
>
> Whatever you pick, practice the full loop (recon, `recon/` files, notes, answering as a question) with Kali offline.

---

**4. Taking notes with a curated report template seems nice in the paper, but while performing the test, you really lose a lot of time in it. Wouldn't be better, based on the need for efficiency, to simplify as much as possible the template so it would ideally be just pasting the data. Little more than that.**

> Yes. The exam has no report, so notes exist only to answer questions and survive a Kali reset ([exam_doubts_faq.md](<../../3. EXAM STRATEGY/exam_doubts_faq.md>) §1, §2.5). Keep only:
>
> - The **live target template** (§5.2): question → answer checklist, open ports/tech, vulnerable endpoint, credentials. Four short sections.
> - Command output saved by the commands themselves (`-o recon/...`, `| tee`). That is the evidence, no retyping.
> - Paste, don't write: full URL + parameter + the value that answered the question.
>
> The findings template (§5.3) is optional and only worth filling when a finding is not already a line in the checklist.

---

**5. Shouldn't the non web services check be more extensive? Right now, it only covers FTP. What about mysql, postgresql, ssh, SMB, NFS...?**

> The walkthrough (block B) keeps only the FTP quick check and points to the cheatsheet, which already covers more: *Non-web services* has FTP, SMB, NFS, MySQL, MSSQL, PostgreSQL, Redis and MongoDB. The scope is layer 7, so the goal of those checks is web files, web config and credentials, not an OS foothold.
>
> **SSH** is left out on purpose: it exposes no web content, so only its version banner matters (a lead for searchsploit) and credentials found elsewhere may be reused on it.

---

**6. What should I look at when inspecting and browsing html source code?**

> Read it with Ctrl+U in the Burp browser (blocks C and G); a regex misses multi-line comments:
>
> - **Comments** (`<!-- -->`): debug notes, internal paths, old credentials, commented-out links.
> - **Hidden fields** (`type="hidden"`): parameters you may not see in the UI.
> - **Forms:** `action`, `method` and every field name, they are your parameter list.
> - **`<script src>` and inline scripts:** `.js` files to grep (API paths, keys, internal IPs).
> - **Links and paths** that were never visited (grey entries in the Site map).
> - **`<meta name="generator">`** and version strings in file names (`jquery-1.4.2.js`): a product and version for searchsploit.
> - **External hosts** (`src`/`href` to other domains): components of the architecture (block M).
>
> Quick first pass: `curl -sk "<SCHEME>://<VHOST>/" | grep -Eio '<!--.*-->|src="[^"]+\.js"|type="hidden"[^>]*' | sort -u`.

---

**7. What happens to 'only code' php files such as 'config.php' that do not render any HTML but execute? How can I access to the content?**

> The server runs the PHP and sends only its output, which for a config file is an empty page (usually `200` with size 0). You cannot read the source through the normal URL. You read it only when something leaks it:
>
> - **A backup or alternate copy** served as text: `config.php.bak`, `config.php~`, `.config.php.swp`, `config.txt`, `config.phps` (block E, *Backup and temp files* and *Alternate extensions*).
> - **Directory listing**, `.git`, or an anonymous FTP/SMB/NFS share that exposes the web root (blocks E, G, B).
> - **A file-read bug (LFI)**: `php://filter/convert.base64-encode/resource=config.php` returns the source base64-encoded. That is a later-phase test, not recon.
>
> An empty `200` is still useful: the file exists, and it may be `include`d by a page that takes a parameter.

---

**8. I understand that, in recon phase, you don't try SQLi or JS payloads, you just enumerate weak, potential attack vectors, right?**

> Right. Recon outputs **targets and leads**, not findings ("What recon is not" in the Summary). Parameters are noted for the SQLi, XSS and IDOR phases. The only active inputs are harmless: form submissions with benign data, `test`/marker values while fuzzing parameter names, and the single benign-vs-suspicious request pair used to spot a WAF (block M).

---

**9. Which should be exactly the steps with BurpSuite manual inspection?**

> Block C, in this order:
>
> 1. **Scope:** `<IP>` and `^(.*\.)?<DOMAIN>$`; intercept off.
> 2. Open the root in the Burp browser and **read the page source** (Ctrl+U).
> 3. **Click everything once:** every link, menu and form, submitting each form with harmless data so the POSTs are recorded.
> 4. **Target → Site map**, in-scope items only, sorted by URL. Visit the grey (linked but never requested) entries.
> 5. **Proxy → HTTP history:** filter by status (3xx/4xx/5xx) and MIME type, and search for `api`, `token`, `password`, `admin`, `<!--`.
> 6. **Send interesting requests to Repeater** (Ctrl+R), rename the tab, and change the method, a parameter or a header to compare responses.
> 7. **Record** every GET parameter, POST field, custom header, cookie and `.js` file. That list is the input for the next phases.
>
> One target at a time, completely. Intercept stays off except when you edit a request on purpose.

---

**10. How can I filter with more precision in searchsploit?**

> ```bash
> searchsploit -t "apache 2.4.49"                  # match the title only (less noise)
> searchsploit -s "apache 2.4.49"                  # strict: exact version, no range matching
> searchsploit -e "Apache HTTP Server"             # exact phrase
> searchsploit apache 2.4 --exclude="dos|DoS|local"   # drop DoS and local/privesc
> searchsploit --cve 2021-41773                    # by CVE
> searchsploit -j apache 2.4 | jq '.RESULTS_EXPLOIT[] | select(.Type=="webapps")'   # by type
> ```
>
> `-s` can hide valid range matches (`2.4.17 < 2.4.38`), so use it to confirm and use `-t` to explore. The five-step selection order is in the cheatsheet → *searchsploit*: same product and component, version inside the range, type `webapps`/`remote`, no login needed.

---

**11. How to quickly read keywords in a large file?**

> ```bash
> grep -Eio '(api_key|secret|token|passw[a-z]*)[^,;]{0,60}' <FILE>   # only the match + 60 chars (best for minified JS)
> grep -niE 'password|secret|token' <FILE>                          # with line numbers
> grep -rniE 'password|passwd|secret|api_key|token' recon/          # across everything saved
> grep -n -C2 'keyword' <FILE>                                      # 2 lines of context
> ```
>
> `-o` matters on minified files: without it, one match prints the whole single-line file. In a terminal, `less <FILE>` then `/keyword` (`n` for the next hit). In Burp, use the search box in the response/HTTP history.

---

**12. Sometimes, directory listing is enabled for source, backend code. Should I pay attention to those? They can be endless.**

> Yes, but do not browse them by hand. Time-box it (the 30–45 min rule): download the tree once (`wget -r -np -R "index.html*" <URL>`), then grep it (see Q11). Read first the files that carry answers: `.sql`, `.bak`, `.zip`/`.tar.gz`, `.env`, `config*`, `.git`, and anything named after a question topic. Source code is a high-value leak because it gives you parameters, hidden endpoints and credentials.

---

**13. Shouldn't we add more keywords also for brute forcing source code files? Also, it's worth to remark some of them need .ext (index.php.bak) and others don't (index.php7)**

> There are two different patterns and the walkthrough should keep them apart:
>
> | Pattern | Example | Where |
> |---|---|---|
> | **Append** to the full file name | `index.php.bak`, `index.php~`, `.index.php.swp`, `index.php.old`, `index.php.txt` | cheatsheet → *ffuf* (`index.phpFUZZ`) |
> | **Replace** the extension | `index.php7`, `index.phtml`, `index.inc`, `index.phps` | block E, *Alternate extensions on a known page* |
>
> Block E's *Backup and temp files* scan is the third case: bare words plus a suffix (`config.bak`, `dump.sql`, `site.zip`). Extending the lists is cheap (`.phps`, `.php7`, `.phtml`, `.inc`, `.txt`, `.save`, `.copy`), but run it only on pages you already know exist, and keep to two fuzzers at once.

---

**14. Curl case insensitivity? It can throw 400's instead of valid 200's (phpmyadmin vs phpMyAdmin)**

> curl is not the cause: the server decides. Linux servers (Apache/nginx) treat paths as **case-sensitive**, so `/phpMyAdmin/` and `/phpmyadmin/` are different URLs; Windows/IIS are case-insensitive. A wrong-case path normally returns `404` (a `400` means something else in the request is malformed, such as an unencoded space). Hostnames in the `Host` header are case-insensitive.
>
> So when a name is suspected but 404s, try its usual casing (`phpMyAdmin`, `phpmyadmin`). The mixed-case `raft-*-words.txt` lists already cover common variants; the one-off keyword loop in block E only tries lowercase.

---

**15. Shouldn't curl command for searching keywords in large files add the insecure parsing with -a? It'd be -aEi instead of -Eio.**

> `-a` and `-o` do different jobs, so combine them: `grep -aEio`. `-a` forces binary-looking input to be treated as text (otherwise grep prints only `Binary file matches` and hides the hits); `-o` keeps the output to the match. Dropping `-o` would print the whole line, which on minified JS is the entire file. Add `-a` whenever you see `Binary file (standard input) matches`; it is harmless otherwise.

---

**16. Manually trying a few keywords is always worse than using wordlists. Why doing this then? It's used in many commands in the walkthrough.**

> Because those loops are not guessing, they are checking **fixed, known names**, and a wordlist adds nothing there:
>
> - Metafiles, `.git/HEAD`, `.env`, `phpinfo.php`, `actuator/env`, `?wsdl`, `swagger.json`: one specific file each, and directory wordlists skip dotfiles.
> - A loop answers in seconds with status and size, so it can run while ffuf is still going.
>
> The one real exception is *Admin keywords* (block E): it is marked optional because `raft-medium-words.txt` already contains those words. **Skip it once the directory scan runs.**

---

**17. Extend web services with more keywords?**

> Yes, the probe in block I is a short fixed list. Worth adding: `rest`, `v1`, `v2`, `api/v1`, `soap`, `ws`, `rpc`, `jsonrpc`, `xmlrpc.php`, `wp-json`, `swagger-ui.html`, `swagger/v1/swagger.json`, `api/swagger.json`, `docs`, `redoc`, `graphiql`, `*.asmx?wsdl`, `*.svc?wsdl`. Once an `/api` path exists, the wordlist step takes over (`api-endpoints.txt` in block I, plus the other lists in SecLists `Discovery/Web-Content/api/`). The loop only finds the door, the wordlist finds the rooms.

---

**18. How to deal with complex baselining? Sometimes, server can return 200 for not found pages, resembling exactly like valid ones. This happens in mutillidae with index.php?page=whatever.php, for example.**

> `-ac` only learns the response of a random miss, so it fails when "not found" is rendered inside a valid page. Calibrate by hand:
>
> 1. Request two or three non-existent values and compare: `curl -sk -o /dev/null -w "%{size_download} %{http_code}\n" "<URL>?page=zz9"`.
> 2. Pick the filter that stays stable: `-fs <SIZE>` (size), `-fw <WORDS>` (word count), `-fl <LINES>` (line count) or `-fr "<error text>"` (regex on the not-found message).
> 3. Alternatively, match the valid case instead: `-mr "<text only valid pages contain>"`.
>
> If the size varies because the page echoes your input, `-fw`/`-fl` are steadier than `-fs`. Burp's Comparer works for one-off checks.

---

**19. What's the action protocol when wafw00f returns positive?**

> 1. **Note** the WAF name in your target notes (block M).
> 2. **Slow down:** lower threads (`-t 2` to `-t 5`) and add a delay (`ffuf -p 0.5`), or the WAF will start blocking your IP.
> 3. **Stop spraying payloads:** use the minimum standard payloads first, then the encoding and filter-bypass tricks (Phase 2 block E, Phase 8).
> 4. **Look around it:** other ports and vhosts, the direct IP, and DOM XSS (client-side, never reaches the WAF).
>
> A "no WAF" result is not proof. If payloads still change the response (`403`/`406`), run the benign-vs-suspicious comparison in block M.

---

**20. Which headers are crucial for the eWPTv2 exam?**

> No source in the vault lists exam-specific headers, so this is a prioritisation by what they can answer (block D):
>
> - **`Server`, `X-Powered-By`, `X-AspNet-Version`:** product and version, for searchsploit and "what runs here" questions.
> - **`Set-Cookie`** (`HttpOnly`, `Secure`, `SameSite`): session tests; `HttpOnly` also decides whether the Phase 2 cookie-theft demo can work.
> - **`Location`:** redirects that reveal hostnames to add to `/etc/hosts`.
> - **`Allow`** (from `OPTIONS`): dangerous verbs (`PUT`, `DELETE`, `TRACE`).
> - **`Via`, `X-Cache`, `CF-Ray`:** proxy, CDN or WAF in front.
> - **`WWW-Authenticate`:** the auth scheme behind a `401`.
> - **`Content-Type`:** API (`json`/`xml`) vs HTML.
> - **Security headers** (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`): informational, report them only if a question asks.
