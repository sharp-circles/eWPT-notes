## FAQ

Block letters (A–H) refer to [🧭 phase-walkthrough.md](<./🧭 phase-walkthrough.md>); *cheatsheet* means [📜 cheatsheet.md](<./📜 cheatsheet.md>).

---

**1. First step is identifying the parameters. With OWASP ZAP could be easier. If baselining is not correctly configured, you might be losing testing surface here. What's the best way to ensure having all parameters discovered?**

> No single tool guarantees it, so build the worklist from several independent sources and merge them (block A):
>
> 1. **Burp manual walk** (Phase 1 block C): every link and form, so the Site map holds real GET/POST parameters.
> 2. **ZAP spider** as a second opinion: its *Params* tab lists every parameter it saw. Diff it against Burp.
> 3. **Parameter fuzzing** (Phase 1 block J) only on pages that look like they take input.
> 4. **Page source and JS:** form field names, hidden inputs, and `fetch`/`XMLHttpRequest` bodies.
> 5. **API docs** (Swagger/WSDL) when they exist.
>
> Merge with `sort -u`. To check the baseline of the fuzzing, send two or three random names first: if they all look identical, `-ac` is fine; if the size or word count wobbles, switch to `-fs`/`-fw`/`-fl` (Phase 1 FAQ Q18). A parameter found later re-enters at block B (restart rule).

---

**2. Apart from parameters, there are more entry points. Form fields, JS files, cookies, headers... How can you perform a quick and efficient identification of them?**

> Block A already defines the worklist: parameters, form fields, `.js` files, cookie names and custom headers. Fast ways to fill it:
>
> - **Forms and fields:** `curl -sk <URL> | grep -Eio '<(form|input|textarea|select)[^>]*>'`.
> - **JS files:** `grep -oE 'src="[^"]+\.js"'` on each page; then `grep -E 'fetch\(|XMLHttpRequest|axios|\.ajax'` in them for hidden API calls.
> - **Cookies:** the `Set-Cookie` lines in Burp's HTTP history (or DevTools → Application).
> - **Headers:** no discovery needed, there is a fixed candidate list: `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Forwarded-Host`, `Origin` (cheatsheet → *Marker sweep variants*).
>
> In Burp, searching the HTTP history for `<form`, `hidden` and `Set-Cookie` covers most of it in a minute.

---

**3. BLOCK B. Do we need to check the headers of every url? And every param of every url?**

> **Parameters: yes, all of them**, but scripted: it is one request per parameter and takes seconds (use the loop in cheatsheet → *Marker sweep variants*). A parameter never marked is a parameter never tested.
>
> **Headers: no, not per URL.** Header reflection depends on the template or code path that prints it, not on each URL. Test them once per distinct page type: the login page, an error page (`404`/`500`), any page that shows request details, and the pages an admin might see (logs, analytics). Do the same for cookies: once per cookie, on a page that uses it.
>
> This is a time-saving heuristic, not a guarantee. If a question hints at a header or log viewer, test it on that page specifically.

---

**4. BLOCK C. Shouldn't I search for the reflected characters better in BurpSuite rather than with curl? I mean it with an eye on efficiency and speed**

> Use each for what it is good at:
>
> - **curl + `grep -o`** for the sweep and the context probe: scriptable over every parameter, and `grep -o "zzXSS9f2a.\{0,40\}"` shows the context in one line. Burp Community's Intruder is throttled, so for more than a handful of parameters curl is faster.
> - **Burp Repeater** when you have to read a response carefully (Ctrl+F on the marker, Inspector, headers) and for every real payload.
> - **The browser** for anything that needs JavaScript to run (DOM XSS, block G): curl never executes scripts.
>
> Rule: sweep with curl, read and exploit in Repeater.

---

**5. BLOCK E. About accepted tags and attributes. Wouldn't it be better with brute force?**

> Yes, and that is what block E is: a loop over a candidate list, the same idea as the PortSwigger labs (find the allowed tag, then the allowed event). The walkthrough shows a short list for speed; the cheatsheet → *Filter bypass cheatsheet* has a longer one. When the short one finds nothing, run the full tag list (about 150 tags) and then the full event list (about 100) against the allowed tag, with the loop or Burp Intruder.
>
> Kali has no internet during the exam, so keep the full lists in your notes before the exam.
>
> One caveat on the loop: it only checks that the marker comes back. If the server HTML-encodes `<` (`&lt;svg x=zz9`), the marker survives although the tag does not, so grep for the whole `<tag x=zzXSS9f2a` string to avoid false positives.

---

**6. BLOCK F. Code 200/302 do not ensure writing success. Wouldn't it be better to do it manually?**

> Right, the status code only says the server answered, and the walkthrough treats it that way: *"This alone proves nothing about XSS yet — persistence does."* The real proof is reading the marker back from the page that renders it (the second step of block F, `grep -o` on `<RENDER_URL>` with `<ROLE_A>` and `<ROLE_B>`).
>
> A hybrid works best: submit **manually in Burp/the browser** when the form needs a CSRF token, several steps, a captcha or a file upload, and read it back **with curl**, which is quick to repeat for every write surface. If the marker is not found anywhere, the write was not accepted or it renders on a page you have not checked yet.
