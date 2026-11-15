## FAQ

- First step is identifying the parameters. With OWASP ZAP could be easier. If baselining is not correctly configured, you might be losing testing surface here. What's the best way to ensure having all parameters discovered?
- Apart from parameters, there are more entry points. Form fields, JS files, cookies, headers... How can you perform a quick and efficient identification of them?
- BLOCK B. Do we need to check the headers of every url? And every param of every url?
- BLOCK C. Shouldn't I search for the reflected characters better in BurpSuite rather than with curl? I mean it with an eye on efficiency and speed
- BLOCK E. About accepted tags and attributes. Wouldn't it be better with brute force?
- BLOCK F. Code 200/302 do not ensure writing success. Wouldn't it be better to do it manually?