# Security Policy

## Responsible Disclosure

- This tool is for **educational and ethical hacking only**.
- **Do not use it on unauthorized systems.**
- Only use ParamStriker against targets where you have **explicit written authorization** — a bug-bounty program's stated scope, an internal red-team engagement, a paid penetration test, or your own infrastructure.
- Any misuse of this software is the **sole responsibility of the user**.

---

## Tool Safety

ParamStriker is **fully offline by design**:

- It does **NOT** make any network requests.
- It does **NOT** scan, fingerprint, or enumerate targets.
- It does **NOT** exploit systems.
- It only writes **payload files to disk** that the operator may choose to load into other tooling (Burp, ffuf, custom harness).

Hard safety caps enforced at runtime:

| Cap | Value | Why |
|---|---|---|
| Max payload size | 256 KiB | Avoid OOM in downstream tooling |
| Max nesting depth | 50 | Avoid stack overflow on parse |
| Max payloads / generator | 100 000 | Avoid runaway generation |
| DoS payload class | disabled | Off unless `--unsafe` flag passed |

---

## Reporting Security Issues with ParamStriker Itself

If you discover a security issue with **ParamStriker the tool** (for example, a path-traversal in the output writer, or behaviour that could harm the user's host system), please open a **private security advisory** on the GitHub repository — **do not** open a public issue.

We will respond within 7 days, work with you on a fix, and credit you in the release notes.

---

## Guidelines for Bug-Bounty / Authorized Testing

When using ParamStriker against any external target:

1. **Verify scope** before running any payloads. Check the program's published scope, rules of engagement, and excluded endpoints.
2. **Respect rate limits** and the program's testing policy.
3. **Throttle** — if you load 3000+ ParamStriker payloads into Burp Intruder, dial down the concurrency so you don't accidentally DoS the target.
4. **Disclose** findings exclusively through the program's official channel.
5. **Never** use ParamStriker payloads to access, modify, copy, exfiltrate, or destroy data on systems you do not own or have explicit authorization to test.
6. **Never** chain ParamStriker payloads into a working exploit and use it against a non-authorized target. ParamStriker only emits **test cases**; the operator is fully responsible for how those test cases are used.

---

## Prohibited Uses

You may **not** use ParamStriker (or any payload it generates) to:

- Test systems you do not own or are not authorized to test.
- Process personal data of EU / UK / California / other-jurisdiction residents outside the bounds of GDPR / CCPA / equivalent law.
- Attack election infrastructure, critical infrastructure, medical devices, or safety-of-life systems.
- Violate any law applicable in your jurisdiction.

---

## Disclaimer

The authors and contributors of ParamStriker assume **no liability** for any misuse of this software. By using ParamStriker, you accept full responsibility for ensuring that your testing is **legal**, **authorized**, and **ethical**.

---

## Maintainer

**Mohnad Alshobaili** · X: [@Mohnad](https://x.com/Mohnad)
