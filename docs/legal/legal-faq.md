# Legal FAQ – ASH SDK

This document answers common legal and usage-related questions
regarding ASH (Application Security Hash).

---

## Is ASH an attack prevention or threat mitigation system?

No.

ASH validates request integrity and enforces single-use constraints.

While these properties may reduce the feasibility or impact of certain
attack scenarios, ASH is not designed, represented, or intended to
function as an attack prevention, detection, or threat mitigation system.

---

## Can ASH be considered a security control?

ASH is a **technical integrity mechanism** and should be used as part of a layered security architecture.

It must not be relied upon as a substitute for authentication,
authorization, firewalls, or secure coding practices.

---

## Does ASH guarantee security?

No.

ASH does not guarantee protection against any class of attack or
security incident.

It validates request integrity and enforces single-use constraints only.

---

## Can ASH stop SQL injection, XSS, or logic attacks?

No.

ASH does not analyze input semantics, validate business logic,
or prevent injection-style vulnerabilities.

These must be handled by the application itself.

---

## Can ASH protect against compromised clients or malware?

No.

If a client or execution environment is compromised, ASH cannot
distinguish malicious requests from legitimate ones.

---

## Is ASH a replacement for TLS, JWT, or OAuth?

No.

ASH does not replace:
- TLS / HTTPS
- JWT, OAuth, sessions, or API keys
- API gateways or firewalls

ASH is designed to complement these mechanisms.

---

## Is ASH free to use?

Yes, subject to the license terms.

ASH Core is released under the Apache License 2.0.

You are free to use, modify, and distribute the open-source code in accordance with the license terms.

However, "ASH" and "ASH Security SDK" are trademarks of 3maem Co.
Forked or modified versions may not use the ASH name, logo, or imply official endorsement without written permission.

---

## Who is responsible for secure deployment?

The implementing party is solely responsible for:

- Correct integration
- Secure configuration
- Operational monitoring
- Overall application security

ASH is provided "as is".

---

## Why is the source code open?

The source code is open under the Apache 2.0 license for transparency, auditability, and community contribution.

You may use, modify, and distribute the code in accordance with the license terms.

The ASH name and branding remain trademarks of 3maem Co.

---

## Who maintains and develops ASH?

All official development, maintenance, and enhancements are
exclusively performed by 3maem Co.

---

© 3maem Co. | شركة عمائم
All Rights Reserved.
