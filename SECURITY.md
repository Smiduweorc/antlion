# Security Policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| 1.x, latest minor | Yes |
| Older 1.x minors | No: upgrade to the latest minor, which is never breaking |
| 0.x | Never published |

A fix ships as a patch release on the latest minor.

## Reporting a vulnerability

Report it privately through GitHub: the **Report a vulnerability** button
under the **Security** tab of
[Smiduweorc/antlion](https://github.com/Smiduweorc/antlion/security/advisories/new).
That opens a private advisory only the maintainers can see. Please don't open
a public issue for it.

Useful to include: the version, the request (or the proof and token shapes)
that gets through, which check you expected to refuse it, and whether it needs
a particular store, framework or Lacewing profile.

## What to expect

Antlion is maintained by one person, as a side project. There is no
response-time promise. What is promised:

- every report gets read, and an answer saying whether it is accepted;
- an accepted report gets a fix, a test that reproduces it, a GitHub security
  advisory, and a CHANGELOG entry, in that release;
- you are credited in the advisory, unless you'd rather not be.

What Antlion does and does not protect against is in
[the threat model](./guides/threat-model.md). A report about something listed
there as out of scope is still welcome, but it is likely to be answered by a
documentation change.

> This document was left empty for a long time as I didn't really want to expose my identity and most of my projects originate as projects from my personal instance of gitlabs. But I also understand that this is something people expect as a bare minimum from a dep that claims to be more security centric.
> Credits to [honeycomb](https://raw.githubusercontent.com/honeycombio/examples/refs/heads/main/SECURITY.md) for the security markdown file.
