# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability
reporting: on https://github.com/zdrng/petschaft open the **Security** tab and choose
**Report a vulnerability** (this creates a draft security advisory visible only to the
maintainers). Do not open a public issue or pull request for a vulnerability.

Include what is affected (version or commit), how to reproduce it and what an attacker
gains. You will get an answer as soon as possible; fixes are published together with a
GitHub Security Advisory, crediting the reporter unless they prefer otherwise.

## Scope

In scope: the code in this repository, i.e. the `pets` CLI and its crates, the SSH
agent, the Python helper, the APK signing pipeline and the Nix package and modules.
Examples of relevant issues:

- something gets signed that the device display did not show, or showed misleadingly;
- a signature is accepted or used without local verification, or a pinned key or host
  key is bypassed;
- the agent signs for a forwarded connection or an unpinned server;
- the pairing credential leaks (logs, files, error messages) or is stored outside the
  OS secret store;
- crashes or unbounded resource use on untrusted input (agent messages, helper frames,
  APK/ZIP, key lines, config).

Out of scope: vulnerabilities in the Trezor firmware, trezorlib, OpenSSH, apksigner,
nixpkgs or other third-party components (please report those upstream), and attacks
that require a compromised computer to lie about what is being signed while the user
confirms without reading the device display.

## Bounty

This is a volunteer project; there is no bug bounty.
