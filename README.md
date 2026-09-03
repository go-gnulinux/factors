# factors

[![Go Reference](https://pkg.go.dev/badge/github.com/go-gnulinux/factors.svg)](https://pkg.go.dev/github.com/go-gnulinux/factors)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-gnulinux/factors/actions/workflows/ci.yml/badge.svg)](https://github.com/go-gnulinux/factors/actions/workflows/ci.yml)

Linux's authentication factors, as factors —
[`mfa.Factor`](https://github.com/go-authn/mfa) values a policy can ask. Pure
Go, `CGO_ENABLED=0`.

```go
r, err := mfa.Verify(ctx, mfa.Policy{Count: 2},
    somethingYouKnow,                              // yours to supply
    factors.SecurityKey("example.test", credID),   // this
)
```

## There is one factor here, and that is the honest count

Linux has no standard biometric service the way macOS has LocalAuthentication
and Windows has Hello. fprintd exists, over D-Bus, on some desktops, for some
readers; PAM sits at a different layer and answers a different question.
Neither is *the platform's authenticator* in the sense the other two packages
mean, and shipping one here would put a factor in front of people that works on
one machine in ten.

So this offers **possession**, and says so. A caller who needs two *kinds*
supplies the other themselves — more honest than a package guessing, and no
worse off than Windows, where
[nothing reports which modality answered](https://github.com/go-mswin/factors)
anyway.

A fingerprint factor over fprintd is the obvious thing to add. It wants its own
bibliography and a machine to be proven on, not a hurried afternoon.

## Almost nothing is here, on purpose

Asking a security key is the same everywhere CTAP is, so it lives once, in
[go-authn/keyfactor](https://github.com/go-authn/keyfactor): the assertion, the
flag checks, the refusal to spend somebody's last PIN attempt. This package was
about to be a second copy of it that differed in one line.

What stays here is what only Linux knows: where a key is, and what its absence
means.

⛔ **A key you may not open is not a key that refused.** `/dev/hidraw*` is
root-only on a stock system; libfido2 ships `udev/70-u2f.rules` to change that.
Reporting it as a refusal would send somebody to touch their key harder when
the answer is a file in `/etc/udev`. It is reported as `mfa.ErrUnavailable`,
and the wrapped error names the rule.

Only the named conditions are excused. Excusing everything would turn every
fault into "no key", which is the same mistake wearing the opposite coat.

## Coverage

100%, on any machine, with no key: the classification, the error mapping and
the seam all run without hardware. `platformOpen` reaches a real
`/dev/hidraw*`, so no runner can exercise it — and the transport it opens
([go-gnulinux/fido](https://github.com/go-gnulinux/fido)) has not been run
against a key either. Both say so.
