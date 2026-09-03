// Copyright (c) the go-gnulinux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package factors makes Linux's authentication factors usable by
// github.com/go-authn/mfa.
//
//	r, err := mfa.Verify(ctx, mfa.Policy{Count: 2},
//	    somethingYouKnow,                            // yours to supply
//	    factors.SecurityKey("example.test", credID), // this
//	)
//
// # There is one factor here, and that is the honest count
//
// Linux has no standard biometric service the way macOS has
// LocalAuthentication and Windows has Hello. fprintd exists, over D-Bus, on
// some desktops, for some readers; PAM sits at a different layer and answers a
// different question. Neither is "the platform's authenticator" in the sense
// the other two packages mean, and shipping one here would put a factor in
// front of people that works on one machine in ten.
//
// So this offers possession, and says so. A caller who needs two KINDS
// supplies the other themselves — which is more honest than a package guessing,
// and no worse off than Windows, where nothing reports which modality answered
// anyway.
//
// A fingerprint factor over fprintd is the obvious thing to add. It wants its
// own bibliography and a machine to be proven on, not a hurried afternoon.
//
// # What is here, and what is elsewhere
//
// Almost nothing. Asking a security key is the same everywhere CTAP is, so it
// lives once, in github.com/go-authn/keyfactor. What Linux knows — where a key
// is, and what its absence means — is what stays here.
package factors

import (
	"context"
	"errors"

	fido "github.com/go-authn/fido"
	"github.com/go-authn/keyfactor"
	"github.com/go-authn/mfa"
)

// SecurityKey is a registered credential on an attached key, as a factor: the
// key must be present and a human must touch it.
//
// credentialID is what a registration returned. Passing none asks the key for
// a discoverable credential, which it has only if one was registered with the
// "rk" option.
func SecurityKey(rpID string, credentialID []byte) mfa.Factor {
	return keyfactor.New(open, keyfactor.Options{RPID: rpID, CredentialID: credentialID})
}

// VerifiedSecurityKey is the same, with the key asked to establish who is
// holding it.
//
// The kind does not change: see github.com/go-authn/keyfactor. A wrong PIN
// costs the key a retry and a key that runs out locks, so how many are left is
// asked for before one is spent.
func VerifiedSecurityKey(rpID string, credentialID []byte, pin string) mfa.Factor {
	return keyfactor.New(open, keyfactor.Options{RPID: rpID, CredentialID: credentialID, PIN: pin})
}

// open is the seam: everything above it is portable, everything below is
// hidraw.
var open keyfactor.Opener = platformOpen

// asUnavailable is what this package knows and the portable half cannot: which
// failures mean there was nothing here to ask.
//
// An empty USB port is the obvious one. ⛔ A key this user may not OPEN is the
// one that matters: /dev/hidraw* is root-only on a stock system, and reporting
// that as a refusal would send somebody to touch their key harder when the
// answer is a udev rule. Nobody refused anything — so it is unavailable, and
// the wrapped error names the rule.
func asUnavailable(err error, sentinels ...error) error {
	for _, s := range sentinels {
		if errors.Is(err, s) {
			return keyfactor.Unavailable(err)
		}
	}
	return err
}

// compile-time proof that what this package opens is what the portable half
// asks for.
var _ func(context.Context) (fido.Transport, error) = open
