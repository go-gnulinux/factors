// Copyright (c) the go-gnulinux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package factors

import (
	"context"
	"errors"
	"testing"

	fido "github.com/go-authn/fido"
	"github.com/go-authn/mfa"
)

// swap installs a fake opener and puts the real one back.
func swap(t *testing.T, o func(context.Context) (fido.Transport, error)) {
	t.Helper()
	old := open
	t.Cleanup(func() { open = old })
	open = o
}

// TestThereIsOnePossessionFactorHere, and no inherence one, deliberately.
// Linux has no standard biometric service, and a factor that worked on one
// machine in ten would be worse than none.
func TestTheFactorIsPossession(t *testing.T) {
	if got := SecurityKey("example.test", nil).Kind(); got != mfa.Possession {
		t.Errorf("a security key is %v, want possession", got)
	}
	if got := VerifiedSecurityKey("example.test", nil, "0000").Kind(); got != mfa.Possession {
		t.Errorf("a verified key is %v, want possession", got)
	}
	// So a two-KIND policy needs something this package does not supply.
	swap(t, func(context.Context) (fido.Transport, error) { return nil, errors.New("no") })
	if _, err := mfa.Verify(context.Background(),
		mfa.Policy{Count: 2, DistinctKinds: true},
		SecurityKey("a.test", nil), VerifiedSecurityKey("b.test", nil, "0000"),
	); err == nil {
		t.Fatal("two keys satisfied a two-KIND policy")
	}
}

// TestAKeyYouMayNotOpenIsNotAKeyThatRefused. /dev/hidraw* is root-only on a
// stock system, and reporting that as a refusal sends somebody to touch their
// key harder when the answer is a udev rule.
func TestAKeyYouMayNotOpenReadsAsUnavailable(t *testing.T) {
	permission := errors.New("a security key is attached but this user cannot open it; install a udev rule")
	wrapped := asUnavailable(permission, permission)
	if !errors.Is(wrapped, mfa.ErrUnavailable) {
		t.Error("a permission failure was reported as a refusal")
	}
	if !errors.Is(wrapped, permission) {
		t.Error("the reason was lost, so nobody learns about the udev rule")
	}
}

// TestSomethingElseGoingWrongIsStillAFailure: only the named conditions are
// excused, because excusing everything would turn every fault into "no key".
func TestAnUnrecognisedFailureIsPassedThrough(t *testing.T) {
	boom := errors.New("the bus caught fire")
	if got := asUnavailable(boom, errors.New("something else")); errors.Is(got, mfa.ErrUnavailable) {
		t.Error("an unrelated failure was excused as an absence")
	} else if !errors.Is(got, boom) {
		t.Error("the failure was altered on its way through")
	}
}

func TestTheFactorsSayWhatTheyAre(t *testing.T) {
	if got := SecurityKey("a", nil).Name(); got != "your security key" {
		t.Errorf("Name() = %q", got)
	}
	if got := VerifiedSecurityKey("a", nil, "0000").Name(); got == SecurityKey("a", nil).Name() {
		t.Error("the verified factor does not say it will ask for a PIN")
	}
}

// TestTheOpenerIsWhatTheSeamCarries. The portable half is asked for exactly
// this shape, and a change on either side must not compile.
func TestTheFactorReachesTheOpener(t *testing.T) {
	called := 0
	swap(t, func(context.Context) (fido.Transport, error) {
		called++
		return nil, errors.New("no key")
	})
	if err := SecurityKey("example.test", []byte("c")).Verify(context.Background()); err == nil {
		t.Fatal("a factor with no key behind it succeeded")
	}
	if called != 1 {
		t.Errorf("the opener was reached %d times", called)
	}
}
