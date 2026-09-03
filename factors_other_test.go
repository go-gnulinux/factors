// Copyright (c) the go-gnulinux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package factors

import (
	"context"
	"errors"
	"testing"

	"github.com/go-authn/mfa"
)

// TestOffLinuxTheFactorIsAbsentRatherThanRefusing.
func TestOffLinuxTheFactorIsAbsent(t *testing.T) {
	err := SecurityKey("example.test", nil).Verify(context.Background())
	if err == nil {
		t.Fatal("the factor succeeded off Linux")
	}
	if !errors.Is(err, mfa.ErrUnavailable) {
		t.Errorf("err = %v, want it to read as unavailable", err)
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("the reason was lost: %v", err)
	}
}
