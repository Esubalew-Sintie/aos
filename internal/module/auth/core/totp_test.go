package core

import (
	"testing"
	"time"
)

func TestTOTPMatchesTheReferenceVectors(t *testing.T) {
	// RFC 6238, appendix B, for SHA1 with the secret "12345678901234567890",
	// truncated to 6 digits.
	secret := []byte("12345678901234567890")
	for _, tc := range []struct {
		at   int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		if got := TOTPCode(secret, TOTPStep(time.Unix(tc.at, 0))); got != tc.code {
			t.Errorf("at %d: got %s, want %s", tc.at, got, tc.code)
		}
	}
}

func TestVerifyTOTPAcceptsNeighboursAndRefusesReplay(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	step := TOTPStep(now)
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, step-1), now, 0); !ok {
		t.Error("the previous step was refused")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, step+1), now, 0); !ok {
		t.Error("the next step was refused")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, step+2), now, 0); ok {
		t.Error("a step two away was accepted")
	}
	if _, ok := VerifyTOTP(secret, "05 04 71", now, 0); !ok {
		t.Error("spaces were not ignored")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, step), now, step); ok {
		t.Error("a replayed code was accepted")
	}
	if _, ok := VerifyTOTP(secret, "000000", now, 0); ok {
		t.Error("a wrong code was accepted")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := NewRecoveryCodes(10)
	if err != nil || len(codes) != 10 {
		t.Fatal(err, codes)
	}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' {
			t.Fatalf("code %q has the wrong shape", c)
		}
	}
	if NormalizeRecoveryCode(" AbCdE-fGh2K ") != "abcdefgh2k" {
		t.Fatal("normalization")
	}
	if u := TOTPURI("Shop", "a@b.c", []byte("12345678901234567890")); u != "otpauth://totp/Shop:a@b.c?algorithm=SHA1&digits=6&issuer=Shop&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Fatalf("uri: %s", u)
	}
}
