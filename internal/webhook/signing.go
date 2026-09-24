package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// SigningInput builds the canonical string: timestamp + "." + raw body.
func SigningInput(timestamp string, body []byte) []byte {
	out := make([]byte, 0, len(timestamp)+1+len(body))
	out = append(out, timestamp...)
	out = append(out, '.')
	out = append(out, body...)
	return out
}

// ComputeSignature returns the hex HMAC-SHA256 used by curl examples. The
// secret string's raw bytes are the HMAC key.
func ComputeSignature(secretHex, timestamp string, body []byte) (string, error) {
	mac := hmac.New(sha256.New, []byte(secretHex))
	mac.Write(SigningInput(timestamp, body))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// verifySignature validates the provided signature in constant time. Both hex
// and standard base64 encodings are accepted.
func verifySignature(secret, timestamp, signature string, body []byte) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(SigningInput(timestamp, body))
	want := mac.Sum(nil)
	got, err := decodeSignature(signature)
	if err != nil {
		return false
	}
	return hmac.Equal(got, want)
}

func decodeSignature(signature string) ([]byte, error) {
	signature = strings.TrimSpace(signature)
	if b, err := hex.DecodeString(signature); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(signature)
}

// validateTimestamp enforces a signed-unix-seconds timestamp within skew.
func validateTimestamp(raw string, now time.Time, skew time.Duration) (int64, error) {
	ts, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || ts <= 0 {
		return 0, ErrTimestampSkew
	}
	diff := now.Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if time.Duration(diff)*time.Second > skew {
		return 0, ErrTimestampSkew
	}
	return ts, nil
}
