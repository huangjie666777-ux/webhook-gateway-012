package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

func VerifySignature(secret, timestamp string, body []byte, signature string, now time.Time, maxSkew time.Duration) bool {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || maxSkew <= 0 {
		return false
	}
	given := make([]byte, hex.DecodedLen(len(signature)))
	n, err := hex.Decode(given, []byte(signature))
	if err != nil {
		return false
	}
	given = given[:n]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	want := mac.Sum(nil)
	eventTime := time.Unix(ts, 0)
	diff := now.Sub(eventTime)
	if diff < 0 {
		diff = -diff
	}
	return diff <= maxSkew && hmac.Equal(given, want)
}
