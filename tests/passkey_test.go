package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jackc/pgx/v5"
)

// softKey plays a platform authenticator: it keeps one key pair per
// credential, verifies the user (by assumption), and counts signatures.
type softKey struct {
	t          *testing.T
	origin     string
	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
	counter    uint32
}

func newSoftKey(t *testing.T, origin string) *softKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		t.Fatal(err)
	}
	return &softKey{t: t, origin: origin, key: key, credID: credID}
}

var b64 = base64.RawURLEncoding

func (k *softKey) clientData(ceremony, challenge string) []byte {
	raw, _ := json.Marshal(map[string]any{"type": ceremony, "challenge": challenge, "origin": k.origin})
	return raw
}

// register answers a registration challenge with a "none" attestation.
func (k *softKey) register(options json.RawMessage) json.RawMessage {
	k.t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opts); err != nil {
		k.t.Fatal(err)
	}
	k.userHandle, _ = b64.DecodeString(opts.PublicKey.User.ID)
	rpHash := sha256.Sum256([]byte(opts.PublicKey.RP.ID))

	// COSE key: EC2, ES256, P-256.
	x := k.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := k.key.PublicKey.Y.FillBytes(make([]byte, 32))
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		k.t.Fatal(err)
	}
	var authData []byte
	authData = append(authData, rpHash[:]...)
	authData = append(authData, 0x45) // UP, UV, AT
	authData = binary.BigEndian.AppendUint32(authData, k.counter)
	authData = append(authData, make([]byte, 16)...) // aaguid
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(k.credID)))
	authData = append(authData, k.credID...)
	authData = append(authData, cose...)
	attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		k.t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.credID), "rawId": b64.EncodeToString(k.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(k.clientData("webauthn.create", opts.PublicKey.Challenge)),
			"attestationObject": b64.EncodeToString(attestation),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults": map[string]any{},
	})
	return raw
}

// assert answers a sign-in challenge. The counter moves forward unless
// the caller wants to replay.
func (k *softKey) assert(options json.RawMessage, replay bool) json.RawMessage {
	k.t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RPID      string `json:"rpId"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opts); err != nil {
		k.t.Fatal(err)
	}
	if !replay {
		k.counter++
	}
	rpHash := sha256.Sum256([]byte(opts.PublicKey.RPID))
	var authData []byte
	authData = append(authData, rpHash[:]...)
	authData = append(authData, 0x05) // UP, UV
	authData = binary.BigEndian.AppendUint32(authData, k.counter)
	clientData := k.clientData("webauthn.get", opts.PublicKey.Challenge)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		k.t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.credID), "rawId": b64.EncodeToString(k.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"authenticatorData": b64.EncodeToString(authData),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(k.userHandle),
		},
		"clientExtensionResults": map[string]any{},
	})
	return raw
}

type challengeData struct {
	ChallengeID string          `json:"challenge_id"`
	Options     json.RawMessage `json:"options"`
}

func TestPasskeysSignInWithoutAnEmail(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop") // app at https://app.test
	id, session := tn.user("hana@example.com", "some-password")
	key := newSoftKey(t, "https://app.test")

	// Adding a passkey: a challenge, then the browser's answer.
	r := tn.front("POST", "/v1/me/passkeys/options", nil, session)
	if r.Status != 200 {
		t.Fatalf("options: %d %s", r.Status, r.Raw)
	}
	var ch challengeData
	r.data(&ch)
	if !strings.Contains(string(ch.Options), `"rp":{"name":"App shop","id":"app.test"}`) && !strings.Contains(string(ch.Options), `"id":"app.test"`) {
		t.Fatalf("options: %s", ch.Options)
	}
	r = tn.front("POST", "/v1/me/passkeys", obj{"challenge_id": ch.ChallengeID, "name": "Laptop", "credential": key.register(ch.Options)}, session)
	if r.Status != 201 {
		t.Fatalf("register: %d %s", r.Status, r.Raw)
	}
	// A challenge works once.
	if r := tn.front("POST", "/v1/me/passkeys", obj{"challenge_id": ch.ChallengeID, "credential": key.register(ch.Options)}, session); r.Status == 201 {
		t.Fatal("a challenge was answered twice")
	}
	var keys []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	tn.front("GET", "/v1/me/passkeys", nil, session).data(&keys)
	if len(keys) != 1 || keys[0].Name != "Laptop" {
		t.Fatalf("passkeys: %+v", keys)
	}
	var factors struct {
		Passkeys int `json:"passkeys"`
	}
	tn.front("GET", "/v1/me/factors", nil, session).data(&factors)
	if factors.Passkeys != 1 {
		t.Fatalf("factors: %+v", factors)
	}

	// Signing in: no email typed. The browser offers the passkey.
	r = tn.front("POST", "/v1/passkey/options", nil, "")
	if r.Status != 200 {
		t.Fatalf("sign-in options: %d %s", r.Status, r.Raw)
	}
	r.data(&ch)
	r = tn.front("POST", "/v1/passkey/sign-in", obj{"challenge_id": ch.ChallengeID, "credential": key.assert(ch.Options, false)}, "")
	if r.Status != 200 {
		t.Fatalf("passkey sign-in: %d %s", r.Status, r.Raw)
	}
	var signedIn struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		SessionToken string `json:"session_token"`
		Session      struct {
			SecondFactorAt string `json:"second_factor_at"`
		} `json:"session"`
	}
	r.data(&signedIn)
	if signedIn.User.ID != id || signedIn.SessionToken == "" || signedIn.Session.SecondFactorAt == "" {
		t.Fatalf("signed in: %s", r.Raw)
	}
	// A verified passkey counts as two factors: no step-up needed.
	tn.back("PUT", "/v1/permissions", obj{"name": "payment.refund", "step_up_seconds": 300})
	tn.back("PUT", "/v1/roles", obj{"name": "Finance", "permissions": []string{"payment.*"}})
	tn.back("POST", "/v1/grants", obj{"principal_id": id, "role": "Finance", "resource": obj{"type": "tenant", "id": "root"}})
	var sess struct {
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
	}
	tn.front("GET", "/v1/session", nil, signedIn.SessionToken).data(&sess)
	var can struct {
		Allowed bool `json:"allowed"`
	}
	tn.back("POST", "/v1/can", obj{"principal_id": id, "permission": "payment.refund", "resource": obj{"type": "tenant", "id": "root"}, "session_id": sess.Session.ID}).data(&can)
	if !can.Allowed {
		t.Fatal("a passkey session needed a step-up")
	}

	// Wrong origin, replayed counter and a foreign challenge are refused.
	tn.front("POST", "/v1/passkey/options", nil, "").data(&ch)
	evil := *key
	evil.origin = "https://evil.test"
	if r := tn.front("POST", "/v1/passkey/sign-in", obj{"challenge_id": ch.ChallengeID, "credential": evil.assert(ch.Options, false)}, ""); r.code() != "passkey_failed" {
		t.Fatalf("wrong origin: %d %s", r.Status, r.Raw)
	}
	tn.front("POST", "/v1/passkey/options", nil, "").data(&ch)
	if r := tn.front("POST", "/v1/passkey/sign-in", obj{"challenge_id": ch.ChallengeID, "credential": key.assert(ch.Options, true)}, ""); r.code() != "passkey_cloned" {
		t.Fatalf("replayed counter: %d %s", r.Status, r.Raw)
	}
	if n := tn.count(`SELECT count(*) FROM aos.audit_log WHERE action = 'passkey.clone_suspected'`); n != 1 {
		t.Fatalf("clone audit: %d", n)
	}
	// Back in step, it works again.
	tn.front("POST", "/v1/passkey/options", nil, "").data(&ch)
	key.counter += 2
	if r := tn.front("POST", "/v1/passkey/sign-in", obj{"challenge_id": ch.ChallengeID, "credential": key.assert(ch.Options, false)}, ""); r.Status != 200 {
		t.Fatalf("sign in after moving on: %d %s", r.Status, r.Raw)
	}

	// With a password, the passkey is offered as the second factor.
	var pending pendingData
	tn.signIn("hana@example.com", "some-password").data(&pending)
	if !pending.SecondFactorRequired || strings.Join(pending.Methods, ",") != "passkey" {
		t.Fatalf("pending: %+v", pending)
	}
	tn.front("POST", "/v1/passkey/options", nil, "").data(&ch)
	r = tn.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "passkey", "challenge_id": ch.ChallengeID, "credential": key.assert(ch.Options, false)}, "")
	if r.Status != 200 {
		t.Fatalf("passkey as second factor: %d %s", r.Status, r.Raw)
	}
	// Someone else's passkey cannot finish Hana's pending sign-in.
	_, sara := tn.user("sara@example.com", "some-password")
	saraKey := newSoftKey(t, "https://app.test")
	tn.front("POST", "/v1/me/passkeys/options", nil, sara).data(&ch)
	tn.front("POST", "/v1/me/passkeys", obj{"challenge_id": ch.ChallengeID, "credential": saraKey.register(ch.Options)}, sara)
	tn.signIn("hana@example.com", "some-password").data(&pending)
	tn.front("POST", "/v1/passkey/options", nil, "").data(&ch)
	if r := tn.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "passkey", "challenge_id": ch.ChallengeID, "credential": saraKey.assert(ch.Options, false)}, ""); r.code() != "wrong_code" {
		t.Fatalf("another person's passkey: %d %s", r.Status, r.Raw)
	}
	// Removal.
	if r := tn.front("DELETE", "/v1/me/passkeys/"+keys[0].ID, nil, signedIn.SessionToken); r.Status != 200 {
		t.Fatalf("delete: %d %s", r.Status, r.Raw)
	}
	tn.front("POST", "/v1/passkey/options", nil, "").data(&ch)
	if r := tn.front("POST", "/v1/passkey/sign-in", obj{"challenge_id": ch.ChallengeID, "credential": key.assert(ch.Options, false)}, ""); r.code() != "passkey_failed" {
		t.Fatalf("a removed passkey still works: %d %s", r.Status, r.Raw)
	}
	// A tenant without an address cannot use passkeys: there is no domain
	// to bind them to.
	bare := e.tenant("bare")
	_, s := bare.user("x@example.com", "some-password")
	if err := e.app.DB.Platform(context.Background(), func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE aos.tenants SET settings = '{}' WHERE id = $1`, bare.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if r := bare.front("POST", "/v1/me/passkeys/options", nil, s); r.code() != "passkeys_unavailable" {
		t.Fatalf("passkeys without an address: %d %s", r.Status, r.Raw)
	}
}
