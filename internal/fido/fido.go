// Package fido wraps libfido2 to use a YubiKey's FIDO2 hmac-secret extension as
// a hardware key-derivation factor.
//
// Two operations are exposed:
//
//   - Enroll creates a non-resident credential carrying the hmac-secret
//     extension and returns its credential id. Run once, at store creation.
//   - HMACSecret feeds a salt to that credential and returns the deterministic
//     32-byte hmac-secret output.
//
// Both require a physical touch. The credential's private key never leaves the
// device; the credential id is not secret and is stored in the envelope header.
package fido

/*
#cgo pkg-config: libfido2
#include <fido.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

const (
	// RelyingPartyID identifies this tool's credentials on the authenticator.
	RelyingPartyID = "with-secrets"
	rpName         = "with-secrets local secrets"

	// SaltLen is the required hmac-secret salt length (single salt).
	SaltLen = 32
	// outputLen is the hmac-secret output length for a single salt.
	outputLen = 32

	clientDataHashLen = 32
)

// userHandle is a fixed, non-secret user id. It is arbitrary for a
// non-resident credential but must be set for makeCredential.
var userHandle = []byte("with-secrets")

var initOnce sync.Once

func ensureInit() { initOnce.Do(func() { C.fido_init(0) }) }

// ErrNoDevice is returned when no FIDO2 authenticator is connected.
var ErrNoDevice = errors.New("fido: no FIDO2 authenticator found (is your YubiKey plugged in?)")

func fidoErr(prefix string, code C.int) error {
	if code == C.FIDO_OK {
		return nil
	}
	return fmt.Errorf("%s: %s", prefix, C.GoString(C.fido_strerr(code)))
}

// firstDevicePath returns the path of the first connected authenticator.
func firstDevicePath() (string, error) {
	const max = 8
	devlist := C.fido_dev_info_new(max)
	if devlist == nil {
		return "", errors.New("fido: fido_dev_info_new failed")
	}
	defer C.fido_dev_info_free(&devlist, max)

	var found C.size_t
	if code := C.fido_dev_info_manifest(devlist, max, &found); code != C.FIDO_OK {
		return "", fidoErr("fido: enumerate", code)
	}
	if found == 0 {
		return "", ErrNoDevice
	}
	di := C.fido_dev_info_ptr(devlist, 0)
	if di == nil {
		return "", ErrNoDevice
	}
	return C.GoString(C.fido_dev_info_path(di)), nil
}

// openDevice opens the first authenticator and returns it with a close func.
func openDevice() (*C.fido_dev_t, func(), error) {
	ensureInit()
	path, err := firstDevicePath()
	if err != nil {
		return nil, nil, err
	}
	dev := C.fido_dev_new()
	if dev == nil {
		return nil, nil, errors.New("fido: fido_dev_new failed")
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	if code := C.fido_dev_open(dev, cPath); code != C.FIDO_OK {
		C.fido_dev_free(&dev)
		return nil, nil, fidoErr("fido: open device", code)
	}
	closeFn := func() {
		C.fido_dev_close(dev)
		C.fido_dev_free(&dev)
	}
	return dev, closeFn, nil
}

// Enroll creates a non-resident hmac-secret credential and returns its id.
// Requires a physical touch. clientDataHash is a caller-supplied 32-byte value
// (its content is irrelevant here; we do not verify attestation).
func Enroll(clientDataHash []byte) ([]byte, error) {
	if len(clientDataHash) != clientDataHashLen {
		return nil, fmt.Errorf("fido: client data hash must be %d bytes", clientDataHashLen)
	}
	dev, closeDev, err := openDevice()
	if err != nil {
		return nil, err
	}
	defer closeDev()

	cred := C.fido_cred_new()
	if cred == nil {
		return nil, errors.New("fido: fido_cred_new failed")
	}
	defer C.fido_cred_free(&cred)

	if code := C.fido_cred_set_type(cred, C.COSE_ES256); code != C.FIDO_OK {
		return nil, fidoErr("fido: set type", code)
	}

	cdh := C.CBytes(clientDataHash)
	defer C.free(cdh)
	if code := C.fido_cred_set_clientdata_hash(cred, (*C.uchar)(cdh), C.size_t(len(clientDataHash))); code != C.FIDO_OK {
		return nil, fidoErr("fido: set clientdata hash", code)
	}

	cRPID := C.CString(RelyingPartyID)
	defer C.free(unsafe.Pointer(cRPID))
	cRPName := C.CString(rpName)
	defer C.free(unsafe.Pointer(cRPName))
	if code := C.fido_cred_set_rp(cred, cRPID, cRPName); code != C.FIDO_OK {
		return nil, fidoErr("fido: set rp", code)
	}

	uid := C.CBytes(userHandle)
	defer C.free(uid)
	cUserName := C.CString(RelyingPartyID)
	defer C.free(unsafe.Pointer(cUserName))
	if code := C.fido_cred_set_user(cred, (*C.uchar)(uid), C.size_t(len(userHandle)), cUserName, cUserName, nil); code != C.FIDO_OK {
		return nil, fidoErr("fido: set user", code)
	}

	if code := C.fido_cred_set_extensions(cred, C.FIDO_EXT_HMAC_SECRET); code != C.FIDO_OK {
		return nil, fidoErr("fido: set extensions", code)
	}
	// Non-resident: nothing stored on the key; id lives in our envelope.
	if code := C.fido_cred_set_rk(cred, C.FIDO_OPT_FALSE); code != C.FIDO_OK {
		return nil, fidoErr("fido: set rk", code)
	}
	// No user verification (this key has no PIN); touch only.
	if code := C.fido_cred_set_uv(cred, C.FIDO_OPT_OMIT); code != C.FIDO_OK {
		return nil, fidoErr("fido: set uv", code)
	}

	if code := C.fido_dev_make_cred(dev, cred, nil); code != C.FIDO_OK {
		return nil, fidoErr("fido: make credential", code)
	}

	idPtr := C.fido_cred_id_ptr(cred)
	idLen := C.fido_cred_id_len(cred)
	if idPtr == nil || idLen == 0 {
		return nil, errors.New("fido: authenticator returned empty credential id")
	}
	return C.GoBytes(unsafe.Pointer(idPtr), C.int(idLen)), nil
}

// HMACSecret returns the 32-byte hmac-secret output for credID and salt.
// Requires a physical touch. Deterministic: same key + credID + salt always
// yields the same output.
func HMACSecret(credID, salt, clientDataHash []byte) ([]byte, error) {
	if len(salt) != SaltLen {
		return nil, fmt.Errorf("fido: salt must be %d bytes", SaltLen)
	}
	if len(clientDataHash) != clientDataHashLen {
		return nil, fmt.Errorf("fido: client data hash must be %d bytes", clientDataHashLen)
	}
	if len(credID) == 0 {
		return nil, errors.New("fido: empty credential id")
	}

	dev, closeDev, err := openDevice()
	if err != nil {
		return nil, err
	}
	defer closeDev()

	assert := C.fido_assert_new()
	if assert == nil {
		return nil, errors.New("fido: fido_assert_new failed")
	}
	defer C.fido_assert_free(&assert)

	cdh := C.CBytes(clientDataHash)
	defer C.free(cdh)
	if code := C.fido_assert_set_clientdata_hash(assert, (*C.uchar)(cdh), C.size_t(len(clientDataHash))); code != C.FIDO_OK {
		return nil, fidoErr("fido: set clientdata hash", code)
	}

	cRPID := C.CString(RelyingPartyID)
	defer C.free(unsafe.Pointer(cRPID))
	if code := C.fido_assert_set_rp(assert, cRPID); code != C.FIDO_OK {
		return nil, fidoErr("fido: set rp", code)
	}

	cCred := C.CBytes(credID)
	defer C.free(cCred)
	if code := C.fido_assert_allow_cred(assert, (*C.uchar)(cCred), C.size_t(len(credID))); code != C.FIDO_OK {
		return nil, fidoErr("fido: allow cred", code)
	}

	if code := C.fido_assert_set_extensions(assert, C.FIDO_EXT_HMAC_SECRET); code != C.FIDO_OK {
		return nil, fidoErr("fido: set extensions", code)
	}

	cSalt := C.CBytes(salt)
	defer C.free(cSalt)
	if code := C.fido_assert_set_hmac_salt(assert, (*C.uchar)(cSalt), C.size_t(len(salt))); code != C.FIDO_OK {
		return nil, fidoErr("fido: set hmac salt", code)
	}

	// Require user presence (touch).
	if code := C.fido_assert_set_up(assert, C.FIDO_OPT_TRUE); code != C.FIDO_OK {
		return nil, fidoErr("fido: set up", code)
	}

	if code := C.fido_dev_get_assert(dev, assert, nil); code != C.FIDO_OK {
		return nil, fidoErr("fido: get assertion", code)
	}

	outPtr := C.fido_assert_hmac_secret_ptr(assert, 0)
	outLen := C.fido_assert_hmac_secret_len(assert, 0)
	if outPtr == nil || outLen != outputLen {
		return nil, fmt.Errorf("fido: unexpected hmac-secret output length %d", int(outLen))
	}
	return C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen)), nil
}
