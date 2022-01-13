package crypto_test

import (
	"context"
	"testing"

	"go.sophtrust.dev/pkg/toolbox/crypto"
)

func TestRandomEncrypt(t *testing.T) {
	ctx := context.TODO()

	ciphertext, err := crypto.EncryptString(ctx, "test_string", "")
	if err != nil {
		t.Errorf("error while encrypting string: %s", err.Error())
	}

	plaintext, err := crypto.DecryptString(ctx, ciphertext, "")
	if err != nil {
		t.Errorf("error while decrypting string: %s", err.Error())
	}
	if plaintext != "test_string" {
		t.Errorf("want: test_string, got: %s", plaintext)
	}
}

func TestEncrypt(t *testing.T) {
	ctx := context.TODO()

	ciphertext, err := crypto.EncryptString(ctx, "test_string", "some_key")
	if err != nil {
		t.Errorf("error while encrypting string: %s", err.Error())
	}

	plaintext, err := crypto.DecryptString(ctx, ciphertext, "some_key")
	if err != nil {
		t.Errorf("error while decrypting string: %s", err.Error())
	}
	if plaintext != "test_string" {
		t.Errorf("want: test_string, got: %s", plaintext)
	}
}
