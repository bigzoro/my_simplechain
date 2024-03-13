package secure

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

type ECDSASignature struct {
	R, S *big.Int
}

func UnmarshalECDSASignature(raw []byte) (*big.Int, *big.Int, error) {
	// Unmarshal
	sig := new(ECDSASignature)
	_, err := asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed unmashalling signature [%s]", err)
	}

	// Validate sig
	if sig.R == nil {
		return nil, nil, errors.New("invalid signature, R must be different from nil")
	}
	if sig.S == nil {
		return nil, nil, errors.New("invalid signature, S must be different from nil")
	}

	if sig.R.Sign() != 1 {
		return nil, nil, errors.New("invalid signature, R must be larger than zero")
	}
	if sig.S.Sign() != 1 {
		return nil, nil, errors.New("invalid signature, S must be larger than zero")
	}

	return sig.R, sig.S, nil
}
func MarshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ECDSASignature{r, s})
}
func isECDSASignatureAlgorithm(algid asn1.ObjectIdentifier) bool {
	// This is the set of ECDSA algorithms supported by Go 1.14 for CRL
	// signatures.
	ecdsaSignaureAlgorithms := []asn1.ObjectIdentifier{
		{1, 2, 840, 10045, 4, 1},    // oidSignatureECDSAWithSHA1
		{1, 2, 840, 10045, 4, 3, 2}, // oidSignatureECDSAWithSHA256
		{1, 2, 840, 10045, 4, 3, 3}, // oidSignatureECDSAWithSHA384
		{1, 2, 840, 10045, 4, 3, 4}, // oidSignatureECDSAWithSHA512
	}
	for _, id := range ecdsaSignaureAlgorithms {
		if id.Equal(algid) {
			return true
		}
	}
	return false
}
