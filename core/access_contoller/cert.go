package access_contoller

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/bigzoro/my_simplechain/core/access_contoller/crypto"
	"github.com/bigzoro/my_simplechain/core/access_contoller/crypto/hash"
	bcx509 "github.com/bigzoro/my_simplechain/core/access_contoller/crypto/x509"
)

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func ComputeSKI(hashType crypto.HashType, pub interface{}) ([]byte, error) {
	encodedPub, err := bcx509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var subPKI subjectPublicKeyInfo
	_, err = asn1.Unmarshal(encodedPub, &subPKI)
	if err != nil {
		return nil, err
	}

	pubHash, err := hash.Get(hashType, subPKI.SubjectPublicKey.Bytes)
	if err != nil {
		return nil, err
	}

	return pubHash[:], nil
}
