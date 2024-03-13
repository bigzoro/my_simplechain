package secure

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
)

func GetCertFromPem(idBytes []byte) (*x509.Certificate, error) {
	if idBytes == nil {
		return nil, errors.New("getCertFromPem error: nil idBytes")
	}
	// Decode the pem bytes
	pemCert, _ := pem.Decode(idBytes)
	if pemCert == nil {
		return nil, errors.New(fmt.Sprintf("getCertFromPem error: could not decode pem bytes [%v]", idBytes))
	}
	// get a cert
	var cert *x509.Certificate
	cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf(" %v getCertFromPem error: failed to parse x509 cert", err))
	}
	return cert, nil
}

// getSubjectKeyIdentifierFromCert returns the Subject Key Identifier for the supplied certificate
// Subject Key Identifier is an identifier of the public key of this certificate
func getSubjectKeyIdentifierFromCert(cert *x509.Certificate) ([]byte, error) {
	var SKI []byte
	for _, ext := range cert.Extensions {
		// Subject Key Identifier is identified by the following ASN.1 tag
		// subjectKeyIdentifier (2 5 29 14) (see https://tools.ietf.org/html/rfc3280.html)
		if reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 14}) {
			_, err := asn1.Unmarshal(ext.Value, &SKI)
			if err != nil {
				return nil, errors.New(fmt.Sprintf("%v failed to unmarshal Subject Key Identifier", err))
			}

			return SKI, nil
		}
	}
	return nil, errors.New("subjectKeyIdentifier not found in certificate")
}
