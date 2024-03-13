package secure

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/bigzoro/my_simplechain/common"
	"github.com/bigzoro/my_simplechain/log"
	"github.com/bigzoro/my_simplechain/rlp"
	mapset "github.com/deckarep/golang-set"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

type SecureConfig struct {
	//root certificates
	TlsRootCerts [][]byte
	// List of TLS intermediate certificates;
	TlsIntermediateCerts [][]byte
	//revocation lists
	RevocationList [][]byte
}
type SecureManager struct {
	opts *x509.VerifyOptions
	// list of CA TLS certs we trust ,setupTLSCAs
	TLSRootCerts [][]byte
	// list of intermediate TLS certs we trust,setupTLSCAs
	TLSIntermediateCerts [][]byte
	// list of certificate revocation lists,setupCRLs
	CRL       []*pkix.CertificateList
	crlHashes mapset.Set
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

// 设置吊销证书
func (s *SecureManager) setupCRLs(conf *SecureConfig) error {
	s.crlHashes = mapset.NewSet()
	// setup the CRL (if present)
	s.CRL = make([]*pkix.CertificateList, len(conf.RevocationList))
	for i, CRLBytes := range conf.RevocationList {
		hash := rlpHash(CRLBytes)
		s.crlHashes.Add(hash)
		crl, err := x509.ParseCRL(CRLBytes)
		if err != nil {
			return errors.New(fmt.Sprintf("could not parse Content %v", err))
		}
		// Massage the ECDSA signature values
		if isECDSASignatureAlgorithm(crl.SignatureAlgorithm.Algorithm) {
			r, s, err := UnmarshalECDSASignature(crl.SignatureValue.RightAlign())
			if err != nil {
				return err
			}
			sig, err := MarshalECDSASignature(r, s)
			if err != nil {
				return err
			}
			crl.SignatureValue = asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}
		}
		s.CRL[i] = crl
	}
	return nil
}
func (s *SecureManager) SaveCRL(dir string, CRLBytes []byte) ([]*big.Int, error) {
	hash := rlpHash(CRLBytes)
	if s.crlHashes != nil && s.crlHashes.Contains(hash) {
		return nil, errors.New("crl exists")
	}
	crl, err := x509.ParseCRL(CRLBytes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("could not parse Content %v", err))
	}
	// Massage the ECDSA signature values
	if isECDSASignatureAlgorithm(crl.SignatureAlgorithm.Algorithm) {
		r, s, err := UnmarshalECDSASignature(crl.SignatureValue.RightAlign())
		if err != nil {
			return nil, err
		}
		sig, err := MarshalECDSASignature(r, s)
		if err != nil {
			return nil, err
		}
		crl.SignatureValue = asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}
	}
	serialNumbers := make([]*big.Int, 0)
	for _, rc := range crl.TBSCertList.RevokedCertificates {
		serialNumbers = append(serialNumbers, rc.SerialNumber)
	}
	s.CRL = append(s.CRL, crl)
	CRLsDir := filepath.Join(dir, CRLsFolder)
	if !PathExists(CRLsDir) {
		os.MkdirAll(CRLsDir, os.ModePerm)
	}
	fileName := fmt.Sprintf("crl_%d.pem", time.Now().Nanosecond())
	fileName = filepath.Join(CRLsDir, fileName)
	log.Info("SecureManager receive crl data,save in", "path", fileName)
	if err = ioutil.WriteFile(fileName, CRLBytes, 0666); err != nil {
		return nil, err
	}
	return serialNumbers, nil
}
func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

// 包括根证书和根证书
func (s *SecureManager) setupTLSCAs(conf *SecureConfig) error {
	opts := &x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	// Load TLS root and intermediate CA identities
	s.TLSRootCerts = make([][]byte, len(conf.TlsRootCerts))
	rootCerts := make([]*x509.Certificate, len(conf.TlsRootCerts))
	for i, trustedCert := range conf.TlsRootCerts {
		cert, err := GetCertFromPem(trustedCert)
		if err != nil {
			return err
		}
		rootCerts[i] = cert
		s.TLSRootCerts[i] = trustedCert
		opts.Roots.AddCert(cert)
	}
	// make and fill the set of intermediate certs (if present)
	s.TLSIntermediateCerts = make([][]byte, len(conf.TlsIntermediateCerts))
	intermediateCerts := make([]*x509.Certificate, len(conf.TlsIntermediateCerts))
	for i, trustedCert := range conf.TlsIntermediateCerts {
		cert, err := GetCertFromPem(trustedCert)
		if err != nil {
			return err
		}
		intermediateCerts[i] = cert
		s.TLSIntermediateCerts[i] = trustedCert
		opts.Intermediates.AddCert(cert)
	}
	s.opts = opts
	// ensure that our CAs are properly formed and that they are valid
	for _, cert := range append(append([]*x509.Certificate{}, rootCerts...), intermediateCerts...) {
		if cert == nil {
			continue
		}
		if !cert.IsCA {
			return errors.New(fmt.Sprintf("CA Certificate did not have the CA attribute, (SN: %x)", cert.SerialNumber))
		}
		if _, err := getSubjectKeyIdentifierFromCert(cert); err != nil {
			return errors.New(fmt.Sprintf("%v CA Certificate problem with Subject Key Identifier extension, (SN: %x)", err, cert.SerialNumber))
		}

		if err := s.validateTLSCAIdentity(cert, opts); err != nil {
			return errors.New(fmt.Sprintf("%v CA Certificate is not valid, (SN: %s)", err, cert.SerialNumber))
		}
	}
	return nil
}

func (s *SecureManager) validateTLSCAIdentity(cert *x509.Certificate, opts *x509.VerifyOptions) error {
	if !cert.IsCA {
		return errors.New("only CA identities can be validated")
	}
	validationChain, err := s.getUniqueValidationChain(cert, *opts)
	if err != nil {
		return errors.New(fmt.Sprintf("%v could not obtain certification chain", err))
	}
	if len(validationChain) == 1 {
		return nil
	}
	return s.validateCertAgainstChain(cert, validationChain)
}

func (s *SecureManager) getUniqueValidationChain(cert *x509.Certificate, opts x509.VerifyOptions) ([]*x509.Certificate, error) {
	// ask golang to validate the cert for us based on the options that we've built at setup time
	if s.opts == nil {
		return nil, errors.New("the supplied identity has no verify options")
	}
	validationChains, err := cert.Verify(opts)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("%v the supplied identity is not valid", err))
	}

	// we only support a single validation chain;
	// if there's more than one then there might
	// be unclarity about who owns the identity
	if len(validationChains) != 1 {
		return nil, errors.New(fmt.Sprintf("%v this MSP only supports a single validation chain, got %d", err, len(validationChains)))
	}

	// Make the additional verification checks that were done in Go 1.14.
	err = verifyLegacyNameConstraints(validationChains[0])
	if err != nil {
		return nil, errors.New(fmt.Sprintf("%v the supplied identity is not valid", err))
	}

	return validationChains[0], nil
}

var (
	oidExtensionSubjectAltName  = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}
)

// verifyLegacyNameConstraints exercises the name constraint validation rules
// that were part of the certificate verification process in Go 1.14.
//
// If a signing certificate contains a name constratint, the leaf certificate
// does not include SAN extensions, and the leaf's common name looks like a
// host name, the validation would fail with an x509.CertificateInvalidError
// and a rason of x509.NameConstraintsWithoutSANs.
func verifyLegacyNameConstraints(chain []*x509.Certificate) error {
	if len(chain) < 2 {
		return nil
	}

	// Leaf certificates with SANs are fine.
	if oidInExtensions(oidExtensionSubjectAltName, chain[0].Extensions) {
		return nil
	}
	// Leaf certificates without a hostname in CN are fine.
	if !validHostname(chain[0].Subject.CommonName) {
		return nil
	}
	// If an intermediate or root have a name constraint, validation
	// would fail in Go 1.14.
	for _, c := range chain[1:] {
		if oidInExtensions(oidExtensionNameConstraints, c.Extensions) {
			return x509.CertificateInvalidError{Cert: chain[0], Reason: x509.NameConstraintsWithoutSANs}
		}
	}
	return nil
}

func oidInExtensions(oid asn1.ObjectIdentifier, exts []pkix.Extension) bool {
	for _, ext := range exts {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// validHostname reports whether host is a valid hostname that can be matched or
// matched against according to RFC 6125 2.2, with some leniency to accommodate
// legacy values.
//
// This implementation is sourced from the standard library.
func validHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")

	if len(host) == 0 {
		return false
	}

	for i, part := range strings.Split(host, ".") {
		if part == "" {
			// Empty label.
			return false
		}
		if i == 0 && part == "*" {
			// Only allow full left-most wildcards, as those are the only ones
			// we match, and matching literal '*' characters is probably never
			// the expected behavior.
			continue
		}
		for j, c := range part {
			if 'a' <= c && c <= 'z' {
				continue
			}
			if '0' <= c && c <= '9' {
				continue
			}
			if 'A' <= c && c <= 'Z' {
				continue
			}
			if c == '-' && j != 0 {
				continue
			}
			if c == '_' || c == ':' {
				// Not valid characters in hostnames, but commonly
				// found in deployments outside the WebPKI.
				continue
			}
			return false
		}
	}

	return true
}
func (s *SecureManager) validateCertAgainstChain(cert *x509.Certificate, validationChain []*x509.Certificate) error {
	// here we know that the identity is valid; now we have to check whether it has been revoked

	// identify the SKI of the CA that signed this cert
	SKI, err := getSubjectKeyIdentifierFromCert(validationChain[1])
	if err != nil {
		return errors.New(fmt.Sprintf("%vcould not obtain Subject Key Identifier for signer cert", err))
	}

	// check whether one of the CRLs we have has this cert's
	// SKI as its AuthorityKeyIdentifier
	for _, crl := range s.CRL {
		aki, err := getAuthorityKeyIdentifierFromCrl(crl)
		if err != nil {
			return errors.New(fmt.Sprintf("%v could not obtain Authority Key Identifier for crl", err))
		}

		// check if the SKI of the cert that signed us matches the AKI of any of the CRLs
		if bytes.Equal(aki, SKI) {
			// we have a CRL, check whether the serial number is revoked
			for _, rc := range crl.TBSCertList.RevokedCertificates {
				if rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					// We have found a CRL whose AKI matches the SKI of
					// the CA (root or intermediate) that signed the
					// certificate that is under validation. As a
					// precaution, we verify that said CA is also the
					// signer of this CRL.
					err = validationChain[1].CheckCRLSignature(crl)
					if err != nil {
						// the CA cert that signed the certificate
						// that is under validation did not sign the
						// candidate CRL - skip
						log.Error(fmt.Sprintf("invalid signature over the identified CRL, error %+v", err))
						continue
					}

					// A CRL also includes a time of revocation so that
					// the CA can say "this cert is to be revoked starting
					// from this time"; however here we just assume that
					// revocation applies instantaneously from the time
					// the MSP config is committed and used so we will not
					// make use of that field
					return errors.New("the certificate has been revoked")
				}
			}
		}
	}

	return nil
}

type authorityKeyIdentifier struct {
	KeyIdentifier             []byte  `asn1:"optional,tag:0"`
	AuthorityCertIssuer       []byte  `asn1:"optional,tag:1"`
	AuthorityCertSerialNumber big.Int `asn1:"optional,tag:2"`
}

// getAuthorityKeyIdentifierFromCrl returns the Authority Key Identifier
// for the supplied CRL. The authority key identifier can be used to identify
// the public key corresponding to the private key which was used to sign the CRL.
func getAuthorityKeyIdentifierFromCrl(crl *pkix.CertificateList) ([]byte, error) {
	aki := authorityKeyIdentifier{}
	for _, ext := range crl.TBSCertList.Extensions {
		// Authority Key Identifier is identified by the following ASN.1 tag
		// authorityKeyIdentifier (2 5 29 35) (see https://tools.ietf.org/html/rfc3280.html)
		if reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 35}) {
			_, err := asn1.Unmarshal(ext.Value, &aki)
			if err != nil {
				return nil, errors.New(fmt.Sprintf("%vfailed to unmarshal AKI", err))
			}

			return aki.KeyIdentifier, nil
		}
	}

	return nil, errors.New("authorityKeyIdentifier not found in certificate")
}

func (s *SecureManager) validateCertAgainst(cert *x509.Certificate) error {
	// check whether one of the CRLs we have has this cert's
	for _, crl := range s.CRL {
		// we have a CRL, check whether the serial number is revoked
		for _, rc := range crl.TBSCertList.RevokedCertificates {
			if rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return errors.New("the certificate has been revoked")
			}
		}
	}
	return nil
}
