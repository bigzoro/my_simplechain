package access_contoller

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	bccrypto "github.com/bigzoro/my_simplechain/core/access_contoller/crypto"
	"github.com/bigzoro/my_simplechain/core/access_contoller/crypto/asym"
	"github.com/bigzoro/my_simplechain/core/access_contoller/crypto/hash"
	bcx509 "github.com/bigzoro/my_simplechain/core/access_contoller/crypto/x509"
	"strings"
)

type certificateMember struct {

	// the CommonName field of the certificate
	id string

	// organization identity who owns this member
	orgId string

	// the X.509 certificate used for authentication
	cert *bcx509.Certificate

	// role of this member
	role Role

	// hash algorithm for chains (It's not the hash algorithm that the certificate uses)
	hashType string

	// the certificate is compressed or not
	isCompressed bool
}

// GetPk returns the public key
func (cm *certificateMember) GetPk() bccrypto.PublicKey {
	return cm.cert.PublicKey
}

// GetMemberId returns the identity of this member (non-uniqueness)
func (cm *certificateMember) GetMemberId() string {
	return cm.id
}

// GetOrgId returns the organization id which this member belongs to
func (cm *certificateMember) GetOrgId() string {
	return cm.orgId
}

// GetRole returns roles of this member
func (cm *certificateMember) GetRole() Role {
	return cm.role
}

// GetUid returns the identity of this member (unique)
func (cm *certificateMember) GetUid() string {
	return hex.EncodeToString(cm.cert.SubjectKeyId)
}

// Verify verifies a signature over some message using this member
func (cm *certificateMember) Verify(hashType string, msg []byte, sig []byte) error {
	hashAlgo, err := bcx509.GetHashFromSignatureAlgorithm(cm.cert.SignatureAlgorithm)
	if err != nil {
		return fmt.Errorf("cert member verify failed: get hash from signature algorithm failed: [%s]", err.Error())
	}
	ok, err := cm.cert.PublicKey.VerifyWithOpts(msg, sig, &bccrypto.SignOpts{
		Hash: hashAlgo,
		UID:  bccrypto.CRYPTO_DEFAULT_UID,
	})
	if err != nil {
		return fmt.Errorf("cert member verify signature failed: [%s]", err.Error())
	}
	if !ok {
		return fmt.Errorf("cert member verify signature failed: invalid signature")
	}
	return nil
}

// GetMember returns Member
func (cm *certificateMember) GetMember() (*Member, error) {
	if cm.isCompressed {
		id, err := GetCertificateIdFromDER(cm.cert.Raw, cm.hashType)
		if err != nil {
			return nil, fmt.Errorf("get pb member failed: [%s]", err.Error())
		}
		return &Member{
			OrgId:      cm.orgId,
			MemberInfo: id,
			MemberType: MemberType_CERT_HASH,
		}, nil
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Bytes: cm.cert.Raw, Type: "CERTIFICATE"})
	return &Member{
		OrgId:      cm.orgId,
		MemberInfo: certPEM,
		MemberType: MemberType_CERT,
	}, nil
}

func newCertMemberFromParam(orgId, role, hashType string, isCompressed bool,
	certPEM []byte) (*certificateMember, error) {
	var (
		cert *bcx509.Certificate
		err  error
	)
	certBlock, rest := pem.Decode(certPEM)
	if certBlock == nil {
		cert, err = bcx509.ParseCertificate(rest)
		if err != nil {
			return nil, fmt.Errorf("new cert member failed, invalid certificate")
		}
	} else {
		cert, err = bcx509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("new cert member failed, invalid certificate")
		}
	}

	if err = cryptoEngineOption(cert); err != nil {
		return nil, fmt.Errorf("set crypto engine failed, err = %s", err)
	}

	id, err := bcx509.GetExtByOid(bcx509.OidNodeId, cert.Extensions)
	if err != nil {
		id = []byte(cert.Subject.CommonName)
	}

	role = strings.ToUpper(role)

	return &certificateMember{
		id:           string(id),
		orgId:        orgId,
		role:         Role(role),
		cert:         cert,
		hashType:     hashType,
		isCompressed: isCompressed,
	}, nil
}

func newMemberFromCertPem(orgId, hashType string, certPEM []byte, isCompressed bool) (*certificateMember, error) {
	var member certificateMember
	member.isCompressed = isCompressed

	var cert *bcx509.Certificate
	var err error
	certBlock, rest := pem.Decode(certPEM)
	if certBlock == nil {
		cert, err = bcx509.ParseCertificate(rest)
		if err != nil {
			return nil, fmt.Errorf("new cert member failed, invalid certificate")
		}
	} else {
		cert, err = bcx509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("new cert member failed, invalid certificate")
		}
	}

	if err = cryptoEngineOption(cert); err != nil {
		return nil, fmt.Errorf("set crypto engine failed, err = %s", err)
	}

	member.hashType = hashType
	member.orgId = orgId

	orgIdFromCert := ""
	if len(cert.Subject.Organization) > 0 {
		orgIdFromCert = cert.Subject.Organization[0]
	}
	if member.orgId == "" {
		member.orgId = orgIdFromCert
	}
	if orgIdFromCert != member.orgId {
		return nil, fmt.Errorf(
			"setup cert member failed, organization information in certificate "+
				"and in input parameter do not match [certificate: %s, parameter: %s]",
			orgIdFromCert,
			orgId,
		)
	}

	id, err := bcx509.GetExtByOid(bcx509.OidNodeId, cert.Extensions)
	if err != nil {
		id = []byte(cert.Subject.CommonName)
	}
	member.id = string(id)
	member.cert = cert
	ou := ""
	if len(cert.Subject.OrganizationalUnit) > 0 {
		ou = cert.Subject.OrganizationalUnit[0]
	}
	ou = strings.ToUpper(ou)
	member.role = Role(ou)
	return &member, nil
}

type signingCertMember struct {
	// Extends Identity
	certificateMember

	// Sign the message
	sk bccrypto.PrivateKey
}

// Sign When using certificate, the signature-hash algorithm suite is from the certificate
// and the input hashType is ignored.
func (scm *signingCertMember) Sign(hashType string, msg []byte) ([]byte, error) {
	hashAlgo, err := bcx509.GetHashFromSignatureAlgorithm(scm.cert.SignatureAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("sign failed: invalid algorithm: %s", err.Error())
	}

	return scm.sk.SignWithOpts(msg, &bccrypto.SignOpts{
		Hash: hashAlgo,
		UID:  bccrypto.CRYPTO_DEFAULT_UID,
	})
}

// NewCertSigningMember 基于传入的参数新建一个SigningMember
// @param hashType
// @param member
// @param privateKeyPem
// @param password
// @return protocol.SigningMember
// @return error
func NewCertSigningMember(hashType string, member *Member, privateKeyPem,
	password string) (SigningMember, error) {

	certMember, err := newMemberFromCertPem(member.OrgId, hashType, member.MemberInfo, false)
	if err != nil {
		return nil, err
	}

	var sk bccrypto.PrivateKey
	//nodeConfig := localconf.ChainMakerConfig.NodeConfig
	//if nodeConfig.P11Config.Enabled {
	//	var handle interface{}
	//	handle, err = getHSMHandle()
	//	if err != nil {
	//		return nil, fmt.Errorf("fail to initialize identity management service: [%v]", err)
	//	}
	//
	//	sk, err = cert.ParseP11PrivKey(handle, []byte(privateKeyPem))
	//	if err != nil {
	//		return nil, fmt.Errorf("fail to initialize identity management service: [%v]", err)
	//	}
	//} else {
	sk, err = asym.PrivateKeyFromPEM([]byte(privateKeyPem), []byte(password))
	if err != nil {
		return nil, err
	}
	//}

	return &signingCertMember{
		*certMember,
		sk,
	}, nil
}

// GetCertificateIdFromDER get certificate id from DER
func GetCertificateIdFromDER(certDER []byte, hashType string) ([]byte, error) {
	if certDER == nil {
		return nil, fmt.Errorf("get cert from der certDER == nil")
	}
	id, err := hash.GetByStrType(hashType, certDER)
	if err != nil {
		return nil, err
	}
	return id, nil
}

// cryptoEngineOption parse public key by CryptoEngine
func cryptoEngineOption(cert *bcx509.Certificate) error {
	pkPem, err := cert.PublicKey.String()
	if err != nil {
		return fmt.Errorf("failed to get public key pem, err = %s", err)
	}
	cert.PublicKey, err = asym.PublicKeyFromPEM([]byte(pkPem))
	if err != nil {
		return fmt.Errorf("failed to parse public key, err = %s", err.Error())
	}
	return nil
}
