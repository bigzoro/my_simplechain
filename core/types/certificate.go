package types

type CertificateContent struct {
	Content   []byte
	Signature []byte
}

type CertificateEvent struct{ CertificateContent *CertificateContent }
