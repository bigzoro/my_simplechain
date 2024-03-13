package secure

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/bigzoro/my_simplechain/p2p/enode"
	mapset "github.com/deckarep/golang-set"
	"math/big"
	"net"
	"path/filepath"
	"time"
)

var defaultDialTimeout = 15 * time.Second

/*
	tls相关的目录的根目录

.
├── crls
├── keystore
├── signcerts
├── tlscacerts
└── tlsintermediatecerts
*/
type ConnectionConfig struct {
	UseTLS bool
	Dir    string //tls相关的目录的根目录
}
type SecureConnection struct {
	config          *ConnectionConfig
	certificate     tls.Certificate
	rootCAs         *x509.CertPool
	secureManager   *SecureManager
	tlsClientConfig *tls.Config
	tlsServerConfig *tls.Config
	crlHashes       mapset.Set
	useTLS          bool
}

func NewSecureConnection(config *ConnectionConfig) (*SecureConnection, error) {
	if config.UseTLS {
		keyPath, err := GetPrivateKeyPath(filepath.Join(config.Dir, KeyFolder))
		if err != nil {
			return nil, err
		}
		certificatePath, err := GetCertificatePath(filepath.Join(config.Dir, CertificateFolder))
		if err != nil {
			return nil, err
		}
		certificate, err := LoadNodeCertificate(keyPath, certificatePath)
		if err != nil {
			return nil, err
		}
		secureManager := &SecureManager{}

		secureConfig, err := GetSecureConfig(config.Dir)
		if err != nil {
			return nil, err
		}
		err = secureManager.setupTLSCAs(secureConfig)
		if err != nil {
			return nil, err
		}
		err = secureManager.setupCRLs(secureConfig)
		if err != nil {
			return nil, err
		}
		return &SecureConnection{
			config:        config,
			certificate:   certificate,
			secureManager: secureManager,
			rootCAs:       secureManager.opts.Roots,
			useTLS:        config.UseTLS,
		}, nil
	} else {
		return &SecureConnection{
			config: config,
			useTLS: config.UseTLS,
		}, nil
	}
}

func (this *SecureConnection) Dial(dest *enode.Node) (net.Conn, error) {
	addr := &net.TCPAddr{IP: dest.IP(), Port: dest.TCP()}
	if this.config.UseTLS {
		//It itself acts as a client to verify the server-side certificate
		if this.tlsClientConfig == nil {
			tlsClientConfig := &tls.Config{
				Certificates:          []tls.Certificate{this.certificate},
				RootCAs:               this.rootCAs,
				VerifyPeerCertificate: this.verifyServerCertificate,
				InsecureSkipVerify:    false,
			}
			this.tlsClientConfig = tlsClientConfig
		}
		netDialer := &net.Dialer{
			Timeout: defaultDialTimeout,
		}
		dialer := &tls.Dialer{
			NetDialer: netDialer,
			Config:    this.tlsClientConfig,
		}
		return dialer.Dial("tcp", addr.String())
	} else {
		dialer := &net.Dialer{Timeout: defaultDialTimeout}
		return dialer.Dial("tcp", addr.String())
	}
}
func (this *SecureConnection) Listen(network, addr string) (net.Listener, error) {
	if this.config.UseTLS {
		//It itself acts as a server to verify client certificates
		if this.tlsServerConfig == nil {
			config := &tls.Config{
				Certificates:          []tls.Certificate{this.certificate},
				ClientAuth:            tls.RequireAndVerifyClientCert,
				ClientCAs:             this.rootCAs,
				VerifyPeerCertificate: this.verifyClientCertificate,
			}
			this.tlsServerConfig = config
		}
		return tls.Listen(network, addr, this.tlsServerConfig)
	} else {
		return net.Listen(network, addr)
	}
}
func (this *SecureConnection) verifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	clientCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		fmt.Println(err)
		return err
	}
	return this.secureManager.validateCertAgainst(clientCert)
}
func (this *SecureConnection) verifyServerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	clientCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		fmt.Println(err)
		return err
	}
	return this.secureManager.validateCertAgainst(clientCert)
}
func (this *SecureConnection) SaveCRL(dir string, CRLBytes []byte) ([]*big.Int, error) {
	if this.useTLS {
		return this.secureManager.SaveCRL(dir, CRLBytes)
	}
	return nil, nil
}
