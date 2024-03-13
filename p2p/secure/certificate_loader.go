package secure

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const (
	CRLsFolder                 = "crls"
	TLSCACertsFolder           = "tlscacerts"
	TLSIntermediateCertsFolder = "tlsintermediatecerts"
	KeyFolder                  = "keystore"
	CertificateFolder          = "signcerts"
)

func GetRootCAPath(dir string) ([]string, error) {
	result := make([]string, 0)
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil, err
	}
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("%v could not read directory %s", err, dir))
	}
	for _, f := range files {
		fullName := filepath.Join(dir, f.Name())
		f, err := os.Stat(fullName)
		if err != nil {
			fmt.Printf("Failed to stat %s: %s\n", fullName, err)
			continue
		}
		if f.IsDir() {
			continue
		}
		result = append(result, fullName)
	}
	return result, nil
}

func GetPrivateKeyPath(key string) (string, error) {
	var filename string
	walkFunc := func(path string, info os.FileInfo, pathErr error) error {
		if !strings.HasSuffix(path, "_sk") {
			return nil
		}
		filename = path
		return nil
	}
	err := filepath.Walk(key, walkFunc)
	if err != nil {
		return "", err
	}
	return filename, err
}
func GetCertificatePath(certificate string) (string, error) {
	var filename string
	walkFunc := func(path string, info os.FileInfo, pathErr error) error {
		if !strings.HasSuffix(path, "pem") {
			return nil
		}
		filename = path
		return nil
	}
	err := filepath.Walk(certificate, walkFunc)
	if err != nil {
		return "", err
	}
	return filename, err
}

func GetSecureConfig(dir string) (*SecureConfig, error) {
	TLSCACertsDir := filepath.Join(dir, TLSCACertsFolder)
	TLSIntermediateCertsDir := filepath.Join(dir, TLSIntermediateCertsFolder)
	TLSCACerts, err := getPemMaterialFromDir(TLSCACertsDir)
	var TLSIntermediateCerts [][]byte
	if os.IsNotExist(err) {
		fmt.Printf("TLS CA certs folder not found at [%s]. Skipping and ignoring TLS intermediate CA folder. [%s] [%s]\n", TLSCACerts, TLSIntermediateCertsDir, err.Error())
	} else if err != nil {
		return nil, errors.New(fmt.Sprintf("%v failed loading TLS ca certs at [%s]", err, TLSCACertsDir))
	} else if len(TLSCACerts) != 0 {
		TLSIntermediateCerts, err = getPemMaterialFromDir(TLSIntermediateCertsDir)
		if os.IsNotExist(err) {
			fmt.Printf("TLS intermediate certs folder not found at [%s]. Skipping. [%s]\n", TLSIntermediateCertsDir, err.Error())
		} else if err != nil {
			return nil, errors.New(fmt.Sprintf("failed loading TLS intermediate ca certs at [%s];error :%s", TLSIntermediateCertsDir, err.Error()))
		}
	} else {
		fmt.Printf("TLS CA certs folder at [%s] is empty. Skipping.\n", TLSCACertsDir)
	}

	//Certificate Revocation List
	CRLsDir := filepath.Join(dir, CRLsFolder)
	CRLs, err := getPemMaterialFromDir(CRLsDir)
	if os.IsNotExist(err) {
		fmt.Printf("crls folder not found at [%s]. Skipping. [%s]\n", CRLsDir, err)
	} else if err != nil {
		return nil, errors.New(fmt.Sprintf(" %v failed loading crls at [%s]", err, CRLsDir))
	}
	config := &SecureConfig{
		RevocationList:       CRLs,
		TlsRootCerts:         TLSCACerts,
		TlsIntermediateCerts: TLSIntermediateCerts,
	}
	return config, nil
}

// get the keyPair from the file system

func LoadNodeCertificate(keyPath, certPath string) (tls.Certificate, error) {
	cert := tls.Certificate{}

	clientKey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return cert, errors.New(fmt.Sprintf("%v error loading node TLS key", err))
	}
	clientCert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return cert, errors.New(fmt.Sprintf("%v error loading node TLS certificate", err))
	}
	cert, err = tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return cert, errors.New(fmt.Sprintf("%v error parsing node TLS key pair", err))
	}
	return cert, nil
}
func getPemMaterialFromDir(dir string) ([][]byte, error) {
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil, err
	}
	content := make([][]byte, 0)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("%v could not read directory %s", err, dir))
	}

	for _, f := range files {

		fullName := filepath.Join(dir, f.Name())

		f, err := os.Stat(fullName)
		if err != nil {
			fmt.Printf("Failed to stat %s: %s\n", fullName, err)
			continue
		}
		if f.IsDir() {
			continue
		}
		item, err := readPemFile(fullName)
		if err != nil {
			fmt.Printf("Failed reading file %s: %s\n", fullName, err)
			continue
		}
		content = append(content, item)
	}

	return content, nil
}
func readPemFile(file string) ([]byte, error) {
	bytes, err := readFile(file)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("%v reading from file %s failed", err, file))
	}
	b, _ := pem.Decode(bytes)
	if b == nil {
		return nil, errors.New(fmt.Sprintf("no pem content for file %s", file))
	}
	return bytes, nil
}
func readFile(file string) ([]byte, error) {
	fileCont, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("%v could not read file %s", err, file))
	}
	return fileCont, nil
}
