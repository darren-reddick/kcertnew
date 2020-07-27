package kcertrenew

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	b64 "encoding/base64"

	"gopkg.in/yaml.v2"
)

// Config type represents the kubeconfig yaml data
type Config struct {
	APIVersion  string      `yaml:"apiVersion"`
	Kind        string      `yaml:"kind"`
	Preferences interface{} `yaml:"preferences"`
	Users       []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		}
	} `yaml:"users"`
	Clusters []struct {
		Cluster struct {
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			Server                   string `yaml:"server"`
			Name                     string `yaml:"name"`
		} `yaml:"cluster"`
	}
	Contexts []struct {
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		}
		Name string `yaml:"name"`
	} `yaml:"contexts"`
}

// LoadPrivateKeyFromFile loads an rsa private key
// from file referred to by path
func LoadPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	p, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blockpriv, _ := pem.Decode([]byte(p))
	privkey, err := x509.ParsePKCS1PrivateKey(blockpriv.Bytes)
	if err != nil {
		return nil, err
	}
	return privkey, nil
}

// LoadPublicCertFromFile loads an x509 certificate from
// file referred to by path
func LoadPublicCertFromFile(path string) (*x509.Certificate, error) {
	cert := &x509.Certificate{}
	p, err := ioutil.ReadFile(path)
	if err != nil {
		return cert, err
	}
	block, _ := pem.Decode([]byte(p))
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return cert, err
	}
	return cert, nil
}

// LoadKubeConfig loads data from a kubeconfig file
// and returns a Config that represents it
func LoadKubeConfig(path string) (Config, error) {
	c := Config{}
	dat, err := ioutil.ReadFile(
		path,
	)
	if err != nil {
		return c, err
	}
	err = yaml.Unmarshal(dat, &c)
	if err != nil {
		return c, err
	}
	return c, nil
}

// BuildCSRTemplateFromCert builds a CSR template based
// on the x509 cert passed to it
func BuildCSRTemplateFromCert(crt x509.Certificate) x509.CertificateRequest {
	return x509.CertificateRequest{
		Subject:            crt.Subject,
		SignatureAlgorithm: x509.SHA512WithRSA,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
				Value:    crt.Extensions[0].Value,
				Critical: true,
			},
		},
	}
}

// BuildCRTTemplateFromCert builds an x509 certificate template from the
// x509 certificate request poassed to it + an expiry date of "expire" months from now
func BuildCRTTemplateFromCert(crt x509.CertificateRequest, expire int) x509.Certificate {
	return x509.Certificate{
		SignatureAlgorithm: x509.SHA512WithRSA,

		PublicKeyAlgorithm: crt.PublicKeyAlgorithm,
		PublicKey:          crt.PublicKey,

		SerialNumber: big.NewInt(2),
		Subject:      crt.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, expire, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// CreateCSR returns an x509 CSR from the private key and template passed in
func CreateCSR(template x509.CertificateRequest, key *rsa.PrivateKey) (*x509.CertificateRequest, error) {
	req := x509.CertificateRequest{}
	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return &req, err
	}

	_, rest := pem.Decode(csrCertificate)

	return x509.ParseCertificateRequest(rest)
}

// GetClientKey returns the rsa privatekey from a Config
func GetClientKey(c Config) (*rsa.PrivateKey, error) {
	uDec, _ := b64.URLEncoding.DecodeString(c.Users[0].User.ClientKeyData)
	block, _ := pem.Decode(uDec)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// GetClientCert returns the x509 certificate from a Config
func GetClientCert(c Config) (*x509.Certificate, error) {
	uDec, _ := b64.URLEncoding.DecodeString(c.Users[0].User.ClientCertificateData)
	block, _ := pem.Decode(uDec)
	return x509.ParseCertificate(block.Bytes)
}

// WriteConfigToFile writes a Config to path as yaml
func WriteConfigToFile(path string, c Config) error {
	yamlout, err := os.Create(path)
	defer yamlout.Close()
	if err != nil {
		return err
	}
	y, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	_, err = yamlout.Write(y)
	if err != nil {
		return err
	}
	return nil

}

// UpdateClientCertConfig updates the ClientCertificateData in Config
// using the raw x509 as byte[]
func UpdateClientCertConfig(c Config, bytes []byte) Config {

	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bytes})
	enc := b64.URLEncoding.EncodeToString(block)
	c.Users[0].User.ClientCertificateData = enc
	return c
}
