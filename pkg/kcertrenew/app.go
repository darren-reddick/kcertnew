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

type Config struct {
	ApiVersion  string      `yaml:"apiVersion"`
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

func CreateCSR(template x509.CertificateRequest, key *rsa.PrivateKey) (*x509.CertificateRequest, error) {
	req := x509.CertificateRequest{}
	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return &req, err
	}

	_, rest := pem.Decode(csrCertificate)

	return x509.ParseCertificateRequest(rest)
}

func GetClientKey(c Config) (*rsa.PrivateKey, error) {
	uDec, _ := b64.URLEncoding.DecodeString(c.Users[0].User.ClientKeyData)
	block, _ := pem.Decode(uDec)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func GetClientCert(c Config) (*x509.Certificate, error) {
	uDec, _ := b64.URLEncoding.DecodeString(c.Users[0].User.ClientCertificateData)
	block, _ := pem.Decode(uDec)
	return x509.ParseCertificate(block.Bytes)
}

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

func UpdateClientCertConfig(c Config, bytes []byte) Config {

	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bytes})
	enc := b64.URLEncoding.EncodeToString(block)
	c.Users[0].User.ClientCertificateData = enc
	return c
}
