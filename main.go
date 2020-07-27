package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"time"

	"encoding/asn1"
	b64 "encoding/base64"
	"encoding/pem"

	"gopkg.in/yaml.v2"
)

const (
	root string = "testdata"
)

type config struct {
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

type userdata struct {
	ClientCertificateData string `yaml:"client-certificate-data"`
	ClientKeyData         string `yaml:"client-key-data"`
}

type user struct {
	Name string   `yaml:"name"`
	User userdata `yaml:"user"`
}

/* type config struct {
	Users []user `yaml:"users"`
} */

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func loadPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	p, err := ioutil.ReadFile(path)
	check(err)
	blockpriv, _ := pem.Decode([]byte(p))
	privkey, err := x509.ParsePKCS1PrivateKey(blockpriv.Bytes)
	check(err)
	return privkey, nil
}

func loadPublicCertFromFile(path string) (*x509.Certificate, error) {
	p, err := ioutil.ReadFile(path)
	check(err)
	block, _ := pem.Decode([]byte(p))
	cert, err := x509.ParseCertificate(block.Bytes)
	check(err)
	return cert, nil
}

func main() {
	kBase := path.Join(root, "/etc/kubernetes")
	dat, err := ioutil.ReadFile(
		path.Join(kBase, "kubelet.conf"),
	)
	check(err)
	//fmt.Print(string(dat))

	c := config{}

	err = yaml.Unmarshal(dat, &c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	//fmt.Printf("%+v\n", c)

	uDec, _ := b64.URLEncoding.DecodeString(c.Users[0].User.ClientCertificateData)
	//fmt.Println(string(uDec))

	block, _ := pem.Decode([]byte(uDec))
	if block == nil {
		panic("failed to parse PEM block containing the public key")
	}

	cakey, err := loadPrivateKeyFromFile(path.Join(kBase, "pki/ca.key"))

	check(err)

	cacert, err := loadPublicCertFromFile(path.Join(kBase, "pki/ca.crt"))

	check(err)

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	var csrTemplate = x509.CertificateRequest{
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

	uDec, _ = b64.URLEncoding.DecodeString(c.Users[0].User.ClientKeyData)
	pemclientkey, _ := pem.Decode(uDec)
	key, err := x509.ParsePKCS1PrivateKey(pemclientkey.Bytes)
	check(err)
	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	check(err)
	//fmt.Println(string(csrCertificate))

	_, rest := pem.Decode(csrCertificate)
	check(err)
	//fmt.Printf("%+v\n", string(rest))
	csrcrt, err := x509.ParseCertificateRequest(rest)
	check(err)

	clientCRTTemplate := x509.Certificate{
		SignatureAlgorithm: x509.SHA512WithRSA,

		PublicKeyAlgorithm: csrcrt.PublicKeyAlgorithm,
		PublicKey:          csrcrt.PublicKey,

		SerialNumber: big.NewInt(2),
		Issuer:       crt.Issuer,
		Subject:      crt.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, cacert, csrcrt.PublicKey, cakey)
	if err != nil {
		panic(err)
	}

	buf := new(bytes.Buffer)

	pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
	enc := b64.URLEncoding.EncodeToString(buf.Bytes())
	//fmt.Println(enc)
	c.Users[0].User.ClientCertificateData = enc

	yamlout, err := os.Create("test.yaml")
	check(err)
	y, err := yaml.Marshal(c)
	check(err)
	yamlout.Write(y)

}
