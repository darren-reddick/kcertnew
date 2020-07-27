package main

import (
	"crypto/rand"
	"crypto/x509"
	"path"

	cr "github.com/dreddick-home/certrenew/pkg/kcertrenew"
)

const (
	root string = "testdata"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	kBase := path.Join(root, "/etc/kubernetes")

	c, err := cr.LoadKubeConfig(path.Join(kBase, "kubelet.conf"))
	check(err)

	cakey, err := cr.LoadPrivateKeyFromFile(path.Join(kBase, "pki/ca.key"))

	check(err)

	cacert, err := cr.LoadPublicCertFromFile(path.Join(kBase, "pki/ca.crt"))

	check(err)

	crt, err := cr.GetClientCert(c)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	csrTemplate := cr.BuildCSRTemplateFromCert(*crt)

	key, err := cr.GetClientKey(c)
	check(err)

	csrcrt, err := cr.CreateCSR(csrTemplate, key)
	check(err)

	clientCRTTemplate := cr.BuildCRTTemplateFromCert(*csrcrt, 1)

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, cacert, csrcrt.PublicKey, cakey)
	if err != nil {
		panic(err)
	}

	c = cr.UpdateClientCertConfig(c, clientCRTRaw)

	cr.WriteConfigToFile("test3.yaml", c)

}
