package kcertrenew

import (
	"crypto/rand"
	"crypto/x509"
	"path"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func Renew(kubeconfig string, root string, output string, expire int) {
	kBase := path.Join(root, "/etc/kubernetes")

	c, err := LoadKubeConfig(path.Join(kBase, kubeconfig))
	check(err)

	cakey, err := LoadPrivateKeyFromFile(path.Join(kBase, "pki/ca.key"))

	check(err)

	cacert, err := LoadPublicCertFromFile(path.Join(kBase, "pki/ca.crt"))

	check(err)

	crt, err := GetClientCert(c)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	csrTemplate := BuildCSRTemplateFromCert(*crt)

	key, err := GetClientKey(c)
	check(err)

	csrcrt, err := CreateCSR(csrTemplate, key)
	check(err)

	clientCRTTemplate := BuildCRTTemplateFromCert(*csrcrt, expire)

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, cacert, csrcrt.PublicKey, cakey)
	if err != nil {
		panic(err)
	}

	c = UpdateClientCertConfig(c, clientCRTRaw)

	WriteConfigToFile(output, c)

}
