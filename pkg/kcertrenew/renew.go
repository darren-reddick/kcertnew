package kcertrenew

import (
	"crypto/rand"
	"crypto/x509"
	"io/ioutil"
	"path"
	"regexp"

	"log"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// RenewKubeconfig renews the client cert data of a kubeconfig file
// by generating a CSR from the expiring cert and signing with the root ca.
func RenewKubeconfig(kubeconfig string, root string, output string, expire int) {
	kBase := path.Join(root, "/etc/kubernetes")

	log.Printf("Using kubernetes config base %s", kBase)

	// Load the kubeconfig from file
	log.Printf("Loading config from %s", path.Join(kBase, kubeconfig))
	c, err := LoadKubeConfig(path.Join(kBase, kubeconfig))
	check(err)

	// Load the CA private key
	log.Printf("Loading CA private key from %s", path.Join(kBase, "pki/ca.key"))
	cakey, err := LoadPrivateKeyFromFile(path.Join(kBase, "pki/ca.key"))

	check(err)

	// Load the CA public cert
	log.Printf("Loading CA public cert from %s", path.Join(kBase, "pki/ca.crt"))
	cacert, err := LoadPublicCertFromFile(path.Join(kBase, "pki/ca.crt"))

	check(err)

	// Parse the client cert from the Config
	crt, err := GetClientCert(c)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	// Build a CSR template using some values from the expiring x509 cert
	csrTemplate := BuildCSRTemplateFromCert(*crt)

	// get client rsa key from the Config
	key, err := GetClientKey(c)
	check(err)

	// Create a CSR using the template and the client RSA key
	csrcrt, err := CreateCSR(csrTemplate, key)
	check(err)

	// Create a cert template using values from the CSR and pass in the expiry time in months
	clientCRTTemplate := BuildCRTTemplateFromCert(*csrcrt, expire)

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, cacert, csrcrt.PublicKey, cakey)
	if err != nil {
		panic(err)
	}

	// Update the ClientCertificateData of the Config with the raw x509 cert data as []byte
	c = UpdateClientCertConfig(c, clientCRTRaw)

	// Write the updated Config to yaml file
	log.Printf("Writing updated kubeconfig to %s", output)
	WriteConfigToFile(output, c)

}

func RenewKubeconfigs(root string, expire int) {
	kBase := path.Join(root, "/etc/kubernetes")
	files, err := ioutil.ReadDir(kBase)
	if err != nil {
		log.Fatal(err)
	}
	re := regexp.MustCompile(`^[\w-]+\.conf$`)
	cfiles := []string{}
	for _, val := range files {
		if val.IsDir() == false && re.MatchString(val.Name()) {
			cfiles = append(cfiles, val.Name())
		}
	}
	for _, f := range cfiles {
		log.Printf("Processing %s", f)
		RenewKubeconfig(f, root, f, expire)
	}

}
