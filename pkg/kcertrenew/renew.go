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
func RenewKubeconfig(kubeconfig string, caKey string, caCert string, outputdir string, expire int) {

	kubconfigBaseName := path.Base(kubeconfig)

	c, err := LoadKubeConfig(kubeconfig)
	check(err)

	// Load the CA private key
	log.Printf("Loading CA private key from %s", caKey)
	cakey, err := LoadPrivateKeyFromFile(caKey)

	check(err)

	// Load the CA public cert
	log.Printf("Loading CA public cert from %s", caCert)
	cacert, err := LoadPublicCertFromFile(caCert)

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

	log.Printf("Expiry date: %s", clientCRTTemplate.NotBefore)

	// Write the updated Config to yaml file
	out := path.Join(outputdir, kubconfigBaseName)
	log.Printf("Writing updated kubeconfig to %s", out)
	log.Printf("Client cert expiry date: %s", clientCRTTemplate.NotBefore)
	err = WriteConfigToFile(out, c)
	if err != nil {
		log.Printf("#### Skipping write to file: %s", err)
	} //

}

// RenewKubeconfigs renews the client cert data of all kubeconfig files found in a directory
// by generating a CSR from the expiring cert and signing with the root ca.
// RenewKubeconfig(kubeconfig string, caKey string, caCert string, outputdir string, expire int)
func RenewKubeconfigs(dir string, caKey string, caCert string, outputdir string, expire int) {
	base := path.Join(dir)
	files, err := ioutil.ReadDir(base)
	if err != nil {
		log.Fatal(err)
	}
	// all files must end in '.conf'
	re := regexp.MustCompile(`^[\w-]+\.conf$`)
	cfiles := []string{}
	for _, val := range files {
		if val.IsDir() == false && re.MatchString(val.Name()) {
			cfiles = append(cfiles, val.Name())
		}
	}
	for _, f := range cfiles {
		log.Printf("Processing %s", f)
		RenewKubeconfig(path.Join(base, f), caKey, caCert, outputdir, expire)
	}

}
