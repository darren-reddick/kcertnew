package kcertrenew

import (
	"path"
	"testing"
)

const (
	root = "../../testdata"
)

var (
	base = path.Join(root, "/etc/kubernetes")
)

func TestLoadPrivateKeyFromFile(t *testing.T) {
	_, err := LoadPrivateKeyFromFile(path.Join(base, "pki/ca.key"))
	if err != nil {
		t.Error(err)
	}

}

func TestLoadPublicCertFromFile(t *testing.T) {
	_, err := LoadPublicCertFromFile(path.Join(base, "pki/ca.crt"))
	if err != nil {
		t.Error(err)
	}

}

func TestLoadKubeConfig(t *testing.T) {
	c, err := LoadKubeConfig(path.Join(base, "controller-manager.conf"))
	if err != nil {
		t.Error(err)
	}
	if n := c.Users[0].Name; n != "system:kube-controller-manager" {
		t.Errorf("Looking for system:kube-controller-manager got %s", n)
	}
}
