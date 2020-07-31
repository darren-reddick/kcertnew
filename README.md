## Usage

### Docker

#### renew


Renew the client cert data in admin.conf using pki files under ./testdata/etc/kubernetes and write to ./testout
```
# Create an output directory
mkdir testout
docker run -v ${PWD}/testout:/testout -v ${PWD}/testdata/etc/kubernetes:/testdata dreddick/kcertrenew:v0.1.2  \
renew --ca-key /testdata/pki/ca.key --ca-cert /testdata/pki/ca.crt \
--kubeconfig /testdata/admin.conf --outputdir /testout
```

#### renewall

Renew the client cert data in all .conf files found in ./testdata/etc/kubernetes using pki files under ./testdata/etc/kubernetes and write to ./testout
```
docker run -v ${PWD}/testout:/testout -v ${PWD}/testdata/etc/kubernetes:/testdata dreddick/kcertrenew:v0.1.2  \
renew --ca-key /testdata/pki/ca.key --ca-cert /testdata/pki/ca.crt \
--kubeconfig /testdata/admin.conf --outputdir /testout
```





