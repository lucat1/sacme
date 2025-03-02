# Developing locally

To develop locally, you need a local ACME server, such as [letsencrypt's Pebble]().
This repository provides an example configuration that will work for with all
challanges supported by sacme. You can run Pebble as follows:

```sh
$ pebble -config ./example/pebble.json
```

Then, you can run sacme with the following command:

```sh
$ SSL_CERT_FILE=$PWD/example/pebble.minica.pem go run ./cmd/sacme -domains-path ./example/domains -state-store-path ./example/state
```
