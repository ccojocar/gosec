package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG123 - TLS resumption bypass of VerifyPeerCertificate when VerifyConnection is unset
var SampleCodeG123 = []CodeSample{
	// Vulnerable: direct config uses VerifyPeerCertificate and leaves session tickets enabled
	{[]string{`
package main

import (
	"crypto/tls"
	"crypto/x509"
)

func main() {
	_ = &tls.Config{
		VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error { return nil },
	}
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: GetConfigForClient returns stricter VerifyPeerCertificate config
	{[]string{`
package main

import (
	"crypto/tls"
	"crypto/x509"
)

func main() {
	_ = &tls.Config{
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			_ = ch
			return &tls.Config{
				VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error { return nil },
			}, nil
		},
	}
}
`}, 2, gosec.NewConfig()},

	// Safe: VerifyConnection is set (runs on resumed connections)
	{[]string{`
package main

import (
	"crypto/tls"
	"crypto/x509"
)

func main() {
	_ = &tls.Config{
		VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error { return nil },
		VerifyConnection:      func(_ tls.ConnectionState) error { return nil },
	}
}
`}, 0, gosec.NewConfig()},

	// Safe: session tickets explicitly disabled alongside VerifyPeerCertificate
	{[]string{`
package main

import (
	"crypto/tls"
	"crypto/x509"
)

func main() {
	cfg := &tls.Config{}
	cfg.VerifyPeerCertificate = func(_ [][]byte, _ [][]*x509.Certificate) error { return nil }
	cfg.SessionTicketsDisabled = true
	_ = cfg
}
`}, 0, gosec.NewConfig()},
}
