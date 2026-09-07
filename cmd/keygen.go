package cmd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lazhari/jwt/internal/jwk"
	"github.com/lazhari/jwt/internal/keys"
)

type keygenFlags struct {
	alg    string
	bits   int
	format string
	out    string
	pub    string
	kid    string
}

const minRSABits = 2048

func newKeygenCmd(streams *ioStreams) *cobra.Command {
	var f keygenFlags
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an HMAC secret or an RSA, EC, or Ed25519 key pair",
		Long: `Generate key material for an algorithm. HMAC secrets are printed as
base64url text sized to the hash. Asymmetric keys are written as PKCS#8
private and PKIX public PEM, or as JWK with --format jwk. Files are created
with mode 0600 and never overwrite an existing file.`,
		Example: `  jwt keygen --alg HS256
  jwt keygen --alg ES256 --out ec.pem --pub ec.pub
  jwt keygen --alg RS256 --format jwk --kid 2025-01 > private.jwk`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runKeygen(cmd, streams, &f)
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&f.alg, "alg", "HS256", "Algorithm the key is for: "+strings.Join(keys.AllAlgs(), ", "))
	fs.IntVar(&f.bits, "bits", minRSABits, "RSA modulus size in bits (minimum 2048)")
	fs.StringVar(&f.format, "format", "pem", "Output format: pem or jwk")
	fs.StringVar(&f.out, "out", "", "Write the private key (or secret) to this file instead of stdout")
	fs.StringVar(&f.pub, "pub", "", "Also write the public key to this file")
	fs.StringVar(&f.kid, "kid", "", "Key ID to include in JWK output")
	return cmd
}

func runKeygen(cmd *cobra.Command, streams *ioStreams, f *keygenFlags) error {
	kind, ok := keys.KindOf(f.alg)
	if !ok {
		return usageError(fmt.Errorf("--alg %q is not a key-bearing algorithm (use one of %s)", f.alg, strings.Join(keys.AllAlgs(), ", ")))
	}
	if f.format != "pem" && f.format != "jwk" {
		return usageError(fmt.Errorf("--format must be pem or jwk, got %q", f.format))
	}
	// A flag that cannot apply is a mistake worth reporting, but only when
	// the user set it: the defaults must stay usable with every algorithm.
	if cmd.Flags().Changed("bits") && kind != keys.RSA {
		return usageError(errors.New("--bits applies only to RSA algorithms"))
	}
	if cmd.Flags().Changed("kid") && f.format != "jwk" {
		return usageError(errors.New("--kid applies only to --format jwk"))
	}
	if kind == keys.RSA && f.bits < minRSABits {
		return usageError(fmt.Errorf("--bits must be at least %d", minRSABits))
	}
	if f.pub != "" && kind == keys.HMAC {
		return usageError(errors.New("--pub does not apply to HMAC secrets"))
	}

	priv, err := generateKey(kind, f.alg, f.bits)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	privOut, pubOut, err := encodeKey(priv, kind, f.format, f.kid)
	if err != nil {
		return err
	}

	// Write every file before touching stdout, so a failure (for example
	// --pub already exists) never leaves private key material on stdout
	// alongside a nonzero exit code.
	if f.pub != "" {
		if err := writeNewFile(f.pub, pubOut); err != nil {
			return err
		}
	}
	if f.out == "" {
		if _, err := streams.out.Write(privOut); err != nil {
			return err
		}
	} else if err := writeNewFile(f.out, privOut); err != nil {
		return err
	}
	return nil
}

// generateKey returns []byte, *rsa.PrivateKey, *ecdsa.PrivateKey, or
// ed25519.PrivateKey.
func generateKey(kind keys.Kind, alg string, bits int) (any, error) {
	switch kind {
	case keys.HMAC:
		size := map[string]int{"HS256": 32, "HS384": 48, "HS512": 64}[alg]
		b := make([]byte, size)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		return b, nil
	case keys.RSA:
		return rsa.GenerateKey(rand.Reader, bits)
	case keys.EC:
		curve := map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()}[alg]
		return ecdsa.GenerateKey(curve, rand.Reader)
	case keys.Ed25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	return nil, fmt.Errorf("unsupported key kind %v", kind)
}

// encodeKey renders private and public forms. pubOut is nil for HMAC.
func encodeKey(priv any, kind keys.Kind, format, kid string) (privOut, pubOut []byte, err error) {
	if format == "jwk" {
		pj, err := jwk.FromKey(priv, kid)
		if err != nil {
			return nil, nil, err
		}
		privOut, err = json.MarshalIndent(pj, "", "  ")
		if err != nil {
			return nil, nil, err
		}
		privOut = append(privOut, '\n')
		if kind != keys.HMAC {
			pubJ, err := jwk.FromKey(publicOf(priv), kid)
			if err != nil {
				return nil, nil, err
			}
			pubOut, err = json.MarshalIndent(pubJ, "", "  ")
			if err != nil {
				return nil, nil, err
			}
			pubOut = append(pubOut, '\n')
		}
		return privOut, pubOut, nil
	}

	if kind == keys.HMAC {
		return []byte(base64.RawURLEncoding.EncodeToString(priv.([]byte)) + "\n"), nil, nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	privOut = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	pubDER, err := x509.MarshalPKIXPublicKey(publicOf(priv))
	if err != nil {
		return nil, nil, err
	}
	pubOut = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privOut, pubOut, nil
}

// publicOf returns the public half of a private key, or the input when it
// has none (HMAC secrets and public keys).
func publicOf(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	}
	return priv
}

// writeNewFile creates path with mode 0600 and refuses to overwrite. The
// mode is best-effort on Windows, which has no POSIX permission bits: the
// file inherits the directory ACL and Go reports 0666 for it.
func writeNewFile(path string, data []byte) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return usageError(fmt.Errorf("%s already exists; remove it or choose another path", path))
		}
		return usageError(err)
	}
	if _, err := fh.Write(data); err != nil {
		_ = fh.Close()
		// Remove the partially written file so a retry is not blocked by
		// the O_EXCL check above finding leftover, truncated content.
		os.Remove(path)
		return err
	}
	if err := fh.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

func init() { commandBuilders = append(commandBuilders, newKeygenCmd) }
