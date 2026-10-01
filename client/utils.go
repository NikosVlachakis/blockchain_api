package client

import (
	"blockchain-api/keystore"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Helper function to load private key from directory
func loadPrivateKeyFromDirectory(keyDir string) ([]byte, error) {
	files, err := os.ReadDir(keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key directory: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no files found in private key directory: %s", keyDir)
	}

	return os.ReadFile(path.Join(keyDir, files[0].Name()))
}

// Helper to compute SHA256 hash of PEM-encoded identity
func IdentityHashFromPEM(pem string) string {
	hash := sha256.Sum256([]byte(pem))
	return hex.EncodeToString(hash[:])
}

// Initialize the setup for the organization.
func Initialize(enrollmentId, userSecret string) (*client.Gateway, error) {
	// userSecret, err := base64.StdEncoding.DecodeString(userSecretB64)
	log.Printf("Initializing connection for %s...\n", orgSetup.OrgName)
	clientConnection, err := newGrpcConnection(enrollmentId, userSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}
	id, err := newIdentity(enrollmentId, []byte(userSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}
	sign, err := newSign(enrollmentId, []byte(userSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to create sign function: %w", err)
	}

	gateway, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gateway: %w", err)
	}
	// setup.Gateway = *gateway
	log.Println("Initialization complete")
	return gateway, nil
}

// Get Gateway from session map
func GetGateway(sessionID string) (*client.Gateway, bool) {
	val, ok := orgGatewaysSessions.Load(sessionID)
	if !ok {
		return nil, false
	}
	return val.(*client.Gateway), true
}

// Remove OrgSetup from session map
func RemoveGateway(sessionID string) {
	orgGatewaysSessions.Delete(sessionID)
}

// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection(enrollmentId, userSecret string) (*grpc.ClientConn, error) {
	var certificate *x509.Certificate
	var err error
	if orgSetup.TLSCertPath != "" {
		certificate, err = loadCertificate(orgSetup.TLSCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, orgSetup.GatewayPeer)

	connection, err := grpc.NewClient(orgSetup.PeerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	return connection, nil
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func newIdentity(enrollmentID string, userSecret []byte) (*identity.X509Identity, error) {
	var certificate *x509.Certificate
	var certficatePEM []byte
	var err error

	if orgSetup.CertPath == "" && orgSetup.KeyPath == "" {
		// Load from keystore
		certficatePEM, _, err = keystore.GetKeyForFabricClient(enrollmentID, orgSetup.MSPID, string(userSecret))
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate from keystore: %w", err)
		}
		certificate, err = identity.CertificateFromPEM(certficatePEM)
	} else {
		// Load from file system
		certificate, err = loadCertificate(orgSetup.CertPath)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	id, err := identity.NewX509Identity(orgSetup.MSPID, certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to create X.509 identity: %w", err)
	}

	return id, nil
}

func parsePrivateKeyPEM(privateKeyPEM []byte) (crypto.PrivateKey, error) {
	// Prefer fabric-gateway helper (SEC1 EC + PKCS8).
	if key, err := identity.PrivateKeyFromPEM(privateKeyPEM); err == nil {
		return key, nil
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key (EC/PKCS8): %w", err)
	}
	return key, nil
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign(enrollmentID string, userSecret []byte) (identity.Sign, error) {
	var privateKeyPEM []byte
	var privateKey crypto.PrivateKey
	var err error

	if orgSetup.KeyPath == "" && orgSetup.CertPath == "" {
		// Load from keystore
		_, privateKeyPEM, err = keystore.GetKeyForFabricClient(enrollmentID, orgSetup.MSPID, string(userSecret))
		if err != nil {
			return nil, fmt.Errorf("failed to get key from keystore: %w", err)
		}

		privateKey, err = parsePrivateKeyPEM(privateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key PEM: %w", err)
		}

	} else {
		// Load from file system
		files, err := os.ReadDir(orgSetup.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key directory: %w", err)
		}
		privateKeyPEM, err = os.ReadFile(path.Join(orgSetup.KeyPath, files[0].Name()))

		privateKey, err = identity.PrivateKeyFromPEM(privateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key PEM: %w", err)
		}
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key sign: %w", err)
	}

	return sign, nil
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}

func getEnvWithDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
