package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"io/ioutil"
	"os"
	"strconv"

	"orange/sonic-netconf-server/lib"
	"orange/sonic-netconf-server/netconf/server"

	gliderssh "github.com/gliderlabs/ssh"
	"github.com/go-redis/redis/v7"
	"github.com/golang/glog"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/google/uuid"
)

// Command line parameters
var (
	port                  int    // Server port
	clientAuth            string // Client auth mode
	redisClient           *redis.Client
	tacplusConfigKey      = "TACACS|NETCONF"
	publicKeyPath         = "/etc/sonic/netconf-key.pub"
	privateKeyPath        = "/etc/sonic/netconf-key"
	ed25519PublicKeyPath  = "/etc/sonic/netconf-key-ed25519.pub"
	ed25519PrivateKeyPath = "/etc/sonic/netconf-key-ed25519"
)

func init() {
	// Parse command line
	flag.IntVar(&port, "port", 830, "Listen port")
	flag.StringVar(&clientAuth, "client_auth", "none", "Client auth mode - none|cert|user|tacacs")
	flag.Parse()
	// Suppress warning messages related to logging before flag parse
	flag.CommandLine.Parse([]string{})

	redisClient = redis.NewClient(&redis.Options{
		Network:  "unix",
		Addr:     "/var/run/redis/redis.sock",
		Password: "",
		DB:       4,
	})
}

func main() {

	MakeSSHKeyPair(publicKeyPath, privateKeyPath)
	MakeEd25519KeyPair(ed25519PublicKeyPath, ed25519PrivateKeyPath)

	srv := &gliderssh.Server{Addr: ":" + strconv.Itoa(port), Handler: server.DefaultHandler}

	srv.SubsystemHandlers = map[string]gliderssh.SubsystemHandler{}

	srv.SetOption(gliderssh.HostKeyFile(privateKeyPath))
	srv.SetOption(gliderssh.HostKeyFile(ed25519PrivateKeyPath))
	srv.SetOption(gliderssh.NoPty())
	srv.SetOption(gliderssh.PasswordAuth(authenticate))

	srv.SubsystemHandlers["netconf"] = server.SessionHandler

	glog.Infof("Server start on port %+v", port)
	srv.ListenAndServe()
}

func authenticate(ctx gliderssh.Context, password string) bool {

	pamAuthenticator := lib.NewPAMAuthenticator(ctx.User(), password)

	if !pamAuthenticator.Authenticate() {
		glog.Errorf("[PAM] Authentication failed user:(%s)", ctx.User())
		return false
	}

	ctx.SetValue("auth-type", "local")
	ctx.SetValue("auth", pamAuthenticator)

	ctx.SetValue("uuid", uuid.New().String())
	glog.Infof("Authentication success user:(%s)", ctx.User())
	return true
}

func MakeSSHKeyPair(pubKeyPath, privateKeyPath string) error {

	if fileExists(publicKeyPath) && fileExists(privateKeyPath) {
		glog.Info("SSH key generation skipped, files exists")
		return nil
	}

	glog.Info("SSH keys not found, generating server keys")

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}

	// generate and write private key as PEM
	privateKeyFile, err := os.Create(privateKeyPath)
	defer privateKeyFile.Close()
	if err != nil {
		return err
	}
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return err
	}

	// generate and write public key
	pub, err := cryptossh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(pubKeyPath, cryptossh.MarshalAuthorizedKey(pub), 0655)
}

// MakeEd25519KeyPair generates an ssh-ed25519 host key pair in OpenSSH format
// when no key file is present. Existing RSA host keys (managed by MakeSSHKeyPair)
// are left untouched so this is purely an additive capability — both algorithms
// are advertised by the SSH server simultaneously.
//
// Modern SSH clients (OpenSSH ≥ 8.8 from 2021) reject the ssh-rsa SHA-1 host key
// algorithm by default and need operators to set HostKeyAlgorithms=+ssh-rsa
// manually. By offering an ed25519 host key the server stops requiring that
// workaround.
func MakeEd25519KeyPair(pubKeyPath, privateKeyPath string) error {

	if fileExists(pubKeyPath) && fileExists(privateKeyPath) {
		glog.Info("ed25519 host key generation skipped, files exists")
		return nil
	}

	glog.Info("ed25519 host key not found, generating server key")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	pemBytes, err := marshalOpenSSHEd25519PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(privateKeyPath, pemBytes, 0600); err != nil {
		return err
	}

	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(pubKeyPath, cryptossh.MarshalAuthorizedKey(sshPub), 0644)
}

// marshalOpenSSHEd25519PrivateKey encodes an ed25519 private key as an
// unencrypted OpenSSH private key (PEM type "OPENSSH PRIVATE KEY"). The output
// matches what `ssh-keygen -t ed25519 -N ""` produces and is the format
// golang.org/x/crypto/ssh.ParsePrivateKey recognises for this key type.
//
// The vendored golang.org/x/crypto in this tree predates ssh.MarshalPrivateKey
// (added 2023), so the format is constructed manually. The shape mirrors the
// parseOpenSSHPrivateKey structures in vendor/golang.org/x/crypto/ssh/keys.go:
// outer = (CipherName, KdfName, KdfOpts, NumKeys, PubKey, PrivKeyBlock); inner
// pk1 = (Check1, Check2, Keytype, {Pub, Priv, Comment, padding}).
func marshalOpenSSHEd25519PrivateKey(priv ed25519.PrivateKey) ([]byte, error) {
	pub := priv.Public().(ed25519.PublicKey)

	var checkBytes [4]byte
	if _, err := rand.Read(checkBytes[:]); err != nil {
		return nil, err
	}
	check := binary.BigEndian.Uint32(checkBytes[:])

	pubKeyPart := cryptossh.Marshal(struct {
		KeyType string
		Pub     []byte
	}{
		KeyType: cryptossh.KeyAlgoED25519,
		Pub:     pub,
	})

	privInner := cryptossh.Marshal(struct {
		Pub     []byte
		Priv    []byte
		Comment string
	}{
		Pub:     pub,
		Priv:    priv,
		Comment: "",
	})

	privBlock := cryptossh.Marshal(struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Rest    []byte `ssh:"rest"`
	}{
		Check1:  check,
		Check2:  check,
		Keytype: cryptossh.KeyAlgoED25519,
		Rest:    privInner,
	})
	for i := 1; len(privBlock)%8 != 0; i++ {
		privBlock = append(privBlock, byte(i))
	}

	outer := cryptossh.Marshal(struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}{
		CipherName:   "none",
		KdfName:      "none",
		KdfOpts:      "",
		NumKeys:      1,
		PubKey:       pubKeyPart,
		PrivKeyBlock: privBlock,
	})

	body := append([]byte("openssh-key-v1\x00"), outer...)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: body,
	}), nil
}

func fileExists(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}
