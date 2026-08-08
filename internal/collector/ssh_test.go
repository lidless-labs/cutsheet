package collector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/lidless-labs/cutsheet/internal/secrets"
	"golang.org/x/crypto/ssh"
)

// cannedEdgeOSConfig is what the fake device returns for any exec request:
// the set-style commands the configdiff edgeos parser consumes.
const cannedEdgeOSConfig = `set system host-name ubnt-gw-01
set interfaces ethernet eth0 address 203.0.113.2/30
set interfaces ethernet eth1 address 198.18.10.1/24
set protocols static route 0.0.0.0/0 next-hop 203.0.113.1
set firewall name WAN_IN default-action drop
`

// sshTestServer is an in-process SSH server that answers exec requests with
// canned EdgeOS-style output and records executed commands.
type sshTestServer struct {
	addr     string
	hostKey  ssh.Signer
	config   *ssh.ServerConfig
	commands chan string
}

// startSSHServer launches the fake device. authorize installs the auth
// callbacks on the ssh.ServerConfig before listening.
func startSSHServer(t *testing.T, authorize func(*ssh.ServerConfig)) *sshTestServer {
	t.Helper()

	config := &ssh.ServerConfig{}
	authorize(config)
	hostKey := generateSigner(t)
	config.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &sshTestServer{
		addr:     listener.Addr().String(),
		hostKey:  hostKey,
		config:   config,
		commands: make(chan string, 16),
	}

	var wg sync.WaitGroup
	t.Cleanup(func() {
		listener.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // listener closed by cleanup
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				srv.handleConn(conn)
			}()
		}
	}()
	return srv
}

func (s *sshTestServer) handleConn(nc net.Conn) {
	defer nc.Close()
	conn, chans, reqs, err := ssh.NewServerConn(nc, s.config)
	if err != nil {
		return // auth failure is a legitimate test outcome
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		go func() {
			defer channel.Close()
			served := false
			for req := range requests {
				var payload struct{ Command string }
				if req.Type != "exec" || served || ssh.Unmarshal(req.Payload, &payload) != nil {
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)
				served = true
				s.commands <- payload.Command
				io.WriteString(channel, cannedEdgeOSConfig)
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				// Close so the client's stdout reader sees EOF; the requests
				// loop then ends when the client closes its side.
				channel.Close()
			}
		}()
	}
}

func generateSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func hostKeyLine(signer ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

func passwordAuth(username, password string) func(*ssh.ServerConfig) {
	return func(cfg *ssh.ServerConfig) {
		cfg.PasswordCallback = func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if meta.User() == username && string(pass) == password {
				return nil, nil
			}
			return nil, errors.New("denied")
		}
	}
}

func publicKeyAuth(username string, authorized ssh.PublicKey) func(*ssh.ServerConfig) {
	marshaled := string(authorized.Marshal())
	return func(cfg *ssh.ServerConfig) {
		cfg.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if meta.User() == username && string(key.Marshal()) == marshaled {
				return nil, nil
			}
			return nil, errors.New("denied")
		}
	}
}

// sshConfigJSON builds an ssh collector config pointing at the fake server.
// fields is a JSON fragment of additional key/value pairs.
func sshConfigJSON(t *testing.T, srv *sshTestServer, fields string) string {
	t.Helper()
	host, port, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatalf("split addr %q: %v", srv.addr, err)
	}
	return `{"host":"` + host + `","port":` + port + `,"username":"netops",` + fields + `}`
}

func testBox(t *testing.T) *secrets.Box {
	t.Helper()
	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	return secrets.New(key)
}

func TestSSHConfigValidation(t *testing.T) {
	valid := `{"host":"gw.example.invalid","username":"netops","password":"x","preset":"edgeos","insecure_ignore_host_key":true}`
	if _, err := New("ssh", []byte(valid), nil); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	tests := []struct {
		name       string
		configJSON string
		wantErr    string
	}{
		{"bad json", `{`, "parse"},
		{"missing host", `{"username":"u","password":"p","preset":"edgeos","insecure_ignore_host_key":true}`, "host"},
		{"missing username", `{"host":"h.example.invalid","password":"p","preset":"edgeos","insecure_ignore_host_key":true}`, "username"},
		{"missing credentials", `{"host":"h.example.invalid","username":"u","preset":"edgeos","insecure_ignore_host_key":true}`, "password"},
		{"missing command and preset", `{"host":"h.example.invalid","username":"u","password":"p","insecure_ignore_host_key":true}`, "command"},
		{"unknown preset", `{"host":"h.example.invalid","username":"u","password":"p","preset":"timeplex","insecure_ignore_host_key":true}`, "preset"},
		{"missing host key policy", `{"host":"h.example.invalid","username":"u","password":"p","preset":"edgeos"}`, "host_key"},
		{"unparseable host key", `{"host":"h.example.invalid","username":"u","password":"p","preset":"edgeos","host_key":"not a key"}`, "host_key"},
		{"port out of range", `{"host":"h.example.invalid","port":65536,"username":"u","password":"p","preset":"edgeos","insecure_ignore_host_key":true}`, "port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New("ssh", []byte(tt.configJSON), nil)
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestSSHPresetCommands(t *testing.T) {
	tests := []struct {
		preset      string
		wantCommand string
	}{
		{"edgeos", "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands"},
		{"vyos", "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands"},
		{"cisco-ios", "show running-config"},
		{"junos", "show configuration | display set"},
		{"fortios", "show full-configuration"},
	}
	for _, tt := range tests {
		t.Run(tt.preset, func(t *testing.T) {
			srv := startSSHServer(t, passwordAuth("netops", "tape-and-string"))
			cfg := sshConfigJSON(t, srv,
				`"password":"tape-and-string","preset":"`+tt.preset+`","host_key":"`+hostKeyLine(srv.hostKey)+`"`)
			c, err := New("ssh", []byte(cfg), nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			out, err := c.Fetch(context.Background())
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if string(out) != cannedEdgeOSConfig {
				t.Fatalf("Fetch output:\n%s\nwant:\n%s", out, cannedEdgeOSConfig)
			}
			if got := <-srv.commands; got != tt.wantCommand {
				t.Fatalf("executed command: got %q, want %q", got, tt.wantCommand)
			}
		})
	}
}

func TestSSHExplicitCommandOverridesPreset(t *testing.T) {
	srv := startSSHServer(t, passwordAuth("netops", "tape-and-string"))
	cfg := sshConfigJSON(t, srv,
		`"password":"tape-and-string","preset":"edgeos","command":"show configuration commands | no-more","host_key":"`+hostKeyLine(srv.hostKey)+`"`)
	c, err := New("ssh", []byte(cfg), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := <-srv.commands; got != "show configuration commands | no-more" {
		t.Fatalf("executed command: got %q, want explicit override", got)
	}
}

func TestSSHPasswordAuthEncrypted(t *testing.T) {
	box := testBox(t)
	enc, err := box.Encrypt([]byte("tape-and-string"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	srv := startSSHServer(t, passwordAuth("netops", "tape-and-string"))
	cfg := sshConfigJSON(t, srv,
		`"password":"`+enc+`","preset":"edgeos","host_key":"`+hostKeyLine(srv.hostKey)+`"`)

	c, err := New("ssh", []byte(cfg), box)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(out) != cannedEdgeOSConfig {
		t.Fatalf("Fetch output mismatch:\n%s", out)
	}
	<-srv.commands

	// Encrypted password without a box fails at fetch time, not add time.
	c2, err := New("ssh", []byte(cfg), nil)
	if err != nil {
		t.Fatalf("New without box: %v", err)
	}
	if _, err := c2.Fetch(context.Background()); err == nil {
		t.Fatal("Fetch with encrypted password and nil box: want error, got nil")
	}
}

func TestSSHPrivateKeyAuth(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pemKey := string(pem.EncodeToMemory(block))

	box := testBox(t)
	encKey, err := box.Encrypt([]byte(pemKey))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	encKeyJSON, err := json.Marshal(encKey)
	if err != nil {
		t.Fatalf("encode key: %v", err)
	}

	srv := startSSHServer(t, publicKeyAuth("netops", sshPub))
	cfg := sshConfigJSON(t, srv,
		`"private_key":`+string(encKeyJSON)+`,"preset":"edgeos","host_key":"`+hostKeyLine(srv.hostKey)+`"`)

	c, err := New("ssh", []byte(cfg), box)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(out) != cannedEdgeOSConfig {
		t.Fatalf("Fetch output mismatch:\n%s", out)
	}
	<-srv.commands
}

func TestSSHWrongPassword(t *testing.T) {
	srv := startSSHServer(t, passwordAuth("netops", "tape-and-string"))
	cfg := sshConfigJSON(t, srv,
		`"password":"wrong","preset":"edgeos","host_key":"`+hostKeyLine(srv.hostKey)+`"`)
	c, err := New("ssh", []byte(cfg), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Fetch(context.Background()); err == nil {
		t.Fatal("Fetch with wrong password: want error, got nil")
	}
}

func TestSSHHostKeyVerification(t *testing.T) {
	t.Run("matching host key passes", func(t *testing.T) {
		srv := startSSHServer(t, passwordAuth("netops", "tape-and-string"))
		cfg := sshConfigJSON(t, srv,
			`"password":"tape-and-string","preset":"edgeos","host_key":"`+hostKeyLine(srv.hostKey)+`"`)
		c, err := New("ssh", []byte(cfg), nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := c.Fetch(context.Background()); err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		<-srv.commands
	})

	t.Run("wrong host key fails", func(t *testing.T) {
		srv := startSSHServer(t, passwordAuth("netops", "tape-and-string"))
		otherKey := generateSigner(t)
		cfg := sshConfigJSON(t, srv,
			`"password":"tape-and-string","preset":"edgeos","host_key":"`+hostKeyLine(otherKey)+`"`)
		c, err := New("ssh", []byte(cfg), nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := c.Fetch(context.Background()); err == nil {
			t.Fatal("Fetch with wrong host key: want error, got nil")
		}
	})

	t.Run("insecure_ignore_host_key skips verification", func(t *testing.T) {
		srv := startSSHServer(t, passwordAuth("netops", "tape-and-string"))
		cfg := sshConfigJSON(t, srv,
			`"password":"tape-and-string","preset":"edgeos","insecure_ignore_host_key":true`)
		c, err := New("ssh", []byte(cfg), nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := c.Fetch(context.Background()); err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		<-srv.commands
	})
}

func TestSSHDefaultPort(t *testing.T) {
	// Port 0 in config means default 22; we can't bind 22 in tests, so just
	// assert the constructed collector resolved the default.
	c, err := New("ssh", []byte(`{"host":"gw.example.invalid","username":"u","password":"p","preset":"edgeos","insecure_ignore_host_key":true}`), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sc, ok := c.(*sshCollector)
	if !ok {
		t.Fatalf("collector type: %T", c)
	}
	if sc.cfg.Port != 22 {
		t.Fatalf("default port: got %d, want 22", sc.cfg.Port)
	}
}

func TestSSHFetchCancelledContext(t *testing.T) {
	srv := startSSHServer(t, passwordAuth("netops", "tape-and-string"))
	cfg := sshConfigJSON(t, srv,
		`"password":"tape-and-string","preset":"edgeos","host_key":"`+hostKeyLine(srv.hostKey)+`"`)
	c, err := New("ssh", []byte(cfg), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Fetch(ctx); err == nil {
		t.Fatal("Fetch with cancelled context: want error, got nil")
	}
}
