package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/lidless-labs/cutsheet/internal/secrets"
	"golang.org/x/crypto/ssh"
)

// sshDialTimeout bounds the TCP dial and SSH handshake.
const sshDialTimeout = 30 * time.Second

// sshPresets maps vendor preset names to the command that produces output the
// matching configdiff parser consumes.
var sshPresets = map[string]string{
	"edgeos":    "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands",
	"vyos":      "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands",
	"cisco-ios": "show running-config",
	"junos":     "show configuration | display set",
	"fortios":   "show full-configuration",
}

// PresetVendor returns the configdiff vendor mode for an ssh preset name, or
// "" if the preset is unknown. Used for vendor defaulting at device-add time.
func PresetVendor(preset string) string {
	if _, ok := sshPresets[preset]; ok {
		return preset
	}
	return ""
}

// sshConfig is the JSON config for the "ssh" collector.
type sshConfig struct {
	Host                  string `json:"host"`
	Port                  int    `json:"port"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	PrivateKey            string `json:"private_key"`
	Command               string `json:"command"`
	Preset                string `json:"preset"`
	HostKey               string `json:"host_key"`
	InsecureIgnoreHostKey bool   `json:"insecure_ignore_host_key"`
}

// sshCollector runs one read-only show command over SSH and returns stdout.
type sshCollector struct {
	cfg     sshConfig
	command string
	hostKey ssh.PublicKey // nil when InsecureIgnoreHostKey
	box     *secrets.Box
}

func newSSHCollector(configJSON []byte, box *secrets.Box) (Collector, error) {
	var cfg sshConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, fmt.Errorf("parse ssh collector config: %w", err)
	}
	if cfg.Host == "" {
		return nil, fmt.Errorf("ssh collector config: %q is required", "host")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("ssh collector config: port %d out of range", cfg.Port)
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("ssh collector config: %q is required", "username")
	}
	if cfg.Password == "" && cfg.PrivateKey == "" {
		return nil, fmt.Errorf("ssh collector config: one of %q or %q is required", "password", "private_key")
	}
	if cfg.Preset != "" {
		if _, ok := sshPresets[cfg.Preset]; !ok {
			return nil, fmt.Errorf("ssh collector config: unknown preset %q (known: edgeos, vyos, cisco-ios, junos, fortios)", cfg.Preset)
		}
	}
	command := cfg.Command
	if command == "" {
		command = sshPresets[cfg.Preset]
	}
	if command == "" {
		return nil, fmt.Errorf("ssh collector config: one of %q or %q is required", "command", "preset")
	}

	var hostKey ssh.PublicKey
	if cfg.HostKey != "" {
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.HostKey))
		if err != nil {
			return nil, fmt.Errorf("ssh collector config: parse host_key: %w", err)
		}
		hostKey = parsed
	} else if !cfg.InsecureIgnoreHostKey {
		return nil, fmt.Errorf("ssh collector config: %q is required unless insecure_ignore_host_key is true", "host_key")
	}

	return &sshCollector{cfg: cfg, command: command, hostKey: hostKey, box: box}, nil
}

func (c *sshCollector) Fetch(ctx context.Context) ([]byte, error) {
	auth, err := c.authMethods()
	if err != nil {
		return nil, fmt.Errorf("ssh collector: %w", err)
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey() // only reachable with explicit insecure_ignore_host_key=true
	if c.hostKey != nil {
		hostKeyCallback = ssh.FixedHostKey(c.hostKey)
	}
	clientConfig := &ssh.ClientConfig{
		User:            c.cfg.Username,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshDialTimeout,
	}

	addr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.Port))
	dialer := net.Dialer{Timeout: sshDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh collector: dial %s: %w", addr, err)
	}
	// Tear the connection down if the fetch context ends mid-session; the
	// in-flight calls below then fail fast instead of hanging.
	stopWatch := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopWatch()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, clientConfig)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh collector: handshake with %s: %w", addr, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh collector: open session: %w", err)
	}
	defer session.Close()

	output, err := session.Output(c.command)
	if err != nil {
		return nil, fmt.Errorf("ssh collector: run %q: %w", c.command, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return output, nil
}

// authMethods resolves the configured credentials, decrypting enc:v1: values.
func (c *sshCollector) authMethods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if c.cfg.PrivateKey != "" {
		keyPEM, err := decryptIfNeeded(c.cfg.PrivateKey, "private_key", c.box)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey([]byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if c.cfg.Password != "" {
		password, err := decryptIfNeeded(c.cfg.Password, "password", c.box)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.Password(password))
	}
	return methods, nil
}
