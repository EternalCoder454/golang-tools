// Command goship builds a Go program for one or more hosts and deploys it over
// SSH: cross-compile per target arch → scp (optionally via a ProxyJump) →
// back up the current binary → install over it → restart its systemd unit →
// health-check → roll back automatically if the health check fails.
//
// It reads a goship.json describing the build and the targets. Pure standard
// library — it shells out to the `go`, `scp` and `ssh` you already use.
//
//	goship [-c goship.json] [-only name,name] [-no-build]
//	goship -init                       # write a starter goship.json
//
// Remote steps use sudo, so the SSH user needs passwordless sudo on each host.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type BuildCfg struct {
	Dir     string   `json:"dir"`     // package to build (default ".")
	Ldflags string   `json:"ldflags"` // optional -ldflags
	Env     []string `json:"env"`     // extra build env, e.g. ["CGO_ENABLED=0"]
}

type Target struct {
	Name    string `json:"name"`
	Arch    string `json:"arch"`            // amd64 | arm64 | …
	OS      string `json:"os,omitempty"`    // default linux
	SSH     string `json:"ssh"`             // user@host
	Jump    string `json:"jump,omitempty"`  // optional ProxyJump user@host
	Dest    string `json:"dest"`            // remote install path
	Restart string `json:"restart,omitempty"` // systemd unit to restart
	Health  string `json:"health,omitempty"`  // health command (default: systemctl is-active <restart>)
}

type Config struct {
	Build   BuildCfg `json:"build"`
	Binary  string   `json:"binary"`
	SSHKey  string   `json:"ssh_key,omitempty"`
	Targets []Target `json:"targets"`
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "goship: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	cfgPath := flag.String("c", "goship.json", "config file")
	only := flag.String("only", "", "comma-separated target names to deploy (default: all)")
	noBuild := flag.Bool("no-build", false, "skip building (reuse cached binaries in the temp dir)")
	doInit := flag.Bool("init", false, "write a starter goship.json and exit")
	flag.Parse()

	if *doInit {
		writeSample(*cfgPath)
		return
	}

	cfg := loadConfig(*cfgPath)
	want := map[string]bool{}
	for _, n := range strings.Split(*only, ",") {
		if n = strings.TrimSpace(n); n != "" {
			want[n] = true
		}
	}

	// Build once per arch (two arm64 targets share a build).
	built := map[string]string{}
	fail := 0
	for _, t := range cfg.Targets {
		if len(want) > 0 && !want[t.Name] {
			continue
		}
		bin, ok := built[t.Arch]
		if !ok {
			if *noBuild {
				bin = tmpBin(cfg.Binary, t.Arch)
			} else {
				bin = build(cfg, t.Arch)
			}
			built[t.Arch] = bin
		}
		if err := deploy(cfg, t, bin); err != nil {
			fmt.Printf("✗ %s: %v\n", t.Name, err)
			fail++
		} else {
			fmt.Printf("✓ %s: deployed and healthy\n", t.Name)
		}
	}
	if fail > 0 {
		os.Exit(1)
	}
}

func loadConfig(path string) Config {
	b, err := os.ReadFile(path)
	if err != nil {
		die("read %s: %v (run `goship -init` to create one)", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		die("parse %s: %v", path, err)
	}
	if c.Binary == "" {
		die("config: \"binary\" is required")
	}
	if c.Build.Dir == "" {
		c.Build.Dir = "."
	}
	return c
}

func tmpBin(binary, arch string) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("goship-%s-%s", binary, arch))
}

func build(cfg Config, arch string) string {
	out := tmpBin(cfg.Binary, arch) // absolute (temp dir), so -o works regardless of cwd
	args := []string{"build", "-trimpath", "-o", out}
	if cfg.Build.Ldflags != "" {
		args = append(args, "-ldflags="+cfg.Build.Ldflags)
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Dir = expand(cfg.Build.Dir) // build from inside the module
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch)
	cmd.Env = append(cmd.Env, cfg.Build.Env...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	fmt.Printf("→ build %s (%s)\n", cfg.Binary, arch)
	if err := cmd.Run(); err != nil {
		die("build %s: %v", arch, err)
	}
	return out
}

// sshBase returns the shared ssh/scp options for a target (key, jump, timeout).
func sshBase(cfg Config, t Target) []string {
	var a []string
	if cfg.SSHKey != "" {
		a = append(a, "-i", expand(cfg.SSHKey))
	}
	a = append(a, "-o", "ConnectTimeout=20")
	if t.Jump != "" {
		a = append(a, "-o", "ProxyJump="+t.Jump)
	}
	return a
}

func deploy(cfg Config, t Target, localBin string) error {
	staged := "/tmp/" + cfg.Binary + ".goship.new"
	// 1. copy the new binary to the host's temp dir
	scpArgs := append(sshBase(cfg, t), localBin, t.SSH+":"+staged)
	if out, err := run("scp", scpArgs...); err != nil {
		return fmt.Errorf("scp: %v\n%s", err, out)
	}
	// 2. install + restart + health, all in one remote shell
	health := t.Health
	if health == "" && t.Restart != "" {
		health = "systemctl is-active " + shq(t.Restart)
	}
	if health == "" {
		health = "true"
	}
	script := strings.Join([]string{
		"set -e",
		fmt.Sprintf("[ -f %s ] && sudo cp -a %s %s.goship.bak || true", shq(t.Dest), shq(t.Dest), shq(t.Dest)),
		fmt.Sprintf("sudo install -m755 %s %s", shq(staged), shq(t.Dest)),
		fmt.Sprintf("rm -f %s", shq(staged)),
		restartLine(t),
		"sleep 1",
		health,
	}, "\n")
	if out, err := run("ssh", append(sshBase(cfg, t), t.SSH, script)...); err != nil {
		// 3. roll back to the backup so a bad deploy doesn't leave the host down
		rollback := fmt.Sprintf("[ -f %s.goship.bak ] && sudo install -m755 %s.goship.bak %s && %s",
			shq(t.Dest), shq(t.Dest), shq(t.Dest), strings.TrimSpace(restartLine(t)))
		run("ssh", append(sshBase(cfg, t), t.SSH, rollback)...)
		return fmt.Errorf("install/health failed (rolled back):\n%s", strings.TrimSpace(out))
	}
	return nil
}

func restartLine(t Target) string {
	if t.Restart == "" {
		return "true"
	}
	return "sudo systemctl restart " + shq(t.Restart)
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// shq single-quotes a string for safe embedding in a remote /bin/sh command.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}

func writeSample(path string) {
	if _, err := os.Stat(path); err == nil {
		die("%s already exists", path)
	}
	sample := Config{
		Build:  BuildCfg{Dir: ".", Env: []string{"CGO_ENABLED=0"}},
		Binary: "myapp",
		SSHKey: "~/.ssh/id_ed25519",
		Targets: []Target{
			{Name: "server1", Arch: "amd64", SSH: "user@192.168.1.10", Dest: "/usr/local/bin/myapp", Restart: "myapp"},
			{Name: "pi", Arch: "arm64", SSH: "user@192.168.1.20", Jump: "user@192.168.1.10", Dest: "/usr/local/bin/myapp", Restart: "myapp"},
		},
	}
	b, _ := json.MarshalIndent(sample, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		die("write %s: %v", path, err)
	}
	fmt.Printf("wrote %s — edit it, then run `goship`\n", path)
}
