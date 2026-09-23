package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Shopify/ejson"
)

func TestDecryptOutputFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX file permissions and a POSIX shell")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("requires a POSIX shell")
	}
	buildDir := t.TempDir()
	binary := filepath.Join(buildDir, "ejson")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}

	publicKey, privateKey, err := ejson.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(fmt.Sprintf(`{"_public_key":%q,"secret":"synthetic test value"}`, publicKey))
	var encrypted bytes.Buffer
	if _, err := ejson.Encrypt(bytes.NewReader(plaintext), &encrypted); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(buildDir, "synthetic.ejson")
	if err := os.WriteFile(fixture, encrypted.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(buildDir, publicKey), []byte(privateKey), 0600); err != nil {
		t.Fatal(err)
	}

	run := func(output, umask string) ([]byte, error) {
		args := []string{"-c", `umask "$1"; shift; exec "$@"`, "ejson-test", umask, binary, "--keydir", buildDir, "decrypt"}
		if output != "" {
			args = append(args, "-o", output)
		}
		args = append(args, fixture)
		cmd := exec.Command(shell, args...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		return cmd.CombinedOutput()
	}

	for _, umask := range []string{"000", "022", "077"} {
		t.Run("new_file_umask_"+umask, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "decrypted.json")
			if message, err := run(output, umask); err != nil {
				t.Fatalf("decrypt: %v\n%s", err, message)
			}
			assertOutput(t, output, plaintext, 0600)
		})
	}

	for _, mode := range []os.FileMode{0600, 0640, 0644, 0660, 0666} {
		t.Run(fmt.Sprintf("existing_mode_%04o", mode), func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "decrypted.json")
			if err := os.WriteFile(output, []byte("old content"), mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(output, mode); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(output)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := os.Open(output)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()

			// Existing files are restricted to 0600 in place: same inode, and
			// any permissive mode left by an earlier version is removed.
			if message, err := run(output, "022"); err != nil {
				t.Fatalf("decrypt: %v\n%s", err, message)
			}
			assertOutput(t, output, plaintext, 0600)
			assertSameFile(t, before, output)
			// Chmod does not revoke descriptors opened earlier; documented residual risk.
			data, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(data, plaintext) {
				t.Errorf("existing reader did not see updated content: %q, %v", data, err)
			}
		})
	}

	for _, dangling := range []bool{false, true} {
		t.Run(fmt.Sprintf("symlink_dangling_%t", dangling), func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			mode := os.FileMode(0600)
			var before os.FileInfo
			if !dangling {
				mode = 0640
				if err := os.WriteFile(target, []byte("old content"), mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(target, mode); err != nil {
					t.Fatal(err)
				}
				before, err = os.Stat(target)
				if err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(dir, "output")
			if err := os.Symlink(target, output); err != nil {
				t.Fatal(err)
			}
			if message, err := run(output, "022"); err != nil {
				t.Fatalf("decrypt through symlink: %v\n%s", err, message)
			}
			link, err := os.Readlink(output)
			if err != nil || link != target {
				t.Errorf("output symlink changed: %q, %v", link, err)
			}
			// The link is followed and the caller-owned target is restricted.
			assertOutput(t, target, plaintext, 0600)
			if before != nil {
				assertSameFile(t, before, target)
			}
		})
	}

	t.Run("hard_link", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		output := filepath.Join(dir, "output")
		if err := os.WriteFile(target, []byte("old content"), 0640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0640); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Link(target, output); err != nil {
			t.Fatal(err)
		}
		if message, err := run(output, "022"); err != nil {
			t.Fatalf("decrypt: %v\n%s", err, message)
		}
		assertOutput(t, target, plaintext, 0600)
		assertSameFile(t, before, target)
		assertSameFile(t, before, output)
	})

	t.Run("non_regular_target", func(t *testing.T) {
		if message, err := run("/dev/null", "022"); err != nil {
			t.Fatalf("decrypt to /dev/null: %v\n%s", err, message)
		}
	})

	t.Run("owned_by_other_user", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("requires root to create a file owned by another user")
		}
		output := filepath.Join(t.TempDir(), "decrypted.json")
		if err := os.WriteFile(output, []byte("theirs"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(output, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if message, err := run(output, "022"); err == nil {
			t.Fatalf("decrypt wrote into a file owned by another user: %s", message)
		}
		assertOutput(t, output, []byte("theirs"), 0644)
	})

	t.Run("existing_file_in_nonwritable_directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses directory permission checks")
		}
		dir := t.TempDir()
		output := filepath.Join(dir, "output")
		if err := os.WriteFile(output, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0500); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chmod(dir, 0700); err != nil {
				t.Error(err)
			}
		}()
		if message, err := run(output, "022"); err != nil {
			t.Fatalf("decrypt existing writable file: %v\n%s", err, message)
		}
		assertOutput(t, output, plaintext, 0600)
	})

	t.Run("directory", func(t *testing.T) {
		if message, err := run(t.TempDir(), "022"); err == nil {
			t.Errorf("decrypt accepted a directory: %s", message)
		}
	})

	t.Run("missing_parent", func(t *testing.T) {
		if message, err := run(filepath.Join(t.TempDir(), "missing", "output"), "022"); err == nil {
			t.Errorf("decrypt accepted a missing parent: %s", message)
		}
	})

	t.Run("stdout", func(t *testing.T) {
		output, err := run("", "022")
		if err != nil || !bytes.Equal(output, plaintext) {
			t.Errorf("stdout changed: got %q, error %v", output, err)
		}
	})
}

func TestDecryptFailurePreservesOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "invalid.ejson")
	output := filepath.Join(dir, "output")
	if err := os.WriteFile(input, []byte("invalid json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := decryptAction([]string{input}, dir, "", output); err == nil {
		t.Fatal("expected decryption failure")
	}
	data, err := os.ReadFile(output)
	if err != nil || string(data) != "untouched" {
		t.Errorf("output changed after decryption failure: %q, %v", data, err)
	}
}

// The refusal path must leave a foreign file untouched, including its contents.
func TestDecryptRefusesFileOwnedByOtherUser(t *testing.T) {
	original := ownedByCaller
	ownedByCaller = func(os.FileInfo) bool { return false }
	defer func() { ownedByCaller = original }()

	dir := t.TempDir()
	output := filepath.Join(dir, "output")
	if err := os.WriteFile(output, []byte("theirs"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(output, 0644); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ejson.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if _, err := ejson.Encrypt(bytes.NewReader([]byte(fmt.Sprintf(`{"_public_key":%q,"k":"v"}`, publicKey))), &encrypted); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "in.ejson")
	if err := os.WriteFile(input, encrypted.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, publicKey), []byte(privateKey), 0600); err != nil {
		t.Fatal(err)
	}
	err = decryptAction([]string{input}, dir, "", output)
	if err == nil || !strings.Contains(err.Error(), "owned by another user") {
		t.Fatalf("expected ownership refusal, got %v", err)
	}
	assertOutput(t, output, []byte("theirs"), 0644)
}

func assertOutput(t *testing.T, path string, plaintext []byte, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != mode {
		t.Errorf("plaintext output permissions: got %04o, want %04o", info.Mode().Perm(), mode)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, plaintext) {
		t.Errorf("plaintext output: got %q, error %v", data, err)
	}
}

func assertSameFile(t *testing.T, before os.FileInfo, path string) {
	t.Helper()
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Errorf("existing inode changed: %s", path)
	}
}
