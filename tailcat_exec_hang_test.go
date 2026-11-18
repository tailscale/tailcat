package tailcat

import (
	"net"
	"os/exec"
	"testing"
	"time"
)

func TestRunConnCommandReturnsAfterCommandExits(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	cmd := exec.Command("go", "version")
	done := make(chan error, 1)
	go func() { done <- runConnCommand(server, cmd) }()
	go func() {
		buf := make([]byte, 256)
		client.Read(buf)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runConnCommand: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runConnCommand hung after the command exited")
	}
}
