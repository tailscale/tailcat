package tailcat

import (
	"testing"

	"github.com/pkg/sftp"
)

func TestSetstatRejectsMalformedAttributes(t *testing.T) {
	r := &sftp.Request{Flags: 0x4}
	h := &rootedFiles{}
	if err := h.setstat(r, "f"); err != sftp.ErrSSHFxBadMessage {
		t.Fatalf("setstat with truncated attributes = %v, want ErrSSHFxBadMessage", err)
	}
}
