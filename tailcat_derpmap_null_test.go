package tailcat

import (
	"context"
	"encoding/json"
	"testing"

	"tailscale.com/tailcfg"
)

func TestExpandSkipsNullDERPRegions(t *testing.T) {
	var dm tailcfg.DERPMap
	if err := json.Unmarshal([]byte(`{"Regions":{"1":null}}`), &dm); err != nil {
		t.Fatal(err)
	}
	ci := &ConnInfo{RegionID: 1}
	if err := ci.Expand(context.Background(), &dm); err == nil {
		t.Fatal("Expand with a null region: got nil error, want rejection")
	}
	if dm.Regions[1] != nil {
		t.Fatal("Expand modified the caller's DERP map")
	}
}
