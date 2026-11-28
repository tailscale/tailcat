package tailcat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
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

func TestFetchDERPMapSkipsNulls(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Regions":{"1":null,"2":{"RegionID":2,"Nodes":[null,{"Name":"2a","RegionID":2,"HostName":"a.example.com"}]}}}`))
	}))
	defer ts.Close()

	dm, err := FetchDERPMap(context.Background(), DERPMapURL(ts.URL), DERPMapCache(new(memDERPMapCache)))
	if err != nil {
		t.Fatal(err)
	}
	if len(dm.Regions) != 1 {
		t.Fatalf("got %d regions, want 1 (null region dropped)", len(dm.Regions))
	}
	r := dm.Regions[2]
	if r == nil || len(r.Nodes) != 1 || r.Nodes[0] == nil || r.Nodes[0].Name != "2a" {
		t.Fatalf("region 2 = %v, want only its non-null node", logger.AsJSON(r))
	}
}
