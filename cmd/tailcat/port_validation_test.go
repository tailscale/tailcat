package main

import "testing"

func TestParsePortSetRejectsInvalidPorts(t *testing.T) {
	for _, spec := range []string{"0", "0-100", "100-0", "5555:0", "5555:65536", "5555:99999"} {
		ports, _, targets, err := parsePortSet(spec)
		if err == nil {
			t.Errorf("parsePortSet(%q) = %v, %v, nil error; want rejection", spec, ports, targets)
		}
	}
}
