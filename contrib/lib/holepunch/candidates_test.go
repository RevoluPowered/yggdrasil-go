package holepunch

import (
	"encoding/json"
	"testing"
)

func TestGatherLocalCandidates(t *testing.T) {
	candidates := GatherLocalCandidates(12345)

	// We should get at least one candidate on any machine with a network interface.
	// On CI or containers this might be zero, so just verify the structure.
	for _, c := range candidates {
		if c.Type != CandidateLocal {
			t.Errorf("expected type %q, got %q", CandidateLocal, c.Type)
		}
		if c.Addr == "" {
			t.Error("candidate address is empty")
		}
	}
}

func TestGatherLocalCandidatesExcludesLoopback(t *testing.T) {
	candidates := GatherLocalCandidates(9999)
	for _, c := range candidates {
		// Should not contain 127.0.0.1 or ::1.
		if c.Addr == "127.0.0.1:9999" || c.Addr == "[::1]:9999" {
			t.Errorf("loopback address should be excluded: %s", c.Addr)
		}
	}
}

func TestMarshalUnmarshalCandidates(t *testing.T) {
	original := []Candidate{
		{Addr: "85.1.2.3:4000", Type: CandidateSTUN},
		{Addr: "192.168.1.5:4000", Type: CandidateLocal},
		{Addr: "85.1.2.3:5678", Type: CandidateUPnP},
	}

	data, err := MarshalCandidates(original)
	if err != nil {
		t.Fatalf("MarshalCandidates: %v", err)
	}

	// Verify it's valid JSON.
	if !json.Valid([]byte(data)) {
		t.Fatalf("MarshalCandidates produced invalid JSON: %s", data)
	}

	parsed, err := UnmarshalCandidates(data)
	if err != nil {
		t.Fatalf("UnmarshalCandidates: %v", err)
	}

	if len(parsed) != len(original) {
		t.Fatalf("len = %d, want %d", len(parsed), len(original))
	}
	for i := range original {
		if parsed[i].Addr != original[i].Addr {
			t.Errorf("[%d] Addr = %q, want %q", i, parsed[i].Addr, original[i].Addr)
		}
		if parsed[i].Type != original[i].Type {
			t.Errorf("[%d] Type = %q, want %q", i, parsed[i].Type, original[i].Type)
		}
	}
}

func TestUnmarshalCandidatesEmpty(t *testing.T) {
	parsed, err := UnmarshalCandidates("[]")
	if err != nil {
		t.Fatalf("UnmarshalCandidates: %v", err)
	}
	if len(parsed) != 0 {
		t.Errorf("expected empty, got %d candidates", len(parsed))
	}
}

func TestUnmarshalCandidatesInvalid(t *testing.T) {
	_, err := UnmarshalCandidates("not json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestCandidateTypeConstants(t *testing.T) {
	// Verify the string values for JSON stability.
	if CandidateSTUN != "stun" {
		t.Errorf("CandidateSTUN = %q, want %q", CandidateSTUN, "stun")
	}
	if CandidateLocal != "local" {
		t.Errorf("CandidateLocal = %q, want %q", CandidateLocal, "local")
	}
	if CandidateUPnP != "upnp" {
		t.Errorf("CandidateUPnP = %q, want %q", CandidateUPnP, "upnp")
	}
}
