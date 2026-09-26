// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"sync"

	"tailscale.com/types/key"
	"tailscale.com/util/set"
)

// KeySet is a set of node public keys that is safe for concurrent
// use. Its zero value is an empty set.
//
// Its Contains method is the usual value for [Server.AllowClient]
// when the allowed clients are a known list rather than a decision
// made per client:
//
//	var allow tailcat.KeySet
//	allow.Add(k)
//	s.AllowClient = allow.Contains
//
// An empty set allows no clients, unlike a nil AllowClient, which
// allows all. Because AllowClient is only consulted when a client
// connects, removing a connected client's key from the set does not
// disconnect it; call [Server.DisconnectClient] as well.
type KeySet struct {
	mu sync.Mutex
	s  set.Set[key.NodePublic]
}

// Add adds k to the set.
func (s *KeySet) Add(k key.NodePublic) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.s.Make()
	s.s.Add(k)
}

// Remove removes k from the set, if present.
func (s *KeySet) Remove(k key.NodePublic) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.s.Delete(k)
}

// Contains reports whether k is in the set.
func (s *KeySet) Contains(k key.NodePublic) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.s.Contains(k)
}
