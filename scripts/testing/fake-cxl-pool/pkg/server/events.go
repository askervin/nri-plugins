// Copyright The NRI Plugins Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"sync"
	"time"

	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/api"
)

// broker fans out events to subscribers. Slow subscribers lose events.
type broker struct {
	mu   sync.Mutex
	subs map[chan api.Event]bool
}

func newBroker() *broker {
	return &broker{subs: map[chan api.Event]bool{}}
}

func (b *broker) subscribe() chan api.Event {
	ch := make(chan api.Event, 64)
	b.mu.Lock()
	b.subs[ch] = true
	b.mu.Unlock()
	return ch
}

func (b *broker) unsubscribe(ch chan api.Event) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
}

func (b *broker) publish(typ string, obj any) {
	ev := api.Event{Type: typ, Time: time.Now().UTC(), Object: obj}
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}
