// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"sync"
)

const backgroundRetries = 1

type retryLimitKey struct{}

// withBackgroundRetries bounds retries for a classification nobody waits on.
func withBackgroundRetries(ctx context.Context) context.Context {
	return context.WithValue(ctx, retryLimitKey{}, backgroundRetries)
}

func (f *Firewall) retryBudget(ctx context.Context) int {
	if limit, ok := ctx.Value(retryLimitKey{}).(int); ok && limit < f.maxRetries {
		return limit
	}
	return f.maxRetries
}

// verdict is one classification started beside the caller's flow.
type verdict struct {
	done   chan struct{}
	result BlockResult
	err    error
}

// pendingVerdicts runs classifications beside the caller. Those that share a
// conversation are sent in the order they were started, and at most
// maxConcurrent are in flight at once.
type pendingVerdicts struct {
	slots     chan struct{}
	maxQueued int

	mu          sync.Mutex
	tails       map[string]*verdict
	depths      map[string]int
	outstanding int
	idle        []chan struct{}
}

func newPendingVerdicts(maxConcurrent, maxQueued int) *pendingVerdicts {
	return &pendingVerdicts{
		slots:     make(chan struct{}, maxConcurrent),
		maxQueued: maxQueued,
		tails:     make(map[string]*verdict),
		depths:    make(map[string]int),
	}
}

// submit starts a classification. A background one is never joined by its
// caller, so it is dropped once its conversation already holds maxQueued.
func (p *pendingVerdicts) submit(conversation string, background bool, call func() (BlockResult, error)) *verdict {
	started := &verdict{done: make(chan struct{})}
	p.mu.Lock()
	if background && conversation != "" && p.depths[conversation] >= p.maxQueued {
		p.mu.Unlock()
		close(started.done)
		return started
	}
	var previous *verdict
	if conversation != "" {
		previous = p.tails[conversation]
		p.tails[conversation] = started
		p.depths[conversation]++
	}
	p.outstanding++
	p.mu.Unlock()

	go func() {
		if previous != nil {
			<-previous.done
		}
		p.slots <- struct{}{}
		started.result, started.err = call()
		<-p.slots
		p.finish(conversation, started)
		close(started.done)
	}()
	return started
}

func (p *pendingVerdicts) finish(conversation string, finished *verdict) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if conversation != "" {
		if p.depths[conversation]--; p.depths[conversation] == 0 {
			delete(p.depths, conversation)
		}
		if p.tails[conversation] == finished {
			delete(p.tails, conversation)
		}
	}
	if p.outstanding--; p.outstanding == 0 {
		for _, waiter := range p.idle {
			close(waiter)
		}
		p.idle = nil
	}
}

// drain waits until no classification is outstanding or ctx is done.
func (p *pendingVerdicts) drain(ctx context.Context) error {
	p.mu.Lock()
	if p.outstanding == 0 {
		p.mu.Unlock()
		return nil
	}
	waiter := make(chan struct{})
	p.idle = append(p.idle, waiter)
	p.mu.Unlock()
	select {
	case <-waiter:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
