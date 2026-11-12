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
	// done closes once result and err are set.
	done chan struct{}
	// released closes once the verdict has left its conversation's queue. A
	// canceled verdict is done before it is released, so its successor still
	// waits for every earlier classification.
	released chan struct{}
	result   BlockResult
	err      error
}

// pendingVerdicts runs classifications beside the caller. Those that share a
// conversation are sent in the order they were started, and at most
// maxConcurrent are in flight at once.
type pendingVerdicts struct {
	slots         chan struct{}
	maxQueued     int
	maxBackground int

	mu          sync.Mutex
	tails       map[string]*verdict
	depths      map[string]int
	background  int
	outstanding int
	idle        []chan struct{}
}

func newPendingVerdicts(maxConcurrent, maxQueued int) *pendingVerdicts {
	return &pendingVerdicts{
		slots:         make(chan struct{}, maxConcurrent),
		maxQueued:     maxQueued,
		maxBackground: maxConcurrent * maxQueued,
		tails:         make(map[string]*verdict),
		depths:        make(map[string]int),
	}
}

// submit starts a classification. A background one is never joined by its
// caller, so it is dropped once its conversation holds maxQueued or the
// client holds maxBackground of them. A joined one stops waiting for its turn
// when ctx is done.
func (p *pendingVerdicts) submit(
	ctx context.Context,
	conversation string,
	background bool,
	call func(context.Context) (BlockResult, error),
) *verdict {
	started := &verdict{done: make(chan struct{}), released: make(chan struct{})}
	p.mu.Lock()
	if background && (p.background >= p.maxBackground ||
		(conversation != "" && p.depths[conversation] >= p.maxQueued)) {
		p.mu.Unlock()
		close(started.done)
		close(started.released)
		return started
	}
	var previous *verdict
	if conversation != "" {
		previous = p.tails[conversation]
		p.tails[conversation] = started
		p.depths[conversation]++
	}
	if background {
		p.background++
	}
	p.outstanding++
	p.mu.Unlock()

	go p.run(ctx, conversation, background, previous, started, call)
	return started
}

func (p *pendingVerdicts) run(
	ctx context.Context,
	conversation string,
	background bool,
	previous *verdict,
	started *verdict,
	call func(context.Context) (BlockResult, error),
) {
	defer func() {
		p.finish(conversation, background, started)
		close(started.released)
	}()
	if previous != nil {
		select {
		case <-previous.released:
		case <-ctx.Done():
			started.err = context.Cause(ctx)
			close(started.done)
			<-previous.released
			return
		}
	}
	select {
	case p.slots <- struct{}{}:
	case <-ctx.Done():
		started.err = context.Cause(ctx)
		close(started.done)
		return
	}
	started.result, started.err = call(ctx)
	<-p.slots
	close(started.done)
}

func (p *pendingVerdicts) finish(conversation string, background bool, finished *verdict) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if background {
		p.background--
	}
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
