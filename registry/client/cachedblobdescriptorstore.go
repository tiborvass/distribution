package client

import (
	"context"

	"github.com/opencontainers/go-digest"
)

// Metrics is used to hold metric counters
// related to the number of times a cache was
// hit or missed.
type Metrics struct {
	Requests uint64
	Hits     uint64
	Misses   uint64
}

// Logger can be provided on the MetricsTracker to log errors.
//
// Usually, this is just a proxy to dcontext.GetLogger.
type Logger interface {
	Errorf(format string, args ...interface{})
}

// MetricsTracker represents a metric tracker
// which simply counts the number of hits and misses.
type MetricsTracker interface {
	Hit()
	Miss()
	Metrics() Metrics
	Logger(context.Context) Logger
}

type cachedBlobStatter struct {
	cache   BlobDescriptorService
	backend BlobDescriptorService
	tracker MetricsTracker
}

// NewCachedBlobStatter creates a new statter which prefers a cache and
// falls back to a backend.
func NewCachedBlobStatter(cache BlobDescriptorService, backend BlobDescriptorService) BlobDescriptorService {
	return &cachedBlobStatter{
		cache:   cache,
		backend: backend,
	}
}

// NewCachedBlobStatterWithMetrics creates a new statter which prefers a cache and
// falls back to a backend. Hits and misses will send to the tracker.
func NewCachedBlobStatterWithMetrics(cache BlobDescriptorService, backend BlobDescriptorService, tracker MetricsTracker) BlobStatter {
	return &cachedBlobStatter{
		cache:   cache,
		backend: backend,
		tracker: tracker,
	}
}

func (cbds *cachedBlobStatter) Stat(ctx context.Context, dgst digest.Digest) (Descriptor, error) {
	desc, err := cbds.cache.Stat(ctx, dgst)
	if err != nil {
		if err != ErrBlobUnknown {
			logErrorf(ctx, cbds.tracker, "error retrieving descriptor from cache: %v", err)
		}

		goto fallback
	}

	if cbds.tracker != nil {
		cbds.tracker.Hit()
	}
	return desc, nil
fallback:
	if cbds.tracker != nil {
		cbds.tracker.Miss()
	}
	desc, err = cbds.backend.Stat(ctx, dgst)
	if err != nil {
		return desc, err
	}

	if err := cbds.cache.SetDescriptor(ctx, dgst, desc); err != nil {
		logErrorf(ctx, cbds.tracker, "error adding descriptor %v to cache: %v", desc.Digest, err)
	}

	return desc, err

}

func (cbds *cachedBlobStatter) Clear(ctx context.Context, dgst digest.Digest) error {
	err := cbds.cache.Clear(ctx, dgst)
	if err != nil {
		return err
	}

	err = cbds.backend.Clear(ctx, dgst)
	if err != nil {
		return err
	}
	return nil
}

func (cbds *cachedBlobStatter) SetDescriptor(ctx context.Context, dgst digest.Digest, desc Descriptor) error {
	if err := cbds.cache.SetDescriptor(ctx, dgst, desc); err != nil {
		logErrorf(ctx, cbds.tracker, "error adding descriptor %v to cache: %v", desc.Digest, err)
	}
	return nil
}

func logErrorf(ctx context.Context, tracker MetricsTracker, format string, args ...interface{}) {
	logger := tracker.Logger(ctx)
	if logger == nil {
		return
	}
	logger.Errorf(format, args...)
}
