package client

import (
	"fmt"
)

// BlobDescriptorCacheProvider provides repository scoped
// BlobDescriptorService cache instances and a global descriptor cache.
type BlobDescriptorCacheProvider interface {
	BlobDescriptorService

	RepositoryScoped(repo string) (BlobDescriptorService, error)
}

// ValidateDescriptor provides a helper function to ensure that caches have
// common criteria for admitting descriptors.
func ValidateDescriptor(desc Descriptor) error {
	if err := desc.Digest.Validate(); err != nil {
		return err
	}

	if desc.Size < 0 {
		return fmt.Errorf("cache: invalid length in descriptor: %v < 0", desc.Size)
	}

	if desc.MediaType == "" {
		return fmt.Errorf("cache: empty mediatype on descriptor: %v", desc)
	}

	return nil
}
