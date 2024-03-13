package my_lru

import (
	lru "github.com/hashicorp/golang-lru"
	"sync"
)

type Cache struct {
	mu    sync.Mutex
	cache *lru.Cache
}

func New(maxEntries int) (*Cache, error) {
	var cache Cache
	var err error
	cache.cache, err = lru.New(maxEntries)
	return &cache, err
}

// Add adds a value to the cache.
func (c *Cache) Add(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.Add(key, value)
}

// Get looks up a key's value from the cache.
func (c *Cache) Get(key string) (value interface{}, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.cache.Get(key)
}

// Remove removes the provided key from the cache.
func (c *Cache) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.Remove(key)
}

// RemoveOldest removes the oldest item from the cache.
func (c *Cache) RemoveOldest() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.RemoveOldest()
}

// Len returns the number of items in the cache.
func (c *Cache) Len() int {
	return c.cache.Len()
}

// Clear purges all stored items from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.Purge()
}
