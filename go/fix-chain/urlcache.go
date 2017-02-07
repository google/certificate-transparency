package fixchain

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type URLCache struct {
	cache map[string][]byte
	// counters may not be totally accurate due to non-atomicity
	hit       uint
	miss      uint
	errors    uint
	badStatus uint
	readFail  uint
}

func (u *URLCache) getURL(url string) ([]byte, error) {
	r, ok := u.cache[url]
	if ok {
		u.hit++
		return r, nil
	}
	c, err := http.Get(url)
	// FIXME: cache errors
	if err != nil {
		u.errors++
		return nil, err
	}
	defer c.Body.Close()
	if c.StatusCode != 200 {
		u.badStatus++
		return nil, errors.New(fmt.Sprintf("can't deal with status %d", c.StatusCode))
	}
	r, err = ioutil.ReadAll(c.Body)
	if err != nil {
		u.readFail++
		return nil, err
	}
	u.miss++
	u.cache[url] = r
	return r, nil
}

func NewURLCache() *URLCache {
	u := &URLCache{cache: make(map[string][]byte)}

	t := time.NewTicker(time.Second)
	go func() {
		for _ = range t.C {
			log.Printf("cache: %d hits, %d misses, %d errors, "+
				"%d bad status, %d read fail, %d cached", u.hit,
				u.miss, u.errors, u.badStatus, u.readFail,
				len(u.cache))
		}
	}()

	return u
}
