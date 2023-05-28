package middlewares

import (
	"bytes"
	"crypto/sha256"
	"net/url"
	"sync"

	"github.com/valyala/fasthttp"
)

func NewPathETag() *PathETag {
	return &PathETag{
		lock: &sync.Mutex{},
		tags: map[string][]byte{},
	}
}

type PathETag struct {
	lock *sync.Mutex
	tags map[string][]byte
}

func (m *PathETag) Middleware(next RequestHandler) RequestHandler {
	hash := sha256.New()

	return func(ctx *AutheliaCtx) {
		var (
			found bool
			furl  *url.URL
			err   error
		)

		if furl, err = ctx.GetXForwardedURL(); err == nil {
			m.lock.Lock()

			defer m.lock.Unlock()

			if etag, ok := m.tags[furl.String()]; ok {
				found = true

				ctx.Response.Header.SetBytesV(fasthttp.HeaderETag, etag)
				ctx.Response.Header.SetBytesK(headerCacheControl, "public, max-age=0, must-revalidate")

				if bytes.Equal(etag, ctx.Request.Header.Peek(fasthttp.HeaderIfNoneMatch)) {
					ctx.SetStatusCode(fasthttp.StatusNotModified)

					return
				}
			}
		}

		next(ctx)

		if !found && furl != nil {
			if _, err = hash.Write(ctx.Response.Body()); err != nil {
				return
			}

			m.tags[furl.String()] = hash.Sum(nil)

			hash.Reset()
		}
	}

}
