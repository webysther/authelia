package handlers

import (
	"github.com/authelia/authelia/v4/internal/middlewares"
)

// NilANY does nothing.
func NilANY(_ *middlewares.AutheliaCtx) {}
