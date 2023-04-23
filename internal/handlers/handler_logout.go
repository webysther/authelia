package handlers

import (
	"fmt"
	"net/url"

	"github.com/authelia/authelia/v4/internal/middlewares"
)

type logoutBody struct {
	TargetURL string `json:"targetURL"`
}

type logoutResponseBody struct {
	SafeTargetURL bool `json:"safeTargetURL"`
}

// LogoutPOST is the handler logging out the user attached to the given cookie.
func LogoutPOST(ctx *middlewares.AutheliaCtx) {
	var (
		body logoutBody
		err  error
	)

	responseBody := logoutResponseBody{SafeTargetURL: false}

	if err = ctx.ParseBody(&body); err != nil {
		ctx.Error(fmt.Errorf("unable to parse body during logout: %w", err), messageOperationFailed)

		return
	}

	if err = ctx.DestroySession(); err != nil {
		ctx.Error(fmt.Errorf("unable to destroy session during logout: %w", err), messageOperationFailed)

		return
	}

	redirectionURL, err := url.ParseRequestURI(body.TargetURL)
	if err == nil {
		responseBody.SafeTargetURL = ctx.IsSafeRedirectionTargetURI(redirectionURL)
	}

	if body.TargetURL != "" {
		ctx.Logger.Debugf("Logout target url is %s, safe %t", body.TargetURL, responseBody.SafeTargetURL)
	}

	if err = ctx.SetJSONBody(responseBody); err != nil {
		ctx.Error(fmt.Errorf("unable to set body during logout: %w", err), messageOperationFailed)
	}
}
