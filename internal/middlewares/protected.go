package middlewares

import (
	"fmt"
	"time"

	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/session"
)

type ProtectionBuilder struct {
	escalation *OTPEscalationProtectedEndpointConfig
	level      *RequiredLevelProtectedEndpointConfig
}

type Protection struct {
	level authentication.Level

	escalationSkip2FA bool
}

func (p *Protection) handler(ctx *AutheliaCtx, userSession *session.UserSession) (level, escalation bool) {
	return p.handleLevel(ctx, userSession), p.handleEscalation(ctx, userSession)
}

func (p *Protection) handleLevel(ctx *AutheliaCtx, userSession *session.UserSession) (level bool) {
	if p.level == authentication.NotAuthenticated {
		return true
	}

}

func (p *Protection) handleEscalation(ctx *AutheliaCtx, userSession *session.UserSession) (escalation bool) {
	if p.escalationSkip2FA && userSession.AuthenticationLevel >= authentication.TwoFactor {
		ctx.Logger.
			WithField("username", userSession.Username).
			Warning("User elevated session check has skipped due to 2FA")

		return true
	}

	if userSession.Elevations.User == nil {
		ctx.Logger.
			WithField("username", userSession.Username).
			Warning("User session elevation has not been created")

		return false
	}

	if userSession.Elevations.User.Expires.Before(ctx.Clock.Now()) {
		ctx.Logger.
			WithField("username", userSession.Username).
			WithField("expires", userSession.Elevations.User.Expires).
			Debug("User session elevation has expired")

		return false
	}

	if !ctx.RemoteIP().Equal(userSession.Elevations.User.RemoteIP) {
		ctx.Logger.
			WithField("username", userSession.Username).
			WithField("elevation_ip", userSession.Elevations.User.RemoteIP).
			Warning("User session elevation IP did not match the request")

		return false
	}

	return true
}

func (p *Protection) Handler(ctx *AutheliaCtx) {
	userSession, err := ctx.GetSession()

	if err != nil || userSession.IsAnonymous() {
		ctx.SetAuthenticationResponseJSON(fasthttp.StatusUnauthorized, fasthttp.StatusMessage(fasthttp.StatusUnauthorized), false, false)

		return
	}

	level, escalation := p.handler(ctx, &userSession)

}

func (p *Protection) Middleware(next RequestHandler) RequestHandler {
	return func(ctx *AutheliaCtx) {
		userSession, err := ctx.GetSession()

		if err != nil || userSession.IsAnonymous() {
			ctx.SetAuthenticationResponseJSON(fasthttp.StatusUnauthorized, fasthttp.StatusMessage(fasthttp.StatusUnauthorized), false, false)

			return
		}

		level, escalation := p.handler(ctx, &userSession)

		if level && escalation {
			next(ctx)

			return
		}

	}

}

type ProtectionEscalation struct {
}

// OTPEscalationProtectedEndpointConfig represents how the Escalation middleware behaves.
type OTPEscalationProtectedEndpointConfig struct {
	Characters                 int
	EmailValidityDuration      time.Duration
	EscalationValidityDuration time.Duration
	Skip2FA                    bool
}

type RequiredLevelProtectedEndpointConfig struct {
	Level authentication.Level
}

type ProtectedEndpointConfig struct {
	OTPEscalation *OTPEscalationProtectedEndpointConfig
	RequiredLevel *RequiredLevelProtectedEndpointConfig
}

func NewProtectedEndpoint(config *ProtectedEndpointConfig) AutheliaMiddleware {
	return ProtectedEndpoint(NewProtectedEndpointHandlers(config)...)
}

func NewProtectedEndpointHandlers(config *ProtectedEndpointConfig) (handlers []ProtectedEndpointHandler) {
	if config.RequiredLevel != nil {
		handlers = append(handlers, &RequiredLevelProtectedEndpointHandler{level: config.RequiredLevel.Level})
	}

	if config.OTPEscalation != nil {
		handlers = append(handlers, &OTPEscalationProtectedEndpointHandler{config: config.OTPEscalation})
	}

	return handlers
}

func ProtectedEndpoint(handlers ...ProtectedEndpointHandler) AutheliaMiddleware {
	n := len(handlers)

	return func(next RequestHandler) RequestHandler {
		return func(ctx *AutheliaCtx) {
			s, err := ctx.GetSession()

			if err != nil || s.IsAnonymous() {
				ctx.SetAuthenticationResponseJSON(fasthttp.StatusUnauthorized, fasthttp.StatusMessage(fasthttp.StatusUnauthorized), false, false)

				return
			}

			failed, failedAuthentication, failedElevation := doCheckProtectionHandlers(ctx, &s, n, handlers)

			if failed {
				ctx.SetAuthenticationResponseJSON(fasthttp.StatusForbidden, fasthttp.StatusMessage(fasthttp.StatusForbidden), failedAuthentication, failedElevation)

				return
			}

			next(ctx)
		}
	}
}

func ProtectedEndpointStatus(handlers ...ProtectedEndpointHandler) RequestHandler {
	n := len(handlers)

	return func(ctx *AutheliaCtx) {
		s, err := ctx.GetSession()

		if err != nil || s.IsAnonymous() {
			ctx.SetAuthenticationResponseJSON(fasthttp.StatusUnauthorized, fasthttp.StatusMessage(fasthttp.StatusUnauthorized), false, false)

			return
		}

		_, failedAuthentication, failedElevation := doCheckProtectionHandlers(ctx, &s, n, handlers)

		ctx.SetAuthenticationResponseJSON(fasthttp.StatusOK, "", failedAuthentication, failedElevation)
	}
}

func doCheckProtectionHandlers(ctx *AutheliaCtx, s *session.UserSession, n int, handlers []ProtectedEndpointHandler) (failed, authentication, elevation bool) {
	for i := 0; i < n; i++ {
		if handlers[i].Check(ctx, s) {
			continue
		}

		failed = true

		if handlers[i].IsAuthentication() {
			authentication = true
		}

		if handlers[i].IsElevation() {
			elevation = true
		}

		handlers[i].Failure(ctx, s)
	}

	return
}

type ProtectedEndpointHandler interface {
	Name() string
	Check(ctx *AutheliaCtx, s *session.UserSession) (success bool)
	Failure(ctx *AutheliaCtx, s *session.UserSession)

	IsAuthentication() bool
	IsElevation() bool
}

func NewRequiredLevelProtectedEndpointHandler(level authentication.Level, statusCode int) *RequiredLevelProtectedEndpointHandler {
	handler := &RequiredLevelProtectedEndpointHandler{
		level:      level,
		statusCode: statusCode,
	}

	if handler.statusCode == 0 {
		handler.statusCode = fasthttp.StatusForbidden
	}

	if handler.level == 0 {
		handler.level = authentication.OneFactor
	}

	return handler
}

type RequiredLevelProtectedEndpointHandler struct {
	level      authentication.Level
	statusCode int
}

func (h *RequiredLevelProtectedEndpointHandler) Name() string {
	return fmt.Sprintf("required_level(%s)", h.level)
}

func (h *RequiredLevelProtectedEndpointHandler) IsAuthentication() bool {
	return true
}

func (h *RequiredLevelProtectedEndpointHandler) IsElevation() bool {
	return false
}

func (h *RequiredLevelProtectedEndpointHandler) Check(ctx *AutheliaCtx, s *session.UserSession) (success bool) {
	return s.AuthenticationLevel >= h.level
}

func (h *RequiredLevelProtectedEndpointHandler) Failure(_ *AutheliaCtx, _ *session.UserSession) {
}

func NewOTPEscalationProtectedEndpointHandler(config OTPEscalationProtectedEndpointConfig) *OTPEscalationProtectedEndpointHandler {
	return &OTPEscalationProtectedEndpointHandler{
		config: &config,
	}
}

type OTPEscalationProtectedEndpointHandler struct {
	config *OTPEscalationProtectedEndpointConfig
}

func (h *OTPEscalationProtectedEndpointHandler) Name() string {
	return "one_time_password"
}

func (h *OTPEscalationProtectedEndpointHandler) IsAuthentication() bool {
	return false
}

func (h *OTPEscalationProtectedEndpointHandler) IsElevation() bool {
	return true
}

func (h *OTPEscalationProtectedEndpointHandler) Check(ctx *AutheliaCtx, s *session.UserSession) (success bool) {
	if h.config.Skip2FA && s.AuthenticationLevel >= authentication.TwoFactor {
		ctx.Logger.
			WithField("username", s.Username).
			Warning("User elevated session check has skipped due to 2FA")

		return true
	}

	if s.Elevations.User == nil {
		ctx.Logger.
			WithField("username", s.Username).
			Warning("User elevated session has not been created")

		return false
	}

	if s.Elevations.User.Expires.Before(ctx.Clock.Now()) {
		ctx.Logger.
			WithField("username", s.Username).
			WithField("expires", s.Elevations.User.Expires).
			Debug("User session elevation has expired")

		return false
	}

	if !ctx.RemoteIP().Equal(s.Elevations.User.RemoteIP) {
		ctx.Logger.
			WithField("username", s.Username).
			WithField("elevation_ip", s.Elevations.User.RemoteIP).
			Warning("User session elevation IP did not match the request")

		return false
	}

	return true
}

func (h *OTPEscalationProtectedEndpointHandler) Failure(ctx *AutheliaCtx, s *session.UserSession) {
	if s.Elevations.User != nil {
		// If we make it here we should destroy the elevation data.
		s.Elevations.User = nil

		if err := ctx.SaveSession(*s); err != nil {
			ctx.Logger.WithError(err).Error("Error session after user elevated session failure")
		}
	}
}

// Require1FA requires the user to have authenticated with at least one-factor authentication (i.e. password).
func Require1FA(next RequestHandler) RequestHandler {
	handler := ProtectedEndpoint(NewRequiredLevelProtectedEndpointHandler(authentication.OneFactor, fasthttp.StatusForbidden))

	return handler(next)
}

// Require2FA requires the user to have authenticated with two-factor authentication.
func Require2FA(next RequestHandler) RequestHandler {
	handler := ProtectedEndpoint(NewRequiredLevelProtectedEndpointHandler(authentication.TwoFactor, fasthttp.StatusForbidden))

	return handler(next)
}

// Require2FAWithAPIResponse requires the user to have authenticated with two-factor authentication.
func Require2FAWithAPIResponse(next RequestHandler) RequestHandler {
	return func(ctx *AutheliaCtx) {
		s, err := ctx.GetSession()

		if err != nil || s.AuthenticationLevel < authentication.TwoFactor {
			ctx.SetAuthenticationResponseJSON(fasthttp.StatusForbidden, "Authentication Required.", true, false)
			return
		}

		next(ctx)
	}
}
