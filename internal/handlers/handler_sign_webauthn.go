package handlers

import (
	"bytes"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/regulation"
	"github.com/authelia/authelia/v4/internal/session"
)

// WebAuthnAssertionGET handler starts the assertion ceremony.
func WebAuthnAssertionGET(ctx *middlewares.AutheliaCtx) {
	var (
		w           *webauthn.WebAuthn
		user        *model.WebAuthnUser
		userSession session.UserSession
		err         error
	)

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred generating a WebAuthn authentication challenge: error occurred retrieving the user session data")

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if userSession.IsAnonymous() {
		ctx.Logger.WithError(fmt.Errorf("user is anonymous")).Error("Error occurred generating a WebAuthn authentication challenge")

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if w, err = handleNewWebAuthn(ctx); err != nil {
		ctx.Logger.WithError(err).Errorf("Error occurred generating a WebAuthn authentication challenge for user '%s': error occurred provisioning the configuration", userSession.Username)

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if user, err = handleGetWebAuthnUserByRPID(ctx, userSession.Username, userSession.DisplayName, w.Config.RPID); err != nil {
		ctx.Logger.WithError(err).Errorf("Error occurred generating a WebAuthn authentication challenge for user '%s': error occurred retrieving the WebAuthn user configuration from storage", userSession.Username)

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	extensions := map[string]any{}

	if user.HasFIDOU2F() {
		extensions["appid"] = w.Config.RPOrigins[0]
	}

	var opts = []webauthn.LoginOption{
		webauthn.WithAllowedCredentials(user.WebAuthnCredentialDescriptors()),
	}

	if len(extensions) != 0 {
		opts = append(opts, webauthn.WithAssertionExtensions(extensions))
	}

	var (
		assertion *protocol.CredentialAssertion
		data      session.WebAuthn
	)

	if assertion, data.SessionData, err = w.BeginLogin(user, opts...); err != nil {
		ctx.Logger.WithError(err).Errorf("Error occurred generating a WebAuthn authentication challenge for user '%s': error occurred starting the authentication session", userSession.Username)

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	userSession.WebAuthn = &data

	if err = ctx.SaveSession(userSession); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred generating a WebAuthn authentication challenge: error occurred saving the user session data")

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if err = ctx.SetJSONBody(assertion); err != nil {
		ctx.Logger.WithError(err).Errorf("Error occurred generating a WebAuthn authentication challenge for user '%s': error occurred writing the response body", userSession.Username)

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageUnableToRegisterSecurityKey)

		return
	}
}

// WebAuthnAssertionPOST handler completes the assertion ceremony after verifying the challenge.
//
//nolint:gocyclo
func WebAuthnAssertionPOST(ctx *middlewares.AutheliaCtx) {
	var (
		userSession session.UserSession

		err error

		w    *webauthn.WebAuthn
		c    *webauthn.Credential
		user *model.WebAuthnUser

		bodyJSON bodySignWebAuthnRequest

		assertionResponse *protocol.ParsedCredentialAssertionData
	)

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred validating a WebAuthn authentication challenge: error occurred retrieving the user session data")

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if userSession.IsAnonymous() {
		ctx.Logger.WithError(fmt.Errorf("user is anonymous")).Error("Error occurred validating a WebAuthn authentication challenge")

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if userSession.WebAuthn == nil || userSession.WebAuthn.SessionData == nil {
		ctx.Logger.WithError(fmt.Errorf("challenge session data is not present")).Errorf("Error occurred validating a WebAuthn authentication challenge for user '%s': error occurred retrieving the user session data", userSession.Username)

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if err = ctx.ParseBody(&bodyJSON); err != nil {
		ctx.Logger.WithError(err).Errorf("Error occurred validating a WebAuthn authentication challenge for user '%s': error parsing the request body", userSession.Username)

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if assertionResponse, err = protocol.ParseCredentialRequestResponseBody(bytes.NewReader(bodyJSON.Response)); err != nil {
		ctx.Logger.WithError(err).Errorf("Error occurred validating a WebAuthn authentication challenge for user '%s': error parsing the request body", userSession.Username)

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if w, err = handleNewWebAuthn(ctx); err != nil {
		ctx.Logger.WithError(err).Errorf("Error occurred validating a WebAuthn authentication challenge for user '%s': error occurred provisioning the configuration", userSession.Username)

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if user, err = handleGetWebAuthnUserByRPID(ctx, userSession.Username, userSession.DisplayName, w.Config.RPID); err != nil {
		ctx.Logger.WithError(err).Errorf("Error occurred validating a WebAuthn authentication challenge for user '%s': error occurred retrieving the WebAuthn user configuration from storage", userSession.Username)

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if c, err = w.ValidateLogin(user, *userSession.WebAuthn.SessionData, assertionResponse); err != nil {
		_ = markAuthenticationAttempt(ctx, false, nil, userSession.Username, regulation.AuthTypeWebAuthn, err)

		ctx.SetStatusCode(fasthttp.StatusForbidden)

		return
	}

	defer func() {
		userSession.WebAuthn = nil

		if err = ctx.SaveSession(userSession); err != nil {
			ctx.Logger.WithError(err).Error("Error occurred validating a WebAuthn authentication challenge: error occurred saving the user session data")
		}
	}()

	var found bool

	for _, credential := range user.Credentials {
		if bytes.Equal(credential.KID.Bytes(), c.ID) {
			credential.UpdateSignInInfo(w.Config, ctx.Clock.Now().UTC(), c.Authenticator)

			found = true

			if err = ctx.Providers.StorageProvider.UpdateWebAuthnCredentialSignIn(ctx, credential); err != nil {
				ctx.Logger.WithError(err).Errorf("Error occurred validating a WebAuthn authentication challenge for user '%s': error occurred saving the credential sign-in information to storage", userSession.Username)

				ctx.SetStatusCode(fasthttp.StatusForbidden)
				ctx.SetJSONError(messageMFAValidationFailed)

				return
			}

			break
		}
	}

	if !found {
		ctx.Logger.WithError(fmt.Errorf("credential was not found")).Errorf("Error occurred validating a WebAuthn authentication challenge for user '%s': error occurred saving the credential sign-in information to storage", userSession.Username)

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if c.Authenticator.CloneWarning {
		ctx.Logger.WithError(fmt.Errorf("authenticator sign count indicates that it is cloned")).Error("Error occurred validating a WebAuthn authentication challenge: error occurred validating the authenticator response")

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if err = ctx.RegenerateSession(); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred validating a WebAuthn authentication challenge: error occurred regenerating the user session cookie value")

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	if err = markAuthenticationAttempt(ctx, true, nil, userSession.Username, regulation.AuthTypeWebAuthn, nil); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred validating a WebAuthn authentication challenge: error occurred recording the authentication result")

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageMFAValidationFailed)

		return
	}

	userSession.SetTwoFactorWebAuthn(ctx.Clock.Now(),
		assertionResponse.Response.AuthenticatorData.Flags.HasUserPresent(),
		assertionResponse.Response.AuthenticatorData.Flags.HasUserVerified())

	if bodyJSON.Workflow == workflowOpenIDConnect {
		handleOIDCWorkflowResponse(ctx, bodyJSON.TargetURL, bodyJSON.WorkflowID)
	} else {
		Handle2FAResponse(ctx, bodyJSON.TargetURL)
	}
}
