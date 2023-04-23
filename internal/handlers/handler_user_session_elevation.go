package handlers

import (
	"database/sql"
	"fmt"
	"net/mail"

	"github.com/authelia/authelia/v4/internal/random"
	"github.com/authelia/authelia/v4/internal/templates"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/session"
)

func UserSessionElevateGET(ctx *middlewares.AutheliaCtx) {
	var (
		userSession session.UserSession
		id          uuid.UUID
		key         []byte
		err         error
	)

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session")

		ctx.ReplyForbidden()

		return
	}

	logger := ctx.Logger.WithFields(map[string]any{"username": userSession.Username})

	if len(userSession.Emails) == 0 {
		logger.WithError(fmt.Errorf("user has no registered emails")).Error("Error sending One Time Password to user")

		ctx.ReplyForbidden()

		return
	}

	if id, err = uuid.NewRandom(); err != nil {
		logger.WithError(err).Error("Error occurred generating UUIDv4 public identifier for One Time Password")

		ctx.ReplyForbidden()

		return
	}

	if key, err = ctx.Providers.Random.BytesCustomErr(ctx.Configuration.IdentityValidation.SessionElevation.OTPCharacters, []byte(random.CharSetUnambiguousUpper)); err != nil {
		logger.WithError(err).Error("Error occurred generating One Time Password")

		ctx.ReplyForbidden()

		return
	}

	if _, err = ctx.Providers.StorageProvider.SaveOneTimePassword(ctx, model.NewOneTimePassword(id, userSession.Username, model.OTPIntentElevateUserSession, ctx.Clock.Now(), ctx.Configuration.IdentityValidation.SessionElevation.ElevationExpiration, ctx.RemoteIP(), key)); err != nil {
		logger.WithError(err).Error("Error occurred saving One Time Password to database")

		ctx.ReplyForbidden()

		return
	}

	data := templates.EmailOneTimePasswordValues{
		Title:           "Session Elevation",
		DisplayName:     userSession.DisplayName,
		RemoteIP:        ctx.RemoteIP().String(),
		Identifier:      id.String(),
		OneTimePassword: string(key),
	}

	recipient := mail.Address{Name: userSession.DisplayName, Address: userSession.Emails[0]}

	if err = ctx.Providers.Notifier.Send(ctx, recipient, "Session Elevation", ctx.Providers.Templates.GetOneTimePasswordEmailTemplate(), data); err != nil {
		logger.WithError(err).Error("Error occurred sending One Time Password to email server")

		ctx.ReplyForbidden()

		return
	}

	ctx.ReplyOK()
}

func UserSessionElevatePOST(ctx *middlewares.AutheliaCtx) {
	var (
		body        bodyUserSessionElevateRequest
		provider    *session.Session
		userSession session.UserSession
		otp         *model.OneTimePassword
		err         error
	)

	if err = ctx.ParseBody(&body); err != nil {
		ctx.Error(fmt.Errorf("unable to parse body for one time password: %w", err), messageOperationFailed)

		return
	}

	if provider, err = ctx.GetSessionProvider(); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving session provider")

		ctx.ReplyForbidden()

		return
	}

	if userSession, err = provider.GetSession(ctx.RequestCtx); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session")

		ctx.ReplyForbidden()

		return
	}

	logger := ctx.Logger.WithFields(map[string]any{"username": userSession.Username})

	if otp, err = ctx.Providers.StorageProvider.LoadOneTimePassword(ctx, userSession.Username, model.OTPIntentElevateUserSession, body.OneTimePassword); err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			logger.Error("No One Time Password with the provided value matched the expected signature")
		default:
			logger.WithError(err).Error("Error occurred looking up One Time password from the database")
		}

		ctx.ReplyForbidden()

		return
	}

	if otp.Consumed.Valid {
		logger.Error("The provided One Time Password was already consumed")

		ctx.ReplyForbidden()

		return
	}

	if otp.Revoked.Valid {
		logger.Error("The provided One Time Password was revoked")

		ctx.ReplyForbidden()

		return
	}

	if !otp.IssuedIP.IP.Equal(ctx.RemoteIP()) {
		logger.WithFields(map[string]any{"issued_ip": otp.IssuedIP.IP.String()}).Error("The provided One Time Password was not issued to a user from that IP address and it will be revoked")

		ctx.ReplyForbidden()

		if err = ctx.Providers.StorageProvider.RevokeOneTimePassword(ctx, otp.PublicID, model.NewIP(ctx.RemoteIP())); err != nil {
			logger.WithError(err).Error("Failed to revoke One Time Password")
		}

		return
	}

	otp.Consume(ctx.Clock.Now(), ctx.RemoteIP())

	if err = ctx.Providers.StorageProvider.ConsumeOneTimePassword(ctx, otp); err != nil {
		logger.WithError(err).Error("Failed to consume One Time Password")

		ctx.ReplyForbidden()

		return
	}

	userSession.Elevations.User = &session.Elevation{
		ID:       otp.ID,
		RemoteIP: ctx.RemoteIP(),
		Expires:  ctx.Clock.Now().Add(ctx.Configuration.IdentityValidation.SessionElevation.ElevationExpiration),
	}

	if err = provider.SaveSession(ctx.RequestCtx, userSession); err != nil {
		logger.WithError(err).Error("Failed to save session for elevation")

		ctx.ReplyForbidden()

		return
	}

	ctx.ReplyOK()
}
