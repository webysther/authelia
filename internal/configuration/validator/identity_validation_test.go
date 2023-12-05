package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func TestShouldRaiseErrorWithUndefinedJWTSecretKey(t *testing.T) {
	validator := schema.NewStructValidator()
	config := newDefaultConfig()
	config.IdentityValidation.ResetPassword.JWTSecret = ""

	ValidateConfiguration(&config, validator)
	require.Len(t, validator.Errors(), 1)
	require.Len(t, validator.Warnings(), 1)

	assert.EqualError(t, validator.Errors()[0], "identity_validation: reset_password: option 'jwt_secret' is required when the reset password functionality isn't disabled")
	assert.EqualError(t, validator.Warnings()[0], "access_control: no rules have been specified so the 'default_policy' of 'two_factor' is going to be applied to all requests")
}
