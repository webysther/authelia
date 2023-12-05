package totp

import (
	"encoding/base32"
	"fmt"
	"time"

	"github.com/authelia/otp"
	"github.com/authelia/otp/totp"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/model"
)

// NewTimeBasedProvider creates a new totp.TimeBased which implements the totp.Provider.
func NewTimeBasedProvider(config schema.TOTP) (provider *TimeBased) {
	provider = &TimeBased{
		opts:      NewTOTPOptionsFromSchema(config),
		issuer:    config.Issuer,
		algorithm: config.DefaultAlgorithm,
		digits:    uint(config.DefaultDigits),
		period:    uint(config.DefaultPeriod),
		size:      uint(config.SecretSize),
	}

	if config.Skew != nil {
		provider.skew = uint(*config.Skew)
	} else {
		provider.skew = 1
	}

	return provider
}

func NewTOTPOptionsFromSchema(config schema.TOTP) *model.TOTPOptions {
	return &model.TOTPOptions{
		Algorithm:  config.DefaultAlgorithm,
		Algorithms: config.AllowedAlgorithms,
		Period:     config.DefaultPeriod,
		Periods:    config.AllowedPeriods,
		Length:     config.DefaultDigits,
		Lengths:    config.AllowedDigits,
	}
}

// TimeBased totp.Provider for production use.
type TimeBased struct {
	opts *model.TOTPOptions

	issuer    string
	algorithm string
	digits    uint
	period    uint
	skew      uint
	size      uint
}

// GenerateCustom generates a TOTP with custom options.
func (p TimeBased) GenerateCustom(username, algorithm, secret string, digits, period, secretSize uint) (config *model.TOTPConfiguration, err error) {
	var key *otp.Key

	var secretData []byte

	if secret != "" {
		if secretData, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
			return nil, fmt.Errorf("totp generate failed: error decoding base32 string: %w", err)
		}
	}

	if secretSize == 0 {
		secretSize = p.size
	}

	opts := totp.GenerateOpts{
		Issuer:      p.issuer,
		AccountName: username,
		Period:      period,
		Secret:      secretData,
		SecretSize:  secretSize,
		Digits:      otp.Digits(digits),
		Algorithm:   otpStringToAlgo(algorithm),
	}

	if key, err = totp.Generate(opts); err != nil {
		return nil, err
	}

	config = &model.TOTPConfiguration{
		CreatedAt: time.Now(),
		Username:  username,
		Issuer:    p.issuer,
		Algorithm: algorithm,
		Digits:    digits,
		Secret:    []byte(key.Secret()),
		Period:    period,
	}

	return config, nil
}

// Generate generates a TOTP with default options.
func (p TimeBased) Generate(username string) (config *model.TOTPConfiguration, err error) {
	return p.GenerateCustom(username, p.algorithm, "", p.digits, p.period, p.size)
}

// Validate the token against the given configuration.
func (p TimeBased) Validate(token string, config *model.TOTPConfiguration) (valid bool, step uint64, err error) {
	opts := totp.ValidateOpts{
		Period:    config.Period,
		Skew:      p.skew,
		Digits:    otp.Digits(config.Digits),
		Algorithm: otpStringToAlgo(config.Algorithm),
	}

	return totp.ValidateCustomStep(token, string(config.Secret), time.Now().UTC(), opts)
}

// Options returns the configured options for this provider.
func (p TimeBased) Options() model.TOTPOptions {
	return *p.opts
}

var (
	_ Provider = (*TimeBased)(nil)
)
