package configuration

import (
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/configuration/validator"
	"github.com/authelia/authelia/v4/internal/utils"
)

func TestShouldErrorSecretNotExist(t *testing.T) {
	dir := t.TempDir()

	testSetEnv(t, "IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE", filepath.Join(dir, "jwt"))
	testSetEnv(t, "DUO_API_SECRET_KEY_FILE", filepath.Join(dir, "duo"))
	testSetEnv(t, "SESSION_SECRET_FILE", filepath.Join(dir, "session"))
	testSetEnv(t, "AUTHENTICATION_BACKEND_LDAP_PASSWORD_FILE", dir)
	testSetEnv(t, "NOTIFIER_SMTP_PASSWORD_FILE", filepath.Join(dir, "notifier"))
	testSetEnv(t, "SESSION_REDIS_PASSWORD_FILE", filepath.Join(dir, "redis"))
	testSetEnv(t, "SESSION_REDIS_HIGH_AVAILABILITY_SENTINEL_PASSWORD_FILE", filepath.Join(dir, "redis-sentinel"))
	testSetEnv(t, "STORAGE_MYSQL_PASSWORD_FILE", filepath.Join(dir, "mysql"))
	testSetEnv(t, "STORAGE_POSTGRES_PASSWORD_FILE", filepath.Join(dir, "postgres"))
	testSetEnv(t, "IDENTITY_PROVIDERS_OIDC_ISSUER_PRIVATE_KEY_FILE", filepath.Join(dir, "oidc-key"))
	testSetEnv(t, "IDENTITY_PROVIDERS_OIDC_HMAC_SECRET_FILE", filepath.Join(dir, "oidc-hmac"))

	val := schema.NewStructValidator()
	_, _, err := Load(val, NewEnvironmentSource(DefaultEnvPrefix, DefaultEnvDelimiter), NewSecretsSource(DefaultEnvPrefix, DefaultEnvDelimiter))

	assert.NoError(t, err)
	assert.Len(t, val.Warnings(), 0)

	errs := val.Errors()
	require.Len(t, errs, 11)

	sort.Sort(utils.ErrSliceSortAlphabetical(errs))

	errFmt := utils.GetExpectedErrTxt("filenotfound")
	errFmtDir := utils.GetExpectedErrTxt("isdir")

	// ignore the errors before this as they are checked by the validator.
	assert.EqualError(t, errs[0], fmt.Sprintf("secrets: error loading secret path %s into key 'authentication_backend.ldap.password': %s", dir, fmt.Sprintf(errFmtDir, dir)))
	assert.EqualError(t, errs[1], fmt.Sprintf("secrets: error loading secret path %s into key 'duo_api.secret_key': file does not exist error occurred: %s", filepath.Join(dir, "duo"), fmt.Sprintf(errFmt, filepath.Join(dir, "duo"))))
	assert.EqualError(t, errs[2], fmt.Sprintf("secrets: error loading secret path %s into key 'identity_validation.reset_password.jwt_secret': file does not exist error occurred: %s", filepath.Join(dir, "jwt"), fmt.Sprintf(errFmt, filepath.Join(dir, "jwt"))))
	assert.EqualError(t, errs[3], fmt.Sprintf("secrets: error loading secret path %s into key 'storage.mysql.password': file does not exist error occurred: %s", filepath.Join(dir, "mysql"), fmt.Sprintf(errFmt, filepath.Join(dir, "mysql"))))
	assert.EqualError(t, errs[4], fmt.Sprintf("secrets: error loading secret path %s into key 'notifier.smtp.password': file does not exist error occurred: %s", filepath.Join(dir, "notifier"), fmt.Sprintf(errFmt, filepath.Join(dir, "notifier"))))
	assert.EqualError(t, errs[5], fmt.Sprintf("secrets: error loading secret path %s into key 'identity_providers.oidc.hmac_secret': file does not exist error occurred: %s", filepath.Join(dir, "oidc-hmac"), fmt.Sprintf(errFmt, filepath.Join(dir, "oidc-hmac"))))
	assert.EqualError(t, errs[6], fmt.Sprintf("secrets: error loading secret path %s into key 'identity_providers.oidc.issuer_private_key': file does not exist error occurred: %s", filepath.Join(dir, "oidc-key"), fmt.Sprintf(errFmt, filepath.Join(dir, "oidc-key"))))
	assert.EqualError(t, errs[7], fmt.Sprintf("secrets: error loading secret path %s into key 'storage.postgres.password': file does not exist error occurred: %s", filepath.Join(dir, "postgres"), fmt.Sprintf(errFmt, filepath.Join(dir, "postgres"))))
	assert.EqualError(t, errs[8], fmt.Sprintf("secrets: error loading secret path %s into key 'session.redis.password': file does not exist error occurred: %s", filepath.Join(dir, "redis"), fmt.Sprintf(errFmt, filepath.Join(dir, "redis"))))
	assert.EqualError(t, errs[9], fmt.Sprintf("secrets: error loading secret path %s into key 'session.redis.high_availability.sentinel_password': file does not exist error occurred: %s", filepath.Join(dir, "redis-sentinel"), fmt.Sprintf(errFmt, filepath.Join(dir, "redis-sentinel"))))
	assert.EqualError(t, errs[10], fmt.Sprintf("secrets: error loading secret path %s into key 'session.secret': file does not exist error occurred: %s", filepath.Join(dir, "session"), fmt.Sprintf(errFmt, filepath.Join(dir, "session"))))
}

func TestLoadShouldReturnErrWithoutValidator(t *testing.T) {
	_, _, err := Load(nil, NewEnvironmentSource(DefaultEnvPrefix, DefaultEnvDelimiter))
	assert.EqualError(t, err, "no validator provided")
}

func TestLoadShouldReturnErrWithoutSources(t *testing.T) {
	_, _, err := Load(schema.NewStructValidator())
	assert.EqualError(t, err, "no sources provided")
}

func TestShouldHaveNotifier(t *testing.T) {
	testSetEnv(t, "SESSION_SECRET", "abc")
	testSetEnv(t, "STORAGE_MYSQL_PASSWORD", "abc")
	testSetEnv(t, "IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET", "abc")
	testSetEnv(t, "AUTHENTICATION_BACKEND_LDAP_PASSWORD", "abc")

	val := schema.NewStructValidator()
	_, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)
	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)
	assert.NotNil(t, config.Notifier)
}

func TestShouldConfigureRefreshIntervalDisable(t *testing.T) {
	testSetEnv(t, "SESSION_SECRET", "abc")
	testSetEnv(t, "STORAGE_MYSQL_PASSWORD", "abc")
	testSetEnv(t, "JWT_SECRET", "abc")
	testSetEnv(t, "AUTHENTICATION_BACKEND_LDAP_PASSWORD", "abc")

	val := schema.NewStructValidator()
	_, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)
	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	require.NotNil(t, config.AuthenticationBackend.RefreshInterval)
	assert.True(t, config.AuthenticationBackend.RefreshInterval.Never())
	assert.False(t, config.AuthenticationBackend.RefreshInterval.Always())
}

func TestShouldParseLargeIntegerDurations(t *testing.T) {
	val := schema.NewStructValidator()
	_, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config.durations.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)
	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	assert.Equal(t, durationMax, config.Regulation.FindTime)
	assert.Equal(t, time.Second*1000, config.Regulation.BanTime)

	require.NotNil(t, config.AuthenticationBackend.RefreshInterval)
	assert.Equal(t, false, config.AuthenticationBackend.RefreshInterval.Always())
	assert.Equal(t, false, config.AuthenticationBackend.RefreshInterval.Never())
	assert.Equal(t, time.Minute*5, config.AuthenticationBackend.RefreshInterval.Value())
}

func TestShouldValidateConfigurationWithEnv(t *testing.T) {
	testSetEnv(t, "SESSION_SECRET", "abc")
	testSetEnv(t, "STORAGE_MYSQL_PASSWORD", "abc")
	testSetEnv(t, "IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET", "abc")
	testSetEnv(t, "AUTHENTICATION_BACKEND_LDAP_PASSWORD", "abc")

	val := schema.NewStructValidator()
	_, _, err := Load(val, NewDefaultSources([]string{"./test_resources/config.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)
	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)
}

func TestShouldValidateConfigurationWithFilters(t *testing.T) {
	testSetEnv(t, "SESSION_SECRET", "abc")
	testSetEnv(t, "STORAGE_MYSQL_PASSWORD", "abc")
	testSetEnv(t, "IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET", "abc")
	testSetEnv(t, "AUTHENTICATION_BACKEND_LDAP_PASSWORD", "abc")

	t.Setenv("ABC_CLIENT_SECRET", "$plaintext$example-abc")
	t.Setenv("XYZ_CLIENT_SECRET", "$plaintext$example-xyz")
	t.Setenv("SERVICES_SERVER", "10.10.10.10")
	t.Setenv("ROOT_DOMAIN", "example.org")

	val := schema.NewStructValidator()
	_, config, err := Load(val, NewDefaultSourcesFiltered([]string{"./test_resources/config.filtered.yml"}, NewFileFiltersDefault(), DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)
	require.Len(t, val.Errors(), 0)
	require.Len(t, val.Warnings(), 0)

	assert.Equal(t, "api-123456789.example.org", config.DuoAPI.Hostname)
	assert.Equal(t, "smtp://10.10.10.10:1025", config.Notifier.SMTP.Address.String())
	assert.Equal(t, "10.10.10.10", config.Session.Redis.Host)

	require.Len(t, config.IdentityProviders.OIDC.Clients, 4)
	assert.Equal(t, "$plaintext$example-abc", config.IdentityProviders.OIDC.Clients[0].Secret.String())
	assert.Equal(t, "$plaintext$example-xyz", config.IdentityProviders.OIDC.Clients[1].Secret.String())
	assert.Equal(t, "$plaintext$example_secret value", config.IdentityProviders.OIDC.Clients[2].Secret.String())
	assert.Equal(t, "$plaintext$abc", config.IdentityProviders.OIDC.Clients[3].Secret.String())

	require.Len(t, config.IdentityProviders.OIDC.IssuerPrivateKeys, 1)

	key, ok := config.IdentityProviders.OIDC.IssuerPrivateKeys[0].Key.(schema.CryptographicPrivateKey)
	assert.True(t, ok)
	require.NotNil(t, key)

	rsakey, ok := key.(*rsa.PrivateKey)
	assert.True(t, ok)
	require.NotNil(t, rsakey)

	assert.Equal(t, 65537, rsakey.E)
	assert.Equal(t, "27171434142509968675194232284375073019792572110439705540328918657232692168643195881620537202636198369160560799743144111431567452741046220953662805104932829188046044673961143220261310008810498023470535975681337666107808278037041152412426963982841905494490761888868583347468199094007084012384588888035364766072411615843478518353414183640511444802956354678240763665865557092671631235272029876735331399857244041249715616453815382050245467939750635216436773618819757152567487060661311335480594478902550197306956880336905504741940598285468339785455485086967213774716099196949673312743795439236046960995348506152278833238987", rsakey.N.String())
	assert.Equal(t, "5706925720915661669195242494994016816721008820974450261113990040996811079258641550734801632578349185215910392731806135371706455696484447433162465664729853270266472449716574399604756584391664331493231727196142834947800188400138417427667686333274620887920797982823077799989315356653608060034390741776504814150513570875362236882334931949786678793855564217596234691391113095918532726196507032878006343060796051755555405212832046478322407013172691936979796693050565243392092102513298609204623359016844719592078589959501078387650387089103850347191460557257744984924144972386173794776498508384237037750896668486369884278793", rsakey.D.String())
}

func TestShouldHandleNoAddressMySQLWithHostEnv(t *testing.T) {
	testSetEnv(t, "STORAGE_MYSQL_HOST", "mysql")

	val := schema.NewStructValidator()
	_, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config_no_address_mysql.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateConfiguration(config, val)

	assert.Len(t, val.Warnings(), 1)
	assert.Len(t, val.Errors(), 1)

	assert.Equal(t, "mysql", config.Storage.MySQL.Host) //nolint:staticcheck
	assert.Equal(t, "tcp://mysql:3306", config.Storage.MySQL.Address.String())
}

func TestShouldHandleNoAddressPostgreSQLWithHostEnv(t *testing.T) {
	testSetEnv(t, "STORAGE_POSTGRES_HOST", "postgres")

	val := schema.NewStructValidator()
	_, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config_no_address_postgres.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateConfiguration(config, val)

	assert.Len(t, val.Warnings(), 1)
	assert.Len(t, val.Errors(), 1)

	assert.Equal(t, "postgres", config.Storage.PostgreSQL.Host) //nolint:staticcheck
	assert.Equal(t, "tcp://postgres:5432", config.Storage.PostgreSQL.Address.String())
}

func TestShouldHandleNoAddressSMTPWithHostEnv(t *testing.T) {
	testSetEnv(t, "NOTIFIER_SMTP_HOST", "smtp")

	val := schema.NewStructValidator()
	_, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config_no_address_smtp.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateConfiguration(config, val)

	assert.Len(t, val.Warnings(), 1)
	assert.Len(t, val.Errors(), 1)

	assert.Equal(t, "smtp", config.Notifier.SMTP.Host) //nolint:staticcheck
	assert.Equal(t, "smtp://smtp:25", config.Notifier.SMTP.Address.String())
}

func TestShouldNotIgnoreInvalidEnvs(t *testing.T) {
	testSetEnv(t, "SESSION_SECRET", "an env session secret")
	testSetEnv(t, "STORAGE_MYSQL_PASSWORD", "an env storage mysql password")
	testSetEnv(t, "STORAGE_MYSQL", "a bad env")
	testSetEnv(t, "IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET", "an env jwt secret")
	testSetEnv(t, "AUTHENTICATION_BACKEND_LDAP_PASSWORD", "an env authentication backend ldap password")
	testSetEnv(t, "AUTHENTICATION_BACKEND_LDAP_ADDRESS", "an env authentication backend ldap password")

	val := schema.NewStructValidator()
	keys, _, err := Load(val, NewDefaultSources([]string{"./test_resources/config.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	require.Len(t, val.Warnings(), 1)
	assert.Len(t, val.Errors(), 1)

	assert.EqualError(t, val.Warnings()[0], fmt.Sprintf("configuration environment variable not expected: %sSTORAGE_MYSQL", DefaultEnvPrefix))
	assert.EqualError(t, val.Errors()[0], "error occurred during unmarshalling configuration: 1 error(s) decoding:\n\n* error decoding 'authentication_backend.ldap.address': could not decode 'an env authentication backend ldap password' to a *schema.AddressLDAP: could not parse string 'an env authentication backend ldap password' as address: expected format is [<scheme>://]<hostname>[:<port>]: parse \"ldaps://an env authentication backend ldap password\": invalid character \" \" in host name")
}

func TestShouldValidateServerAddressValues(t *testing.T) {
	testCases := []struct {
		name string
		data []byte

		envHost, envPort, envAddress string

		envMetricsAddress      string
		expectedHTTP           string
		expectedNetAddrHTTP    string
		expectedMetrics        string
		expectedNetAddrMetrics string
		errs                   []string
	}{
		{
			"ShouldSetDefaultValues",
			nil,
			"",
			"",
			"",
			"",
			"tcp://:9091/",
			":9091",
			"tcp://:9959/metrics",
			":9959",
			nil,
		},
		{
			"ShouldMapEnvValuesWithConfigTemplate",
			func() []byte {
				data, err := os.ReadFile("config.template.yml")
				if err != nil {
					panic(err)
				}

				return data
			}(),
			"127.0.0.1",
			"8080",
			"",
			"",
			"tcp://127.0.0.1:8080/",
			"127.0.0.1:8080",
			"tcp://:9959/metrics",
			":9959",
			nil,
		},
		{
			"ShouldOverrideDefault",
			func() []byte {
				data, err := os.ReadFile("config.template.yml")
				if err != nil {
					panic(err)
				}

				return data
			}(),
			"",
			"",
			"tcp://127.0.0.2:7071",
			"tcp://127.0.0.3:8080",
			"tcp://127.0.0.2:7071/",
			"127.0.0.2:7071",
			"tcp://127.0.0.3:8080/metrics",
			"127.0.0.3:8080",
			nil,
		},
		{
			"ShouldErrorOnDeprecatedEnvAndModernConfigFileListenerOptions",
			[]byte("server:\n  address: 'tcp://:1000'"),
			"127.0.0.1",
			"8080",
			"",
			"tcp://:",
			"tcp://:1000/",
			":1000",
			"tcp://:9959/metrics",
			":9959",
			[]string{
				"server: option 'host' and 'port' can't be configured at the same time as 'address'",
			},
		},
		{
			"ShouldErrorOnDeprecatedEnvAndModernEnvListenerOptions",
			nil,
			"127.0.0.1",
			"8080",
			"tcp://:10000",
			"tcp://:",
			"tcp://:10000/",
			":10000",
			"tcp://:9959/metrics",
			":9959",
			[]string{
				"server: option 'host' and 'port' can't be configured at the same time as 'address'",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testSetEnv(t, "TELEMETRY_METRICS_ENABLED", "true")

			if tc.envHost != "" {
				testSetEnv(t, "SERVER_HOST", tc.envHost)
			}

			if tc.envPort != "" {
				testSetEnv(t, "SERVER_PORT", tc.envPort)
			}

			if tc.envAddress != "" {
				testSetEnv(t, "SERVER_ADDRESS", tc.envAddress)
			}

			if tc.envMetricsAddress != "" {
				testSetEnv(t, "TELEMETRY_METRICS_ADDRESS", tc.envMetricsAddress)
			}

			sources := []Source{
				NewBytesSource(tc.data),
				NewEnvironmentSource(DefaultEnvPrefix, DefaultEnvDelimiter),
				NewSecretsSource(DefaultEnvPrefix, DefaultEnvDelimiter),
			}

			val := schema.NewStructValidator()
			keys, config, err := Load(val, sources...)

			assert.NoError(t, err)

			validator.ValidateKeys(keys, DefaultEnvPrefix, val)

			assert.Len(t, val.Errors(), 0)

			assert.NotEmpty(t, config)

			val.Clear()

			validator.ValidateServer(config, val)
			validator.ValidateTelemetry(config, val)

			assert.Len(t, val.Warnings(), 0)

			errs := val.Errors()

			if n := len(tc.errs); n == 0 {
				assert.Len(t, errs, 0)
			} else {
				require.Len(t, errs, n)

				for i := 0; i < n; i++ {
					assert.EqualError(t, errs[i], tc.errs[i])
				}
			}

			assert.Equal(t, tc.expectedHTTP, config.Server.Address.String())
			assert.Equal(t, "tcp", config.Server.Address.Network())
			assert.Equal(t, tc.expectedNetAddrHTTP, config.Server.Address.NetworkAddress())

			assert.Equal(t, tc.expectedMetrics, config.Telemetry.Metrics.Address.String())
			assert.Equal(t, "tcp", config.Telemetry.Metrics.Address.Network())
			assert.Equal(t, tc.expectedNetAddrMetrics, config.Telemetry.Metrics.Address.NetworkAddress())
		})
	}
}

func TestShouldValidateAndRaiseErrorsOnNormalConfigurationAndSecret(t *testing.T) {
	testSetEnv(t, "SESSION_SECRET", "an env session secret")
	testSetEnv(t, "SESSION_SECRET_FILE", "./test_resources/example_secret")
	testSetEnv(t, "STORAGE_MYSQL_PASSWORD", "an env storage mysql password")
	testSetEnv(t, "IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE", "./test_resources/example_secret")
	testSetEnv(t, "AUTHENTICATION_BACKEND_LDAP_PASSWORD", "an env authentication backend ldap password")
	testSetEnv(t, "STORAGE_ENCRYPTION_KEY", "a_very_bad_encryption_key")

	val := schema.NewStructValidator()
	_, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)
	require.Len(t, val.Errors(), 1)
	assert.Len(t, val.Warnings(), 0)

	assert.EqualError(t, val.Errors()[0], "secrets: error loading secret into key 'session.secret': it's already defined in other configuration sources")

	assert.Equal(t, "example_secret value", config.IdentityValidation.ResetPassword.JWTSecret)
	assert.Equal(t, "example_secret value", config.Session.Secret)
	assert.Equal(t, "an env storage mysql password", config.Storage.MySQL.Password)
	assert.Equal(t, "an env authentication backend ldap password", config.AuthenticationBackend.LDAP.Password)
	assert.Equal(t, "a_very_bad_encryption_key", config.Storage.EncryptionKey)
}

func TestShouldRaiseIOErrOnUnreadableFile(t *testing.T) {
	if runtime.GOOS == constWindows {
		t.Skip("skipping test due to being on windows")
	}

	dir := t.TempDir()

	assert.NoError(t, os.WriteFile(filepath.Join(dir, "myconf.yml"), []byte("server:\n  port: 9091\n"), 0000))

	cfg := filepath.Join(dir, "myconf.yml")

	val := schema.NewStructValidator()
	_, _, err := Load(val, NewFileSource(cfg))

	assert.NoError(t, err)
	require.Len(t, val.Errors(), 1)
	assert.Len(t, val.Warnings(), 0)
	assert.EqualError(t, val.Errors()[0], fmt.Sprintf("failed to load configuration from file path(%s) source: open %s: permission denied", cfg, cfg))
}

func TestShouldValidateConfigurationWithEnvSecrets(t *testing.T) {
	testSetEnv(t, "SESSION_SECRET_FILE", "./test_resources/example_secret")
	testSetEnv(t, "STORAGE_MYSQL_PASSWORD_FILE", "./test_resources/example_secret")
	testSetEnv(t, "IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE", "./test_resources/example_secret")
	testSetEnv(t, "AUTHENTICATION_BACKEND_LDAP_PASSWORD_FILE", "./test_resources/example_secret")
	testSetEnv(t, "STORAGE_ENCRYPTION_KEY_FILE", "./test_resources/example_secret")

	val := schema.NewStructValidator()
	_, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)
	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	assert.Equal(t, "example_secret value", config.IdentityValidation.ResetPassword.JWTSecret)
	assert.Equal(t, "example_secret value", config.Session.Secret)
	assert.Equal(t, "example_secret value", config.AuthenticationBackend.LDAP.Password)
	assert.Equal(t, "example_secret value", config.Storage.MySQL.Password)
	assert.Equal(t, "example_secret value", config.Storage.EncryptionKey)
}

func TestShouldLoadURLList(t *testing.T) {
	val := schema.NewStructValidator()
	keys, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config_oidc.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	require.Len(t, config.IdentityProviders.OIDC.CORS.AllowedOrigins, 2)
	assert.Equal(t, "https://google.com", config.IdentityProviders.OIDC.CORS.AllowedOrigins[0].String())
	assert.Equal(t, "https://example.com", config.IdentityProviders.OIDC.CORS.AllowedOrigins[1].String())
}

func TestShouldDisableOIDCEntropy(t *testing.T) {
	val := schema.NewStructValidator()
	keys, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config_oidc_disable_entropy.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	assert.Equal(t, -1, config.IdentityProviders.OIDC.MinimumParameterEntropy)

	validator.ValidateIdentityProviders(&config.IdentityProviders, val)

	assert.Len(t, val.Errors(), 1)
	require.Len(t, val.Warnings(), 2)

	assert.EqualError(t, val.Warnings()[0], "identity_providers: oidc: option 'minimum_parameter_entropy' is disabled which is considered unsafe and insecure")
	assert.Equal(t, -1, config.IdentityProviders.OIDC.MinimumParameterEntropy)
}

func TestShouldConfigureConsent(t *testing.T) {
	val := schema.NewStructValidator()
	keys, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config_oidc.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	require.Len(t, config.IdentityProviders.OIDC.Clients, 1)
	assert.Equal(t, config.IdentityProviders.OIDC.Clients[0].ConsentMode, "explicit")
	assert.Equal(t, "none", config.IdentityProviders.OIDC.Clients[0].UserinfoSignedResponseAlg)
}

func TestShouldValidateAndRaiseErrorsOnBadConfiguration(t *testing.T) {
	testSetEnv(t, "SESSION_SECRET", "abc")
	testSetEnv(t, "STORAGE_MYSQL_PASSWORD", "abc")
	testSetEnv(t, "IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET", "abc")
	testSetEnv(t, "AUTHENTICATION_BACKEND_LDAP_PASSWORD", "abc")

	val := schema.NewStructValidator()
	keys, c, err := Load(val, NewDefaultSources([]string{"./test_resources/config_bad_keys.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	require.Len(t, val.Errors(), 1)
	require.Len(t, val.Warnings(), 1)

	assert.EqualError(t, val.Errors()[0], "configuration key not expected: loggy_file")
	assert.EqualError(t, val.Warnings()[0], "configuration key 'logs_level' is deprecated in 4.7.0 and has been replaced by 'log.level': this has been automatically mapped for you but you will need to adjust your configuration to remove this message")

	assert.Equal(t, "debug", c.Log.Level)
}

func TestShouldValidateDeprecatedEnvNames(t *testing.T) {
	testSetEnv(t, "AUTHENTICATION_BACKEND_LDAP_URL", "ldap://from-env")

	val := schema.NewStructValidator()
	keys, c, err := Load(val, NewDefaultSources([]string{"./test_resources/config.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	assert.Len(t, val.Errors(), 0)
	require.Len(t, val.Warnings(), 1)

	assert.EqualError(t, val.Warnings()[0], "configuration key 'authentication_backend.ldap.url' is deprecated in 4.38.0 and has been replaced by 'authentication_backend.ldap.address': this has not been automatically mapped for you because the replacement key also exists and you will need to adjust your configuration to remove this message")

	assert.Equal(t, "ldap://127.0.0.1:389", c.AuthenticationBackend.LDAP.Address.String())
}

func TestShouldValidateDeprecatedEnvNamesWithDeprecatedKeys(t *testing.T) {
	testSetEnv(t, "AUTHENTICATION_BACKEND_LDAP_URL", "ldap://from-env")
	testSetEnv(t, "JWT_SECRET_FILE", "./test_resources/example_secret")

	val := schema.NewStructValidator()
	keys, c, err := Load(val, NewDefaultSources([]string{"./test_resources/config.deprecated.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	assert.Len(t, val.Errors(), 0)

	warnings := val.Warnings()
	require.Len(t, warnings, 11)

	sort.Sort(utils.ErrSliceSortAlphabetical(warnings))

	assert.EqualError(t, warnings[0], "configuration key 'authentication_backend.ldap.url' is deprecated in 4.38.0 and has been replaced by 'authentication_backend.ldap.address': this has been automatically mapped for you but you will need to adjust your configuration to remove this message")
	assert.EqualError(t, warnings[1], "configuration key 'jwt_secret' is deprecated in 4.38.0 and has been replaced by 'identity_validation.reset_password.jwt_secret': this has been automatically mapped for you but you will need to adjust your configuration to remove this message")
	assert.EqualError(t, warnings[2], "configuration key 'notifier.smtp.host' is deprecated in 4.38.0 and has been replaced by 'notifier.smtp.address' when combined with the 'notifier.smtp.port' in the format of '[tcp://]<hostname>[:<port>]': this should be automatically mapped for you but you will need to adjust your configuration to remove this message")
	assert.EqualError(t, warnings[3], "configuration key 'notifier.smtp.port' is deprecated in 4.38.0 and has been replaced by 'notifier.smtp.address' when combined with the 'notifier.smtp.host' in the format of '[tcp://]<hostname>[:<port>]': this should be automatically mapped for you but you will need to adjust your configuration to remove this message")
	assert.EqualError(t, warnings[4], "configuration key 'server.host' is deprecated in 4.38.0 and has been replaced by 'server.address' when combined with the 'server.port' and 'server.path' in the format of '[tcp[(4|6)]://]<hostname>[:<port>][/<path>]' or 'tcp[(4|6)://][hostname]:<port>[/<path>]': this should be automatically mapped for you but you will need to adjust your configuration to remove this message")
	assert.EqualError(t, warnings[5], "configuration key 'server.path' is deprecated in 4.38.0 and has been replaced by 'server.address' when combined with the 'server.host' and 'server.port' in the format of '[tcp[(4|6)]://]<hostname>[:<port>][/<path>]' or 'tcp[(4|6)://][hostname]:<port>[/<path>]': this should be automatically mapped for you but you will need to adjust your configuration to remove this message")
	assert.EqualError(t, warnings[6], "configuration key 'server.port' is deprecated in 4.38.0 and has been replaced by 'server.address' when combined with the 'server.host' and 'server.path' in the format of '[tcp[(4|6)]://]<hostname>[:<port>][/<path>]' or 'tcp[(4|6)://][hostname]:<port>[/<path>]': this should be automatically mapped for you but you will need to adjust your configuration to remove this message")
	assert.EqualError(t, warnings[7], "configuration key 'storage.mysql.host' is deprecated in 4.38.0 and has been replaced by 'storage.mysql.address' when combined with the 'storage.mysql.port' in the format of '[tcp://]<hostname>[:<port>]': this should be automatically mapped for you but you will need to adjust your configuration to remove this message")
	assert.EqualError(t, warnings[8], "configuration key 'storage.mysql.port' is deprecated in 4.38.0 and has been replaced by 'storage.mysql.address' when combined with the 'storage.mysql.host' in the format of '[tcp://]<hostname>[:<port>]': this should be automatically mapped for you but you will need to adjust your configuration to remove this message")
	assert.EqualError(t, warnings[9], "configuration key 'storage.postgres.host' is deprecated in 4.38.0 and has been replaced by 'storage.postgres.address' when combined with the 'storage.postgres.port' in the format of '[tcp://]<hostname>[:<port>]': this should be automatically mapped for you but you will need to adjust your configuration to remove this message")
	assert.EqualError(t, warnings[10], "configuration key 'storage.postgres.port' is deprecated in 4.38.0 and has been replaced by 'storage.postgres.address' when combined with the 'storage.postgres.host' in the format of '[tcp://]<hostname>[:<port>]': this should be automatically mapped for you but you will need to adjust your configuration to remove this message")

	assert.Equal(t, "ldap://from-env:389", c.AuthenticationBackend.LDAP.Address.String())
	assert.Equal(t, "example_secret value", c.IdentityValidation.ResetPassword.JWTSecret)
}

func TestShouldRaiseErrOnInvalidNotifierSMTPSender(t *testing.T) {
	val := schema.NewStructValidator()
	keys, _, err := Load(val, NewDefaultSources([]string{"./test_resources/config_smtp_sender_invalid.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	require.Len(t, val.Errors(), 1)
	assert.Len(t, val.Warnings(), 0)

	assert.EqualError(t, val.Errors()[0], "error occurred during unmarshalling configuration: 1 error(s) decoding:\n\n* error decoding 'notifier.smtp.sender': could not decode 'admin' to a mail.Address (RFC5322): mail: missing '@' or angle-addr")
}

func TestShouldHandleErrInvalidatorWhenSMTPSenderBlank(t *testing.T) {
	val := schema.NewStructValidator()
	keys, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config_smtp_sender_blank.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	assert.Equal(t, "", config.Notifier.SMTP.Sender.Name)
	assert.Equal(t, "", config.Notifier.SMTP.Sender.Address)

	validator.ValidateNotifier(&config.Notifier, val)

	require.Len(t, val.Errors(), 1)
	assert.Len(t, val.Warnings(), 0)

	assert.EqualError(t, val.Errors()[0], "notifier: smtp: option 'sender' is required")
}

func TestShouldDecodeSMTPSenderWithoutName(t *testing.T) {
	val := schema.NewStructValidator()
	keys, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	assert.Equal(t, "", config.Notifier.SMTP.Sender.Name)
	assert.Equal(t, "admin@example.com", config.Notifier.SMTP.Sender.Address)
}

func TestShouldDecodeServerTLS(t *testing.T) {
	testSetEnv(t, "SERVER_TLS_KEY", "abc")
	testSetEnv(t, "SERVER_TLS_CERTIFICATE", "123")
	testSetEnv(t, "SERVER_TLS_CLIENT_CERTIFICATES", "abc,123")

	val := schema.NewStructValidator()
	keys, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	assert.Equal(t, "abc", config.Server.TLS.Key)
	assert.Equal(t, "123", config.Server.TLS.Certificate)
	assert.Equal(t, []string{"abc", "123"}, config.Server.TLS.ClientCertificates)
}

func TestShouldDecodeSMTPSenderWithName(t *testing.T) {
	val := schema.NewStructValidator()
	keys, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config_alt.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	assert.Equal(t, "Admin", config.Notifier.SMTP.Sender.Name)
	assert.Equal(t, "admin@example.com", config.Notifier.SMTP.Sender.Address)
	assert.Equal(t, schema.RememberMeDisabled, config.Session.RememberMe)
}

func TestShouldConfigureRefreshIntervalAlways(t *testing.T) {
	val := schema.NewStructValidator()
	keys, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config_alt.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	require.NotNil(t, config.AuthenticationBackend.RefreshInterval)
	assert.False(t, config.AuthenticationBackend.RefreshInterval.Never())
	assert.True(t, config.AuthenticationBackend.RefreshInterval.Always())
}

func TestShouldConfigureRefreshIntervalDefault(t *testing.T) {
	val := schema.NewStructValidator()
	keys, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config.no-refresh.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	validator.ValidateAuthenticationBackend(&config.AuthenticationBackend, val)

	require.NotNil(t, config.AuthenticationBackend.RefreshInterval)
	assert.False(t, config.AuthenticationBackend.RefreshInterval.Always())
	assert.False(t, config.AuthenticationBackend.RefreshInterval.Never())
	assert.Equal(t, time.Minute*5, config.AuthenticationBackend.RefreshInterval.Value())
}

func TestShouldParseRegex(t *testing.T) {
	val := schema.NewStructValidator()
	keys, config, err := Load(val, NewDefaultSources([]string{"./test_resources/config_domain_regex.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	validator.ValidateRules(config, val)

	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)

	assert.Len(t, config.AccessControl.Rules[0].DomainsRegex[0].SubexpNames(), 2)
	assert.Equal(t, "", config.AccessControl.Rules[0].DomainsRegex[0].SubexpNames()[0])
	assert.Equal(t, "", config.AccessControl.Rules[0].DomainsRegex[0].SubexpNames()[1])

	assert.Len(t, config.AccessControl.Rules[1].DomainsRegex[0].SubexpNames(), 2)
	assert.Equal(t, "", config.AccessControl.Rules[1].DomainsRegex[0].SubexpNames()[0])
	assert.Equal(t, "User", config.AccessControl.Rules[1].DomainsRegex[0].SubexpNames()[1])

	assert.Len(t, config.AccessControl.Rules[2].DomainsRegex[0].SubexpNames(), 3)
	assert.Equal(t, "", config.AccessControl.Rules[2].DomainsRegex[0].SubexpNames()[0])
	assert.Equal(t, "User", config.AccessControl.Rules[2].DomainsRegex[0].SubexpNames()[1])
	assert.Equal(t, "Group", config.AccessControl.Rules[2].DomainsRegex[0].SubexpNames()[2])
}

func TestShouldErrOnParseInvalidRegex(t *testing.T) {
	val := schema.NewStructValidator()
	keys, _, err := Load(val, NewDefaultSources([]string{"./test_resources/config_domain_bad_regex.yml"}, DefaultEnvPrefix, DefaultEnvDelimiter)...)

	assert.NoError(t, err)

	validator.ValidateKeys(keys, DefaultEnvPrefix, val)

	require.Len(t, val.Errors(), 1)
	assert.Len(t, val.Warnings(), 0)

	assert.EqualError(t, val.Errors()[0], "error occurred during unmarshalling configuration: 1 error(s) decoding:\n\n* error decoding 'access_control.rules[0].domain_regex[0]': could not decode '^\\K(public|public2).example.com$' to a regexp.Regexp: error parsing regexp: invalid escape sequence: `\\K`")
}

func TestShouldNotReadConfigurationOnFSAccessDenied(t *testing.T) {
	if runtime.GOOS == constWindows {
		t.Skip("skipping test due to being on windows")
	}

	dir := t.TempDir()

	cfg := filepath.Join(dir, "config.yml")
	assert.NoError(t, testCreateFile(filepath.Join(dir, "config.yml"), "port: 9091\n", 0000))

	val := schema.NewStructValidator()
	_, _, err := Load(val, NewFileSource(cfg))

	assert.NoError(t, err)
	require.Len(t, val.Errors(), 1)

	assert.EqualError(t, val.Errors()[0], fmt.Sprintf("failed to load configuration from file path(%s) source: open %s: permission denied", cfg, cfg))
}

func TestShouldLoadDirectoryConfiguration(t *testing.T) {
	dir := t.TempDir()

	cfg := filepath.Join(dir, "myconf.yml")
	assert.NoError(t, testCreateFile(cfg, "server:\n  port: 9091\n", 0700))

	val := schema.NewStructValidator()
	_, _, err := Load(val, NewFileSource(dir))

	assert.NoError(t, err)
	assert.Len(t, val.Errors(), 0)
	require.Len(t, val.Warnings(), 1)

	assert.EqualError(t, val.Warnings()[0], "configuration key 'server.port' is deprecated in 4.38.0 and has been replaced by 'server.address' when combined with the 'server.host' and 'server.path' in the format of '[tcp[(4|6)]://]<hostname>[:<port>][/<path>]' or 'tcp[(4|6)://][hostname]:<port>[/<path>]': this should be automatically mapped for you but you will need to adjust your configuration to remove this message")
}

func testSetEnv(t *testing.T, key, value string) {
	t.Setenv(DefaultEnvPrefix+key, value)
}

func testCreateFile(path, value string, perm os.FileMode) (err error) {
	return os.WriteFile(path, []byte(value), perm)
}

func TestShouldErrorOnNoPath(t *testing.T) {
	val := schema.NewStructValidator()
	_, _, err := Load(val, NewFileSource(""))

	assert.NoError(t, err)
	assert.Len(t, val.Errors(), 1)
	assert.ErrorContains(t, val.Errors()[0], "invalid file path source configuration")
}

func TestShouldErrorOnInvalidPath(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "invalid-folder/config")

	val := schema.NewStructValidator()
	_, _, err := Load(val, NewFileSource(cfg))

	assert.NoError(t, err)
	assert.Len(t, val.Errors(), 1)
	assert.ErrorContains(t, val.Errors()[0], fmt.Sprintf("stat %s: no such file or directory", cfg))
}

func TestShouldErrorOnDirFSPermissionDenied(t *testing.T) {
	if runtime.GOOS == constWindows {
		t.Skip("skipping test due to being on windows")
	}

	dir := t.TempDir()
	err := os.Chmod(dir, 0200)
	assert.NoError(t, err)

	val := schema.NewStructValidator()
	_, _, err = Load(val, NewFileSource(dir))

	assert.NoError(t, err)
	assert.Len(t, val.Errors(), 1)
	assert.ErrorContains(t, val.Errors()[0], fmt.Sprintf("open %s: permission denied", dir))
}

func TestShouldSkipDirOnLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "some-dir")

	err := os.Mkdir(path, 0700)
	assert.NoError(t, err)

	val := schema.NewStructValidator()
	_, _, err = Load(val, NewFileSource(dir))

	assert.NoError(t, err)
	assert.Len(t, val.Errors(), 0)
	assert.Len(t, val.Warnings(), 0)
}

func TestShouldFailIfYmlIsInvalid(t *testing.T) {
	dir := t.TempDir()

	cfg := filepath.Join(dir, "myconf.yml")
	assert.NoError(t, testCreateFile(cfg, "an invalid contend\n", 0700))

	val := schema.NewStructValidator()
	_, _, err := Load(val, NewFileSource(dir))

	assert.NoError(t, err)
	assert.Len(t, val.Errors(), 1)
	assert.ErrorContains(t, val.Errors()[0], "unmarshal errors")
}
