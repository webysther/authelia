package model_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/oidc"
)

func TestNewOAuth2SessionFromRequest(t *testing.T) {
	challenge := model.NullUUID(uuid.Must(uuid.Parse("a9e4638d-e273-4636-a43e-3b34cc9a76ee")))
	session := &oidc.Session{
		ChallengeID: challenge,
		DefaultSession: &openid.DefaultSession{
			Subject: "sub",
		},
	}

	sessionBytes, _ := json.Marshal(session)

	testCaases := []struct {
		name      string
		signature string
		have      fosite.Requester
		expected  *model.OAuth2Session
		err       string
	}{
		{
			"ShouldNewUpStandard",
			"abc",
			&fosite.Request{
				ID: "example",
				Client: &fosite.DefaultClient{
					ID: "client_id",
				},
				Session:        session,
				RequestedScope: fosite.Arguments{oidc.ScopeOpenID},
				GrantedScope:   fosite.Arguments{oidc.ScopeOpenID},
			},
			&model.OAuth2Session{
				ChallengeID:     challenge,
				RequestID:       "example",
				ClientID:        "client_id",
				Signature:       "abc",
				Subject:         sql.NullString{String: "sub", Valid: true},
				RequestedScopes: model.StringSlicePipeDelimited{oidc.ScopeOpenID},
				GrantedScopes:   model.StringSlicePipeDelimited{oidc.ScopeOpenID},
				Active:          true,
				Session:         sessionBytes,
			},
			"",
		},
		{
			"ShouldNewUpWithoutScopes",
			"abc",
			&fosite.Request{
				ID: "example",
				Client: &fosite.DefaultClient{
					ID: "client_id",
				},
				Session:        session,
				RequestedScope: nil,
				GrantedScope:   nil,
			},
			&model.OAuth2Session{
				ChallengeID:     challenge,
				RequestID:       "example",
				ClientID:        "client_id",
				Signature:       "abc",
				Subject:         sql.NullString{String: "sub", Valid: true},
				RequestedScopes: model.StringSlicePipeDelimited{},
				GrantedScopes:   model.StringSlicePipeDelimited{},
				Active:          true,
				Session:         sessionBytes,
			},
			"",
		},
		{
			"ShouldRaiseErrorOnInvalidSessionType",
			"abc",
			&fosite.Request{
				ID: "example",
				Client: &fosite.DefaultClient{
					ID: "client_id",
				},
				Session:        &openid.DefaultSession{},
				RequestedScope: nil,
				GrantedScope:   nil,
			},
			nil,
			"failed to create new *model.OAuth2Session: the session type OpenIDSession was expected but the type '*openid.DefaultSession' was used",
		},
		{
			"ShouldRaiseErrorOnNilRequester",
			"abc",
			nil,
			nil,
			"failed to create new *model.OAuth2Session: the fosite.Requester was nil",
		},
	}

	for _, tc := range testCaases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := model.NewOAuth2SessionFromRequest(tc.signature, tc.have)

			if len(tc.err) > 0 {
				assert.Nil(t, actual)
				assert.EqualError(t, err, tc.err)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, actual)

				assert.Equal(t, tc.expected, actual)
			}
		})
	}
}

func TestOAuth2Session_SetSubject(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected sql.NullString
	}{
		{
			"ShouldParseValidNullString",
			"example",
			sql.NullString{String: "example", Valid: true},
		},
		{
			"ShouldParseEmptyNullString",
			"",
			sql.NullString{String: "", Valid: false},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			x := &model.OAuth2Session{}

			assert.Equal(t, x.Subject, sql.NullString{})

			x.SetSubject(tc.have)

			assert.Equal(t, tc.expected, x.Subject)
		})
	}
}

func TestOAuth2PARContext_ToAuthorizeRequest(t *testing.T) {
	const (
		parclientid = "par-client-id"
		requestid   = "rid123"
	)

	testCases := []struct {
		name     string
		setup    func(mock *mocks.MockFositeStorage)
		have     *model.OAuth2PARContext
		expected *fosite.AuthorizeRequest
		err      string
	}{
		{
			"ShouldErrorInvalidJSONData",
			nil,
			&model.OAuth2PARContext{},
			&fosite.AuthorizeRequest{},
			"error occurred while mapping PAR context back to an Authorize Request while trying to unmarshal the JSON session data: unexpected end of JSON input",
		},
		{
			"ShouldErrorInvalidClient",
			func(mock *mocks.MockFositeStorage) {
				mock.EXPECT().GetClient(context.TODO(), parclientid).Return(nil, fosite.ErrNotFound)
			},
			&model.OAuth2PARContext{
				ClientID: parclientid,
				Session:  []byte("{}"),
			},
			&fosite.AuthorizeRequest{},
			"error occurred while mapping PAR context back to an Authorize Request while trying to lookup the registered client: not_found",
		},
		{
			"ShouldErrorOnBadForm",
			func(mock *mocks.MockFositeStorage) {
				mock.EXPECT().GetClient(context.TODO(), parclientid).Return(&oidc.BaseClient{ID: parclientid}, nil)
			},
			&model.OAuth2PARContext{
				ID:        1,
				Signature: fmt.Sprintf("%sexample", oidc.RedirectURIPrefixPushedAuthorizationRequestURN),
				RequestID: requestid,
				ClientID:  parclientid,
				Session:   []byte("{}"),
				Form:      ";;;&;;;!@IO#JNM@($*!H@#(&*)!H#E*()!@&GE*)!@QGE*)@G#E*!@&G",
			},
			nil,
			"error occurred while mapping PAR context back to an Authorize Request while trying to parse the original form: invalid semicolon separator in query",
		},
		{
			"ShouldErrorOnBadFormRedirectURI",
			func(mock *mocks.MockFositeStorage) {
				mock.EXPECT().GetClient(context.TODO(), parclientid).Return(&oidc.BaseClient{ID: parclientid}, nil)
			},
			&model.OAuth2PARContext{
				ID:        1,
				Signature: fmt.Sprintf("%sexample", oidc.RedirectURIPrefixPushedAuthorizationRequestURN),
				RequestID: requestid,
				ClientID:  parclientid,
				Session:   []byte("{}"),
				Form:      fmt.Sprintf("redirect_uri=%s", string([]byte{0x00})),
			},
			nil,
			"error occurred while mapping PAR context back to an Authorize Request while trying to parse the original redirect uri: parse \"\\x00\": net/url: invalid control character in URL",
		},
		{
			"ShouldRestoreAuthorizeRequest",
			func(mock *mocks.MockFositeStorage) {
				mock.EXPECT().GetClient(context.TODO(), parclientid).Return(&oidc.BaseClient{ID: parclientid}, nil)
			},
			&model.OAuth2PARContext{
				ID:          1,
				Signature:   fmt.Sprintf("%sexample", oidc.RedirectURIPrefixPushedAuthorizationRequestURN),
				RequestID:   requestid,
				ClientID:    parclientid,
				Session:     []byte("{}"),
				RequestedAt: time.Unix(10000000, 0),
				Scopes:      model.StringSlicePipeDelimited{oidc.ScopeOpenID, oidc.ScopeOffline},
				Audience:    model.StringSlicePipeDelimited{parclientid},
				Form: url.Values{
					oidc.FormParameterRedirectURI:  []string{"https://example.com"},
					oidc.FormParameterState:        []string{"abc123"},
					oidc.FormParameterResponseType: []string{oidc.ResponseTypeAuthorizationCodeFlow},
				}.Encode(),
				ResponseMode:         oidc.ResponseModeQuery,
				DefaultResponseMode:  oidc.ResponseModeQuery,
				HandledResponseTypes: model.StringSlicePipeDelimited{oidc.ResponseTypeAuthorizationCodeFlow},
			},
			&fosite.AuthorizeRequest{
				RedirectURI:          MustParseRequestURI("https://example.com"),
				State:                "abc123",
				ResponseMode:         fosite.ResponseModeQuery,
				DefaultResponseMode:  fosite.ResponseModeQuery,
				ResponseTypes:        fosite.Arguments{oidc.ResponseTypeAuthorizationCodeFlow},
				HandledResponseTypes: fosite.Arguments{oidc.ResponseTypeAuthorizationCodeFlow},
				Request: fosite.Request{
					ID:                requestid,
					Client:            &oidc.BaseClient{ID: parclientid},
					RequestedScope:    fosite.Arguments{oidc.ScopeOpenID, oidc.ScopeOffline},
					RequestedAudience: fosite.Arguments{parclientid},
					RequestedAt:       time.Unix(10000000, 0),
					Session:           oidc.NewSession(),
					Form: url.Values{
						oidc.FormParameterRedirectURI:  []string{"https://example.com"},
						oidc.FormParameterState:        []string{"abc123"},
						oidc.FormParameterResponseType: []string{oidc.ResponseTypeAuthorizationCodeFlow},
					},
				},
			},
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			defer ctrl.Finish()

			mock := mocks.NewMockFositeStorage(ctrl)

			if tc.setup != nil {
				tc.setup(mock)
			}

			actual, err := tc.have.ToAuthorizeRequest(context.TODO(), oidc.NewSession(), mock)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, actual)
			} else {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, actual)
			}
		})
	}
}

func TestNewOAuth2PARContext(t *testing.T) {
	testCases := []struct {
		name     string
		have     fosite.AuthorizeRequester
		id       string
		expected *model.OAuth2PARContext
		err      string
	}{
		{
			"ShouldCreatePARContext",
			&fosite.AuthorizeRequest{
				HandledResponseTypes: fosite.Arguments{oidc.ResponseTypeHybridFlowIDToken},
				ResponseMode:         fosite.ResponseModeQuery,
				DefaultResponseMode:  fosite.ResponseModeFragment,
				Request: fosite.Request{
					ID:                "a-id",
					RequestedAt:       time.Time{},
					Client:            &oidc.BaseClient{ID: "a-client"},
					RequestedScope:    fosite.Arguments{oidc.ScopeOpenID},
					Form:              url.Values{oidc.FormParameterRedirectURI: []string{"https://example.com"}},
					Session:           &oidc.Session{},
					RequestedAudience: fosite.Arguments{"a-client"},
				},
			},
			"123",
			&model.OAuth2PARContext{
				Signature:            "123",
				RequestID:            "a-id",
				ClientID:             "a-client",
				RequestedAt:          time.Time{},
				Scopes:               model.StringSlicePipeDelimited{oidc.ScopeOpenID},
				Audience:             model.StringSlicePipeDelimited{"a-client"},
				HandledResponseTypes: model.StringSlicePipeDelimited{oidc.ResponseTypeHybridFlowIDToken},
				ResponseMode:         oidc.ResponseModeQuery,
				DefaultResponseMode:  oidc.ResponseModeFragment,
				Form:                 "redirect_uri=https%3A%2F%2Fexample.com",
				Session:              []byte(`{"id_token":null,"challenge_id":null,"kid":"","client_id":"","exclude_nbf_claim":false,"allowed_top_level_claims":null,"extra":null}`),
			},
			"",
		},
		{
			"ShouldFailCreateWrongSessionType",
			&fosite.AuthorizeRequest{
				HandledResponseTypes: fosite.Arguments{oidc.ResponseTypeHybridFlowIDToken},
				ResponseMode:         fosite.ResponseModeQuery,
				DefaultResponseMode:  fosite.ResponseModeFragment,
				Request: fosite.Request{
					ID:                "a-id",
					RequestedAt:       time.Time{},
					Client:            &oidc.BaseClient{ID: "a-client"},
					RequestedScope:    fosite.Arguments{oidc.ScopeOpenID},
					Form:              url.Values{oidc.FormParameterRedirectURI: []string{"https://example.com"}},
					Session:           &openid.DefaultSession{},
					RequestedAudience: fosite.Arguments{"a-client"},
				},
			},
			"123",
			nil,
			"failed to create new PAR context: can't assert type '*openid.DefaultSession' to an *OAuth2Session",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := model.NewOAuth2PARContext(tc.id, tc.have)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, actual)
			} else {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, actual)
			}
		})
	}
}

func TestOAuth2Session_ToRequest(t *testing.T) {
	const (
		parclientid = "par-client-id"
		requestid   = "rid123"
	)

	testCases := []struct {
		name     string
		setup    func(mock *mocks.MockFositeStorage)
		have     *model.OAuth2Session
		expected *fosite.Request
		err      string
	}{
		{
			"ShouldErrorInvalidJSONData",
			nil,
			&model.OAuth2Session{},
			&fosite.Request{},
			"error occurred while mapping OAuth 2.0 Session back to a Request while trying to unmarshal the JSON session data: unexpected end of JSON input",
		},
		{
			"ShouldErrorInvalidClient",
			func(mock *mocks.MockFositeStorage) {
				mock.EXPECT().GetClient(context.TODO(), parclientid).Return(nil, fosite.ErrNotFound)
			},
			&model.OAuth2Session{
				ClientID: parclientid,
				Session:  []byte("{}"),
			},
			&fosite.Request{},
			"error occurred while mapping OAuth 2.0 Session back to a Request while trying to lookup the registered client: not_found",
		},
		{
			"ShouldErrorOnBadForm",
			func(mock *mocks.MockFositeStorage) {
				mock.EXPECT().GetClient(context.TODO(), parclientid).Return(&oidc.BaseClient{ID: parclientid}, nil)
			},
			&model.OAuth2Session{
				ID:        1,
				Signature: fmt.Sprintf("%sexample", oidc.RedirectURIPrefixPushedAuthorizationRequestURN),
				RequestID: requestid,
				ClientID:  parclientid,
				Session:   []byte("{}"),
				Form:      ";;;&;;;!@IO#JNM@($*!H@#(&*)!H#E*()!@&GE*)!@QGE*)@G#E*!@&G",
			},
			nil,
			"error occurred while mapping OAuth 2.0 Session back to a Request while trying to parse the original form: invalid semicolon separator in query",
		},
		{
			"ShouldRestoreRequest",
			func(mock *mocks.MockFositeStorage) {
				mock.EXPECT().GetClient(context.TODO(), parclientid).Return(&oidc.BaseClient{ID: parclientid}, nil)
			},
			&model.OAuth2Session{
				ID:                1,
				Signature:         fmt.Sprintf("%sexample", oidc.RedirectURIPrefixPushedAuthorizationRequestURN),
				RequestID:         requestid,
				ClientID:          parclientid,
				Session:           []byte("{}"),
				RequestedAt:       time.Unix(10000000, 0),
				RequestedScopes:   model.StringSlicePipeDelimited{oidc.ScopeOpenID, oidc.ScopeOffline},
				RequestedAudience: model.StringSlicePipeDelimited{parclientid},
				Form: url.Values{
					oidc.FormParameterRedirectURI:  []string{"https://example.com"},
					oidc.FormParameterState:        []string{"abc123"},
					oidc.FormParameterResponseType: []string{oidc.ResponseTypeAuthorizationCodeFlow},
				}.Encode(),
			},
			&fosite.Request{
				ID:                requestid,
				Client:            &oidc.BaseClient{ID: parclientid},
				RequestedScope:    fosite.Arguments{oidc.ScopeOpenID, oidc.ScopeOffline},
				RequestedAudience: fosite.Arguments{parclientid},
				RequestedAt:       time.Unix(10000000, 0),
				Session:           oidc.NewSession(),
				Form: url.Values{
					oidc.FormParameterRedirectURI:  []string{"https://example.com"},
					oidc.FormParameterState:        []string{"abc123"},
					oidc.FormParameterResponseType: []string{oidc.ResponseTypeAuthorizationCodeFlow},
				},
			},
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			defer ctrl.Finish()

			mock := mocks.NewMockFositeStorage(ctrl)

			if tc.setup != nil {
				tc.setup(mock)
			}

			actual, err := tc.have.ToRequest(context.TODO(), oidc.NewSession(), mock)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, actual)
			} else {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, actual)
			}
		})
	}
}

func TestOAuth2ConsentPreConfig(t *testing.T) {
	config := &model.OAuth2ConsentPreConfig{
		ClientID: "abc",
	}

	assert.True(t, config.CanConsent())

	config.Revoked = true

	assert.False(t, config.CanConsent())

	config.Revoked = false
	config.ExpiresAt = sql.NullTime{Valid: true}

	assert.False(t, config.CanConsent())

	assert.False(t, config.HasExactGrants([]string{oidc.ScopeProfile}, []string{"abc"}))

	config.Scopes = []string{oidc.ScopeProfile}

	assert.False(t, config.HasExactGrants([]string{oidc.ScopeProfile}, []string{"abc"}))

	config.Audience = []string{"abc"}

	assert.True(t, config.HasExactGrants([]string{oidc.ScopeProfile}, []string{"abc"}))
}

func TestOAuth2ConsentSession(t *testing.T) {
	session := &model.OAuth2ConsentSession{
		ID:       0,
		ClientID: "a-client",
	}

	assert.False(t, session.CanGrant())

	session.Subject = uuid.NullUUID{Valid: true}

	assert.True(t, session.CanGrant())
	assert.False(t, session.IsDenied())
	assert.False(t, session.Responded())
	assert.False(t, session.IsAuthorized())

	session.RespondedAt = sql.NullTime{Valid: true}

	assert.True(t, session.Responded())
	assert.True(t, session.IsDenied())

	session.Authorized = true

	assert.True(t, session.IsAuthorized())
	assert.False(t, session.IsDenied())

	session.Granted = true

	assert.False(t, session.CanGrant())

	assert.False(t, session.HasExactGrants([]string{oidc.ScopeOpenID}, []string{"abc"}))

	session.GrantedScopes = model.StringSlicePipeDelimited{oidc.ScopeOpenID}

	assert.False(t, session.HasExactGrants([]string{oidc.ScopeOpenID}, []string{"abc"}))

	session.GrantedAudience = model.StringSlicePipeDelimited{"abc"}

	assert.True(t, session.HasExactGrants([]string{oidc.ScopeOpenID}, []string{"abc"}))

	session.GrantedScopes = nil
	session.GrantedAudience = nil

	session.Grant()

	assert.Nil(t, session.GrantedScopes)
	session.HasExactGrantedAudience([]string{"a-client"})

	session.RequestedScopes = []string{oidc.ScopeOpenID}
	session.RequestedAudience = []string{"abc"}

	session.Grant()

	session.HasExactGrantedScopes([]string{oidc.ScopeOpenID})
	session.HasExactGrantedAudience([]string{"abc", "a-client"})

	form, err := session.GetForm()

	assert.NoError(t, err)
	assert.Equal(t, url.Values{}, form)

	session.Form = "scope=abc"

	form, err = session.GetForm()

	assert.NoError(t, err)
	assert.Equal(t, url.Values{oidc.FormParameterScope: []string{"abc"}}, form)

	session.Form = ";;;&;;;;"

	form, err = session.GetForm()

	assert.EqualError(t, err, "invalid semicolon separator in query")
	assert.Equal(t, url.Values{}, form)
}

func TestMisc(t *testing.T) {
	jti := model.NewOAuth2BlacklistedJTI("abc", time.Unix(10000, 0).UTC())

	assert.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", jti.Signature)
	assert.Equal(t, time.Unix(10000, 0).UTC(), jti.ExpiresAt)

	sub := uuid.MustParse("b9423f3a-65da-4ea8-8f6b-1dafb141f3a8")

	session, err := model.NewOAuth2ConsentSession(sub, &fosite.Request{Client: &oidc.BaseClient{ID: "abc"}})

	assert.NoError(t, err)
	assert.NotNil(t, session)
}

func MustParseRequestURI(uri string) (parsed *url.URL) {
	var err error

	if parsed, err = url.ParseRequestURI(uri); err != nil {
		panic(err)
	}

	return parsed
}
