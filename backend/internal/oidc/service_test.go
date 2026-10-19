package oidc

import (
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/libtnb/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.getarcane.app/kit/pkg"
	"gorm.io/gorm"

	"github.com/getarcaneapp/arcane/backend/v2/internal/auth"
	"github.com/getarcaneapp/arcane/backend/v2/internal/config"
	"github.com/getarcaneapp/arcane/backend/v2/internal/database"
	"github.com/getarcaneapp/arcane/backend/v2/internal/event"
	"github.com/getarcaneapp/arcane/backend/v2/internal/role"
	"github.com/getarcaneapp/arcane/backend/v2/internal/session"
	"github.com/getarcaneapp/arcane/backend/v2/internal/settings"
	"github.com/getarcaneapp/arcane/backend/v2/internal/user"
	"github.com/getarcaneapp/arcane/backend/v2/pkg/utils/oidcjwk"
)

func TestValidateMobileRedirectURI(t *testing.T) {
	ctx := t.Context()
	s := &OidcService{
		config: &config.Config{
			OidcMobileRedirectUris: "arcane-mobile://oidc-callback, arcane-mobile://oauth",
		},
	}

	cases := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"exact match first", "arcane-mobile://oidc-callback", false},
		{"exact match second", "arcane-mobile://oauth", false},
		{"empty rejected", "", true},
		{"scheme-only attack", "arcane-mobile://attacker", true},
		{"different scheme", "https://oidc-callback", true},
		{"trailing-slash mismatch", "arcane-mobile://oidc-callback/", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.ValidateMobileRedirectURI(ctx, tc.uri)

			require.Equal(t, tc.wantErr, err != nil,
				"ValidateMobileRedirectURI(%q): wantErr=%v got err=%v", tc.uri, tc.wantErr, err)
		})
	}
}

func TestGetMobileRedirectAllowlistTrimsWhitespace(t *testing.T) {
	ctx := t.Context()
	s := &OidcService{
		config: &config.Config{
			OidcMobileRedirectUris: "  arcane-mobile://a  ,arcane-mobile://b ,, arcane-mobile://c",
		},
	}

	got := s.GetMobileRedirectAllowlist(ctx)
	want := []string{"arcane-mobile://a", "arcane-mobile://b", "arcane-mobile://c"}
	if len(got) != len(want) {
		require.Len(t, got, len(want),
			"got %d entries (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i, w := range want {
		require.Equal(t, w, got[i],
			"entry %d: got %q, want %q", i, got[i], w)
	}
}

func TestGetMobileRedirectAllowlistUsesSettings(t *testing.T) {
	ctx := t.Context()
	db := setupSettingsTestDB(t)
	settingsService, err := newSettingsServiceForTest(t, ctx, db)

	require.NoError(t, err,
		"settings.NewSettingsService: %v", err)
	{

		updateSettingErr := settingsService.UpdateSetting(ctx, "oidcMobileRedirectUris", "arcane-mobile://db-callback")
		require.NoError(t, updateSettingErr,
			"UpdateSetting: %v", updateSettingErr)
	}

	s := &OidcService{
		settingsService: settingsService,
		config: &config.Config{
			OidcMobileRedirectUris: "arcane-mobile://config-callback",
		},
	}
	{

		validateMobileRedirectURIErr := s.ValidateMobileRedirectURI(ctx, "arcane-mobile://db-callback")
		require.NoError(t, validateMobileRedirectURIErr,
			"ValidateMobileRedirectURI db value: %v", validateMobileRedirectURIErr)
	}
	{

		validateMobileRedirectURIErr2 := s.ValidateMobileRedirectURI(ctx, "arcane-mobile://config-callback")
		require.Error(t, validateMobileRedirectURIErr2,
			"ValidateMobileRedirectURI config fallback should fail when DB setting is configured")
	}
}

// Test fixtures shared by this package's tests.

func setupSettingsTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&settings.SettingVariable{}))
	return &database.DB{DB: db}
}

func newSettingsServiceForTest(t testing.TB, ctx context.Context, db *database.DB) (*settings.SettingsService, error) {
	t.Helper()
	svc, err := settings.NewSettingsService(ctx, db)
	if err == nil {
		t.Cleanup(func() { require.NoError(t, svc.Stop(context.WithoutCancel(t.Context()))) })
	}
	return svc, err
}

const (
	testOidcClientID = "arcane-client"
	testOidcSubject  = "subject-1"
)

type oidcTestIssuer struct {
	IssuerURL          string
	EndSessionEndpoint string
	private            *mldsa.PrivateKey
	keyID              string
	server             *httptest.Server
}

func newOidcTestIssuer(t *testing.T, endSessionPath string) *oidcTestIssuer {
	t.Helper()

	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA87())
	require.NoError(t, err)

	issuer := &oidcTestIssuer{
		private: privateKey,
		keyID:   "oidc-test-key",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		metadata := map[string]any{
			"issuer":                                issuer.IssuerURL,
			"jwks_uri":                              issuer.IssuerURL + "/jwks",
			"authorization_endpoint":                issuer.IssuerURL + "/authorize",
			"token_endpoint":                        issuer.IssuerURL + "/token",
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{jwa.MLDSA87().String()},
		}
		if issuer.EndSessionEndpoint != "" {
			metadata["end_session_endpoint"] = issuer.EndSessionEndpoint
		}
		assert.NoError(t, json.NewEncoder(w).Encode(metadata))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "AKP",
					"use": "sig",
					"kid": issuer.keyID,
					"alg": jwa.MLDSA87().String(),
					"pub": base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
				},
			},
		}))
	})

	issuer.server = httptest.NewServer(mux)
	issuer.IssuerURL = issuer.server.URL
	issuer.EndSessionEndpoint = kit.Ternary(endSessionPath == "", "", issuer.server.URL+endSessionPath)
	t.Cleanup(issuer.server.Close)

	return issuer
}

func (i *oidcTestIssuer) logoutToken(t *testing.T, subject string, claims map[string]any) string {
	t.Helper()

	now := time.Now()
	builder := jwt.NewBuilder().
		Issuer(i.IssuerURL).
		Subject(subject).
		Audience([]string{testOidcClientID}).
		IssuedAt(now).
		Expiration(now.Add(5 * time.Minute)).
		JwtID(kit.RandomString(16))
	for name, value := range claims {
		builder = builder.Claim(name, value)
	}
	token, err := builder.Build()
	require.NoError(t, err)
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.KeyIDKey, i.keyID))
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.MLDSA87(), i.private, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return string(signed)
}

func backchannelLogoutClaims() map[string]any {
	return map[string]any{
		"events": map[string]any{backchannelLogoutEvent: map[string]any{}},
	}
}

func setupOidcLogoutService(t *testing.T, issuer *oidcTestIssuer) (*OidcService, *database.DB) {
	t.Helper()

	ctx := t.Context()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	gormDB, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gormDB.AutoMigrate(
		&settings.SettingVariable{},
		&user.User{},
		&session.UserSession{},
		&role.Role{},
		&role.UserRoleAssignment{},
		&event.Event{},
	))
	sqlDB, err := gormDB.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	db := &database.DB{DB: gormDB}

	settingsSvc, err := newSettingsServiceForTest(t, ctx, db)
	require.NoError(t, err)
	for key, value := range map[string]string{
		"oidcEnabled":   "true",
		"oidcClientId":  testOidcClientID,
		"oidcIssuerUrl": issuer.IssuerURL,
	} {
		require.NoError(t, settingsSvc.UpdateSetting(ctx, key, value))
	}

	roleSvc := role.NewRoleService(db)
	userSvc := user.NewUserService(db, roleSvc, session.RevokeAllUserSessionsExceptInDB)
	authSvc := auth.NewAuthService(userSvc, settingsSvc, event.NewEventService(db, &config.Config{}, nil), session.NewSessionService(db), roleSvc, &config.Config{})

	keySetManager := oidcjwk.NewKeySetManager(t.Context())
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
		defer cancel()
		require.NoError(t, keySetManager.Shutdown(shutdownCtx))
	})

	return NewOidcService(authSvc, settingsSvc, userSvc, &config.Config{}, issuer.server.Client(), keySetManager), db
}

func createOidcUserWithSessions(t *testing.T, db *database.DB) []string {
	t.Helper()

	ctx := t.Context()
	oidcUser := user.User{
		BaseModel:     database.BaseModel{ID: "user-oidc"},
		Username:      "oidc-user",
		OidcSubjectId: new(testOidcSubject),
	}
	require.NoError(t, db.WithContext(ctx).Create(&oidcUser).Error)

	sessionIDs := []string{"session-a", "session-b"}
	for _, sessionID := range sessionIDs {
		require.NoError(t, db.WithContext(ctx).Create(&session.UserSession{
			BaseModel:        database.BaseModel{ID: sessionID},
			UserID:           oidcUser.ID,
			RefreshTokenHash: "hash-" + sessionID,
			Source:           session.UserSessionSourceOidc,
			LastUsedAt:       time.Now(),
			ExpiresAt:        time.Now().Add(time.Hour),
		}).Error)
	}
	return sessionIDs
}

func activeSessionCount(t *testing.T, db *database.DB, sessionIDs []string) int64 {
	t.Helper()

	var count int64
	require.NoError(t, db.WithContext(t.Context()).Model(&session.UserSession{}).
		Where("id IN ? AND revoked_at IS NULL", sessionIDs).
		Count(&count).Error)
	return count
}

func TestHandleBackchannelLogoutRevokesUserSessions(t *testing.T) {
	issuer := newOidcTestIssuer(t, "")
	service, db := setupOidcLogoutService(t, issuer)
	sessionIDs := createOidcUserWithSessions(t, db)

	require.NoError(t, service.HandleBackchannelLogout(t.Context(), issuer.logoutToken(t, testOidcSubject, backchannelLogoutClaims())))
	require.Zero(t, activeSessionCount(t, db, sessionIDs))
}

func TestGetEndSessionURLBuildsQuery(t *testing.T) {
	issuer := newOidcTestIssuer(t, "/logout?tenant=main")
	service, _ := setupOidcLogoutService(t, issuer)

	endSessionURL, err := service.GetEndSessionURL(t.Context(), "https://arcane.example.com")
	require.NoError(t, err)

	parsed, err := url.Parse(endSessionURL)
	require.NoError(t, err)
	require.Equal(t, issuer.IssuerURL+"/logout", parsed.Scheme+"://"+parsed.Host+parsed.Path)
	require.Equal(t, url.Values{
		"tenant":                   {"main"},
		"client_id":                {testOidcClientID},
		"post_logout_redirect_uri": {"https://arcane.example.com/login"},
	}, parsed.Query())
}
