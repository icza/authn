package authn

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var client *mongo.Client

func init() {
	options := options.Client().ApplyURI("mongodb://localhost:27017")
	ctx := context.Background()
	var err error
	client, err = mongo.Connect(options)
	if err != nil {
		panic(err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		panic(err)
	}
}

var (
	emptySendEmail    = func(ctx context.Context, to, body string) error { return nil }
	validatorOK       = func(ctx context.Context, token *Token, client *Client) error { return nil }
	errValidationTest = errors.New("validation test error")
	validatorErr      = func(ctx context.Context, token *Token, client *Client) error { return errValidationTest }
)

func TestNewAuthenticator(t *testing.T) {
	expectPanic := func(name string) {
		if r := recover(); r == nil {
			t.Errorf("expected panic for %s", name)
		}
	}

	func() {
		defer expectPanic("nil mongoClient")
		NewAuthenticator[any](nil, nil, Config{})
	}()

	func() {
		defer expectPanic("nil sendEmail")
		NewAuthenticator[any](client, nil, Config{})
	}()

	a := NewAuthenticator[any](client, emptySendEmail, Config{})

	defCfg := Config{
		AuthnDBName:          DefaultAuthnDBName,
		TokensCollectionName: DefaultTokensCollectionName,
		UsersCollectionName:  DefaultUsersCollectionName,
		EntryCodeBytes:       DefaultEntryCodeBytes,
		EntryCodeExpiration:  DefaultEntryCodeExpiration,
		TokenValueBytes:      DefaultTokenValueBytes,
		TokenExpiration:      DefaultTokenExpiration,
		EmailTemplate:        DefaultEmailTemplate,
	}
	if a.mongoClient != client {
		t.Errorf("Expected %#v, got: %#v", client, a.mongoClient)
	}
	if a.sendEmail == nil {
		t.Errorf("Expected non-nil: %#v", a.sendEmail)
	}
	if a.cfg != defCfg {
		t.Errorf("Expected %#v, got: %#v", defCfg, a.cfg)
	}
	if a.emailTempl == nil {
		t.Errorf("Expected non-nil: %#v", a.emailTempl)
	}

	// Test custom config
	cfg := Config{
		AuthnDBName:          fmt.Sprint("tdb", time.Now().UnixNano()), // random name
		TokensCollectionName: "tcname",
		UsersCollectionName:  "ucname",
		EntryCodeBytes:       100,
		EntryCodeExpiration:  time.Minute,
		TokenValueBytes:      101,
		TokenExpiration:      time.Hour,
		EmailTemplate:        "etempl",
	}

	a = NewAuthenticator[any](client, emptySendEmail, cfg)
	if a.cfg != cfg {
		t.Errorf("Expected %#v, got: %#v", cfg, a.cfg)
	}
	// clear temp db
	if err := client.Database(cfg.AuthnDBName).Drop(context.Background()); err != nil {
		t.Errorf("Failed to clear temp db: %v", err)
	}
}

func initCollection(ctx context.Context, c *mongo.Collection, t *testing.T, savedDocs ...any) {
	// Clear docs
	if _, err := c.DeleteMany(ctx, bson.M{}); err != nil {
		t.Errorf("Failed to clear docs: %v", err)
	}

	for _, doc := range savedDocs {
		if v := reflect.ValueOf(doc); doc == nil || v.Kind() == reflect.Ptr && v.IsNil() {
			continue
		}
		if _, err := c.InsertOne(ctx, doc); err != nil {
			t.Errorf("Failed to insert doc: %v", err)
		}
	}
}

func TestSendEntryCode(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		title        string
		email        string
		cfg          Config
		sendEmailErr error
		client       *Client
		data         map[string]any
		expBody      string
		expErr       bool
		expErrValue  error
		expToken     *Token
	}{
		{
			title:       "invalid-email",
			email:       "invalid",
			expErr:      true,
			expErrValue: ErrInvalidEmail,
		},
		{
			title: "template-exec-error",
			email: "as@as.hu",
			cfg: Config{
				EmailTemplate: "{{.Invalid}}",
			},
			expErr: true,
		},
		{
			title:        "sendEmail error",
			email:        "as@as.hu",
			sendEmailErr: errors.New("test error"),
			expErr:       true,
		},
		{
			title:  "success",
			email:  "As@as.hu",
			client: &Client{UserAgent: "ua1", IP: "1.2.3.4"},
			expToken: &Token{
				Email:        "As@as.hu",
				LoweredEmail: "as@as.hu",
				EntryClient:  &Client{UserAgent: "ua1", IP: "1.2.3.4"},
			},
		},
		{
			title: "success-no-client",
			email: "As@as.hu",
			expToken: &Token{
				Email:        "As@as.hu",
				LoweredEmail: "as@as.hu",
			},
		},
		{
			title:  "success-empty-client",
			email:  "As@as.hu",
			client: &Client{},
			expToken: &Token{
				Email:        "As@as.hu",
				LoweredEmail: "as@as.hu",
				EntryClient:  &Client{},
			},
		},
		{
			title: "success-custom-data",
			email: "As@as.hu",
			cfg: Config{
				EmailTemplate: "{{.Data.Seven}}",
			},
			data:    map[string]any{"Seven": 7},
			expBody: "7",
			expToken: &Token{
				Email:        "As@as.hu",
				LoweredEmail: "as@as.hu",
			},
		},
	}

	for _, c := range cases {
		sendEmail := func(ctx context.Context, to, body string) error {
			if c.expBody != "" && c.expBody != body {
				t.Errorf("[%s] Expected: %v, got: %v", c.title, c.expBody, body)
			}
			return c.sendEmailErr
		}
		a := NewAuthenticator[any](client, sendEmail, c.cfg)

		initCollection(ctx, a.ct, t)

		err := a.SendEntryCode(ctx, c.email, c.client, c.data)
		if gotErr := err != nil; gotErr != c.expErr {
			t.Errorf("[%s] Expected err: %v, got: %v", c.title, c.expErr, gotErr)
		}
		if err != nil {
			if c.expErrValue != nil && !errors.Is(err, c.expErrValue) {
				t.Errorf("[%s] Expected: %v, got: %v", c.title, c.expErrValue, err)
			}
			// If an error is returned, we expect no "left-over" tokens:
			if n, err := a.ct.CountDocuments(ctx, bson.M{}); err != nil {
				t.Errorf("Failed to count tokens: %v", err)
			} else {
				if n > 0 {
					t.Errorf("[%s] Expected no left-over tokens, got: %d", c.title, n)
				}
			}
		} else {
			// Verify token:
			now := time.Now()
			var token *Token
			if err := a.ct.FindOne(ctx, bson.M{}).Decode(&token); err != nil {
				t.Errorf("[%s] Can't find token: %v", c.title, err)
			}
			c.expToken.EntryCode = token.EntryCode
			c.expToken.Value = token.Value
			c.expToken.Created = now
			c.expToken.Expires = now.Add(a.cfg.EntryCodeExpiration)
			if c.client != nil {
				c.expToken.EntryClient.At = now
			}
			if tokensDiffer(c.expToken, token) ||
				len(token.EntryCode) != a.cfg.EntryCodeBytes*2 || // Entry code must be of specific length
				len(token.Value) < a.cfg.TokenValueBytes*4/3 { // Token be of specific length (base64)
				t.Errorf("[%s]\nExpected: %+v,\ngot:      %+v", c.title, c.expToken, token)
				t.Errorf("[%s]\nExpected: %+v,\ngot:      %+v", c.title, c.expToken.EntryClient, token.EntryClient)
			}
		}
	}
}

func TestVerifyEntryCode(t *testing.T) {
	ctx := context.Background()

	uid := bson.ObjectID([12]byte{1})

	cases := []struct {
		title      string
		savedToken *Token
		savedUser  *User[any]
		entryCode  string
		client     *Client
		validators []Validator
		expErr     error
		expToken   *Token
	}{
		{
			title:     "unknown-entry-code-error",
			entryCode: "unknown",
			expErr:    ErrUnknown,
		},
		{
			title:      "already-verified-error",
			entryCode:  "ec1",
			savedToken: &Token{EntryCode: "ec1", Verified: true},
			expErr:     ErrAlreadyVerified,
		},
		{
			title:      "expired-error",
			entryCode:  "ec1",
			savedToken: &Token{EntryCode: "ec1", Expires: time.Now().Add(-time.Second)},
			expErr:     ErrExpired,
		},
		{
			title:      "validator-error",
			entryCode:  "ec1",
			savedToken: &Token{EntryCode: "ec1", Expires: time.Now().Add(time.Minute)},
			validators: []Validator{validatorErr},
			expErr:     errValidationTest,
		},
		{
			title:     "success",
			entryCode: "ec1",
			savedToken: &Token{
				EntryCode:   "ec1",
				Expires:     time.Now().Add(time.Hour),
				EntryClient: &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
			},
			client: &Client{UserAgent: "ua2", IP: "2.2.3.4"},
			expToken: &Token{
				EntryCode:   "ec1",
				EntryClient: &Client{UserAgent: "ua2", IP: "2.2.3.4"},
				Verified:    true,
			},
		},
		{
			title:     "success-existing-user",
			entryCode: "ec1",
			savedToken: &Token{
				Email:        "As@as.hu",
				LoweredEmail: "as@as.hu",
				EntryCode:    "ec1",
				Expires:      time.Now().Add(time.Hour),
				EntryClient:  &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
			},
			savedUser: &User[any]{
				ID:            uid,
				LoweredEmails: []string{"as@as.hu"},
				Created:       time.Now().Add(-time.Hour),
			},
			client: &Client{UserAgent: "ua2", IP: "2.2.3.4"},
			expToken: &Token{
				Email:        "As@as.hu",
				LoweredEmail: "as@as.hu",
				EntryCode:    "ec1",
				EntryClient:  &Client{UserAgent: "ua2", IP: "2.2.3.4"},
				Verified:     true,
				UserID:       uid,
			},
		},
		{
			title:     "success-validators",
			entryCode: "ec1",
			savedToken: &Token{
				Email:        "As@as.hu",
				LoweredEmail: "as@as.hu",
				EntryCode:    "ec1",
				Expires:      time.Now().Add(time.Hour),
				EntryClient:  &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
			},
			savedUser: &User[any]{
				ID:            uid,
				LoweredEmails: []string{"as@as.hu"},
				Created:       time.Now().Add(-time.Hour),
			},
			client: &Client{UserAgent: "ua2", IP: "2.2.3.4"},
			validators: []Validator{
				validatorOK,
				func(ctx context.Context, token *Token, client *Client) error {
					if token.EntryClient.UserAgent != "ua" || client.UserAgent != "ua2" || token.UserID != uid {
						return fmt.Errorf("unexpected validator params")
					}
					return nil
				},
			},
			expToken: &Token{
				Email:        "As@as.hu",
				LoweredEmail: "as@as.hu",
				EntryCode:    "ec1",
				EntryClient:  &Client{UserAgent: "ua2", IP: "2.2.3.4"},
				Verified:     true,
				UserID:       uid,
			},
		},
		{
			title:     "success-nil-client",
			entryCode: "ec1",
			savedToken: &Token{
				EntryCode:   "ec1",
				Expires:     time.Now().Add(time.Hour),
				EntryClient: &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
			},
			expToken: &Token{
				EntryCode:   "ec1",
				EntryClient: &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
				Verified:    true,
			},
		},
		{
			title:     "success-nil-client-no-saved-client",
			entryCode: "ec1",
			savedToken: &Token{
				EntryCode: "ec1",
				Expires:   time.Now().Add(time.Hour),
			},
			expToken: &Token{
				EntryCode: "ec1",
				Verified:  true,
			},
		},
	}

	for _, c := range cases {
		a := NewAuthenticator[any](client, emptySendEmail, Config{})

		initCollection(ctx, a.ct, t, c.savedToken)
		initCollection(ctx, a.cu, t, c.savedUser)

		token, err := a.VerifyEntryCode(ctx, c.entryCode, c.client, c.validators...)
		if c.expErr != nil {
			if !errors.Is(err, c.expErr) {
				t.Errorf("[%s] Expected: %+v, got: %+v", c.title, c.expErr, err)
			}
		} else {
			// Verify returned and persisted token consistency:
			var loadedToken *Token
			if err := a.ct.FindOne(ctx, bson.M{"ecode": c.entryCode}).Decode(&loadedToken); err != nil {
				t.Errorf("[%s] Failed to load token: %v", c.title, err)
			}
			if tokensDiffer(loadedToken, token) {
				t.Errorf("[%s]\nExpected: %+v,\ngot:      %+v", c.title, loadedToken, token)
				t.Errorf("[%s]\nExpected: %+v,\ngot:      %+v", c.title, loadedToken.EntryClient, token.EntryClient)
			}

			// User must exist
			if token.UserID.IsZero() {
				t.Errorf("[%s] Expected UserID, got nil", c.title)
			}
			var loadedUser *User[any]
			if err := a.cu.FindOne(ctx, bson.M{"lemails": token.LoweredEmail}).Decode(&loadedUser); err != nil {
				t.Errorf("[%s] Failed to load user: %v", c.title, err)
			}
			if loadedUser.ID != token.UserID {
				t.Errorf("[%s] Expected %v, got %v", c.title, loadedUser.ID, token.UserID)
			}
			now := time.Now()
			if c.savedUser == nil {
				// User must be new:
				if timesDiffer(now, loadedUser.Created) {
					t.Errorf("[%s] Expected %v, got %v", c.title, now, loadedUser.Created)
				}
			}

			// Verify token:
			c.expToken.Expires = now.Add(a.cfg.TokenExpiration)
			if c.savedUser == nil {
				c.expToken.UserID = token.UserID
			}
			if c.client != nil {
				c.expToken.EntryClient.At = now
			}
			if tokensDiffer(c.expToken, token) {
				t.Errorf("[%s]\nExpected: %+v,\ngot:      %+v", c.title, c.expToken, token)
				t.Errorf("[%s]\nExpected: %+v,\ngot:      %+v", c.title, c.expToken.EntryClient, token.EntryClient)
			}
		}
	}
}

func TestVerifyToken(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		title      string
		savedToken *Token
		tokenValue string
		client     *Client
		validators []Validator
		expErr     error
		expToken   *Token
	}{
		{
			title:      "unknown-token-value-error",
			tokenValue: "unknown",
			expErr:     ErrUnknown,
		},
		{
			title:      "expired-error",
			tokenValue: "t1",
			savedToken: &Token{Value: "t1", Expires: time.Now().Add(-time.Second)},
			expErr:     ErrExpired,
		},
		{
			title:      "validator-error",
			tokenValue: "t1",
			savedToken: &Token{Value: "t1", Expires: time.Now().Add(time.Minute)},
			validators: []Validator{validatorErr},
			expErr:     errValidationTest,
		},
		{
			title:      "success",
			tokenValue: "t1",
			savedToken: &Token{
				Value:   "t1",
				Expires: time.Now().Add(time.Hour),
				Client:  &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
			},
			client: &Client{UserAgent: "ua2", IP: "2.2.3.4"},
			expToken: &Token{
				Value:   "t1",
				Expires: time.Now().Add(time.Hour),
				Client:  &Client{UserAgent: "ua2", IP: "2.2.3.4"},
				Used:    1,
			},
		},
		{
			title:      "success-validator",
			tokenValue: "t1",
			savedToken: &Token{
				Value:   "t1",
				Expires: time.Now().Add(time.Hour),
				Client:  &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
			},
			client: &Client{UserAgent: "ua2", IP: "2.2.3.4"},
			validators: []Validator{
				validatorOK,
				func(ctx context.Context, token *Token, client *Client) error {
					if token.Client.UserAgent != "ua" || client.UserAgent != "ua2" {
						return fmt.Errorf("unexpected validator params")
					}
					return nil
				},
			},
			expToken: &Token{
				Value:   "t1",
				Expires: time.Now().Add(time.Hour),
				Client:  &Client{UserAgent: "ua2", IP: "2.2.3.4"},
				Used:    1,
			},
		},
		{
			title:      "success-nil-client",
			tokenValue: "t1",
			savedToken: &Token{
				Value:   "t1",
				Expires: time.Now().Add(time.Hour),
				Client:  &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
			},
			expToken: &Token{
				Value:   "t1",
				Expires: time.Now().Add(time.Hour),
				Client:  &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
			},
		},
		{
			title:      "success-nil-client-no-saved-client",
			tokenValue: "t1",
			savedToken: &Token{
				Value:   "t1",
				Expires: time.Now().Add(time.Hour),
			},
			expToken: &Token{
				Value:   "t1",
				Expires: time.Now().Add(time.Hour),
			},
		},
		{
			title:      "success-existing-used",
			tokenValue: "t1",
			savedToken: &Token{
				Value:   "t1",
				Expires: time.Now().Add(time.Hour),
				Client:  &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
				Used:    10,
			},
			client: &Client{UserAgent: "ua2", IP: "2.2.3.4"},
			expToken: &Token{
				Value:   "t1",
				Expires: time.Now().Add(time.Hour),
				Client:  &Client{UserAgent: "ua2", IP: "2.2.3.4"},
				Used:    11,
			},
		},
		{
			title:      "success-nil-client-existing-used",
			tokenValue: "t1",
			savedToken: &Token{
				Value:   "t1",
				Expires: time.Now().Add(time.Hour),
				Client:  &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
				Used:    10,
			},
			expToken: &Token{
				Value:   "t1",
				Expires: time.Now().Add(time.Hour),
				Client:  &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
				Used:    10,
			},
		},
	}

	for _, c := range cases {
		a := NewAuthenticator[any](client, emptySendEmail, Config{})

		initCollection(ctx, a.ct, t, c.savedToken)

		token, err := a.VerifyToken(ctx, c.tokenValue, c.client, c.validators...)
		if c.expErr != nil {
			if !errors.Is(err, c.expErr) {
				t.Errorf("[%s] Expected: %+v, got: %+v", c.title, c.expErr, err)
			}
		} else {
			// Verify returned and persisted token consistency:
			var loadedToken *Token
			if err := a.ct.FindOne(ctx, bson.M{"value": c.tokenValue}).Decode(&loadedToken); err != nil {
				t.Errorf("[%s] Failed to load token: %v", c.title, err)
			}
			if tokensDiffer(loadedToken, token) {
				t.Errorf("[%s]\nExpected: %+v,\ngot:      %+v", c.title, loadedToken, token)
				t.Errorf("[%s]\nExpected: %+v,\ngot:      %+v", c.title, loadedToken.Client, token.Client)
			}

			// Verify expected token:
			now := time.Now()
			if c.client != nil {
				c.expToken.Client.At = now
			}
			if tokensDiffer(c.expToken, token) {
				t.Errorf("[%s]\nExpected: %+v,\ngot:      %+v", c.title, c.expToken, token)
				t.Errorf("[%s]\nExpected: %+v,\ngot:      %+v", c.title, c.expToken.EntryClient, token.EntryClient)
			}
		}
	}
}

func TestInvalidateToken(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		title      string
		savedToken *Token
		tokenValue string
		expErr     error
	}{
		{
			title:      "unknown-token-value-error",
			tokenValue: "unknown",
			expErr:     ErrUnknown,
		},
		{
			title:      "expired-error",
			tokenValue: "t1",
			savedToken: &Token{Value: "t1", Expires: time.Now().Add(-time.Second)},
			expErr:     ErrExpired,
		},
		{
			title:      "success",
			tokenValue: "t1",
			savedToken: &Token{
				Value:   "t1",
				Expires: time.Now().Add(time.Hour),
			},
		},
	}

	for _, c := range cases {
		sendEmail := func(ctx context.Context, to, body string) error { return nil }
		a := NewAuthenticator[any](client, sendEmail, Config{})

		initCollection(ctx, a.ct, t, c.savedToken)

		err := a.InvalidateToken(ctx, c.tokenValue)
		if c.expErr != nil {
			if !errors.Is(err, c.expErr) {
				t.Errorf("[%s] Expected: %+v, got: %+v", c.title, c.expErr, err)
			}
		} else {
			var loadedToken *Token
			if err := a.ct.FindOne(ctx, bson.M{"value": c.tokenValue}).Decode(&loadedToken); err != nil {
				t.Errorf("[%s] Failed to load token: %v", c.title, err)
			}
			if !loadedToken.Expired() {
				t.Errorf("[%s]\nExpected expired", c.title)
			}
		}
	}
}

func TestTokens(t *testing.T) {
	ctx := context.Background()

	uid1, uid2 := bson.ObjectID([12]byte{1}), bson.ObjectID([12]byte{2})

	cases := []struct {
		title          string
		savedTokens    []any
		tokenValue     string
		userID         bson.ObjectID
		expErr         error
		expTokenValues []string
	}{
		{
			title:      "unknown-token-value-error",
			tokenValue: "unknown",
			expErr:     ErrUnknown,
		},
		{
			title:      "expired-error",
			tokenValue: "t1",
			savedTokens: []any{
				&Token{Value: "t1", UserID: uid1, Expires: time.Now().Add(-time.Second)},
			},
			userID: uid1,
			expErr: ErrExpired,
		},
		{
			title:      "success",
			tokenValue: "t1",
			savedTokens: []any{
				&Token{Verified: true, UserID: uid1, Value: "t1", Expires: time.Now().Add(time.Hour)},
			},
			userID:         uid1,
			expTokenValues: []string{"t1"},
		},
		{
			title:      "success-multiple-tokens",
			tokenValue: "t1",
			savedTokens: []any{
				// Good ones
				&Token{Verified: true, UserID: uid1, EntryCode: "e1", Value: "t1", Expires: time.Now().Add(time.Hour)},
				&Token{Verified: true, UserID: uid1, EntryCode: "e2", Value: "t2", Expires: time.Now().Add(365 * 24 * time.Hour)},
				&Token{Verified: true, UserID: uid1, EntryCode: "e3", Value: "t3", Expires: time.Now().Add(time.Minute)},
				// Bad ones:
				&Token{Verified: false, UserID: uid1, EntryCode: "e4", Value: "t4", Expires: time.Now().Add(time.Hour)},
				&Token{Verified: true, UserID: uid1, EntryCode: "e5", Value: "t5", Expires: time.Now().Add(-time.Minute)},
				&Token{Verified: true, UserID: uid2, EntryCode: "e6", Value: "t6", Expires: time.Now().Add(time.Hour)},
			},
			userID:         uid1,
			expTokenValues: []string{"t1", "t2", "t3"},
		},
	}

	for _, c := range cases {
		a := NewAuthenticator[any](client, emptySendEmail, Config{})

		initCollection(ctx, a.ct, t, c.savedTokens...)

		tokens, err := a.Tokens(ctx, c.tokenValue)

		verifyTokens := func() {
			if len(tokens) != len(c.expTokenValues) {
				t.Errorf("[%s] Expected: %d, got: %d", c.title, len(tokens), len(c.expTokenValues))
			}
			sort.Strings(c.expTokenValues)
			sort.Slice(tokens, func(i int, j int) bool {
				return tokens[i].Value < tokens[j].Value
			})
			for i, expTokenValue := range c.expTokenValues {
				if tokens[i].Value != expTokenValue {
					t.Errorf("[%s] Expected: %+v, got: %+v", c.title, expTokenValue, tokens[i].Value)
				}
			}
		}

		if c.expErr != nil {
			if !errors.Is(err, c.expErr) {
				t.Errorf("[%s] Expected: %+v, got: %+v", c.title, c.expErr, err)
			}
		} else {
			verifyTokens()
		}

		if !c.userID.IsZero() {
			tokens, err = a.UserTokens(ctx, c.userID)
			if err != nil {
				t.Errorf("[%s] Expected no error, got: %v", c.title, err)
			} else {
				verifyTokens()
			}
		}
	}
}

func TestGetUser(t *testing.T) {
	ctx := context.Background()

	uid1, uid2, uid3 := bson.ObjectID([12]byte{1}), bson.ObjectID([12]byte{2}), bson.ObjectID([12]byte{3})

	cases := []struct {
		title      string
		savedUsers []any
		userID     bson.ObjectID
		expErr     bool
		expUser    *User[any]
	}{
		{
			title:  "unknown-user-ID",
			expErr: true,
		},
		{
			title: "unknown-user-ID-2",
			savedUsers: []any{
				&User[any]{ID: uid1, LoweredEmails: []string{"as@as.hu"}},
				&User[any]{ID: uid2, LoweredEmails: []string{"bs@as.hu"}},
			},
			userID: uid3,
			expErr: true,
		},
		{
			title: "success",
			savedUsers: []any{
				&User[any]{ID: uid1, LoweredEmails: []string{"as@as.hu"}},
				&User[any]{ID: uid2, LoweredEmails: []string{"bs@as.hu"}},
			},
			userID:  uid1,
			expUser: &User[any]{ID: uid1, LoweredEmails: []string{"as@as.hu"}},
		},
		{
			title: "success-2",
			savedUsers: []any{
				&User[any]{ID: uid1, LoweredEmails: []string{"as@as.hu"}},
				&User[any]{ID: uid2, LoweredEmails: []string{"bs@as.hu"}},
			},
			userID:  uid2,
			expUser: &User[any]{ID: uid2, LoweredEmails: []string{"bs@as.hu"}},
		},
	}

	for _, c := range cases {
		a := NewAuthenticator[any](client, emptySendEmail, Config{})

		initCollection(ctx, a.cu, t, c.savedUsers...)

		user, err := a.GetUser(ctx, c.userID)
		if gotErr := err != nil; gotErr != c.expErr {
			t.Errorf("[%s] Expected err: %v, got: %v", c.title, c.expErr, gotErr)
		}

		if err == nil {
			if user.ID != c.expUser.ID {
				t.Errorf("[%s] Expected: %v, got: %v", c.title, c.expUser.ID, user.ID)
			}
		}
	}
}

func TestGetUserCustomData(t *testing.T) {
	ctx := context.Background()

	type userData struct {
		Role  string
		Limit int
	}

	uid := bson.ObjectID([12]byte{1})

	cases := []struct {
		title     string
		savedUser *User[*userData]
	}{
		{
			title:     "no-user-data",
			savedUser: &User[*userData]{ID: uid, LoweredEmails: []string{"as@as.hu"}},
		},
		{
			title:     "user-data",
			savedUser: &User[*userData]{ID: uid, LoweredEmails: []string{"as@as.hu"}, Data: &userData{Role: "admin", Limit: 10}},
		},
	}

	for _, c := range cases {
		a := NewAuthenticator[*userData](client, emptySendEmail, Config{})

		initCollection(ctx, a.cu, t, c.savedUser)

		user, err := a.GetUser(ctx, c.savedUser.ID)
		if err != nil {
			t.Errorf("[%s] Expected no error,  got: %v", c.title, err)
		}

		if err == nil {
			if !reflect.DeepEqual(c.savedUser.Data, user.Data) {
				t.Errorf("[%s] Expected: %v, got: %v", c.title, c.savedUser.Data, user.Data)
			}
		}
	}
}

func TestSetUserEmails(t *testing.T) {
	ctx := context.Background()

	uid1, uid2 := bson.ObjectID([12]byte{1}), bson.ObjectID([12]byte{2})

	cases := []struct {
		title         string
		savedUsers    []any
		userID        bson.ObjectID
		loweredEmails []string
		expErr        bool
	}{
		{
			title:  "unknown-user-ID",
			userID: uid1,
			expErr: true,
		},
		{
			title: "unknown-user-ID-2",
			savedUsers: []any{
				&User[any]{ID: uid1, LoweredEmails: []string{"as@as.hu"}},
			},
			userID: uid2,
			expErr: true,
		},
		{
			title: "error-existing-email",
			savedUsers: []any{
				&User[any]{ID: uid1, LoweredEmails: []string{"as@as.hu"}},
				&User[any]{ID: uid2, LoweredEmails: []string{"bs@as.hu"}},
			},
			userID:        uid1,
			loweredEmails: []string{"bs@as.hu"},
			expErr:        true,
		},
		{
			title: "success",
			savedUsers: []any{
				&User[any]{ID: uid1, LoweredEmails: []string{"as@as.hu"}},
			},
			userID:        uid1,
			loweredEmails: []string{"bs@as.hu"},
		},
		{
			title: "success-2",
			savedUsers: []any{
				&User[any]{ID: uid1, LoweredEmails: []string{"as@as.hu"}},
			},
			userID:        uid1,
			loweredEmails: []string{"bs@as.hu", "as@as.hu"},
		},
	}

	for _, c := range cases {
		a := NewAuthenticator[any](client, emptySendEmail, Config{})

		initCollection(ctx, a.cu, t, c.savedUsers...)

		err := a.SetUserEmails(ctx, c.userID, c.loweredEmails)
		if gotErr := err != nil; gotErr != c.expErr {
			t.Errorf("[%s] Expected err: %v, got: %v", c.title, c.expErr, gotErr)
		}

		if err == nil {
			// Verify
			var loadedUser *User[any]
			if err := a.cu.FindOne(ctx, bson.M{"_id": c.userID}).Decode(&loadedUser); err != nil {
				t.Errorf("[%s] Failed to load user: %v", c.title, err)
			}
			if !reflect.DeepEqual(c.loweredEmails, loadedUser.LoweredEmails) {
				t.Errorf("[%s] Expected %v, got %v", c.title, c.loweredEmails, loadedUser.LoweredEmails)
			}
		}
	}
}

// tokensDiffer compares to tokens "deeply", comparing timestamps using diffTime().
func tokensDiffer(t1, t2 *Token) bool {
	return t1.Email != t2.Email ||
		t1.LoweredEmail != t2.LoweredEmail ||
		timesDiffer(t1.Created, t2.Created) ||
		t1.EntryCode != t2.EntryCode ||
		clientsDiffer(t1.EntryClient, t2.EntryClient) ||
		t1.Verified != t2.Verified ||
		clientsDiffer(t1.Client, t2.Client) ||
		timesDiffer(t1.Expires, t2.Expires) ||
		t1.Value != t2.Value ||
		t1.UserID != t2.UserID ||
		t1.Used != t2.Used
}

// clientsDiffer compares to clients "deeply", comparing timestamps using diffTime().
func clientsDiffer(c1, c2 *Client) bool {
	if c1 == nil && c2 == nil {
		return false
	}
	if c1 == nil || c2 == nil {
		return true // Only one is nil, they can't match
	}
	return c1.UserAgent != c2.UserAgent ||
		c1.IP != c2.IP ||
		timesDiffer(c1.At, c2.At)
}

// timesDiffer compares if 2 time instances, concluding mismatch if the
// difference is bigger than 1 second.
func timesDiffer(t1, t2 time.Time) bool {
	const maxDelta = time.Second
	delta := t1.Sub(t2)
	return delta > maxDelta || delta < -maxDelta
}
