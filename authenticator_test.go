package authn

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client

func init() {
	options := options.Client().ApplyURI("mongodb://localhost:27017")
	ctx := context.Background()
	var err error
	client, err = mongo.Connect(ctx, options)
	if err != nil {
		panic(err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		panic(err)
	}
}

func TestNewAuthenticator(t *testing.T) {
	expectPanic := func(name string) {
		if r := recover(); r == nil {
			t.Errorf("expected panic for %s", name)
		}
	}

	func() {
		defer expectPanic("nil mongoClient")
		NewAuthenticator(nil, nil, Config{})
	}()

	func() {
		defer expectPanic("nil sendEmail")
		NewAuthenticator(client, nil, Config{})
	}()

	sendEmail := func(ctx context.Context, to, body string) error { return nil }
	a := NewAuthenticator(client, sendEmail, Config{})

	defCfg := Config{
		AuthnDBName:          DefaultAuthnDBName,
		TokensCollectionName: DefaultTokensCollectionName,
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
		EntryCodeBytes:       100,
		EntryCodeExpiration:  time.Minute,
		TokenValueBytes:      101,
		TokenExpiration:      time.Hour,
		EmailTemplate:        "etempl",
	}

	a = NewAuthenticator(client, sendEmail, cfg)
	if a.cfg != cfg {
		t.Errorf("Expected %#v, got: %#v", cfg, a.cfg)
	}
	// clear temp db
	if err := client.Database(cfg.AuthnDBName).Drop(context.Background()); err != nil {
		t.Errorf("Failed to clear temp db: %v", err)
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
		data         map[string]interface{}
		expBody      string
		expErr       bool
		expToken     *Token
	}{
		{
			title:  "invalid email",
			email:  "invalid",
			expErr: true,
		},
		{
			title: "template exec error",
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
			data:    map[string]interface{}{"Seven": 7},
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
		a := NewAuthenticator(client, sendEmail, c.cfg)

		// Clear tokens
		if _, err := a.c.DeleteMany(ctx, bson.M{}); err != nil {
			t.Errorf("Failed to clear tokens: %v", err)
		}

		err := a.SendEntryCode(ctx, c.email, c.client, c.data)
		if gotErr := err != nil; gotErr != c.expErr {
			t.Errorf("[%s] Expected err: %v, got: %v", c.title, c.expErr, gotErr)
		}
		if err != nil {
			// If an error is returned, we expect no "left-over" tokens:
			if n, err := a.c.CountDocuments(ctx, bson.M{}); err != nil {
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
			if err := a.c.FindOne(ctx, bson.M{}).Decode(&token); err != nil {
				t.Errorf("[%s] Can't find token: %v", c.title, err)
			}
			c.expToken.EntryCode = token.EntryCode
			c.expToken.Value = token.Value
			c.expToken.Created = now
			c.expToken.Expiration = now.Add(a.cfg.EntryCodeExpiration)
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

	cases := []struct {
		title      string
		savedToken *Token
		entryCode  string
		client     *Client
		expErr     error
		expToken   *Token
	}{
		{
			title:     "unknown entry code error",
			entryCode: "unknown",
			expErr:    ErrUnknown,
		},
		{
			title:      "already verified error",
			entryCode:  "ec1",
			savedToken: &Token{EntryCode: "ec1", EntryCodeVerified: true},
			expErr:     ErrEntryCodeAlreadyVerified,
		},
		{
			title:      "expired error",
			entryCode:  "ec1",
			savedToken: &Token{EntryCode: "ec1", Expiration: time.Now().Add(-time.Second)},
			expErr:     ErrExpired,
		},
		{
			title:     "success",
			entryCode: "ec1",
			savedToken: &Token{
				EntryCode:   "ec1",
				Expiration:  time.Now().Add(time.Hour),
				EntryClient: &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
			},
			client: &Client{UserAgent: "ua2", IP: "2.2.3.4"},
			expToken: &Token{
				EntryCode:         "ec1",
				EntryClient:       &Client{UserAgent: "ua2", IP: "2.2.3.4"},
				EntryCodeVerified: true,
			},
		},
		{
			title:     "success-nil-client",
			entryCode: "ec1",
			savedToken: &Token{
				EntryCode:   "ec1",
				Expiration:  time.Now().Add(time.Hour),
				EntryClient: &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
			},
			expToken: &Token{
				EntryCode:         "ec1",
				EntryClient:       &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
				EntryCodeVerified: true,
			},
		},
		{
			title:     "success-nil-client-no-saved-client",
			entryCode: "ec1",
			savedToken: &Token{
				EntryCode:  "ec1",
				Expiration: time.Now().Add(time.Hour),
			},
			expToken: &Token{
				EntryCode:         "ec1",
				EntryCodeVerified: true,
			},
		},
	}

	for _, c := range cases {
		sendEmail := func(ctx context.Context, to, body string) error { return nil }
		a := NewAuthenticator(client, sendEmail, Config{})

		// Clear tokens
		if _, err := a.c.DeleteMany(ctx, bson.M{}); err != nil {
			t.Errorf("Failed to clear tokens: %v", err)
		}
		if c.savedToken != nil {
			if _, err := a.c.InsertOne(ctx, c.savedToken); err != nil {
				t.Errorf("Failed to insert token: %v", err)
			}
		}

		token, err := a.VerifyEntryCode(ctx, c.entryCode, c.client)
		if c.expErr != nil {
			if err != c.expErr {
				t.Errorf("[%s] Expected: %+v, got: %+v", c.title, c.expErr, err)
			}
		} else {
			now := time.Now()
			// Verify token:
			c.expToken.Expiration = now.Add(a.cfg.TokenExpiration)
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
		expErr     error
		expToken   *Token
	}{
		{
			title:      "unknown token value error",
			tokenValue: "unknown",
			expErr:     ErrUnknown,
		},
		{
			title:      "expired error",
			tokenValue: "t1",
			savedToken: &Token{Value: "t1", Expiration: time.Now().Add(-time.Second)},
			expErr:     ErrExpired,
		},
		{
			title:      "success",
			tokenValue: "t1",
			savedToken: &Token{
				Value:      "t1",
				Expiration: time.Now().Add(time.Hour),
				Client:     &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
			},
			client: &Client{UserAgent: "ua2", IP: "2.2.3.4"},
			expToken: &Token{
				Value:      "t1",
				Expiration: time.Now().Add(time.Hour),
				Client:     &Client{UserAgent: "ua2", IP: "2.2.3.4"},
			},
		},
		{
			title:      "success-nil-client",
			tokenValue: "t1",
			savedToken: &Token{
				Value:      "t1",
				Expiration: time.Now().Add(time.Hour),
				Client:     &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
			},
			expToken: &Token{
				Value:      "t1",
				Expiration: time.Now().Add(time.Hour),
				Client:     &Client{UserAgent: "ua", IP: "1.2.3.4", At: time.Now().Add(-time.Minute)},
			},
		},
		{
			title:      "success-nil-client-no-saved-client",
			tokenValue: "t1",
			savedToken: &Token{
				Value:      "t1",
				Expiration: time.Now().Add(time.Hour),
			},
			expToken: &Token{
				Value:      "t1",
				Expiration: time.Now().Add(time.Hour),
			},
		},
	}

	for _, c := range cases {
		sendEmail := func(ctx context.Context, to, body string) error { return nil }
		a := NewAuthenticator(client, sendEmail, Config{})

		// Clear tokens
		if _, err := a.c.DeleteMany(ctx, bson.M{}); err != nil {
			t.Errorf("Failed to clear tokens: %v", err)
		}
		if c.savedToken != nil {
			if _, err := a.c.InsertOne(ctx, c.savedToken); err != nil {
				t.Errorf("Failed to insert token: %v", err)
			}
		}

		token, err := a.VerifyToken(ctx, c.tokenValue, c.client)
		if c.expErr != nil {
			if err != c.expErr {
				t.Errorf("[%s] Expected: %+v, got: %+v", c.title, c.expErr, err)
			}
		} else {
			now := time.Now()
			// Verify token:
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

// tokensMatch compares to tokens "deeply", comparing timestamps using diffTime().
func tokensDiffer(t1, t2 *Token) bool {
	return t1.Email != t2.Email ||
		t2.LoweredEmail != t2.LoweredEmail ||
		timesDiffer(t1.Created, t2.Created) ||
		t1.EntryCode != t2.EntryCode ||
		clientsDiffer(t1.EntryClient, t2.EntryClient) ||
		t1.EntryCodeVerified != t2.EntryCodeVerified ||
		clientsDiffer(t1.Client, t2.Client) ||
		timesDiffer(t1.Expiration, t2.Expiration) ||
		t1.Value != t2.Value
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

// timesDiffer tells if 2 time instances are different from each other
// in the meaning that their difference is bigger than 1 second.
func timesDiffer(t1, t2 time.Time) bool {
	const maxDelta = time.Second
	delta := t1.Sub(t2)
	return delta > maxDelta || delta < -maxDelta
}
