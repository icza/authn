package authn

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
			title: "insertFail error",
			email: "as@as.hu",
			cfg: Config{
				AuthnDBName: "/\\. \"$\x00", // Invalid dbname (invalid chars) so insert will fail
			},
			expErr: true,
		},
		{
			title:  "success",
			email:  "As@as.hu",
			client: &Client{UserAgent: "ua1", IP: "1.2.3.4"},
		},
		{
			title:  "success-custom-data",
			email:  "As@as.hu",
			client: &Client{UserAgent: "ua1", IP: "1.2.3.4"},
			cfg: Config{
				EmailTemplate: "{{.Data.Seven}}",
			},
			data:    map[string]interface{}{"Seven": 7},
			expBody: "7",
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

		if c.cfg.AuthnDBName == "" {
			// Clear tokens
			if _, err := a.c.DeleteMany(ctx, bson.M{}); err != nil {
				t.Errorf("Failed to clear tokens: %v", err)
			}
		}

		err := a.SendEntryCode(ctx, c.email, c.client, c.data)
		if gotErr := err != nil; gotErr != c.expErr {
			t.Errorf("[%s] Expected err: %v, got: %v", c.title, c.expErr, gotErr)
		}

		if err == nil {
			// Verify token:
			var token *Token
			if err := a.c.FindOne(ctx, bson.M{}).Decode(&token); err != nil {
				t.Errorf("[%s] Can't find token: %v", c.title, err)
			}
			expToken := new(Token)
			*expToken = *token
			expToken.Email = c.email
			expToken.LoweredEmail = strings.ToLower(c.email)
			expToken.Client = nil
			expToken.EntryClient.At = c.client.At
			expToken.Value = ""
			now := time.Now()
			if *token != *expToken || *token.EntryClient != *c.client || // Explicit set fields above must match
				len(token.EntryCode) != a.cfg.EntryCodeBytes*2 || // Entry code must be of specific length
				diffTime(now.Add(a.cfg.EntryCodeExpiration), token.Expiration) || // Expiration must be set
				diffTime(now, token.Created) || // Created must be set
				diffTime(now, token.EntryClient.At) { // EntryClient.At must be set
				t.Errorf("[%s] Expected: %+v, got: %+v", c.title, expToken, token)
			}
		}
	}
}

// diffTime tells if 2 time instances are different from each other
// in the meaning that their difference is bigger than 1 second.
func diffTime(t1, t2 time.Time) bool {
	const maxDelta = time.Second
	delta := t1.Sub(t2)
	return delta > maxDelta || delta < -maxDelta
}
