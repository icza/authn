package authn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"strings"
	"text/template"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	// DefaultAuthnDBName is the default for Config.AuthnDBName.
	DefaultAuthnDBName = "authn"

	// DefaultTokensCollectionName is the default for Config.TokensCollectionName.
	DefaultTokensCollectionName = "tokens"

	// DefaultEntryCodeBytes is the default for Config.EntryCodeBytes.
	DefaultEntryCodeBytes = 8

	// DefaultEntryCodeExpiration is the default for Config.EntryCodeExpiration.
	DefaultEntryCodeExpiration = 20 * time.Minute

	// DefaultTokenValueBytes is the default for Config.TokenValueBytes.
	DefaultTokenValueBytes = 24

	// DefaultTokenExpiration is the default for Config.TokenExpiration.
	DefaultTokenExpiration = 6 * 31 * 24 * time.Hour // ~6 months
)

// Config holds Authenticator configuration.
// A zero value is a valid configuration, see constants for default values.
type Config struct {
	// AuthnDBName is the name of the database used by the Authenticator.
	AuthnDBName string

	// TokensCollectionName is the name of the database collection used by the
	// Authenticator to store tokens.
	TokensCollectionName string

	// EntryCodeBytes tells how many bytes to use for entry codes.
	// The actual entry code is a hex string, will be twice as many hex digits.
	EntryCodeBytes int

	// EntryCodeExpiration tells how long an unverified entry code remains valid.
	EntryCodeExpiration time.Duration

	// TokenValueBytes tells how many bytes to use for token values.
	// The actual token string is base64, will be roughly 4/3 times longer.
	TokenValueBytes int

	// TokenExpiration tells how long a token remains valid.
	TokenExpiration time.Duration

	// EmailTemplate is the template text of the emails to be sent out
	// with entry codes.
	EmailTemplate string

	// SiteName is used in the entry code emails.
	// Has no default, should be provided if the default email template is used.
	SiteName string

	// SenderName is used in the entry code emails.
	// Has no default, should be provided if the default email template is used.
	SenderName string
}

// Authenticator is the implementation of a passwordless authenticator.
// It's safe for concurrent use by multiple goroutines.
type Authenticator struct {
	// mongoClient used for database operations.
	mongoClient *mongo.Client

	// sendEmail is a function to send emails.
	// It's on the implementation to use a proper "Subject" and appropriate "From" field.
	sendEmail EmailSenderFunc

	// cfg to use.
	cfg Config

	// emailTempl generates the email body for sending out entry codes.
	emailTempl *template.Template

	// c is the token collection
	c *mongo.Collection
}

// EmailSenderFunc is the type of the function used to send out emails.
type EmailSenderFunc func(ctx context.Context, to, body string) error

// NewAuthenticator creates a new Authenticator.
// This function panics if mongoClient or sendEmail are nil, or if
// Config.EmailTemplate is provided but is invalid.
func NewAuthenticator(
	mongoClient *mongo.Client,
	sendEmail EmailSenderFunc,
	cfg Config,
) *Authenticator {

	if mongoClient == nil {
		panic("mongoClient must be provided")
	}
	if sendEmail == nil {
		panic("sendEmail must be provided")
	}

	if cfg.AuthnDBName == "" {
		cfg.AuthnDBName = DefaultAuthnDBName
	}
	if cfg.TokensCollectionName == "" {
		cfg.TokensCollectionName = DefaultTokensCollectionName
	}
	if cfg.EntryCodeBytes == 0 {
		cfg.EntryCodeBytes = DefaultEntryCodeBytes
	}
	if cfg.EntryCodeExpiration == 0 {
		cfg.EntryCodeExpiration = DefaultEntryCodeExpiration
	}
	if cfg.TokenValueBytes == 0 {
		cfg.TokenValueBytes = DefaultTokenValueBytes
	}
	if cfg.TokenExpiration == 0 {
		cfg.TokenExpiration = DefaultTokenExpiration
	}
	if cfg.EmailTemplate == "" {
		cfg.EmailTemplate = DefaultEmailTemplate
	}

	a := &Authenticator{
		mongoClient: mongoClient,
		sendEmail:   sendEmail,
		cfg:         cfg,
		emailTempl:  template.Must(template.New("").Parse(cfg.EmailTemplate)),
		c:           mongoClient.Database(cfg.AuthnDBName).Collection(cfg.TokensCollectionName),
	}

	a.initDB()

	return a
}

// initDB initializes the authn database. This includes:
//   - ensure required indices exist
func (a *Authenticator) initDB() {
	_, err := a.c.Indexes().CreateMany(context.Background(), []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "ecode", Value: 1},
			},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{
				{Key: "value", Value: 1},
			},
			Options: options.Index().SetUnique(true),
		},
	})
	if err != nil {
		log.Printf("Failed to create authn db indices: %v", err)
	}
}

// SendEntryCode sends a one-time entry code to the given email address.
// Should be called when a user wants to login.
// If client is provided, it will be saved as Token.EntryClient.
//
// data is set as EmailParams.Data, and will be available in the email template.
// The default email template does not use it, so it may be nil if you use the
// default email template.
func (a *Authenticator) SendEntryCode(ctx context.Context, email string, client *Client, data map[string]interface{}) (err error) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	codeData := make([]byte, a.cfg.EntryCodeBytes)
	if _, err := rand.Read(codeData); err != nil {
		return fmt.Errorf("failed to read random data: %w", err)
	}
	// Technically value is not yet required at this phase, but it's unique in DB
	// so we must generate it too (else insertion would fail).
	valueData := make([]byte, a.cfg.TokenValueBytes)
	if _, err := rand.Read(valueData); err != nil {
		return fmt.Errorf("failed to read random data: %w", err)
	}

	// Entry code and token must be unique. Check it by inserting first to avoid
	// emailing out someone else's entry code or token.

	if client == nil {
		client = &Client{}
	}
	now := time.Now()
	client.At = now
	token := &Token{
		Email:        addr.Address,
		LoweredEmail: strings.ToLower(addr.Address),
		Created:      now,
		EntryCode:    hex.EncodeToString(codeData),
		EntryClient:  client,
		Expiration:   now.Add(a.cfg.EntryCodeExpiration),
		Value:        base64.RawURLEncoding.EncodeToString(valueData),
	}

	if _, err := a.c.InsertOne(ctx, token); err != nil {
		return fmt.Errorf("failed to insert token: %w", err)
	}

	// Now try to send email...
	// But if error occurs further down the road, remove the inserted token.
	defer func() {
		if err != nil {
			// Remove inserted token:
			if _, err2 := a.c.DeleteOne(ctx, bson.M{"ecode": token.EntryCode}); err2 != nil {
				// We can't do anything about it.
				log.Printf("Can't remove token with entry code %q: %v", token.EntryCode, err2)
			}
		}
	}()

	emailParams := &EmailParams{
		Email:               addr.Address,
		SiteName:            a.cfg.SiteName,
		EntryCode:           token.EntryCode,
		EntryCodeExpiration: a.cfg.EntryCodeExpiration,
		Data:                data,
		SenderName:          a.cfg.SenderName,
	}
	body := &strings.Builder{}
	if err := a.emailTempl.Execute(body, emailParams); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	if err := a.sendEmail(ctx, addr.Address, body.String()); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

var (
	// ErrEntryCodeAlreadyVerified indicates an attempt to verify an already
	// verified entry code.
	ErrEntryCodeAlreadyVerified = errors.New("entry code already verified")

	// ErrUnknown indicates that the entry code or token value is unknown.
	ErrUnknown = errors.New("unknown")

	// ErrExpired indicates that the entry code or token has expired.
	ErrExpired = errors.New("expired")
)

// VerifyEntryCode verifies the given entry code.
// Should be called to verify user's email upon login.
// If client is provided, it will be saved as Token.EntryClient.
//
// If the entry code is unknown, ErrUnknown is returned.
// If the entry code has expired, ErrExpired is returned.
//
// An entry code can only be verified once. If the entry code is known
// but has been verified before, ErrEntryCodeAlreadyVerified is returned.
func (a *Authenticator) VerifyEntryCode(ctx context.Context, code string, client *Client) (token *Token, err error) {
	if err = a.c.FindOne(ctx, bson.M{"ecode": code}).Decode(&token); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrUnknown
		}
		return nil, fmt.Errorf("failed to load token: %w", err)
	}
	if token.EntryCodeVerified {
		return nil, ErrEntryCodeAlreadyVerified
	}
	if token.Expired() {
		return nil, ErrExpired
	}

	// Fill new state into token (only returned if update succeeds):
	token.EntryCodeVerified = true
	if client != nil {
		token.EntryClient = client
	} else {
		if token.EntryClient == nil {
			token.EntryClient = &Client{}
		}
	}
	now := time.Now()
	token.EntryClient.At = now
	token.Expiration = now.Add(a.cfg.TokenExpiration)

	// Use 2-phase update:
	var updateResult *mongo.UpdateResult
	updateResult, err = a.c.UpdateOne(ctx,
		bson.M{
			"ecode":         code,
			"ecodeVerified": false,
		},
		bson.M{
			"$set": bson.M{
				"ecodeVerified": true,
				"eclient":       token.EntryClient,
				"exp":           token.Expiration,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update token: %w", err)
	}
	if updateResult.ModifiedCount == 0 {
		// We end up here if the entry code was concurrently verified.
		return nil, ErrEntryCodeAlreadyVerified
	}

	// All good:
	return
}

// VerifyToken verifies the given token value.
// Should be called to verify the authenticity of a logged in user.
// If client is provided, it will be saved as Token.Client.
//
// If the token value is unknown, ErrUnknown is returned.
// If the token has expired, ErrExpired is returned.
func (a *Authenticator) VerifyToken(ctx context.Context, tokenValue string, client *Client) (token *Token, err error) {
	filter := bson.M{"value": tokenValue}
	if err = a.c.FindOne(ctx, filter).Decode(&token); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrUnknown
		}
		return nil, fmt.Errorf("failed to load token: %w", err)
	}
	if token.Expired() {
		return nil, ErrExpired
	}

	// Update token's client
	if client != nil {
		token.Client = client
	} else {
		if token.Client == nil {
			token.Client = &Client{}
		}
	}
	now := time.Now()
	token.Client.At = now

	_, err = a.c.UpdateOne(ctx,
		filter,
		bson.M{
			"$set": bson.M{
				"client": token.Client,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update token: %w", err)
	}

	// All good:
	return
}

// InvalidateToken invalidates the given token.
// If the token value is unknown or the token is already invalidated, this method is a no-op.
// Should be called when a user wants to log out (only the given session).
func (a *Authenticator) InvalidateToken(tokenValue string) (err error) {
	// TODO
	return
}

// Tokens returns all valid tokens associated with the owner of the given token.
func (a *Authenticator) Tokens(tokenValue string) (tokens []*Token, err error) {
	// TODO
	return
}
