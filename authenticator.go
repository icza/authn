package authn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	entryCode := hex.EncodeToString(codeData)

	// Entry code must be unique. Check it by inserting first to avoid
	// emailing out someone else's entry code.

	now := time.Now()
	if client != nil {
		client.At = now
	}
	token := &Token{
		Email:        addr.Address,
		LoweredEmail: strings.ToLower(addr.Address),
		Created:      now,
		EntryCode:    entryCode,
		EntryClient:  client,
		Expiration:   now.Add(a.cfg.EntryCodeExpiration),
	}

	if _, err := a.c.InsertOne(ctx, token); err != nil {
		return fmt.Errorf("failed to insert token: %w", err)
	}

	// Now try to send email...
	// But if error occurs further down the road, remove the inserted token.
	defer func() {
		if err != nil {
			// Remove inserted token:
			if _, err2 := a.c.DeleteOne(ctx, bson.M{"ecode": entryCode}); err2 != nil {
				// TODO we can't do anything about it.
			}
		}
	}()

	emailParams := &EmailParams{
		Email:               addr.Address,
		SiteName:            a.cfg.SiteName,
		EntryCode:           entryCode,
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

// VerifyEntryCode verifies the given entry code.
// If the code is invalid, token will be nil.
// Should be called to verify user's email upon login.
// If client is provided, it will be saved as Token.EntryClient.
func (a *Authenticator) VerifyEntryCode(code string, client *Client) (token *Token, err error) {
	// TODO
	return
}

// VerifyToken verifies the given token value.
// If the token value is invalid, token will be nil.
// Should be called to verify the authenticity of a logged in user.
// If client is provided, it will be saved as Token.Client.
func (a *Authenticator) VerifyToken(tokenValue string, client *Client) (token *Token, err error) {
	// TODO
	return
}

// InvalidateToken invalidates the given token.
// If the token value is invalid or the token is already invalidated, this method is a no-op.
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
