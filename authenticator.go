/*
Package authn provides passwordless, email-based user authentication.

The flow is the following:

  1. A user wants to login. He/she provides his/her email.
  2. A one-time entry code is emailed to him/her by Authenticator.SendEntryCode().
  3. User copies the entry code from the email, which can be verified by Authenticator.VerifyEntryCode().
  4. If the entry code was valid, a Token is presented whose value can be used
     later to authenticate the user.
  5. Authenticity of a user can be verified by Authenticator.VerifyToken().
  6. The user can be logged out by calling Authenticator.InvalidateToken().

A user may have multiple valid tokens (multiple sessions).
Authenticator.InvalidateToken() only invalidates the given token.
Authenticator.Tokens() may be used to query all valid sessions of a user.

Authenticator uses MongoDB as the persistent store, accessed via the official
mongo-go driver.

*/
package authn

import (
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

const (
	// DefaultAuthnDBName is the default for Config.AuthnDBName.
	DefaultAuthnDBName = "auth"

	// DefaultTokensCollectionName is the default for Config.TokensCollectionName.
	DefaultTokensCollectionName = "tokens"

	// DefaultEntryCodeBytes is the default for Config.EntryCodeBytes.
	DefaultEntryCodeBytes = 8

	// DefaultEntryCodeExpiration is the default for Config.EntryCodeExpiration.
	DefaultEntryCodeExpiration = 30 * time.Minute

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
}

// Authenticator is the implementation of a passwordless authenticator.
// It's safe to use it concurrently from multiple goroutines.
type Authenticator struct {
	// mongoClient used for database operations.
	mongoClient *mongo.Client

	// sendEmail is a function to send emails.
	sendEmail func(to, from, subject, body string) error

	// cfg to use
	cfg Config
}

// NewAuthenticator creates a new Authenticator.
// This function panics if mongoClient or sendEmail are nil.
func NewAuthenticator(
	mongoClient *mongo.Client,
	sendEmail func(to, from, subject, body string) error,
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

	return &Authenticator{
		mongoClient: mongoClient,
		sendEmail:   sendEmail,
		cfg:         cfg,
	}
}

// SendEntryCode sends a one-time entry code to the given email address.
// Should be called when a user wants to login.
// If client is provided, it will be saved as Token.EntryClient.
func (a *Authenticator) SendEntryCode(email string, client *Client) (err error) {
	// TODO
	return nil
}

// VerifyEntryCode verifies the given entry code.
// If the code is invalid, token will be nil.
// Should be called to verify users email upon login.
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
