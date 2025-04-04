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

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	// DefaultAuthnDBName is the default for Config.AuthnDBName.
	DefaultAuthnDBName = "authn"

	// DefaultTokensCollectionName is the default for Config.TokensCollectionName.
	DefaultTokensCollectionName = "tokens"

	// DefaultUsersCollectionName is the default for Config.UsersCollectionName.
	DefaultUsersCollectionName = "users"

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

	// UsersCollectionName is the name of the database collection used by the
	// Authenticator to store users.
	UsersCollectionName string

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
type Authenticator[UserData any] struct {
	// mongoClient used for database operations.
	mongoClient *mongo.Client

	// sendEmail is a function to send emails.
	// It's on the implementation to use a proper "Subject" and appropriate "From" field.
	sendEmail EmailSenderFunc

	// cfg to use.
	cfg Config

	// emailTempl generates the email body for sending out entry codes.
	emailTempl *template.Template

	// ct is the tokens collection
	ct *mongo.Collection

	// cu is the users collection
	cu *mongo.Collection
}

// EmailSenderFunc is the type of the function used to send out emails.
type EmailSenderFunc func(ctx context.Context, to, body string) error

// NewAuthenticator creates a new Authenticator.
// This function panics if mongoClient or sendEmail are nil, or if
// Config.EmailTemplate is provided but is invalid.
func NewAuthenticator[UserData any](
	mongoClient *mongo.Client,
	sendEmail EmailSenderFunc,
	cfg Config,
) *Authenticator[UserData] {

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
	if cfg.UsersCollectionName == "" {
		cfg.UsersCollectionName = DefaultUsersCollectionName
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

	db := mongoClient.Database(cfg.AuthnDBName)

	a := &Authenticator[UserData]{
		mongoClient: mongoClient,
		sendEmail:   sendEmail,
		cfg:         cfg,
		emailTempl:  template.Must(template.New("").Parse(cfg.EmailTemplate)),
		ct:          db.Collection(cfg.TokensCollectionName),
		cu:          db.Collection(cfg.UsersCollectionName),
	}

	a.initDB()

	return a
}

// initDB initializes the authn database. This includes:
//   - ensure required indices exist
func (a *Authenticator[_]) initDB() {
	_, err := a.ct.Indexes().CreateMany(context.Background(), []mongo.IndexModel{
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
		{
			Keys: bson.D{
				{Key: "userID", Value: 1},
				{Key: "verified", Value: 1},
				{Key: "exp", Value: 1},
			},
		},
	})
	if err != nil {
		log.Printf("Failed to create authn db indices: %v", err)
	}

	_, err = a.cu.Indexes().CreateMany(context.Background(), []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "lemails", Value: 1},
			},
			Options: options.Index().SetUnique(true),
		},
	})
	if err != nil {
		log.Printf("Failed to create authn db indices: %v", err)
	}
}

// ErrInvalidEmail indicates that the provided email address is invalid.
var ErrInvalidEmail = errors.New("invalid email")

// SendEntryCode sends a one-time entry code to the given email address.
// Should be called when a user wants to login.
//
// If client is provided, it will be saved as Token.EntryClient, At field filled
// with current timestamp. If client is nil, EntryClient will not be set.
//
// If email is invalid,  ErrInvalidEmail is returned.
//
// data is set as EmailParams.Data, and will be available in the email template.
// The default email template does not use it, so it may be nil if you use the
// default email template.
func (a *Authenticator[_]) SendEntryCode(ctx context.Context, email string, client *Client, data map[string]any) (err error) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return ErrInvalidEmail
	}

	codeData := make([]byte, a.cfg.EntryCodeBytes)
	if _, err := rand.Read(codeData); err != nil {
		return fmt.Errorf("failed to read random data: %w", err)
	}
	// Technically value is not yet required at this phase, but it's unique in DB
	// so we must generate it here (else insertion would fail).
	valueData := make([]byte, a.cfg.TokenValueBytes)
	if _, err := rand.Read(valueData); err != nil {
		return fmt.Errorf("failed to read random data: %w", err)
	}

	// Entry code and token must be unique. Check it by inserting first to avoid
	// emailing out someone else's entry code or token.

	now := time.Now()
	if client != nil {
		client.At = now
	}
	token := &Token{
		Email:        addr.Address,
		LoweredEmail: strings.ToLower(addr.Address),
		Created:      now,
		EntryCode:    hex.EncodeToString(codeData),
		EntryClient:  client,
		Expires:      now.Add(a.cfg.EntryCodeExpiration),
		Value:        base64.RawURLEncoding.EncodeToString(valueData),
	}

	if _, err := a.ct.InsertOne(ctx, token); err != nil {
		return fmt.Errorf("failed to insert token: %w", err)
	}

	// Now try to send email...
	// But if error occurs further down the road, remove the inserted token.
	defer func() {
		if err != nil {
			// Remove inserted token:
			if _, err2 := a.ct.DeleteOne(ctx, bson.M{"ecode": token.EntryCode}); err2 != nil {
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
		SenderName:          a.cfg.SenderName,
		Data:                data,
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
	// ErrAlreadyVerified indicates an attempt to verify an already
	// verified entry code.
	ErrAlreadyVerified = errors.New("already verified")

	// ErrUnknown indicates that the entry code or token value is unknown.
	ErrUnknown = errors.New("unknown")

	// ErrExpired indicates that the entry code or token has expired.
	ErrExpired = errors.New("expired")
)

// Validator is a function which can check a token before it is accepted and updated
// in Authenticator.VerifyEntryCode() and Authenticator.VerifyToken(). The validator
// receives the persisted, un-updated token and the new client passed to the
// above functions.
//
// Validators may be used to perform extensive checks on the client, e.g. check
// and restrict IP addresses or disallow changed user agents.
type Validator func(ctx context.Context, token *Token, client *Client) error

// VerifyEntryCode verifies the given entry code.
// Should be called to verify user's email upon login.
//
// If client is provided, it will be saved as Token.EntryClient, At field filled
// with current timestamp. If client is nil, EntryClient will not be updated.
//
// If the entry code is unknown, ErrUnknown is returned.
// If the entry code has expired, ErrExpired is returned.
//
// An entry code can only be verified once. If the entry code is known
// but has been verified before, ErrAlreadyVerified is returned.
//
// If there are validators passed, they are called before the token is accepted
// and updated, in the order they are provided, which may veto the decision.
// If a validation error occurs, an error wrapping that is returned early.
// If a user exists associated with the token's email at the time of the verification,
// Token.UserID is set to the existing user's ID. If no such user exists, no user is created
// when calling the validators.
//
// If validation passes and no user exists associated with the token's email address,
// a new user is created automatically, and Token.UserID is set to this new user's ID.
// Changes to the user's email later on will not affect Token.UserID.
func (a *Authenticator[UserData]) VerifyEntryCode(ctx context.Context, code string, client *Client, validators ...Validator) (token *Token, err error) {
	if err = a.ct.FindOne(ctx, bson.M{"ecode": code}).Decode(&token); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrUnknown
		}
		return nil, fmt.Errorf("failed to load token: %w", err)
	}
	if token.Verified {
		return nil, ErrAlreadyVerified
	}
	if token.Expired() {
		return nil, ErrExpired
	}

	// Lookup user (we do this so validators can use this information if they want to):
	var user *User[UserData]
	if err = a.cu.FindOne(ctx, bson.M{"lemails": token.LoweredEmail}).Decode(&user); err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("failed to load user: %w", err)
		}
	}
	if user != nil {
		token.UserID = user.ID
	}

	for _, validator := range validators {
		if err := validator(ctx, token, client); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
	}

	if user == nil {
		// Create new user:
		user = &User[UserData]{
			ID:            bson.NewObjectID(),
			LoweredEmails: []string{token.LoweredEmail},
			Created:       time.Now(),
		}
		if _, err := a.cu.InsertOne(ctx, user); err != nil {
			return nil, fmt.Errorf("failed to insert user: %w", err)
		}
		token.UserID = user.ID
	}

	// Fill new state into token (only returned if update succeeds):
	token.Verified = true
	now := time.Now()
	token.Expires = now.Add(a.cfg.TokenExpiration)

	setDoc := bson.M{
		"verified": true,
		"userID":   token.UserID,
		"exp":      token.Expires,
	}

	if client != nil {
		token.EntryClient = client
		token.EntryClient.At = now
		setDoc["eclient"] = token.EntryClient
	}

	// Use 2-phase update:
	var updateResult *mongo.UpdateResult
	updateResult, err = a.ct.UpdateOne(ctx,
		bson.M{
			"ecode":    code,
			"verified": false,
		},
		bson.M{"$set": setDoc},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update token: %w", err)
	}
	if updateResult.ModifiedCount == 0 {
		// We end up here if the entry code was concurrently verified.
		return nil, ErrAlreadyVerified
	}

	// All good:
	return
}

// VerifyToken verifies the given token value.
// Should be called to verify the authenticity of a logged in user.
//
// If client is provided, it will be saved as Token.Client, At field filled
// with current timestamp, and Token.Used will also be incremented.
// If client is nil, Client will not be updated.
//
// If the token value is unknown, ErrUnknown is returned.
// If the token has expired, ErrExpired is returned.
//
// If there are validators passed, they are called before the token is accepted
// and updated, in the order they are provided, which may veto the decision.
// If a validation error occurs, an error wrapping that is returned early.
func (a *Authenticator[_]) VerifyToken(ctx context.Context, tokenValue string, client *Client, validators ...Validator) (token *Token, err error) {
	filter := bson.M{"value": tokenValue}
	if err = a.ct.FindOne(ctx, filter).Decode(&token); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrUnknown
		}
		return nil, fmt.Errorf("failed to load token: %w", err)
	}
	if token.Expired() {
		return nil, ErrExpired
	}

	for _, validator := range validators {
		if err := validator(ctx, token, client); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
	}

	if client != nil {
		// Update token's client
		now := time.Now()
		token.Client = client
		token.Client.At = now

		_, err = a.ct.UpdateOne(ctx,
			filter,
			bson.M{
				"$set": bson.M{
					"client": token.Client,
				},
				"$inc": bson.M{
					"used": 1,
				},
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to update token: %w", err)
		}
		token.Used++
	}

	// All good:
	return
}

// InvalidateToken invalidates the given token.
// Should be called when a user wants to log out (only the given session).
//
// If the token value is unknown, ErrUnknown is returned.
// If the token has expired (or has already been invalidated), ErrExpired is returned.
func (a *Authenticator[_]) InvalidateToken(ctx context.Context, tokenValue string) (err error) {
	filter := bson.M{"value": tokenValue}
	var token *Token
	if err = a.ct.FindOne(ctx, filter).Decode(&token); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return ErrUnknown
		}
		return fmt.Errorf("failed to load token: %w", err)
	}
	if token.Expired() {
		return ErrExpired
	}

	// Update token's expiration to make it expired.
	_, err = a.ct.UpdateOne(ctx,
		filter,
		bson.M{
			"$set": bson.M{
				"exp": time.Now(),
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to update token: %w", err)
	}

	// All good:
	return
}

// Tokens returns all valid tokens associated with the owner of the given token.
//
// If the token value is unknown, ErrUnknown is returned.
// If the token has expired (or has already been invalidated), ErrExpired is returned.
func (a *Authenticator[_]) Tokens(ctx context.Context, tokenValue string) (tokens []*Token, err error) {
	var token *Token
	if err = a.ct.FindOne(ctx, bson.M{"value": tokenValue}).Decode(&token); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrUnknown
		}
		return nil, fmt.Errorf("failed to load token: %w", err)
	}
	if token.Expired() {
		return nil, ErrExpired
	}

	return a.UserTokens(ctx, token.UserID)
}

// UserTokens returns all valid tokens for the given user.
// No error is reported if the given user does not exists (tokens will be empty of course).
func (a *Authenticator[_]) UserTokens(ctx context.Context, userID bson.ObjectID) (tokens []*Token, err error) {
	filter := bson.M{
		"userID":   userID,
		"exp":      bson.M{"$gt": time.Now()},
		"verified": true,
	}

	curs, err := a.ct.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}
	if err = curs.All(ctx, &tokens); err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}

	// All good:
	return
}

// GetUser returns the user document for the given ID.
func (a *Authenticator[UserData]) GetUser(ctx context.Context, userID bson.ObjectID) (user *User[UserData], err error) {
	err = a.cu.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
	return
}

// SetUserEmails sets the assigned (lowercased) emails of a user.
//
// Emails must be unique across all users. Attempting to set an email that is
// already associated to another user will result in an error.
func (a *Authenticator[_]) SetUserEmails(ctx context.Context, userID bson.ObjectID, loweredEmails []string) (err error) {
	var updateResult *mongo.UpdateResult
	updateResult, err = a.cu.UpdateByID(ctx,
		userID,
		bson.M{"$set": bson.M{"lemails": loweredEmails}},
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	if updateResult.ModifiedCount == 0 {
		return ErrUnknown
	}

	return
}
