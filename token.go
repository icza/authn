package authn

import "time"

// Client holds some information about the client.
type Client struct {
	// User agent of the client.
	UserAgent string `bson:"agent,omitempty"`

	// IP address of the client.
	IP string `bson:"ip,omitempty"`

	// At tells when the token was accessed.
	At time.Time `bson:"at"`
}

// Token represents a token which authenticates users.
type Token struct {
	// Case-sensitive email of the owner of the token.
	Email string `bson:"email"`

	// Lowercased email of the owner of the token.
	// Used for lookups.
	LoweredEmail string `bson:"lemail"`

	// Token creation timestamp.
	Created time.Time `bson:"c"`

	// One-time entry code for the token.
	EntryCode string `bson:"ecode"`

	// EntryClient is the client information of the entry code verification.
	EntryClient *Client `bson:"eclient,omitempty"`

	// EntryCodeVerified tells if this entry code has been verified.
	EntryCodeVerified bool `bson:"ecodeVerified"`

	// Client information of the last access.
	Client *Client `bson:"client,omitempty"`

	// Expiration tells when this entry code or token expires.
	Expiration time.Time `bson:"exp"`

	// Reusable token value for authentication.
	Value string `bson:"value"`
}

// Expired tells if this token has expired.
func (t *Token) Expired() bool {
	return time.Now().After(t.Expiration)
}
