package authn

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

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
	// ID of the token.
	ID primitive.ObjectID `bson:"_id,omitempty"`

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

	// Verified tells if the token's entry code has been verified.
	Verified bool `bson:"verified"`

	// UserID is the ID of the owner of the token.
	UserID primitive.ObjectID `bson:"userID"`

	// Client information of the last access.
	Client *Client `bson:"client,omitempty"`

	// Expires tells when this entry code or token expires.
	Expires time.Time `bson:"exp"`

	// Reusable token value for authentication.
	Value string `bson:"value"`
}

// Expired tells if this token has expired.
func (t *Token) Expired() bool {
	return time.Now().After(t.Expires)
}
