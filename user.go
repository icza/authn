package authn

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// User represents a user that owns tokens.
// A user may have multiple emails, and emails may be changed later,
// the User (identified by its ID) will remain the same.
type User[UserData any] struct {
	// ID of the user.
	ID bson.ObjectID `bson:"_id"`

	// Lowercased emails of the user.
	LoweredEmails []string `bson:"lemails"`

	// User creation timestamp.
	Created time.Time `bson:"c"`

	// Data may hold arbitrary data.
	Data UserData `bson:"data,omitempty"`
}
