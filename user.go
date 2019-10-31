package authn

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User represents a user that owns tokens.
// A user may have multiple emails, and emails may be changed later,
// the User (identified by its ID) will remain the same.
type User struct {
	// ID of the user.
	ID primitive.ObjectID `bson:"_id"`

	// Lowercased emails of the user.
	LoweredEmails []string `bson:"lemails"`

	// User creation timestamp.
	Created time.Time `bson:"c"`
}
