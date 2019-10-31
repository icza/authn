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

The package automatically manages user identities. When an entry code verification
passes, a user identity (User) is created if one does not yet exist for the email.
This user identity (UserID) is attached to and returned with all tokens.
A user may have multiple emails, and emails can be changed
(Authenticator.SetUserEmails()) without affecting the user identity.

A user may have multiple valid tokens (multiple sessions).
Authenticator.InvalidateToken() only invalidates the given token.
Authenticator.Tokens() may be used to query all valid sessions of a user.

Authenticator uses MongoDB as the persistent store, accessed via the official
mongo-go driver.

*/
package authn
