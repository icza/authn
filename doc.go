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
