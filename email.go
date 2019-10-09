package authn

import "time"

// EmailParams is passed as data when executing the email template.
type EmailParams struct {
	Email               string
	EntryCode           string
	EntryCodeExpiration time.Duration

	// Data may hold custom data.
	// Its value comes from Authenticator.SendEntryCode().
	// When the default email template is used, as a minimum, it should contain
	// "Site" and "SenderName".
	Data map[string]interface{}
}

// DefaultEmailTemplate is the default for Config.EmailTemplate.
const DefaultEmailTemplate = `Hi {{.Email}},

This is your entry code to {{.Data.Site}}:

{{.EntryCode}}

The entry code is valid for {{printf "%.0f" .EntryCodeExpiration.Minutes}} minutes.

If you did not request an entry code, you can ignore this email.


Regards,

{{.Data.SenderName}}
`
