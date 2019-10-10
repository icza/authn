package authn

import "time"

// EmailParams is passed as data when executing the email template.
type EmailParams struct {
	Email               string
	SiteName            string
	EntryCode           string
	EntryCodeExpiration time.Duration
	SenderName          string

	// Data may hold custom data.
	// Its value comes from Authenticator.SendEntryCode().
	Data map[string]interface{}
}

// DefaultEmailTemplate is the default for Config.EmailTemplate.
const DefaultEmailTemplate = `Hi {{.Email}},

This is your entry code to {{.SiteName}}:

{{.EntryCode}}

The entry code is valid for {{printf "%.f" .EntryCodeExpiration.Minutes}} minutes.

If you did not request an entry code, you can ignore this email.


Regards,

{{.SenderName}}
`
