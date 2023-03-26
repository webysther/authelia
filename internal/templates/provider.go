package templates

import (
	"fmt"
	th "html/template"
	"path"
)

// New creates a new templates' provider.
func New(config Config) (provider *Provider, err error) {
	provider = &Provider{
		config: config,
	}

	if err = provider.load(); err != nil {
		return nil, err
	}

	return provider, nil
}

// Provider of templates.
type Provider struct {
	config    Config
	templates Templates
}

// GetPasswordResetEmailTemplate returns the EmailTemplate for Password Reset notifications.
func (p *Provider) GetPasswordResetEmailTemplate() (t *EmailTemplate) {
	return p.templates.notification.passwordReset
}

// GetIdentityVerificationEmailTemplate returns the EmailTemplate for Identity Verification notifications.
func (p *Provider) GetIdentityVerificationEmailTemplate() (t *EmailTemplate) {
	return p.templates.notification.identityVerification
}

// GetOpenIDConnectAuthorizeResponseFormPostTemplate returns a Template used to generate the OpenID Connect 1.0 Form Post Authorize Response.
func (p *Provider) GetOpenIDConnectAuthorizeResponseFormPostTemplate() (t *th.Template) {
	return p.templates.oidc.formpost
}

func (p *Provider) load() (err error) {
	var errs []error

	if p.templates.notification.identityVerification, err = loadEmailTemplate(TemplateNameEmailIdentityVerification, p.config.EmailTemplatesPath); err != nil {
		errs = append(errs, err)
	}

	if p.templates.notification.passwordReset, err = loadEmailTemplate(TemplateNameEmailPasswordReset, p.config.EmailTemplatesPath); err != nil {
		errs = append(errs, err)
	}

	var data []byte

	if data, err = embedFS.ReadFile(path.Join("src", TemplateCategoryOpenIDConnect, TemplateNameOIDCAuthorizeFormPost)); err != nil {
		errs = append(errs, err)
	} else if p.templates.oidc.formpost, err = th.
		New("oidc/AuthorizeResponseFormPost.html").
		Funcs(FuncMap()).
		Parse(string(data)); err != nil {
		errs = append(errs, err)
	}

	if len(errs) != 0 {
		for i, e := range errs {
			if i == 0 {
				err = e
				continue
			}

			err = fmt.Errorf("%v, %w", err, e)
		}

		return fmt.Errorf("one or more errors occurred loading templates: %w", err)
	}

	return nil
}
