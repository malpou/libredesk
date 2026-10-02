package oidc

import (
	"database/sql"
	"embed"
	"fmt"
	"strings"

	"github.com/abhinavxd/libredesk/internal/crypto"
	"github.com/abhinavxd/libredesk/internal/dbutil"
	"github.com/abhinavxd/libredesk/internal/envelope"
	"github.com/abhinavxd/libredesk/internal/oidc/models"
	"github.com/abhinavxd/libredesk/internal/stringutil"
	"github.com/jmoiron/sqlx"
	"github.com/knadh/go-i18n"
	"github.com/zerodha/logf"
)

var (
	//go:embed queries.sql
	efs         embed.FS
	redirectURL = "/api/v1/oidc/%d/finish"
)

// Manager handles oidc-related operations.
type Manager struct {
	q             queries
	lo            *logf.Logger
	i18n          *i18n.I18n
	setting       settingsStore
	encryptionKey string
	// envClientID is set only when both oidc.client_id and oidc.client_secret are configured.
	envClientID string
}

// Opts contains options for initializing the Manager.
type Opts struct {
	DB            *sqlx.DB
	Lo            *logf.Logger
	I18n          *i18n.I18n
	EncryptionKey string
	// EnvClientID and EnvClientSecret are the oidc.client_id / oidc.client_secret config values.
	// When both are set, the provider with this client ID gets its secret from config and its credentials are locked in the admin API.
	EnvClientID     string
	EnvClientSecret string
}

// queries contains prepared SQL queries.
type queries struct {
	GetAllOIDC *sqlx.Stmt `query:"get-all-oidc"`
	GetOIDC    *sqlx.Stmt `query:"get-oidc"`
	InsertOIDC *sqlx.Stmt `query:"insert-oidc"`
	UpdateOIDC *sqlx.Stmt `query:"update-oidc"`
	DeleteOIDC *sqlx.Stmt `query:"delete-oidc"`
}

type settingsStore interface {
	GetAppRootURL() (string, error)
}

// New creates and returns a new instance of the oidc Manager.
func New(opts Opts, setting settingsStore) (*Manager, error) {
	var q queries
	if err := dbutil.ScanSQLFile("queries.sql", &q, opts.DB, efs); err != nil {
		return nil, err
	}
	return &Manager{
		q:             q,
		lo:            opts.Lo,
		i18n:          opts.I18n,
		setting:       setting,
		encryptionKey: opts.EncryptionKey,
		envClientID:   envClientID(opts.EnvClientID, opts.EnvClientSecret),
	}, nil
}

// envClientID returns the configured client ID when both credentials are configured, else "".
func envClientID(clientID, clientSecret string) string {
	if clientID == "" || clientSecret == "" {
		return ""
	}
	return clientID
}

// secretFromEnv reports whether the provider with this client ID uses the configured secret.
func (o *Manager) secretFromEnv(clientID string) bool {
	return o.envClientID != "" && clientID == o.envClientID
}

// Get returns an oidc by id.
func (o *Manager) Get(id int) (models.OIDC, error) {
	var oidc models.OIDC
	if err := o.q.GetOIDC.Get(&oidc, id); err != nil {
		if err == sql.ErrNoRows {
			return oidc, envelope.NewError(envelope.NotFoundError, o.i18n.T("validation.notFoundOidcProvider"), nil)
		}

		o.lo.Error("error fetching oidc", "error", err)
		return oidc, envelope.NewError(envelope.GeneralError, o.i18n.T("globals.messages.somethingWentWrong"), nil)
	}

	o.decryptOIDC(&oidc)

	oidc.SetProviderLogo()
	rootURL, err := o.setting.GetAppRootURL()
	if err != nil {
		return models.OIDC{}, err
	}
	oidc.RedirectURI = fmt.Sprintf(rootURL+redirectURL, oidc.ID)
	oidc.ClientSecretFromEnv = o.secretFromEnv(oidc.ClientID)
	return oidc, nil
}

// GetAll retrieves all oidc.
func (o *Manager) GetAll() ([]models.OIDC, error) {
	var oidc = make([]models.OIDC, 0)
	if err := o.q.GetAllOIDC.Select(&oidc); err != nil {
		o.lo.Error("error fetching oidc", "error", err)
		return oidc, envelope.NewError(envelope.GeneralError, o.i18n.T("globals.messages.somethingWentWrong"), nil)
	}

	// Get root URL of the app.
	rootURL, err := o.setting.GetAppRootURL()
	if err != nil {
		return nil, err
	}

	o.decryptOIDCSlice(oidc)

	// Set logo and redirect URL for each record
	for i := range oidc {
		oidc[i].RedirectURI = fmt.Sprintf(rootURL+redirectURL, oidc[i].ID)
		oidc[i].SetProviderLogo()
		oidc[i].ClientSecretFromEnv = o.secretFromEnv(oidc[i].ClientID)
	}
	return oidc, nil
}

// Create adds a new oidc.
func (o *Manager) Create(oidc models.OIDC) (models.OIDC, error) {
	if err := o.validateCredentials(oidc); err != nil {
		return models.OIDC{}, err
	}

	// Encrypt sensitive fields before saving
	encryptedClientID, encryptedClientSecret, err := o.encryptOIDC(oidc.ClientID, oidc.ClientSecret)
	if err != nil {
		return models.OIDC{}, envelope.NewError(envelope.GeneralError, o.i18n.T("globals.messages.somethingWentWrong"), nil)
	}

	var createdOIDC models.OIDC
	if err := o.q.InsertOIDC.Get(&createdOIDC, oidc.Name, oidc.Provider, oidc.ProviderURL, encryptedClientID, encryptedClientSecret, oidc.LogoURL); err != nil {
		o.lo.Error("error inserting oidc", "error", err)
		return models.OIDC{}, envelope.NewError(envelope.GeneralError, o.i18n.T("globals.messages.somethingWentWrong"), nil)
	}

	o.decryptOIDC(&createdOIDC)
	createdOIDC.ClientSecretFromEnv = o.secretFromEnv(createdOIDC.ClientID)

	return createdOIDC, nil
}

// Update updates a oidc by id.
func (o *Manager) Update(id int, oidc models.OIDC) (models.OIDC, error) {
	current, err := o.Get(id)
	if err != nil {
		return models.OIDC{}, err
	}

	// A masked secret keeps the stored one.
	if strings.Contains(oidc.ClientSecret, stringutil.PasswordDummy) {
		oidc.ClientSecret = current.ClientSecret
	}
	if oidc, err = o.lockEnvCredentials(current, oidc); err != nil {
		return models.OIDC{}, err
	}
	if err := o.validateCredentials(oidc); err != nil {
		return models.OIDC{}, err
	}

	// Encrypt sensitive fields before updating
	encryptedClientID, encryptedClientSecret, err := o.encryptOIDC(oidc.ClientID, oidc.ClientSecret)
	if err != nil {
		return models.OIDC{}, envelope.NewError(envelope.GeneralError, o.i18n.T("globals.messages.somethingWentWrong"), nil)
	}

	var updatedOIDC models.OIDC
	if err := o.q.UpdateOIDC.Get(&updatedOIDC, id, oidc.Name, oidc.Provider, oidc.ProviderURL, encryptedClientID, encryptedClientSecret, oidc.Enabled, oidc.LogoURL); err != nil {
		o.lo.Error("error updating oidc", "error", err)
		return models.OIDC{}, envelope.NewError(envelope.GeneralError, o.i18n.T("globals.messages.somethingWentWrong"), nil)
	}

	o.decryptOIDC(&updatedOIDC)
	updatedOIDC.ClientSecretFromEnv = o.secretFromEnv(updatedOIDC.ClientID)

	return updatedOIDC, nil
}

// Delete deletes a oidc by its id.
func (o *Manager) Delete(id int) error {
	if _, err := o.q.DeleteOIDC.Exec(id); err != nil {
		o.lo.Error("error deleting oidc", "error", err)
		return envelope.NewError(envelope.GeneralError, o.i18n.T("globals.messages.somethingWentWrong"), nil)
	}
	return nil
}

// validateCredentials rejects a blank client id or secret; either one fails every token exchange, locking out OIDC-only agents with nothing to show the admin went wrong.
func (o *Manager) validateCredentials(oidc models.OIDC) error {
	if strings.TrimSpace(oidc.ClientID) == "" {
		return envelope.NewError(envelope.InputError, o.i18n.Ts("globals.messages.empty", "name", "`client_id`"), nil)
	}
	if strings.TrimSpace(oidc.ClientSecret) == "" && !o.secretFromEnv(oidc.ClientID) {
		return envelope.NewError(envelope.InputError, o.i18n.Ts("globals.messages.empty", "name", "`client_secret`"), nil)
	}
	return nil
}

// lockEnvCredentials keeps the stored credentials of a provider whose secret comes from config.
// The client ID cannot change (it is what ties the provider to the configured secret), and an empty secret keeps the stored one.
func (o *Manager) lockEnvCredentials(current, req models.OIDC) (models.OIDC, error) {
	if !o.secretFromEnv(current.ClientID) {
		return req, nil
	}
	if req.ClientID != current.ClientID || (req.ClientSecret != "" && req.ClientSecret != current.ClientSecret) {
		return models.OIDC{}, envelope.NewError(envelope.InputError, o.i18n.T("admin.sso.credentialsManagedByEnv"), nil)
	}
	req.ClientSecret = current.ClientSecret
	return req, nil
}

// encryptOIDC encrypts sensitive OIDC fields (ClientID and ClientSecret).
// Returns the encrypted values and any error encountered.
func (o *Manager) encryptOIDC(clientID, clientSecret string) (encClientID, encClientSecret string, err error) {
	encClientID, err = crypto.Encrypt(clientID, o.encryptionKey)
	if err != nil {
		o.lo.Error("error encrypting client_id", "error", err)
		return "", "", err
	}

	encClientSecret, err = crypto.Encrypt(clientSecret, o.encryptionKey)
	if err != nil {
		o.lo.Error("error encrypting client_secret", "error", err)
		return "", "", err
	}

	return encClientID, encClientSecret, nil
}

// Decrypt failures clear the field so the app stays usable across encryption_key rotation.
func (o *Manager) decryptOIDC(oidc *models.OIDC) {
	if oidc.ClientID != "" {
		decrypted, err := crypto.Decrypt(oidc.ClientID, o.encryptionKey)
		if err != nil {
			o.lo.Error("error decrypting client_id, clearing field", "error", err, "oidc_id", oidc.ID)
			oidc.ClientID = ""
		} else {
			oidc.ClientID = decrypted
		}
	}

	if oidc.ClientSecret != "" {
		decrypted, err := crypto.Decrypt(oidc.ClientSecret, o.encryptionKey)
		if err != nil {
			o.lo.Error("error decrypting client_secret, clearing field", "error", err, "oidc_id", oidc.ID)
			oidc.ClientSecret = ""
		} else {
			oidc.ClientSecret = decrypted
		}
	}
}

func (o *Manager) decryptOIDCSlice(oidcs []models.OIDC) {
	for i := range oidcs {
		o.decryptOIDC(&oidcs[i])
	}
}
