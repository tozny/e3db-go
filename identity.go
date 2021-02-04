package e3db

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/identityClient"
	"github.com/tozny/e3db-clients-go/storageClient"
	"golang.org/x/crypto/blake2b"
)

// Identity wraps a Tozny Identity, which contains identity, realm, and client information.
type Identity struct {
	ID        int64
	Username  string
	FirstName string
	LastName  string
	Realm     *Realm
	*ToznySDKV3
}

// Realm wraps information for connecting to a Tozny Identity realm with a specific application
type Realm struct {
	Name               string
	App                string
	APIEndpoint        string
	BrokerTargetURL    string
	EmailExpiryMinutes int
	realmInfo          *identityClient.RealmInfo
}

type realmInfo struct {
	Domain string
}

type identityData struct {
	RealmName       string `json:"realm_name"`
	RealmDomain     string `json:"realm_domain"`
	AppName         string `json:"app_name"`
	APIEndpoint     string `json:"api_url"`
	UserID          int64  `json:"user_id"`
	BrokerTargetURL string `json:"broker_target_url"`
	FirstName       string `json:"first_name,omitempty"`
	LastName        string `json:"last_name,omitempty"`
}

type serializedIdentity struct {
	Config  string `json:"config"`
	Storage string `json:"storage"`
}

func (r *Realm) Info() (*identityClient.RealmInfo, error) {
	if r.realmInfo == nil {
		client := identityClient.New(e3dbClients.ClientConfig{
			Host: r.APIEndpoint,
		})
		info, err := client.RealmInfo(context.Background(), r.Name)
		if err != nil {
			return r.realmInfo, err
		}
		r.realmInfo = info
	}
	return r.realmInfo, nil
}

func (r *Realm) Register(username, password, registrationToken, email, firstName, lastName string) (*Identity, error) {
	identity := &Identity{
		Realm: r,
	}
	if r.BrokerTargetURL == "" {
		return identity, fmt.Errorf("realm BrokerTargetURL can not be empty")
	}
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		return identity, err
	}
	signingKeyPair, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		return identity, err
	}
	info, err := r.Info()
	if err != nil {
		return identity, err
	}
	payload := identityClient.RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              info.Name,
		Identity: identityClient.Identity{
			Name:        strings.ToLower(username),
			Email:       email,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeyPair.Public.Type: signingKeyPair.Public.Material},
			FirstName:   firstName,
			LastName:    lastName,
		},
	}
	client := identityClient.New(e3dbClients.ClientConfig{
		Host: r.APIEndpoint,
	})
	registration, err := client.RegisterIdentity(context.Background(), payload)
	if err != nil {
		return identity, err
	}

	storageClient, err := NewToznySDKV3(ToznySDKConfig{
		ClientConfig: e3dbClients.ClientConfig{
			ClientID:  registration.Identity.ToznyID.String(),
			APIKey:    registration.Identity.APIKeyID,
			APISecret: registration.Identity.APIKeySecret,
			Host:      r.APIEndpoint,
			AuthNHost: r.APIEndpoint,
			EncryptionKeys: e3dbClients.EncryptionKeys{
				Public: e3dbClients.Key{
					Material: encryptionKeyPair.Public.Material,
					Type:     e3dbClients.DefaultEncryptionKeyType,
				},
				Private: e3dbClients.Key{
					Material: encryptionKeyPair.Private.Material,
					Type:     e3dbClients.DefaultEncryptionKeyType,
				},
			},
			SigningKeys: e3dbClients.SigningKeys{
				Public: e3dbClients.Key{
					Material: signingKeyPair.Public.Material,
					Type:     e3dbClients.DefaultSigningKeyType,
				},
				Private: e3dbClients.Key{
					Material: signingKeyPair.Private.Material,
					Type:     e3dbClients.DefaultSigningKeyType,
				},
			},
		},
		APIEndpoint: r.APIEndpoint,
	})
	if err != nil {
		return identity, err
	}
	identity.ID = registration.Identity.ID
	identity.Username = registration.Identity.Name
	identity.FirstName = registration.Identity.FirstName
	identity.LastName = registration.Identity.LastName
	identity.ToznySDKV3 = storageClient

	_, err = identity.writePasswordNote(password)
	if err != nil {
		return identity, err
	}
	_, err = identity.writeBrokerNotes(email)
	if err != nil {
		return identity, err
	}

	return identity, nil
}

func (i *Identity) deriveCredentails(password string, nameSalt string) (string, e3dbClients.EncryptionKeys, e3dbClients.SigningKeys, error) {
	nameSeed := fmt.Sprintf("%s@realm:%s", i.Username, i.Realm.Name)
	if nameSalt != "" {
		nameSeed = fmt.Sprintf("%s:%s", nameSalt, nameSeed)
	}
	hashedMessageAccumlator, err := blake2b.New(e3dbClients.Blake2BBytes, nil)
	if err != nil {
		return "", e3dbClients.EncryptionKeys{}, e3dbClients.SigningKeys{}, err
	}
	hashedMessageAccumlator.Write([]byte(nameSeed))
	hashedMessageBytes := hashedMessageAccumlator.Sum(nil)
	noteName := e3dbClients.Base64Encode(hashedMessageBytes)
	cryptoPublicKey, cryptoPrivateKey := e3dbClients.DeriveCryptoKey(
		[]byte(password),
		[]byte(nameSeed),
		e3dbClients.IdentityDerivationRounds,
	)
	cryptoKeyPair := e3dbClients.EncryptionKeys{
		Public: e3dbClients.Key{
			Type:     e3dbClients.DefaultEncryptionKeyType,
			Material: e3dbClients.Base64Encode(cryptoPublicKey[:]),
		},
		Private: e3dbClients.Key{
			Type:     e3dbClients.DefaultEncryptionKeyType,
			Material: e3dbClients.Base64Encode(cryptoPrivateKey[:]),
		},
	}
	signingPublicKey, signingPrivateKey := e3dbClients.DeriveSigningKey(
		[]byte(password),
		[]byte(cryptoKeyPair.Public.Material+cryptoKeyPair.Private.Material),
		e3dbClients.IdentityDerivationRounds,
	)
	signingKeyPair := e3dbClients.SigningKeys{
		Public: e3dbClients.Key{
			Type:     e3dbClients.DefaultSigningKeyType,
			Material: e3dbClients.Base64Encode(signingPublicKey[:]),
		},
		Private: e3dbClients.Key{
			Type:     e3dbClients.DefaultSigningKeyType,
			Material: e3dbClients.Base64Encode(signingPrivateKey[:]),
		},
	}
	return noteName, cryptoKeyPair, signingKeyPair, nil
}

func (i *Identity) writePasswordNote(password string) (*storageClient.Note, error) {
	info, err := i.Realm.Info()
	if err != nil {
		return &storageClient.Note{}, err
	}
	noteName, encryptionKeyPair, signingKeyPair, err := i.deriveCredentails(password, "")
	if err != nil {
		return &storageClient.Note{}, err
	}
	eacp := storageClient.TozIDEACP{
		RealmName: info.Domain,
	}
	eacps := &storageClient.EACP{
		TozIDEACP: &eacp,
	}
	return i.writeCredentialNote(noteName, &encryptionKeyPair, &signingKeyPair, eacps)
}

func (i *Identity) writeBrokerNotes(email string) ([]*storageClient.Note, error) {
	realmInfo, err := i.Realm.Info()
	if err != nil {
		return []*storageClient.Note{}, err
	}
	// Skip credential notes if there is no broker
	if realmInfo.BrokerIdentityToznyID == uuid.Nil {
		return []*storageClient.Note{}, nil
	}
	// Fetch the public broker info
	brokerInfo, err := i.ClientInfo(context.Background(), realmInfo.BrokerIdentityToznyID.String())
	if brokerInfo == nil {
		err = fmt.Errorf("Broker info not found for realm", realmInfo.Name)
	}
	if err != nil {
		return []*storageClient.Note{}, err
	}
	// If there is no broker, do not try to write broker notes
	// otherwise, get the broker's info
	// Email EACP
	emailEACP := storageClient.EmailEACP{
		EmailAddress:             email,
		Template:                 "claim_account",
		ProviderLink:             i.Realm.BrokerTargetURL,
		DefaultExpirationMinutes: i.Realm.EmailExpiryMinutes,
	}
	// format the name based on if first and last are provided
	name := ""
	if i.FirstName != "" {
		name = i.FirstName
	}
	if i.LastName != "" {
		if name != "" {
			name = name + " "
		}
		name = name + i.LastName
	}
	if name != "" {
		emailEACP.TemplateFields = map[string]string{"name": name}
	}
	// Create struct for looping and processing
	brokerNotes := []struct {
		eacps     *storageClient.EACP
		keyPrefix string
		keyType   string
	}{
		{
			eacps: &storageClient.EACP{
				EmailEACP: &emailEACP,
			},
			keyPrefix: "brokerKey",
			keyType:   "broker",
		},
		{
			eacps: &storageClient.EACP{
				ToznyOTPEACP: &storageClient.ToznyOTPEACP{
					Include: true,
				},
			},
			keyPrefix: "broker_otp",
			keyType:   "tozny_otp",
		},
	}
	writtenNotes := []*storageClient.Note{}
	for _, noteInfo := range brokerNotes {
		// TODO: refactor to run these concurrently
		noteKey, keyNote, err := i.writeKeyNote(noteInfo.keyPrefix, brokerInfo.PublicKey.Curve25519, brokerInfo.SigningKey.Ed25519, noteInfo.eacps)
		if err != nil {
			return []*storageClient.Note{}, err
		}
		noteName, cryptoKeyPair, signingKeyPair, err := i.deriveCredentails(noteKey, noteInfo.keyType)
		if err != nil {
			return []*storageClient.Note{}, err
		}
		keyNoteID, err := uuid.Parse(keyNote.NoteID)
		if err != nil {
			return []*storageClient.Note{}, err
		}
		brokeredEACP := &storageClient.EACP{
			LastAccessEACP: &storageClient.LastAccessEACP{
				LastReadNoteID: keyNoteID,
			},
		}
		credentialNote, err := i.writeCredentialNote(noteName, &cryptoKeyPair, &signingKeyPair, brokeredEACP)
		if err != nil {
			return []*storageClient.Note{}, err
		}
		writtenNotes = append(writtenNotes, keyNote, credentialNote)
	}
	return writtenNotes, nil
}

func (i *Identity) writeCredentialNote(noteName string, encryptionKeyPair *e3dbClients.EncryptionKeys, signingKeyPair *e3dbClients.SigningKeys, eacps *storageClient.EACP) (*storageClient.Note, error) {
	serialized, err := i.Serialize()
	rawNoteBody := NoteBody{
		"config":  serialized.Config,
		"storage": serialized.Storage,
	}

	rawCredentialNote := storageClient.Note{
		IDString:            noteName,
		ClientID:            i.ClientID,
		Mode:                e3dbClients.DefaultCryptographicMode,
		RecipientSigningKey: signingKeyPair.Public.Material,
		WriterSigningKey:    i.StorageClient.SigningKeys.Public.Material,
		WriterEncryptionKey: i.StorageClient.EncryptionKeys.Public.Material,
		Data:                rawNoteBody,
		MaxViews:            -1,
		Expires:             false,
		EACPS:               eacps,
	}
	// Sign over all the note data and the signature material itself
	privateSigningKeyBytes, err := e3dbClients.Base64Decode(i.StorageClient.SigningKeys.Private.Material)
	if err != nil {
		return &storageClient.Note{}, err
	}
	notePrivateSigningKey := [e3dbClients.SigningKeySize]byte{}
	copy(notePrivateSigningKey[:], privateSigningKeyBytes)
	signingSalt := "4fad1a84-9fd2-41f6-ba39-a4655ac1ffa5" //uuid.New().String()
	signedNote, err := i.SignNote(rawCredentialNote, &notePrivateSigningKey, signingSalt)
	if err != nil {
		return &storageClient.Note{}, err
	}
	accessKey := e3dbClients.RandomSymmetricKey()
	encryptedAccessKey, err := e3dbClients.EncryptAccessKey(accessKey, e3dbClients.EncryptionKeys{
		Private: e3dbClients.Key{
			Type:     e3dbClients.DefaultEncryptionKeyType,
			Material: i.StorageClient.EncryptionKeys.Private.Material,
		},
		Public: e3dbClients.Key{
			Type:     e3dbClients.DefaultEncryptionKeyType,
			Material: encryptionKeyPair.Public.Material,
		},
	})
	if err != nil {
		return &storageClient.Note{}, err
	}
	// Encrypt the signed note and add the encrypted version of the access
	// key to the note for the reader to be able to decrypt the note
	encryptedNoteBody := e3dbClients.EncryptData(signedNote.Data, accessKey)
	signedNote.Data = *encryptedNoteBody
	signedNote.EncryptedAccessKey = encryptedAccessKey
	// Write the credential note
	credentialNote, err := i.WriteNote(context.Background(), signedNote)
	if err != nil {
		return &storageClient.Note{}, err
	}
	return credentialNote, nil
}

func (i *Identity) writeKeyNote(prefix, cryptoKey, signingKey string, eacps *storageClient.EACP) (string, *storageClient.Note, error) {
	nameSeed := fmt.Sprintf("%s:%s@realm:%s", prefix, i.Username, i.Realm.Name)
	hashedMessageAccumlator, err := blake2b.New(e3dbClients.Blake2BBytes, nil)
	if err != nil {
		return "", &storageClient.Note{}, err
	}
	hashedMessageAccumlator.Write([]byte(nameSeed))
	hashedMessageBytes := hashedMessageAccumlator.Sum(nil)
	noteName := e3dbClients.Base64Encode(hashedMessageBytes)
	keyBytes := make([]byte, 64)
	_, err = rand.Read(keyBytes)
	if err != nil {
		return "", &storageClient.Note{}, err
	}
	noteKey := e3dbClients.Base64Encode(keyBytes)
	rawNoteBody := NoteBody{
		"broker_key": noteKey,
		"username":   i.Username,
	}

	rawCredentialNote := storageClient.Note{
		IDString:            noteName,
		ClientID:            i.ClientID,
		Mode:                e3dbClients.DefaultCryptographicMode,
		RecipientSigningKey: signingKey,
		WriterSigningKey:    i.StorageClient.SigningKeys.Public.Material,
		WriterEncryptionKey: i.StorageClient.EncryptionKeys.Public.Material,
		Data:                rawNoteBody,
		MaxViews:            -1,
		Expires:             false,
		EACPS:               eacps,
	}
	// Sign over all the broker note data and the signature material itself
	privateSigningKeyBytes, err := e3dbClients.Base64Decode(i.StorageClient.SigningKeys.Private.Material)
	if err != nil {
		return "", &storageClient.Note{}, err
	}
	notePrivateSigningKey := [e3dbClients.SigningKeySize]byte{}
	copy(notePrivateSigningKey[:], privateSigningKeyBytes)
	signingSalt := uuid.New().String()
	signedNote, err := i.SignNote(rawCredentialNote, &notePrivateSigningKey, signingSalt)
	if err != nil {
		return "", &storageClient.Note{}, err
	}
	accessKey := e3dbClients.RandomSymmetricKey()
	encryptedAccessKey, err := e3dbClients.EncryptAccessKey(accessKey, e3dbClients.EncryptionKeys{
		Private: e3dbClients.Key{
			Type:     e3dbClients.DefaultEncryptionKeyType,
			Material: i.StorageClient.EncryptionKeys.Private.Material,
		},
		Public: e3dbClients.Key{
			Type:     e3dbClients.DefaultEncryptionKeyType,
			Material: cryptoKey,
		},
	})
	if err != nil {
		return "", &storageClient.Note{}, err
	}
	// Encrypt the signed note and add the encrypted version of the access
	// key to the note for the reader to be able to decrypt the note
	encryptedNoteBody := e3dbClients.EncryptData(signedNote.Data, accessKey)
	signedNote.Data = *encryptedNoteBody
	signedNote.EncryptedAccessKey = encryptedAccessKey
	// Write the broker key note
	keyNote, err := i.WriteNote(context.Background(), signedNote)
	if err != nil {
		return "", &storageClient.Note{}, err
	}
	return noteKey, keyNote, nil
}

func (i *Identity) Serialize() (serializedIdentity, error) {
	var serialized serializedIdentity
	info, err := i.Realm.Info()
	if err != nil {
		return serialized, err
	}
	config := identityData{
		RealmName:       i.Realm.Name,
		RealmDomain:     info.Domain,
		AppName:         i.Realm.App,
		APIEndpoint:     i.Realm.APIEndpoint,
		UserID:          i.ID,
		BrokerTargetURL: i.Realm.BrokerTargetURL,
		FirstName:       i.FirstName,
		LastName:        i.LastName,
	}
	configBytes, err := json.Marshal(config)
	if err != nil {
		return serialized, err
	}
	storage := ClientConfig{
		APIKeyID:          i.StorageClient.APIKey,
		APISecret:         i.StorageClient.APISecret,
		APIURL:            i.APIEndpoint,
		ClientEmail:       "",
		ClientID:          i.ClientID,
		PublicKey:         i.StorageClient.EncryptionKeys.Public.Material,
		PrivateKey:        i.StorageClient.EncryptionKeys.Private.Material,
		PublicSigningKey:  i.StorageClient.SigningKeys.Public.Material,
		PrivateSigningKey: i.StorageClient.SigningKeys.Private.Material,
		Version:           2,
	}
	storageBytes, err := json.Marshal(storage)
	if err != nil {
		return serialized, err
	}
	serialized.Config = string(configBytes)
	serialized.Storage = string(storageBytes)
	return serialized, nil
}
