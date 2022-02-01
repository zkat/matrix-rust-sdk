initSidebarItems({"enum":[["DecryptorError","Error type for attachment decryption."],["IncomingResponse","Enum over all the incoming responses we need to receive."],["KeyExportError","Error representing a failure during key export or import."],["LocalTrust","The local trust state of a device."],["MegolmError","Error representing a failure during a group encryption operation."],["OlmError","Error representing a failure during a device to device cryptographic operation."],["OutgoingRequests","Enum over the different outgoing requests we can have."],["OutgoingVerificationRequest","An enum over the different outgoing verification based requests."],["ReadOnlyUserIdentities","Enum over the different user identity types we can have."],["ScanError","An error for the different failure modes that can happen during the validation of a scanned QR code."],["SignatureError","Error type describin different errors that happen when we check or create signatures for a Matrix JSON object."],["UserIdentities","Enum over the different user identity types we can have."],["Verification","An enum over the different verification types the SDK supports."]],"fn":[["decrypt_key_export","Try to decrypt a reader into a list of exported room keys."],["encrypt_key_export","Encrypt the list of exported room keys using the given passphrase."]],"mod":[["olm","The crypto specific Olm objects."],["store","Types and traits to implement the storage layer for the `OlmMachine`"]],"struct":[["AcceptSettings","Customize the accept-reply for a verification process"],["AttachmentDecryptor","A wrapper that transparently encrypts anything that implements `Read` as an Matrix attachment."],["AttachmentEncryptor","A wrapper that transparently encrypts anything that implements `Read`."],["CancelInfo","Information about the cancellation of a verification request or verification flow."],["CrossSigningStatus","Struct representing the state of our private cross signing keys, it shows which private cross signing keys we have locally stored."],["Device","A device represents a E2EE capable client of an user."],["Emoji","An emoji that is used for interactive verification using a short auth string."],["EncryptionSettings","Settings for an encrypted room."],["KeysBackupRequest","A request that will back up a batch of room keys to the server."],["KeysQueryRequest","Customized version of `ruma_client_api::r0::keys::get_keys::Request`, without any references."],["MasterPubkey","Wrapper for a cross signing key marking it as the master key."],["MediaEncryptionInfo","Struct holding all the information that is needed to decrypt an encrypted file."],["OlmMachine","State machine implementation of the Olm/Megolm encryption protocol used for Matrix end to end encryption."],["OutgoingRequest","Outgoing request type, holds the unique ID of the request and the actual request."],["OwnUserIdentity","Struct representing a cross signing identity of a user."],["QrVerification","An object controlling QR code style key verification flows."],["ReadOnlyDevice","A read-only version of a `Device`."],["ReadOnlyOwnUserIdentity","Struct representing a cross signing identity of our own user."],["ReadOnlyUserIdentity","Struct representing a cross signing identity of a user."],["RoomKeyImportResult","Return type for the room key importing."],["RoomMessageRequest","Customized owned request type for sending out room messages."],["Sas","Short authentication string object."],["ToDeviceRequest","Customized version of `ruma_client_api::r0::to_device::send_event_to_device::Request`"],["UploadSigningKeysRequest","Request that will publish a cross signing identity."],["UserDevices","A read only view over all devices belonging to a user."],["UserIdentity","Struct representing a cross signing identity of a user."],["VerificationRequest","An object controlling key verification requests."]]});