initSidebarItems({"derive":[["Incoming","Generating an ‘Incoming’ version of the type this derive macro is used on."]],"enum":[["DeviceKeyAlgorithm","The basic key algorithms in the specification."],["EventEncryptionAlgorithm","An encryption algorithm to be used to encrypt messages sent to a room."],["IdParseError","An error encountered when trying to parse an invalid ID string."],["RoomVersionId","A Matrix room version ID."],["SigningKeyAlgorithm","The signing key algorithms defined in the Matrix spec."]],"macro":[["assign","Mutate a struct value in a declarative style."],["device_id","Shorthand for `<&DeviceId>::from`."],["device_key_id","Compile-time checked `DeviceKeyId` construction."],["event_id","Compile-time checked `EventId` construction."],["int","Creates an `Int` from a numeric literal."],["mxc_uri","Compile-time checked `MxcUri` construction."],["room_alias_id","Compile-time checked `RoomAliasId` construction."],["room_id","Compile-time checked `RoomId` construction."],["room_version_id","Compile-time checked `RoomVersionId` construction."],["server_name","Compile-time checked `ServerName` construction."],["server_signing_key_id","Compile-time checked `ServerSigningKeyId` construction."],["uint","Creates a `UInt` from a numeric literal."],["user_id","Compile-time checked `UserId` construction."]],"mod":[["api","(De)serializable types for various Matrix APIs requests and responses and abstractions for them."],["common","Common types for the Ruma crates."],["signatures","Digital signatures according to the Matrix specification."]],"struct":[["ClientSecret","A client secret."],["DeviceId","A Matrix key ID."],["DeviceKeyId","A key algorithm and a device id, combined with a ‘:’."],["EventId","A Matrix event ID."],["Int","An integer limited to the range of integers that can be represented exactly by an f64."],["KeyId","A key algorithm and key name delimited by a colon."],["KeyName","A Matrix key identifier."],["MatrixToUri","The `matrix.to` URI representation of a user, room or event."],["MilliSecondsSinceUnixEpoch","A timestamp represented as the number of milliseconds since the unix epoch."],["MxcUri","A URI that should be a Matrix-spec compliant MXC URI."],["RoomAliasId","A Matrix room alias ID."],["RoomId","A Matrix room ID."],["RoomOrAliasId","A Matrix room ID or a Matrix room alias ID."],["SecondsSinceUnixEpoch","A timestamp represented as the number of seconds since the unix epoch."],["ServerName","A Matrix-spec compliant server name."],["SessionId","A session ID."],["Signatures","Map of all signatures, grouped by entity"],["TransactionId","A Matrix transaction ID."],["UInt","An integer limited to the range of non-negative integers that can be represented exactly by an f64."],["UserId","A Matrix user ID."]],"type":[["DeviceSignatures","Map of device signatures for an event, grouped by user."],["DeviceSigningKeyId","Algorithm + key name for device keys."],["EntitySignatures","Map of key identifier to signature values."],["ServerSignatures","Map of server signatures for an event, grouped by server."],["ServerSigningKeyId","Algorithm + key name for homeserver signing keys."]]});