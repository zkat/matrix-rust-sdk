(function() {var implementors = {};
implementors["matrix_crypto"] = [{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_crypto/struct.MigrationData.html\" title=\"struct matrix_crypto::MigrationData\">MigrationData</a>","synthetic":false,"types":["matrix_crypto::MigrationData"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_crypto/struct.PickledAccount.html\" title=\"struct matrix_crypto::PickledAccount\">PickledAccount</a>","synthetic":false,"types":["matrix_crypto::PickledAccount"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_crypto/struct.PickledSession.html\" title=\"struct matrix_crypto::PickledSession\">PickledSession</a>","synthetic":false,"types":["matrix_crypto::PickledSession"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_crypto/struct.PickledInboundGroupSession.html\" title=\"struct matrix_crypto::PickledInboundGroupSession\">PickledInboundGroupSession</a>","synthetic":false,"types":["matrix_crypto::PickledInboundGroupSession"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_crypto/struct.CrossSigningKeyExport.html\" title=\"struct matrix_crypto::CrossSigningKeyExport\">CrossSigningKeyExport</a>","synthetic":false,"types":["matrix_crypto::CrossSigningKeyExport"]}];
implementors["matrix_sdk_base"] = [{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"matrix_sdk_base/enum.RoomType.html\" title=\"enum matrix_sdk_base::RoomType\">RoomType</a>","synthetic":false,"types":["matrix_sdk_base::rooms::normal::RoomType"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_base/struct.RoomInfo.html\" title=\"struct matrix_sdk_base::RoomInfo\">RoomInfo</a>","synthetic":false,"types":["matrix_sdk_base::rooms::normal::RoomInfo"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"matrix_sdk_base/enum.DisplayName.html\" title=\"enum matrix_sdk_base::DisplayName\">DisplayName</a>","synthetic":false,"types":["matrix_sdk_base::rooms::DisplayName"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_base/struct.Session.html\" title=\"struct matrix_sdk_base::Session\">Session</a>","synthetic":false,"types":["matrix_sdk_base::session::Session"]},{"text":"impl&lt;'de, C:&nbsp;StateEventContent + RedactContent&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"matrix_sdk_base/enum.MinimalStateEvent.html\" title=\"enum matrix_sdk_base::MinimalStateEvent\">MinimalStateEvent</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C::Redacted: StateEventContent + RedactedEventContent + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;C: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,&nbsp;</span>","synthetic":false,"types":["matrix_sdk_base::utils::MinimalStateEvent"]},{"text":"impl&lt;'de, C&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_base/struct.OriginalMinimalStateEvent.html\" title=\"struct matrix_sdk_base::OriginalMinimalStateEvent\">OriginalMinimalStateEvent</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: StateEventContent,<br>&nbsp;&nbsp;&nbsp;&nbsp;C: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,&nbsp;</span>","synthetic":false,"types":["matrix_sdk_base::utils::OriginalMinimalStateEvent"]},{"text":"impl&lt;'de, C&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_base/struct.RedactedMinimalStateEvent.html\" title=\"struct matrix_sdk_base::RedactedMinimalStateEvent\">RedactedMinimalStateEvent</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: StateEventContent + RedactedEventContent,<br>&nbsp;&nbsp;&nbsp;&nbsp;C: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,&nbsp;</span>","synthetic":false,"types":["matrix_sdk_base::utils::RedactedMinimalStateEvent"]}];
implementors["matrix_sdk_common"] = [{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_common/deserialized_responses/struct.AmbiguityChange.html\" title=\"struct matrix_sdk_common::deserialized_responses::AmbiguityChange\">AmbiguityChange</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::AmbiguityChange"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_common/deserialized_responses/struct.AmbiguityChanges.html\" title=\"struct matrix_sdk_common::deserialized_responses::AmbiguityChanges\">AmbiguityChanges</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::AmbiguityChanges"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"matrix_sdk_common/deserialized_responses/enum.VerificationState.html\" title=\"enum matrix_sdk_common::deserialized_responses::VerificationState\">VerificationState</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::VerificationState"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"matrix_sdk_common/deserialized_responses/enum.AlgorithmInfo.html\" title=\"enum matrix_sdk_common::deserialized_responses::AlgorithmInfo\">AlgorithmInfo</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::AlgorithmInfo"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_common/deserialized_responses/struct.EncryptionInfo.html\" title=\"struct matrix_sdk_common::deserialized_responses::EncryptionInfo\">EncryptionInfo</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::EncryptionInfo"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_common/deserialized_responses/struct.SyncRoomEvent.html\" title=\"struct matrix_sdk_common::deserialized_responses::SyncRoomEvent\">SyncRoomEvent</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::SyncRoomEvent"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_common/deserialized_responses/struct.SyncResponse.html\" title=\"struct matrix_sdk_common::deserialized_responses::SyncResponse\">SyncResponse</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::SyncResponse"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_common/deserialized_responses/struct.Rooms.html\" title=\"struct matrix_sdk_common::deserialized_responses::Rooms\">Rooms</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::Rooms"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_common/deserialized_responses/struct.JoinedRoom.html\" title=\"struct matrix_sdk_common::deserialized_responses::JoinedRoom\">JoinedRoom</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::JoinedRoom"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_common/deserialized_responses/struct.UnreadNotificationsCount.html\" title=\"struct matrix_sdk_common::deserialized_responses::UnreadNotificationsCount\">UnreadNotificationsCount</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::UnreadNotificationsCount"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_common/deserialized_responses/struct.LeftRoom.html\" title=\"struct matrix_sdk_common::deserialized_responses::LeftRoom\">LeftRoom</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::LeftRoom"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_common/deserialized_responses/struct.Timeline.html\" title=\"struct matrix_sdk_common::deserialized_responses::Timeline\">Timeline</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::Timeline"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_common/deserialized_responses/struct.TimelineSlice.html\" title=\"struct matrix_sdk_common::deserialized_responses::TimelineSlice\">TimelineSlice</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::TimelineSlice"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"matrix_sdk_common/deserialized_responses/enum.MemberEvent.html\" title=\"enum matrix_sdk_common::deserialized_responses::MemberEvent\">MemberEvent</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::MemberEvent"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_common/deserialized_responses/struct.MembersResponse.html\" title=\"struct matrix_sdk_common::deserialized_responses::MembersResponse\">MembersResponse</a>","synthetic":false,"types":["matrix_sdk_common::deserialized_responses::MembersResponse"]}];
implementors["matrix_sdk_crypto"] = [{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/struct.MediaEncryptionInfo.html\" title=\"struct matrix_sdk_crypto::MediaEncryptionInfo\">MediaEncryptionInfo</a>","synthetic":false,"types":["matrix_sdk_crypto::file_encryption::attachments::MediaEncryptionInfo"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/store/struct.GossipRequest.html\" title=\"struct matrix_sdk_crypto::store::GossipRequest\">GossipRequest</a>","synthetic":false,"types":["matrix_sdk_crypto::gossiping::GossipRequest"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"matrix_sdk_crypto/store/enum.SecretInfo.html\" title=\"enum matrix_sdk_crypto::store::SecretInfo\">SecretInfo</a>","synthetic":false,"types":["matrix_sdk_crypto::gossiping::SecretInfo"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/struct.ReadOnlyDevice.html\" title=\"struct matrix_sdk_crypto::ReadOnlyDevice\">ReadOnlyDevice</a>","synthetic":false,"types":["matrix_sdk_crypto::identities::device::ReadOnlyDevice"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"matrix_sdk_crypto/enum.LocalTrust.html\" title=\"enum matrix_sdk_crypto::LocalTrust\">LocalTrust</a>","synthetic":false,"types":["matrix_sdk_crypto::identities::device::LocalTrust"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/struct.MasterPubkey.html\" title=\"struct matrix_sdk_crypto::MasterPubkey\">MasterPubkey</a>","synthetic":false,"types":["matrix_sdk_crypto::identities::user::MasterPubkey"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"matrix_sdk_crypto/enum.ReadOnlyUserIdentities.html\" title=\"enum matrix_sdk_crypto::ReadOnlyUserIdentities\">ReadOnlyUserIdentities</a>","synthetic":false,"types":["matrix_sdk_crypto::identities::user::ReadOnlyUserIdentities"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/struct.ReadOnlyUserIdentity.html\" title=\"struct matrix_sdk_crypto::ReadOnlyUserIdentity\">ReadOnlyUserIdentity</a>","synthetic":false,"types":["matrix_sdk_crypto::identities::user::ReadOnlyUserIdentity"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/struct.ReadOnlyOwnUserIdentity.html\" title=\"struct matrix_sdk_crypto::ReadOnlyOwnUserIdentity\">ReadOnlyOwnUserIdentity</a>","synthetic":false,"types":["matrix_sdk_crypto::identities::user::ReadOnlyOwnUserIdentity"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/olm/struct.OlmMessageHash.html\" title=\"struct matrix_sdk_crypto::olm::OlmMessageHash\">OlmMessageHash</a>","synthetic":false,"types":["matrix_sdk_crypto::olm::account::OlmMessageHash"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/olm/struct.PickledAccount.html\" title=\"struct matrix_sdk_crypto::olm::PickledAccount\">PickledAccount</a>","synthetic":false,"types":["matrix_sdk_crypto::olm::account::PickledAccount"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/olm/struct.PickledInboundGroupSession.html\" title=\"struct matrix_sdk_crypto::olm::PickledInboundGroupSession\">PickledInboundGroupSession</a>","synthetic":false,"types":["matrix_sdk_crypto::olm::group_sessions::inbound::PickledInboundGroupSession"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/olm/struct.EncryptionSettings.html\" title=\"struct matrix_sdk_crypto::olm::EncryptionSettings\">EncryptionSettings</a>","synthetic":false,"types":["matrix_sdk_crypto::olm::group_sessions::outbound::EncryptionSettings"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/olm/struct.ShareInfo.html\" title=\"struct matrix_sdk_crypto::olm::ShareInfo\">ShareInfo</a>","synthetic":false,"types":["matrix_sdk_crypto::olm::group_sessions::outbound::ShareInfo"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/olm/struct.PickledOutboundGroupSession.html\" title=\"struct matrix_sdk_crypto::olm::PickledOutboundGroupSession\">PickledOutboundGroupSession</a>","synthetic":false,"types":["matrix_sdk_crypto::olm::group_sessions::outbound::PickledOutboundGroupSession"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/olm/struct.ExportedRoomKey.html\" title=\"struct matrix_sdk_crypto::olm::ExportedRoomKey\">ExportedRoomKey</a>","synthetic":false,"types":["matrix_sdk_crypto::olm::group_sessions::ExportedRoomKey"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/olm/struct.PickledSession.html\" title=\"struct matrix_sdk_crypto::olm::PickledSession\">PickledSession</a>","synthetic":false,"types":["matrix_sdk_crypto::olm::session::PickledSession"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/olm/struct.PickledCrossSigningIdentity.html\" title=\"struct matrix_sdk_crypto::olm::PickledCrossSigningIdentity\">PickledCrossSigningIdentity</a>","synthetic":false,"types":["matrix_sdk_crypto::olm::signing::PickledCrossSigningIdentity"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/olm/struct.CrossSigningStatus.html\" title=\"struct matrix_sdk_crypto::olm::CrossSigningStatus\">CrossSigningStatus</a>","synthetic":false,"types":["matrix_sdk_crypto::olm::signing::CrossSigningStatus"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/struct.ToDeviceRequest.html\" title=\"struct matrix_sdk_crypto::ToDeviceRequest\">ToDeviceRequest</a>","synthetic":false,"types":["matrix_sdk_crypto::requests::ToDeviceRequest"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/store/struct.EncryptedPickleKey.html\" title=\"struct matrix_sdk_crypto::store::EncryptedPickleKey\">EncryptedPickleKey</a>","synthetic":false,"types":["matrix_sdk_crypto::store::pickle_key::EncryptedPickleKey"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/store/struct.RecoveryKey.html\" title=\"struct matrix_sdk_crypto::store::RecoveryKey\">RecoveryKey</a>","synthetic":false,"types":["matrix_sdk_crypto::store::RecoveryKey"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/types/struct.CrossSigningKey.html\" title=\"struct matrix_sdk_crypto::types::CrossSigningKey\">CrossSigningKey</a>","synthetic":false,"types":["matrix_sdk_crypto::types::cross_signing_key::CrossSigningKey"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/types/struct.DeviceKeys.html\" title=\"struct matrix_sdk_crypto::types::DeviceKeys\">DeviceKeys</a>","synthetic":false,"types":["matrix_sdk_crypto::types::device_keys::DeviceKeys"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/types/struct.UnsignedDeviceInfo.html\" title=\"struct matrix_sdk_crypto::types::UnsignedDeviceInfo\">UnsignedDeviceInfo</a>","synthetic":false,"types":["matrix_sdk_crypto::types::device_keys::UnsignedDeviceInfo"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_crypto/types/struct.SignedKey.html\" title=\"struct matrix_sdk_crypto::types::SignedKey\">SignedKey</a>","synthetic":false,"types":["matrix_sdk_crypto::types::one_time_keys::SignedKey"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"matrix_sdk_crypto/types/enum.OneTimeKey.html\" title=\"enum matrix_sdk_crypto::types::OneTimeKey\">OneTimeKey</a>","synthetic":false,"types":["matrix_sdk_crypto::types::one_time_keys::OneTimeKey"]}];
implementors["matrix_sdk_store_encryption"] = [{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"matrix_sdk_store_encryption/struct.EncryptedValue.html\" title=\"struct matrix_sdk_store_encryption::EncryptedValue\">EncryptedValue</a>","synthetic":false,"types":["matrix_sdk_store_encryption::EncryptedValue"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()