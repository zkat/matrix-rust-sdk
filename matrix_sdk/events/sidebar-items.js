initSidebarItems({"enum":[["AnyBasicEvent","Any basic event."],["AnyBasicEventContent","Any basic event."],["AnyEphemeralRoomEvent","Any ephemeral room event."],["AnyEphemeralRoomEventContent","Any ephemeral room event."],["AnyEvent","Any event."],["AnyInitialStateEvent","Any state event."],["AnyMessageEvent","Any message event."],["AnyMessageEventContent","Any message event."],["AnyPossiblyRedactedMessageEvent","An enum that holds either regular un-redacted events or redacted events."],["AnyPossiblyRedactedStateEvent","An enum that holds either regular un-redacted events or redacted events."],["AnyPossiblyRedactedStrippedStateEvent","An enum that holds either regular un-redacted events or redacted events."],["AnyPossiblyRedactedSyncMessageEvent","An enum that holds either regular un-redacted events or redacted events."],["AnyPossiblyRedactedSyncStateEvent","An enum that holds either regular un-redacted events or redacted events."],["AnyRedactedMessageEvent","Any message event."],["AnyRedactedStateEvent","Any state event."],["AnyRedactedStrippedStateEvent","Any state event."],["AnyRedactedSyncMessageEvent","Any message event."],["AnyRedactedSyncStateEvent","Any state event."],["AnyRoomEvent","Any room event."],["AnyStateEvent","Any state event."],["AnyStateEventContent","Any state event."],["AnyStrippedStateEvent","Any state event."],["AnySyncEphemeralRoomEvent","Any ephemeral room event."],["AnySyncMessageEvent","Any message event."],["AnySyncRoomEvent","Any sync room event (room event without a `room_id`, as returned in `/sync` responses)"],["AnySyncStateEvent","Any state event."],["AnyToDeviceEvent","Any to-device event."],["AnyToDeviceEventContent","Any to-device event."],["EventType","The type of an event."]],"mod":[["call","Modules for events in the m.call namespace."],["custom","Types for custom events outside of the Matrix specification."],["direct","Types for the m.direct event."],["dummy","Types for the m.dummy event."],["forwarded_room_key","Types for the m.forwarded_room_key event."],["fully_read","Types for the m.fully_read event."],["ignored_user_list","Types for the m.ignored_user_list event."],["key","Modules for events in the m.key namespace."],["macros","Re-export of all the derives needed to create your own event types."],["pdu","Types for persistent data unit schemas"],["policy","Modules for events in the m.policy namespace."],["presence","A presence event is represented by a struct with a set content field."],["push_rules","Types for the m.push_rules event."],["reaction","Types for the m.reaction event."],["receipt","Types for the m.receipt event."],["relation","Types describing event relations after MSC 2674, 2675, 2676, 2677."],["room","Modules for events in the m.room namespace."],["room_key","Types for the m.room_key event."],["room_key_request","Types for the m.room_key_request event."],["sticker","Types for the m.sticker event."],["tag","Types for the m.tag event."],["typing","Types for the m.typing event."]],"struct":[["BasicEvent","A basic event – one that consists only of it’s type and the `content` object."],["EphemeralRoomEvent","An ephemeral room event."],["FromStrError","An error when attempting to create a value from a string via the `FromStr` trait."],["InitialStateEvent","A minimal state event, used for creating a new room."],["InvalidInput","An error returned when attempting to create an event with data that would make it invalid."],["MessageEvent","A message event."],["RedactedMessageEvent","A redacted message event."],["RedactedStateEvent","A redacted state event."],["RedactedStrippedStateEvent","A stripped-down redacted state event."],["RedactedSyncMessageEvent","A redacted message event without a `room_id`."],["RedactedSyncStateEvent","A redacted state event without a `room_id`."],["RedactedSyncUnsigned","Extra information about a redacted sync event that is not incorporated into the sync event’s hash."],["RedactedUnsigned","Extra information about a redacted event that is not incorporated into the event’s hash."],["Relations","Precompiled list of relations to this event grouped by relation type."],["StateEvent","A state event."],["StrippedStateEvent","A stripped-down state event, used for previews of rooms the user has been invited to."],["SyncEphemeralRoomEvent","An ephemeral room event without a `room_id`."],["SyncMessageEvent","A message event without a `room_id`."],["SyncStateEvent","A state event without a `room_id`."],["ToDeviceEvent","An event sent using send-to-device messaging."],["Unsigned","Extra information about an event that is not incorporated into the event’s hash."]],"trait":[["BasicEventContent","Marker trait for the content of a basic event."],["EphemeralRoomEventContent","Marker trait for the content of an ephemeral room event."],["EventContent","The base trait that all event content types implement."],["MessageEventContent","Marker trait for the content of a message event."],["RawExt","Extension trait for Raw"],["RedactedEventContent","The base trait that all redacted event content types implement."],["RedactedMessageEventContent","Marker trait for the content of a redacted message event."],["RedactedStateEventContent","Marker trait for the content of a redacted state event."],["RoomEventContent","Marker trait for the content of a room event."],["StateEventContent","Marker trait for the content of a state event."]]});