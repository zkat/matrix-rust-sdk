initSidebarItems({"attr":[["async_trait",""]],"enum":[["Error","Internal representation of errors."],["RoomType","Enum keeping track in which state the room is, e.g. if our own user is joined, invited, or has left the room."],["StoreError","State store specific error type."]],"mod":[["deserialized_responses",""],["executor","Abstraction over an executor so we can spawn tasks under WASM the same way we do usually."],["instant",""],["locks",""],["media","Common types for media content."]],"struct":[["BaseClient","A no IO Client implementation."],["BaseClientConfig","Configuration for the creation of the `BaseClient`."],["Room","The underlying room data structure collecting state for joined, left and invited rooms."],["RoomInfo","The underlying pure data structure for joined and left rooms."],["RoomMember","A member of a room."],["Session","A user session, containing an access token and information about the associated user account."],["StateChanges","Store state changes and pass them to the StateStore."],["Store","A state store wrapper for the SDK."]],"trait":[["AsyncTraitDeps","Super trait that is used for our store traits, this trait will differ if it’s used on WASM. WASM targets will not require `Send` and `Sync` to have implemented, while other targets will."],["StateStore","An abstract state store trait that can be used to implement different stores for the SDK."]],"type":[["Result","Result type of the rust-sdk."]]});