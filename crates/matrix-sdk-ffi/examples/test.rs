use std::sync::Arc;

use futures_util::StreamExt;
use matrix_sdk::{config::SyncSettings, ruma::RoomId, LoopCtrl, deserialized_responses::SyncRoomEvent, Error};
use matrix_sdk_ffi::{*, client::Client};

fn main() {

    let room_id = <&RoomId>::try_from("!NMoyFpQxIVYaQIfQHG:matrix.org").unwrap();

    let client = login_new_client(
        "./RustTest".to_owned(),
        "".to_owned(),
        "".to_owned(),
    )
    .unwrap();

    let restore_token = client.restore_token().unwrap();
    fetch_backward_batch(client, room_id);

    let restored_client = login_with_token("./RustTests".to_owned(), restore_token).unwrap();
    fetch_backward_batch(restored_client, room_id);
}

fn fetch_backward_batch(client: Arc<Client>, room_id: &RoomId) {
    RUNTIME.block_on(client.sync_with_callback(SyncSettings::default(), |_| async {
        let room = client.get_room(room_id).unwrap();

        let backward_stream = room.timeline_backward().await.expect("Failed acquiring timeline streams");

        let results = backward_stream.take(30).collect::<Vec<_>>().await;
        print_results(results);

        LoopCtrl::Break
    }));
}

fn print_results(results: Vec<Result<SyncRoomEvent, Error>>) {
    for result in results.iter() {
        match result {
            Ok(event) => { 
                match event.event_id() {
                    Some(id) => { println!("{}", id)}
                    _ => {}
                }
             }
            _ => {}
        }
    }    

    println!("")
}
