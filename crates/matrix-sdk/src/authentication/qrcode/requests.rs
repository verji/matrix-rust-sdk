// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod create_rendezvous {
    use http::header::{CONTENT_TYPE, ETAG, EXPIRES, LAST_MODIFIED, LOCATION};
    use ruma::{
        api::{request, response, Metadata},
        metadata,
    };

    pub const METADATA: Metadata = metadata! {
        method: POST,
        rate_limited: true,
        authentication: None,
        history: {
            // TODO: Once we have a working rendezvous server, switch to the correct MSC.
            // unstable => "/_matrix/client/unstable/org.matrix.msc4108/rendezvous",
            unstable => "/_matrix/client/unstable/org.matrix.msc3886/rendezvous",
        }
    };

    #[request]
    #[derive(Default)]
    pub struct Request {}

    #[response]
    pub struct Response {
        #[ruma_api(header = LOCATION)]
        pub location: String,
        #[ruma_api(header = ETAG)]
        pub etag: String,
        #[ruma_api(header = EXPIRES)]
        pub expires: String,
        #[ruma_api(header = LAST_MODIFIED)]
        pub last_modified: String,
        #[ruma_api(header = CONTENT_TYPE)]
        pub content_type: Option<String>,
    }
}
