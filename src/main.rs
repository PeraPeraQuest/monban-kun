// main.rs
// Copyright 2025 Patrick Meade
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Json, Redirect},
    routing::get,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serenity::model::guild::Member;
use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info};
use tracing_subscriber::{
    EnvFilter, fmt, fmt::format::FmtSpan, prelude::__tracing_subscriber_SubscriberExt,
    registry::Registry,
};
use uuid::Uuid;

/// application level state for Monban-kun
#[derive(Clone)]
struct MonbanKunState {
    /// the session table; everybody authorized to play
    sessions: Arc<Mutex<HashMap<String, UserSession>>>,
    /// a shared reqwest Client used to make web calls
    client: Client,
    /// this is the PeraPera Quest application
    discord_client_id: String,
    /// this is the PeraPera Quest application secret
    discord_client_secret: String,
    /// this is the ID of the PeraPera Quest Discord guild
    discord_guild_id: String,
    /// this is the redirect URL that Discord is expecting
    discord_redirect_uri: String,
    /// optional: provide a Discord webhook URL if you want monban-kun
    /// to announce the people who connect to play PeraPera Quest
    discord_webhook_url: Option<String>,
}

/// the user's session, with their Discord identity; PeraPera Quest
/// can use this to identify the player so they can play the game
#[derive(Serialize)]
struct UserSession {
    /// the UUID for this session; generated at auth time, stored in a
    /// cookie in the user's browser
    session_uuid: String,
    /// the Member struct from Discord
    discord: Member,
}

/// OAuthQueryParams are the parameters provided to the authorization
/// callback, after Discord verifies that the User does intend to authorize
/// PeraPera Quest to access their Discord information.
#[derive(Deserialize)]
struct OAuthQueryParams {
    /// authorization code provided by Discord
    code: String,
    /// security nonce originally provided to Discord at request time
    state: Option<String>,
}

/// OAuthResponse is the response from Discord after redeeming the
/// authorization code provided to the authorization callback. Discord
/// issues an access_token (with requested scope(s)) that can be used
/// with the Discord API to query information about user.
#[derive(Deserialize)]
#[allow(dead_code)]
struct OAuthResponse {
    /// the type of token issued (i.e.: "Bearer")
    token_type: String,
    /// the secret that allow us to query the Discord API about the user
    access_token: String,
    /// number of seconds until our access token expires
    expires_in: u64,
    /// the secret to get another token without a whole re-auth cycle
    refresh_token: String,
    /// the scopes available to this token
    scope: String,
}

/// main function; the microservice application starts here
#[tokio::main]
async fn main() {
    // setup logging and log something nice
    setup_logging();
    info!("Monban-kun starting up...");

    // build our application state using environment variables
    let sessions = Arc::new(Mutex::new(HashMap::new()));
    let client = Client::new();
    let discord_client_id = env::var("DISCORD_CLIENT_ID").expect("Missing DISCORD_CLIENT_ID");
    let discord_client_secret =
        env::var("DISCORD_CLIENT_SECRET").expect("Missing DISCORD_CLIENT_SECRET");
    let discord_guild_id = env::var("DISCORD_GUILD_ID").expect("Missing DISCORD_GUILD_ID");
    let discord_redirect_uri =
        env::var("DISCORD_REDIRECT_URI").expect("Missing DISCORD_REDIRECT_URI");
    let discord_webhook_url = env::var("DISCORD_WEBHOOK_URL").ok();
    let state = MonbanKunState {
        sessions,
        client,
        discord_client_id,
        discord_client_secret,
        discord_guild_id,
        discord_redirect_uri,
        discord_webhook_url,
    };

    // build the application routing and layers
    let app = Router::new()
        .route("/auth/discord", get(handle_auth_discord))
        .route("/login", get(handle_login))
        .route("/whoami", get(handle_whoami))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // bind the port we want to listen on for requests
    let addr = std::env::var("BIND_ADDRESS_AND_PORT").expect("BIND_ADDRESS_AND_PORT must be set");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let socket_addr = listener.local_addr().unwrap();
    info!("Listening for login requests on {}", socket_addr);

    // start the microservice
    axum::serve(listener, app).await.unwrap();
}

/// handler for /auth/discord; the user will call this route to tell us
/// that they've authorized PeraPera Quest to query the Discord API
/// to get information about user, like thier Discord user id, their
/// Discord avatar, and what roles they have in the PeraPera Quest guild
async fn handle_auth_discord(
    State(state): State<MonbanKunState>,
    jar: CookieJar,
    Query(params): Query<OAuthQueryParams>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // if the security nonce doesn't fit
    if !verify_security_nonce(&jar, &params) {
        // get out of here, you little shit
        return Err(StatusCode::UNAUTHORIZED);
    }
    // delete the oauth_state cookie; it's no longer necessary
    let jar = jar.remove(Cookie::from("oauth_state"));

    // exchange the authorization code provided by Discord (`code`)
    // for an access_token so we can query the Discord API about the
    // user who wants to play PeraPera Quest
    info!("Exchanging the code for an access token");
    let response = match state
        .client
        .post("https://discord.com/api/oauth2/token")
        .form(&[
            ("client_id", state.discord_client_id.as_str()),
            ("client_secret", state.discord_client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", params.code.as_str()),
            ("redirect_uri", state.discord_redirect_uri.as_str()),
        ])
        .send()
        .await
    {
        Ok(r) => r,
        // whoops, that didn't work, please try again
        Err(e) => {
            error!("/api/oauth2/token - network error: {}", e);
            return Ok((jar, Redirect::to("/login")));
        }
    };

    // read the response body, and if we're debugging then log it so we
    // can figure out why errors are showing up
    let body_bytes = match response.bytes().await {
        Ok(b) => {
            debug!("response body: {}", String::from_utf8_lossy(&b));
            b
        }
        // we couldn't decode the response body? ouch.
        Err(e) => {
            error!("failed to read body: {}", e);
            return Ok((jar, Redirect::to("/login")));
        }
    };

    // attempt to decode the response body as a JSON representation
    // of an OAuthResponse object; hopefully that's what Discord provided
    let oauth_response: OAuthResponse = match serde_json::from_slice(&body_bytes) {
        Ok(u) => u,
        // we couldn't deserialize the response? ouch.
        Err(e) => {
            error!("couldn't deserialize OAuthResponse: {}", e);
            return Ok((jar, Redirect::to("/login")));
        }
    };

    // awesome, we got an access_token, so now we can ask the Discord API
    // for some information about the user
    info!("Access token granted; let's query about the user and their server roles");
    let access_token = oauth_response.access_token;

    // fetch the Member (Guild Member) from Discord; with this we can
    // figure out who the user is, and what roles they have in the Discord
    let discord_guild_id = state.discord_guild_id;
    let guild_member_url =
        format!("https://discord.com/api/users/@me/guilds/{discord_guild_id}/member");
    let member: Member = match state
        .client
        .get(guild_member_url)
        .bearer_auth(access_token)
        .send()
        .await
    {
        Ok(response) => match response.json::<Member>().await {
            Ok(m) => m,
            Err(e) => {
                error!("couldn't deserialize Member: {}", e);
                return Ok((jar, Redirect::to("/login")));
            }
        },
        Err(e) => {
            error!(
                "/api/users/@me/guilds/{discord_guild_id}/member - network error: {}",
                e
            );
            return Ok((jar, Redirect::to("/login")));
        }
    };

    // create a new session for the user; we're going to store that in
    // our session table, so that when PeraPera Quest calls the /whoami
    // route, it can discover which user is playing the game
    let session_uuid = Uuid::new_v4().to_string();
    let user_session = UserSession {
        session_uuid: session_uuid.clone(),
        discord: member.clone(),
    };
    state
        .sessions
        .lock()
        .unwrap()
        .insert(session_uuid.clone(), user_session);

    // tell the user to save `session_uuid` as a Cookie; this will get
    // supplied to the /whoami route so the proper session can be looked up
    // in the session table and returned to PeraPera Quest
    let cookie = Cookie::build(("session_uuid", session_uuid.clone()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();
    let jar = jar.add(cookie);

    // if we were configured with a webhook to announce logins
    if let Some(webhook_url) = state.discord_webhook_url {
        // announce the user's login via a Discord web hook
        let display_name = member.nick.unwrap_or(member.user.name);
        let _ = state.client.post(webhook_url)
            .json(&json!({
                "content": format!("Monban-kun has checked {} and issued them a pass to play PeraPera Quest!", display_name),
            }))
            .send().await;
    }

    // let's play PeraPera Quest!
    Ok((jar, Redirect::to("/")))
}

/// handler for /login; we send the user to the Discord OAuth2 flow
/// i.e.: Login with Discord. When the user is logged in with Discord
/// and confirms that PeraPera Quest is allowed to access their Discord
/// information, then they'll call back to /auth/discord to tell us
async fn handle_login(
    State(state): State<MonbanKunState>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // save our security nonce in a cookie
    let nonce = Uuid::new_v4().to_string();
    let cookie = Cookie::build(("oauth_state", nonce.clone()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();
    // tell the user to go ask Discord for an authorization code
    let params = vec![
        // client_id = tell Discord you want the PeraPera Quest application
        ("client_id", state.discord_client_id.as_str()),
        // response_type = tell Discord you want an authorization code to exchange for a token
        ("response_type", "code"),
        // redirect_uri = tell Discord the authorization response should be posted to the game's auth handler
        ("redirect_uri", state.discord_redirect_uri.as_str()),
        // scope = tell Discord we want to know the user's Discord ID,
        //         and which roles they belong to in the PeraPera Quest guild
        ("scope", "identify guilds.members.read"),
        // state = tell Discord this security nonce, so leet evil haxors don't clickjack us
        ("state", &nonce),
    ];
    let url = reqwest::Url::parse_with_params("https://discord.com/api/oauth2/authorize", &params)
        .unwrap();
    info!("Redirecting to: {}", url.as_str());
    Ok((jar.add(cookie), Redirect::to(url.as_str())))
}

/// handler for /whoami; PeraPera Quest uses this to inquire about the
/// identity of the user connected to the game. if they've gone through
/// the authorization process monban-kun will have issued them a
/// `session_uuid` cookie with a UUID. that UUID can be used to look up
/// their session, including the user's PeraPera Quest ID and their
/// Discord ID and roles in the PeraPera Quest Discord server
async fn handle_whoami(
    State(state): State<MonbanKunState>,
    jar: CookieJar,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // if the cookie jar has a `session_uuid` cookie in it
    if let Some(cookie) = jar.get("session_uuid") {
        // get the value from that cookie
        let session_id = cookie.value();
        // do we have that session in the session table?
        match state.sessions.lock().unwrap().get(session_id) {
            // we do, so return it to the caller
            Some(user_session) => {
                return Ok(Json(json!({ "session": user_session })));
            }
            // we don't, so log about that and do nothing
            None => {
                error!("Unknown session: {}", session_id);
            }
        }
    }
    // we didn't find a cookie or we didn't find the session
    // either way, we have no idea who this user is
    Err(StatusCode::UNAUTHORIZED)
}

/// configure logging for the application
fn setup_logging() {
    // figure out what things we want to look by looking at
    // RUST_LOG from the environment or default to "info"
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // figure out how we want those logging messages to be formatted
    // and where the logging messages should be sent
    let fmt_layer = fmt::layer()
        // produce JSON‐formatted logs
        // .json()
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_span_events(FmtSpan::CLOSE)
        .with_writer(std::io::stdout);

    // build the logging subscriber (filter + formatting)
    let subscriber = Registry::default().with(env_filter).with(fmt_layer);

    // install our subscriber as the global default
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global tracing subscriber");
}

/// we provided a security nonce and told the user to hold on to that in
/// a cookie (`oauth_state`); we expect that same value to come back from
/// Discord when they call our callback (`state`); if these two don't
/// match, then maybe some evil leet haxors are trying to clickjack the
/// user (i.e.: trying to break into the user's PeraPera Quest account)
/// this function returns true if everything matches like it should, and
/// returns false if anything is missing or mismatched
fn verify_security_nonce(jar: &CookieJar, params: &OAuthQueryParams) -> bool {
    // get the security nonce we expect to see from the cookie
    let expected_state = match jar.get("oauth_state") {
        Some(cookie) => cookie.value(),
        None => {
            error!("No 'oauth_state' cookie");
            return false;
        }
    };
    // get the security nonce we got from the Discord call back
    let provided_state = match &params.state {
        Some(x) => x,
        None => {
            error!("No 'state' query parameter provided from Discord");
            return false;
        }
    };
    // if the security nonce doesn't match
    if expected_state != provided_state {
        error!(
            "Mismatch - expected_state:{} - provided_state:{}",
            expected_state, provided_state
        );
        return false;
    }
    // everything matches up correctly, good to go
    true
}
