use std::{collections::BTreeMap, io::Write};

use anyhow::Result;
use clap::Parser;
use futures_util::{pin_mut, Stream, StreamExt};
use matrix_sdk::{
    config::SyncSettings,
    crypto::ReadOnlyDevice,
    ruma::{OwnedDeviceId, OwnedUserId, UserId},
    Client,
};
use tokio::spawn;
use url::Url;

async fn wait_for_pickle_key(client: Client) {
    println!("\nEnter a pickle key: ");
    std::io::stdout().flush().expect("We should be able to flush stdout");

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("error: unable to read user input");

    let pickle_key = input.trim();

    create_dehydrated_device(client, pickle_key.to_owned()).await
}

async fn create_dehydrated_device(client: Client, pickle_key: String) {
    let own_user = client.user_id().expect("We should know our own user id by now.");
    let devices_stream = client.encryption().devices_stream().await;
    let dehydrated_device = client.encryption().dehydrated_device_foo().await;

    // TODO: get the pickle key from the user.
    let pickle_key_bytes = [0u8; 32];

    if let Err(e) = dehydrated_device.create(&pickle_key_bytes).await {
        eprintln!("Couldn't create a dehydrated device: {e:?}");
    } else {
        println!("Successfully created a dehydrated device, waiting for server echo");

        pin_mut!(devices_stream);

        while let Some(update) = devices_stream.next().await {
            if update.contains_key(own_user) {
                print_devices(own_user, &client).await;

                break;
            }
        }
    }
}

async fn rehydrate(client: Client, pickle_key: String) {
    let devices_stream = client.encryption().devices_stream().await;
    let dehydrated_device = client.encryption().dehydrated_device_foo().await;

    // TODO: get the pickle key from the user.
    let pickle_key_bytes = [0u8; 32];

    match dehydrated_device.rehydrate(&pickle_key_bytes).await {
        Ok(n) => println!("Successfully rehydrated a device, imported {n} room keys."),
        Err(e) => eprintln!("Couldn't rehydrate a device: {e:?}."),
    }
}

async fn print_devices(user_id: &UserId, client: &Client) {
    println!("Devices of user {user_id}");

    for device in client.encryption().get_user_devices(user_id).await.unwrap().devices() {
        if device.device_id()
            == client.device_id().expect("We should be logged in now and know our device id")
        {
            continue;
        }

        println!(
            "   {:<10} {:<30} {:<}",
            device.device_id(),
            device.display_name().unwrap_or("-"),
            if device.is_verified() { "✅" } else { "❌" }
        );
    }
}

async fn sync(client: Client) -> matrix_sdk::Result<()> {
    client.sync(SyncSettings::new()).await?;

    Ok(())
}

#[derive(Parser, Debug)]
struct Cli {
    /// The homeserver to connect to.
    #[clap(value_parser)]
    homeserver: Url,

    /// The user name that should be used for the login.
    #[clap(value_parser)]
    user_name: String,

    /// The password that should be used for the login.
    #[clap(value_parser)]
    password: String,

    /// Set the proxy that should be used for the connection.
    #[clap(short, long)]
    proxy: Option<Url>,

    /// Enable verbose logging output.
    #[clap(short, long, action)]
    verbose: bool,
}

async fn login(cli: Cli) -> Result<Client> {
    let builder = Client::builder().homeserver_url(cli.homeserver);

    let builder = if let Some(proxy) = cli.proxy { builder.proxy(proxy) } else { builder };

    let client = builder.build().await?;

    client
        .matrix_auth()
        .login_username(&cli.user_name, &cli.password)
        .initial_device_display_name("device-dehydration-example")
        .await?;

    Ok(client)
}

async fn handle_new_devices(
    client: Client,
    stream: impl Stream<Item = BTreeMap<OwnedUserId, BTreeMap<OwnedDeviceId, ReadOnlyDevice>>>,
) {
    pin_mut!(stream);

    while let Some(update) = stream.next().await {
        if update.contains_key(client.user_id().expect("We should know our own user id by now")) {
            rehydrate(client, "TODO".to_owned()).await;
            // wait_for_pickle_key(client).await;
            break;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt::init();
    }

    let client = login(cli).await?;

    let devices = client.encryption().devices_stream().await;
    spawn(handle_new_devices(client.to_owned(), devices));

    sync(client).await?;

    Ok(())
}
