//! An RFB proxy that enables WebSockets and audio.
//!
//! This crate proxies a TCP Remote Framebuffer server connection and exposes a WebSocket endpoint,
//! translating the connection between them. It can optionally enable audio using the Replit Audio
//! messages if the `--enable-audio` flag is passed or the `VNC_ENABLE_EXPERIMENTAL_AUDIO`
//! environment variable is set to a non-empty value.

mod audio;
mod auth;
mod messages;
mod rfb;


use std::sync::Arc;

use anyhow::{/* bail,  */Context, Result};

// use futures::{SinkExt, StreamExt};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// The protobuf definitions.
mod api {
    include!(concat!(env!("OUT_DIR"), "/api.rs"));
}

/// Forwards the data between `socket` and `ws_stream`. Doesn't do anything with the bytes.
async fn forward_streams<Stream>(
    mut socket: TcpStream,
    mut ws_stream: TcpStream,
) -> Result<()>
where
    Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut rws, mut wws) = ws_stream.split();
    let (mut rs, mut ws) = socket.split();

    let client_to_server = async move {
        let mut buffer = [0u8; 1024];
        loop {
            match rws.read(&mut buffer[..]).await {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    if let Err(err) = ws.write_all(&buffer[..n]).await {
                        log::error!("failed to write a message to the server: {:#}", err);
                        break;
                    }
                }
                Err(err) => {
                    log::error!("failed to read a message from the client: {:#}", err);
                    break;
                }
            }
        }

        log::info!("client disconnected");
        ws.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };

    let server_to_client = async move {
        let mut buffer = [0u8; 4096];
        loop {
            match rs.read(&mut buffer[..]).await {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    if let Err(err) = wws.write_all(&buffer[..n]).await {
                        log::error!("failed to write a message to the client: {:#}", err);
                        break;
                    }
                }
                Err(err) => {
                    log::error!("failed to read a message from the server: {:#}", err);
                    break;
                }
            }
        }

        log::info!("server disconnected");
        wws.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };

    let (cts, stc) = tokio::join!(client_to_server, server_to_client);
    cts?;
    stc?;
    Ok(())
}

/// Handles a single WebSocket connection. If `enable_audio` is false, it will just forward the
/// data between them. Otherwise, it will parse and interpret each RFB packet and inject audio
/// data.
async fn handle_connection<Stream>(
    rfb_addr: std::net::SocketAddr,
    mut ws_stream: tokio::net::TcpStream,
    authentication: &auth::RfbAuthentication,
    enable_audio: bool,
) -> Result<()>
where
    Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let mut socket = TcpStream::connect(rfb_addr).await?;
    socket.set_nodelay(true).expect("set_nodelay call failed");

    auth::authenticate(authentication, &mut socket, &mut ws_stream).await?;

    if !enable_audio {
        return forward_streams::<Stream>(socket, ws_stream).await;
    }
    let (server_tx, _server_rx) = mpsc::channel(2);
    let (client_tx, mut client_rx) = mpsc::channel(2);
    let mut conn = rfb::RfbConnection::new::<Stream>(socket, &mut ws_stream, server_tx, client_tx).await?;

    let (mut rws, mut wws) = ws_stream.split();
    let (mut rs, mut ws) = conn.split();

    let client_to_server = async {
        let mut buffer = [0u8; 1024];
        loop {
            match rws.read(&mut buffer[..]).await {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    if let Err(err) = ws.write_all(&buffer[..n]).await {
                        log::error!("failed to write a message to the server: {:#}", err);
                        break;
                    }
                }
                Err(err) => {
                    log::error!("failed to read a message from the client: {:#}", err);
                    break;
                }
            }
        }

        log::info!("client disconnected");
        ws.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };

    let server_to_client = async {
        loop {
            let payload = tokio::select! {
                Some(payload) = client_rx.recv() => Some(payload),
                message = rs.read_server_message() => {
                    match message.context("failed to read server-to-client message")? {
                        None => break,
                        Some(msg) => {
                            log::debug!("<-: {:?}", &msg);
                            Some(msg.into_data())
                        }
                    }
                },
                else => break,
            };

            if let Some(payload) = payload {
                wws.write_all(&payload).await?;
            }
        }
        log::info!("server disconnected");
        wws.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };

    let (cts, stc) = tokio::join!(client_to_server, server_to_client);
    cts?;
    stc?;

    Ok(())
}


#[doc(hidden)]
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let matches = clap::App::new("rfbproxy")
        .about("An RFB proxy that enables WebSockets and audio")
        .arg(
            clap::Arg::with_name("address")
                .long("address")
                .value_name("HOST:PORT")
                .default_value("0.0.0.0:5900")
                .help("The hostname and port in which the server will bind")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("rfb-server")
                .long("rfb-server")
                .value_name("HOST:PORT")
                .default_value("127.0.0.1:5901")
                .help("The hostname and port where the original RFB server is listening")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("enable-audio")
                .long("enable-audio")
                .help("Whether the muxer will support audio muxing or be a simple WebSocket proxy"),
        )
        .arg(
            clap::Arg::with_name("allow")
                .long("allow")
                .value_name("IP")
                .help("The client ip that is allowed to connect to rfbproxy")
                .takes_value(true),
        )
        .get_matches();

    // Create the event loop and TCP listener we'll accept connections on.
    let local_addr = matches
        .value_of("address")
        .context("missing --address arg")?;
    let rfb_addr: std::net::SocketAddr = matches
        .value_of("rfb-server")
        .context("missing --rfb-server arg")?
        .parse()?;
    let enable_audio = matches.is_present("enable-audio")
        || std::env::var("VNC_ENABLE_EXPERIMENTAL_AUDIO").unwrap_or_else(|_| String::new()) != "";
    let authentication = if enable_audio {
        Arc::new(auth::RfbAuthentication::Passthrough)
    } else {
        // If both audio and the replit authentications are disabled, we can let the server and
        // client talk directly to each other without interfering since we don't need to parse any
        // of the messages.
        Arc::new(auth::RfbAuthentication::Null)
    };

    // ensure rfb server can be connected
    let mut socket = TcpStream::connect(rfb_addr).await?;
    socket.shutdown().await?;

    let listener = TcpListener::bind(&local_addr).await?;
    log::info!("Listening on: {}", local_addr);

    while let Ok((raw_stream, remote_addr)) = listener.accept().await {
        // check if remote ip is allowed to connect
        if matches.value_of("allow").is_some() {
            if remote_addr.ip().to_string() != matches.value_of("allow").unwrap().to_string() {
                log::error!("{} not allowed", remote_addr);
                continue;
            }
        }
        
        let authentication = authentication.clone();
        raw_stream.set_nodelay(true).expect("set_nodelay call failed");
        tokio::spawn(async move {
            log::info!("Incoming TCP connection from: {}", remote_addr);
            if let Err(e) =
                handle_connection::<tokio::net::TcpStream>(rfb_addr, raw_stream, &authentication, enable_audio).await
            {
                log::error!("error in client connection: {:#}", e);
            }
            log::info!("{} disconnected", remote_addr);
        });
    }
    
    Ok(())
}