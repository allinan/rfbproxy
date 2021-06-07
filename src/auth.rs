//! A wrapper for performing Remote Framebuffer authentication.

use anyhow::{bail, Result};
// use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What kind of authentication to use for an RFB connection.
pub enum RfbAuthentication {
    /// A null authentication. It does not perform the initial handshake, so it relies on the rest
    /// of the connection to pass through the data as-is without parsing.
    Null,

    /// An authentication that parses the initial ProtocolVersion and Security handshakes, and
    /// passes them as-is to the peer, without acting on it. This leaves the stream in a state
    /// where the ClientInit handshake is expected to appear next, followed by a stream of normal
    /// RFB messages can appear.
    Passthrough,
}

/// A way of authenticating an RFB connection.
pub async fn authenticate<SocketStream>(
    authentication: &RfbAuthentication,
    stream: &mut SocketStream,
    ws_stream: &mut SocketStream,
) -> Result<()>
where
    SocketStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    match authentication {
        RfbAuthentication::Null => Ok(()),
        RfbAuthentication::Passthrough => authenticate_passthrough(stream, ws_stream).await
    }
}

async fn authenticate_passthrough<SocketStream>(
    stream: &mut SocketStream,
    ws_stream: &mut SocketStream,
) -> Result<()>
where
    SocketStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let mut buf = [0u8; 1024];
    let mut remote_buf = [0u8; 1024];

    // ProtocolVersion handshake.
    let n = stream.read(&mut buf[0..12]).await?;
    if n != 12 {
        bail!("unexpected server handshake: {:?}", &buf[..n]);
    }
    log::debug!("<-: {:?}, {:?}", &buf[0..12], std::str::from_utf8(&buf[0..12])?);
    ws_stream.write_all(&buf[0..12]).await?;

    let m = ws_stream.read(&mut remote_buf).await?;
    if m != 12 {
        bail!("unexpected client handshake: {:?}", &remote_buf[..m]);
    }
    log::debug!("<-: {:?}, {:?}", &buf[0..m], std::str::from_utf8(&remote_buf[0..m]));
    stream.write_all(&remote_buf[0..m]).await?;


    // Security handshake.
    let mut n = stream.read(&mut buf).await?;
    log::debug!("<-: {:?}", &buf[0..n]);
    ws_stream.write_all(&buf[0..n]).await?;

    let mut m = ws_stream.read(&mut remote_buf).await?;
    log::debug!("<-: {:?}", &remote_buf[0..m]);
    if m != 1 {
        bail!(
            "unexpected security-type length. got {}, expected 1",
            m
        );
    }
    stream.write_all(&remote_buf[0..m]).await?;
    let client_security_handshake = remote_buf[0];

    match client_security_handshake {
        1 => {
            // None security type
        }
        2 => {
            // VNC Authentication security type
            n = stream.read(&mut buf).await?;
            log::debug!("<-: {:?}", &buf[0..n]);
            ws_stream.write_all(&buf[0..n]).await?;

            m = ws_stream.read(&mut remote_buf).await?;
            log::debug!("<-: {:?}", &remote_buf[0..m]);
            stream.write_all(&remote_buf[0..m]).await?;
        }
        unsupported => bail!("unsupported security type {}", unsupported),
    }

    // SecurityResult handshake.
    n = stream.read(&mut buf).await?;
    log::debug!("<-: {:?}", &buf[0..n]);
    ws_stream.write_all(&buf[0..n]).await?;

    Ok(())
}


