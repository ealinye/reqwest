use crate::async_impl::h3_client::dns::resolve;
use crate::dns::DynResolver;
use crate::error::BoxError;
use bytes::Bytes;
use h3::client::SendRequest;
use h3_shim::quic::qbase::param::ClientParameters;
use h3_shim::quic::QuicClient;
use h3_shim::{conn::OpenStreams, QuicConnection};
use http::Uri;
use hyper_util::client::legacy::connect::dns::Name;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

type H3Connection = (
    h3::client::Connection<QuicConnection, Bytes>,
    SendRequest<OpenStreams, Bytes>,
);

#[derive(Clone)]
pub(crate) struct H3Connector {
    resolver: DynResolver,
    client: Arc<QuicClient>,
}

impl H3Connector {
    pub fn new(
        resolver: DynResolver,
        tls: rustls::ClientConfig,
        local_addr: Option<IpAddr>,
        transport_config: ClientParameters,
    ) -> Result<H3Connector, BoxError> {
        let socket_addr = match local_addr {
            Some(ip) => SocketAddr::new(ip, 0),
            None => "[::]:0".parse::<SocketAddr>().unwrap(),
        };

        let client = QuicClient::bind_with_tls([socket_addr], tls)
            .with_parameters(transport_config)
            .build();
        let client = client.into();
        Ok(Self { resolver, client })
    }

    pub async fn connect(&mut self, dest: Uri) -> Result<H3Connection, BoxError> {
        let host = dest
            .host()
            .ok_or("destination must have a host")?
            .trim_start_matches('[')
            .trim_end_matches(']');
        let port = dest.port_u16().unwrap_or(443);

        let addrs = if let Some(addr) = IpAddr::from_str(host).ok() {
            // If the host is already an IP address, skip resolving.
            vec![SocketAddr::new(addr, port)]
        } else {
            let addrs = resolve(&mut self.resolver, Name::from_str(host)?).await?;
            let addrs = addrs.map(|mut addr| {
                addr.set_port(port);
                addr
            });
            addrs.collect()
        };

        self.remote_connect(addrs, host).await
    }

    async fn remote_connect(
        &mut self,
        addrs: Vec<SocketAddr>,
        server_name: &str,
    ) -> Result<H3Connection, BoxError> {
        let mut err = None;
        for addr in addrs {
            match self.client.connect(server_name, addr) {
                Ok(new_conn) => {
                    let gm_quic_conn = QuicConnection::new(new_conn).await;
                    return Ok(h3::client::new(gm_quic_conn).await?);
                }
                Err(e) => err = Some(e),
            }
        }

        match err {
            Some(e) => Err(Box::new(e) as BoxError),
            None => Err("failed to establish connection for HTTP/3 request".into()),
        }
    }
}
