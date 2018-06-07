extern crate failure;
extern crate futures;
extern crate hyper;
extern crate tls_api;
extern crate tokio_io;
extern crate tokio_tls_api;

use failure::Error;
use futures::{Future, Poll};
use hyper::client::connect::{Connect, Connected, Destination, HttpConnector};
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::Arc;
use tls_api::{TlsConnector, TlsConnectorBuilder};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_tls_api::TlsStream;

#[derive(Clone)]
pub struct HttpsConnector<T, S> {
    hostname_verification: bool,
    force_https: bool,
    http: T,
    tls: Arc<S>,
}

impl<S: TlsConnector> HttpsConnector<HttpConnector, S> {
    /// Construct a new HttpsConnector
    ///
    /// Takes number of DNS worker threads
    pub fn new(threads: usize) -> Result<Self, Error> {
        let mut http = HttpConnector::new(threads);
        http.enforce_http(false);
        let tls = S::builder()?.build()?;
        Ok(HttpsConnector::from((http, tls)))
    }
}

impl<T, S> From<(T, S)> for HttpsConnector<T, S> {
    fn from(args: (T, S)) -> HttpsConnector<T, S> {
        HttpsConnector {
            hostname_verification: true,
            force_https: false,
            http: args.0,
            tls: Arc::new(args.1),
        }
    }
}

impl<T, S> HttpsConnector<T, S> {
    /// Disable hostname verification when connecting.
    ///
    /// Think twice before setting this.
    pub fn danger_disable_hostname_verification(&mut self, disable: bool) {
        self.hostname_verification = !disable;
    }

    /// Force the use of HTTPS. Non-HTTPS connections will fail.
    pub fn force_https(&mut self, enable: bool) {
        self.force_https = enable;
    }
}

impl<T: fmt::Debug, S> fmt::Debug for HttpsConnector<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HttpsConnector")
            .field("hostname_verification", &self.hostname_verification)
            .field("force_https", &self.force_https)
            .field("http", &self.http)
            .finish()
    }
}

impl<T, S> Connect for HttpsConnector<T, S>
where
    T: Connect<Error = io::Error>,
    T::Transport: 'static,
    T::Future: 'static,
    S: Sync,
    S: Send,
{
    type Transport = MaybeHttpsStream<T::Transport>;
    type Error = io::Error;
    type Future = HttpsConnecting<T::Transport>;

    fn connect(&self, dst: Destination) -> Self::Future {
        unimplemented!()
    }
}

type BoxedFut<T> = Box<Future<Item = (MaybeHttpsStream<T>, Connected), Error = io::Error> + Send>;

pub struct HttpsConnecting<T>(BoxedFut<T>);

impl<T> Future for HttpsConnecting<T> {
    type Item = (MaybeHttpsStream<T>, Connected);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let oh = self.0;
        oh.poll()
    }
}

impl<T> fmt::Debug for HttpsConnecting<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad("HttpsConnecting")
    }
}

/// A stream that might be protected with TLS.
pub enum MaybeHttpsStream<T> {
    /// A stream over plain text.
    Http(T),
    /// A stream protected with TLS.
    Https(TlsStream<T>),
}

impl<T> fmt::Debug for MaybeHttpsStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MaybeHttpsStream::Http(..) => f.pad("Http(..)"),
            MaybeHttpsStream::Https(..) => f.pad("Https(..)"),
        }
    }
}

impl<T: Read + Write> Write for MaybeHttpsStream<T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.write(buf),
            MaybeHttpsStream::Https(ref mut s) => s.write(buf),
        }
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.flush(),
            MaybeHttpsStream::Https(ref mut s) => s.flush(),
        }
    }
}

impl<T: Read + Write> Read for MaybeHttpsStream<T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.read(buf),
            MaybeHttpsStream::Https(ref mut s) => s.read(buf),
        }
    }
}

impl<T: AsyncRead + AsyncWrite> AsyncRead for MaybeHttpsStream<T> {
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [u8]) -> bool {
        match *self {
            MaybeHttpsStream::Http(ref s) => s.prepare_uninitialized_buffer(buf),
            MaybeHttpsStream::Https(ref s) => s.prepare_uninitialized_buffer(buf),
        }
    }
}

impl<T: AsyncWrite + AsyncRead> AsyncWrite for MaybeHttpsStream<T> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => {
                let f: () = s.shutdown();
                f
                //s.shutdown()
            }
            MaybeHttpsStream::Https(ref mut s) => {
                let f: () = s.shutdown();
                f
                //s.shutdown()
            }
        }
    }
}
