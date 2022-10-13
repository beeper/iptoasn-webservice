use crate::asns::*;
use iron::headers::{CacheControl, CacheDirective, Expires, HttpDate, Vary};
use iron::mime::*;
use iron::modifiers::Header;
use iron::prelude::*;
use iron::status;
use iron::{typemap, BeforeMiddleware};
use router::Router;

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use time::{self, Duration};
use unicase::UniCase;
use log::{warn};

const TTL: u32 = 86_400;

struct ASNsMiddleware {
    asns_arc: Arc<RwLock<Arc<ASNs>>>,
}

impl typemap::Key for ASNsMiddleware {
    type Value = Arc<ASNs>;
}

impl ASNsMiddleware {
    fn new(asns_arc: Arc<RwLock<Arc<ASNs>>>) -> ASNsMiddleware {
        ASNsMiddleware { asns_arc }
    }
}

impl BeforeMiddleware for ASNsMiddleware {
    fn before(&self, req: &mut Request<'_, '_>) -> IronResult<()> {
        req.extensions
            .insert::<ASNsMiddleware>(self.asns_arc.read().unwrap().clone());
        Ok(())
    }
}

pub struct WebService;

impl WebService {
    fn index(_: &mut Request<'_, '_>) -> IronResult<Response> {
        Ok(Response::with((
            status::Ok,
            Mime(
                TopLevel::Text,
                SubLevel::Plain,
                vec![(Attr::Charset, Value::Utf8)],
            ),
            Header(CacheControl(vec![
                CacheDirective::Public,
                CacheDirective::MaxAge(TTL),
            ])),
            Header(Expires(HttpDate(
                time::now() + Duration::seconds(TTL.into()),
            ))),
            "Beep beep",
        )))
    }

    fn output_json(
        map: &serde_json::Map<String, serde_json::value::Value>,
        cache_headers: (Header<CacheControl>, Header<Expires>),
        vary_header: Header<Vary>,
    ) -> IronResult<Response> {
        let json = serde_json::to_string(&map).unwrap();
        let mime_json = Mime(
            TopLevel::Application,
            SubLevel::Json,
            vec![(Attr::Charset, Value::Utf8)],
        );
        Ok(Response::with((
            status::Ok,
            mime_json,
            cache_headers.0,
            cache_headers.1,
            vary_header,
            json,
        )))
    }

    fn ip_lookup(req: &mut Request<'_, '_>) -> IronResult<Response> {
        let mime_text = Mime(
            TopLevel::Text,
            SubLevel::Plain,
            vec![(Attr::Charset, Value::Utf8)],
        );
        let cache_headers = (
            Header(CacheControl(vec![
                CacheDirective::Public,
                CacheDirective::MaxAge(TTL),
            ])),
            Header(Expires(HttpDate(
                time::now() + Duration::seconds(TTL.into()),
            ))),
        );
        let vary_header = Header(Vary::Items(vec![
            UniCase::from_str("accept-encoding").unwrap(),
            UniCase::from_str("accept").unwrap(),
        ]));
        let ip_str = match req.extensions.get::<Router>().unwrap().find("ip") {
            None => {
                let response = Response::with((
                    status::BadRequest,
                    mime_text,
                    cache_headers,
                    "Missing IP address",
                ));
                return Ok(response);
            }
            Some(ip_str) => ip_str,
        };
        let ip = match IpAddr::from_str(ip_str) {
            Err(_) => {
                return Ok(Response::with((
                    status::BadRequest,
                    mime_text,
                    cache_headers,
                    "Invalid IP address",
                )));
            }
            Ok(ip) => ip,
        };
        let asns = req.extensions.get::<ASNsMiddleware>().unwrap();
        let mut map = serde_json::Map::new();
        map.insert(
            "ip".to_string(),
            serde_json::value::Value::String(ip_str.to_string()),
        );
        let found = match asns.lookup_by_ip(ip) {
            None => {
                map.insert(
                    "announced".to_string(),
                    serde_json::value::Value::Bool(false),
                );
                return Self::output_json(&map, cache_headers, vary_header);
            }
            Some(found) => found,
        };
        map.insert(
            "announced".to_string(),
            serde_json::value::Value::Bool(true),
        );
        map.insert(
            "first_ip".to_string(),
            serde_json::value::Value::String(found.first_ip.to_string()),
        );
        map.insert(
            "last_ip".to_string(),
            serde_json::value::Value::String(found.last_ip.to_string()),
        );
        map.insert(
            "as_number".to_string(),
            serde_json::value::Value::Number(serde_json::Number::from(found.number)),
        );
        map.insert(
            "as_country_code".to_string(),
            serde_json::value::Value::String(found.country.clone()),
        );
        map.insert(
            "as_description".to_string(),
            serde_json::value::Value::String(found.description.clone()),
        );
        Self::output_json(&map, cache_headers, vary_header)
    }

    pub fn start(asns_arc: Arc<RwLock<Arc<ASNs>>>, listen_addr: &str) {
        let router = router!(index: get "/" => Self::index,
                             ip_lookup: get "/v1/as/ip/:ip" => Self::ip_lookup);
        let mut chain = Chain::new(router);
        let asns_middleware = ASNsMiddleware::new(asns_arc);
        chain.link_before(asns_middleware);
        warn!("webservice ready");
        Iron::new(chain).http(listen_addr).unwrap();
    }
}
