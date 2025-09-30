use proxy_wasm::hostcalls;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;


// ---------- logging ----------
fn hlog(level: LogLevel, msg: &str) {
    let _ = hostcalls::log(level, msg);
}

// ---------- settings ----------
#[derive(serde::Deserialize, Clone, Debug)]
struct FallbackItem {
    path: String,
    body: String,
}

#[derive(serde::Deserialize, Clone, Debug)]
struct Config {
    #[serde(default = "default_rewrite_true")]
    rewrite_status_to_200: bool,
    #[serde(default)]
    fallbacks: Vec<FallbackItem>,

    // logging detail, default false
    #[serde(default)]
    log_verbose: bool,
}

fn default_rewrite_true() -> bool { true }


impl Default for Config {
    fn default() -> Self {
        Self {
            rewrite_status_to_200: true,
            fallbacks: Vec::new(),
            log_verbose: false,
        }
    }
}

// ---------- Root / Http contexts ----------

proxy_wasm::main! {{
    // Global Loglevel by Envoy：Error, Warn, Info, Debug or Trace if you want.
    proxy_wasm::set_log_level(LogLevel::Debug);
    proxy_wasm::set_root_context(|_| Box::new(FallbackRoot::default()));
}}

#[derive(Default)]
struct FallbackRoot {
    cfg: Config,
}

impl Context for FallbackRoot {}

impl RootContext for FallbackRoot {
    fn on_configure(&mut self, _: usize) -> bool {
        match self.get_plugin_configuration() {
            Some(raw) if !raw.is_empty() => {
                match serde_json::from_slice::<Config>(&raw) {
                    Ok(cfg) => {
                        hlog(LogLevel::Debug, "[fallback] plugin configuring…");
                        hlog(
                            LogLevel::Debug,
                            &format!(
                                "[fallback] loaded config: rewrite_status_to_200={}, rules={}, log_verbose={}",
                                cfg.rewrite_status_to_200, cfg.fallbacks.len(), cfg.log_verbose
                            ),
                        );
                        self.cfg = cfg;
                        true
                    }
                    Err(e) => {
                        hlog(LogLevel::Error, &format!("[fallback] invalid pluginConfig JSON: {e}"));
                        self.cfg = Config::default();
                        true
                    }
                }
            }
            _ => {
                hlog(LogLevel::Warn, "[fallback] empty pluginConfig; plugin is effectively disabled");
                self.cfg = Config::default();
                true
            }
        }
    }

    fn get_type(&self) -> Option<ContextType> { Some(ContextType::HttpContext) }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        if self.cfg.log_verbose {
            hlog(LogLevel::Debug, "[fallback] create_http_context()");
        }
        Some(Box::new(FallbackHttp {
            cfg: self.cfg.clone(),
            path: String::new(),
            req_id: 0,
        }))
    }
}

struct FallbackHttp {
    cfg: Config,
    path: String,
    req_id: u64,
}

impl Context for FallbackHttp {}
fn kv<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    // HTTP/2 pseudo headers are lowercase (":status", ":path"); Envoy lowercases normal headers.
    headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

impl HttpContext for FallbackHttp {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // SAFER: pull all request headers once
        let req = self.get_http_request_headers();
        self.path = kv(&req, ":path").unwrap_or_default().to_string();

        if self.cfg.log_verbose {
            let method = kv(&req, ":method").unwrap_or("-");
            let authority = kv(&req, ":authority").unwrap_or("-");
            hlog(LogLevel::Debug, &format!(
                "[fallback][req#{:06}] request headers: method={}, host={}, path={}",
                self.req_id, method, authority, self.path
            ));
        }
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _: usize, _: bool) -> Action {
        // Pull all response headers at once (no per-key hostcalls)
        let resp = self.get_http_response_headers();

        if resp.is_empty() {
            // No header map available (common on certain local errors) — just pass through
            if self.cfg.log_verbose {
                hlog(LogLevel::Debug, &format!(
                    "[fallback][req#{:06}] no response headers map -> continue", self.req_id
                ));
            }
            return Action::Continue;
        }

        // gRPC guard by request headers (captured earlier if you prefer)
        let req = self.get_http_request_headers();
        if let Some(ct) = kv(&req, "content-type") {
            if ct.starts_with("application/grpc") {
                return Action::Continue;
            }
        }

        // status parsing (default 200 if missing)
        let status: u16 = kv(&resp, ":status")
            .and_then(|s| s.parse().ok())
            .unwrap_or(200);

        if self.cfg.log_verbose {
            hlog(LogLevel::Debug, &format!(
                "[fallback][req#{:06}] upstream status={}; path={}",
                self.req_id, status, self.path
            ));
        }

        if status < 500 || self.cfg.fallbacks.is_empty() {
            return Action::Continue;
        }

        if let Some(item) = self
            .cfg
            .fallbacks
            .iter()
            .find(|it| self.path.starts_with(&it.path))
        {
            let code = if self.cfg.rewrite_status_to_200 { 200 } else { status as u32 };
            hlog(LogLevel::Debug, &format!(
                "[fallback][req#{:06}] TRIGGERED on `{}` -> local reply {}",
                self.req_id, item.path, code
            ));
            // IMPORTANT: Do Not Call Any Hostcalls After This!!!
            let headers = vec![
                ("content-type", "application/json"),
                ("x-fallback", "wasm"),
            ];
            self.send_http_response(code, headers, Some(item.body.as_bytes()));
            return Action::Pause;
        }

        Action::Continue
    }
}
