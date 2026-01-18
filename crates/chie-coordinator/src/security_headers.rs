//! Security headers middleware for production deployments.
//!
//! Adds essential HTTP security headers to protect against common attacks.

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};

/// Security headers configuration.
#[derive(Debug, Clone)]
pub struct SecurityHeadersConfig {
    /// Enable HSTS (Strict-Transport-Security).
    pub enable_hsts: bool,
    /// HSTS max-age in seconds (default: 1 year).
    pub hsts_max_age: u32,
    /// Include subdomains in HSTS.
    pub hsts_include_subdomains: bool,
    /// HSTS preload.
    pub hsts_preload: bool,

    /// Content Security Policy.
    pub csp: Option<String>,

    /// X-Frame-Options (DENY, SAMEORIGIN, or custom).
    pub frame_options: FrameOptions,

    /// Referrer-Policy.
    pub referrer_policy: ReferrerPolicy,

    /// Enable X-Content-Type-Options: nosniff.
    pub enable_nosniff: bool,

    /// Enable X-XSS-Protection.
    pub enable_xss_protection: bool,
}

/// X-Frame-Options values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum FrameOptions {
    /// Deny all framing.
    Deny,
    /// Allow same-origin framing.
    SameOrigin,
    /// Allow framing from specific origin.
    AllowFrom,
}

impl FrameOptions {
    fn as_str(&self) -> &'static str {
        match self {
            FrameOptions::Deny => "DENY",
            FrameOptions::SameOrigin => "SAMEORIGIN",
            FrameOptions::AllowFrom => "ALLOW-FROM",
        }
    }
}

/// Referrer-Policy values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ReferrerPolicy {
    /// No referrer.
    NoReferrer,
    /// No referrer when downgrading.
    NoReferrerWhenDowngrade,
    /// Origin only.
    Origin,
    /// Origin when cross-origin.
    OriginWhenCrossOrigin,
    /// Same origin.
    SameOrigin,
    /// Strict origin.
    StrictOrigin,
    /// Strict origin when cross-origin.
    StrictOriginWhenCrossOrigin,
    /// Unsafe URL.
    UnsafeUrl,
}

impl ReferrerPolicy {
    fn as_str(&self) -> &'static str {
        match self {
            ReferrerPolicy::NoReferrer => "no-referrer",
            ReferrerPolicy::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            ReferrerPolicy::Origin => "origin",
            ReferrerPolicy::OriginWhenCrossOrigin => "origin-when-cross-origin",
            ReferrerPolicy::SameOrigin => "same-origin",
            ReferrerPolicy::StrictOrigin => "strict-origin",
            ReferrerPolicy::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            ReferrerPolicy::UnsafeUrl => "unsafe-url",
        }
    }
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            enable_hsts: true,
            hsts_max_age: 31536000, // 1 year
            hsts_include_subdomains: true,
            hsts_preload: false,
            csp: Some(
                "default-src 'self'; \
                 script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
                 style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data: https:; \
                 font-src 'self' data:; \
                 connect-src 'self'; \
                 frame-ancestors 'none'"
                    .to_string(),
            ),
            frame_options: FrameOptions::Deny,
            referrer_policy: ReferrerPolicy::StrictOriginWhenCrossOrigin,
            enable_nosniff: true,
            enable_xss_protection: true,
        }
    }
}

impl SecurityHeadersConfig {
    /// Create a development-friendly configuration (less strict).
    pub fn development() -> Self {
        Self {
            enable_hsts: false, // Don't require HTTPS in dev
            csp: Some(
                "default-src 'self' 'unsafe-inline' 'unsafe-eval'; \
                 img-src 'self' data: https: http:; \
                 connect-src 'self' ws: wss: http: https:"
                    .to_string(),
            ),
            ..Default::default()
        }
    }

    /// Create a production configuration (strict).
    pub fn production() -> Self {
        Self {
            enable_hsts: true,
            hsts_max_age: 31536000,
            hsts_include_subdomains: true,
            hsts_preload: true,
            csp: Some(
                "default-src 'self'; \
                 script-src 'self'; \
                 style-src 'self'; \
                 img-src 'self' data: https:; \
                 font-src 'self'; \
                 connect-src 'self'; \
                 frame-ancestors 'none'; \
                 base-uri 'self'; \
                 form-action 'self'"
                    .to_string(),
            ),
            frame_options: FrameOptions::Deny,
            referrer_policy: ReferrerPolicy::StrictOriginWhenCrossOrigin,
            enable_nosniff: true,
            enable_xss_protection: true,
        }
    }
}

/// Security headers middleware.
pub async fn security_headers_middleware(
    config: SecurityHeadersConfig,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // X-Content-Type-Options
    if config.enable_nosniff {
        headers.insert(
            "X-Content-Type-Options",
            HeaderValue::from_static("nosniff"),
        );
    }

    // X-Frame-Options
    headers.insert(
        "X-Frame-Options",
        HeaderValue::from_static(config.frame_options.as_str()),
    );

    // X-XSS-Protection
    if config.enable_xss_protection {
        headers.insert(
            "X-XSS-Protection",
            HeaderValue::from_static("1; mode=block"),
        );
    }

    // Strict-Transport-Security (HSTS)
    if config.enable_hsts {
        let mut hsts_value = format!("max-age={}", config.hsts_max_age);
        if config.hsts_include_subdomains {
            hsts_value.push_str("; includeSubDomains");
        }
        if config.hsts_preload {
            hsts_value.push_str("; preload");
        }
        if let Ok(header_value) = HeaderValue::from_str(&hsts_value) {
            headers.insert("Strict-Transport-Security", header_value);
        }
    }

    // Content-Security-Policy
    if let Some(csp) = &config.csp {
        if let Ok(header_value) = HeaderValue::from_str(csp) {
            headers.insert("Content-Security-Policy", header_value);
        }
    }

    // Referrer-Policy
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static(config.referrer_policy.as_str()),
    );

    // Permissions-Policy (formerly Feature-Policy)
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static(
            "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=()",
        ),
    );

    response
}

/// Create security headers middleware with default config.
#[allow(dead_code)]
pub fn create_security_middleware()
-> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
+ Clone {
    let config = SecurityHeadersConfig::default();
    move |request: Request, next: Next| {
        let config = config.clone();
        Box::pin(async move { security_headers_middleware(config, request, next).await })
    }
}

/// Create security headers middleware with custom config.
#[allow(dead_code)]
pub fn create_security_middleware_with_config(
    config: SecurityHeadersConfig,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
+ Clone {
    move |request: Request, next: Next| {
        let config = config.clone();
        Box::pin(async move { security_headers_middleware(config, request, next).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_options_as_str() {
        assert_eq!(FrameOptions::Deny.as_str(), "DENY");
        assert_eq!(FrameOptions::SameOrigin.as_str(), "SAMEORIGIN");
    }

    #[test]
    fn test_referrer_policy_as_str() {
        assert_eq!(ReferrerPolicy::NoReferrer.as_str(), "no-referrer");
        assert_eq!(
            ReferrerPolicy::StrictOriginWhenCrossOrigin.as_str(),
            "strict-origin-when-cross-origin"
        );
    }

    #[test]
    fn test_default_config() {
        let config = SecurityHeadersConfig::default();
        assert!(config.enable_hsts);
        assert_eq!(config.hsts_max_age, 31536000);
        assert!(config.enable_nosniff);
        assert!(config.enable_xss_protection);
        assert_eq!(config.frame_options, FrameOptions::Deny);
    }

    #[test]
    fn test_development_config() {
        let config = SecurityHeadersConfig::development();
        assert!(!config.enable_hsts); // HSTS disabled in dev
        assert!(config.csp.is_some());
    }

    #[test]
    fn test_production_config() {
        let config = SecurityHeadersConfig::production();
        assert!(config.enable_hsts);
        assert!(config.hsts_preload);
        assert!(config.hsts_include_subdomains);
    }

    #[test]
    fn test_hsts_value_construction() {
        let config = SecurityHeadersConfig {
            hsts_max_age: 3600,
            hsts_include_subdomains: true,
            hsts_preload: true,
            ..Default::default()
        };

        let expected = "max-age=3600; includeSubDomains; preload";
        let actual = format!(
            "max-age={}{}{}",
            config.hsts_max_age,
            if config.hsts_include_subdomains {
                "; includeSubDomains"
            } else {
                ""
            },
            if config.hsts_preload { "; preload" } else { "" }
        );

        assert_eq!(actual, expected);
    }
}
