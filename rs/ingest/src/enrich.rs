// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! server-side enrichment — UA parsing and referrer→source→channel.
//!
//! enrichment is server-attested, never visitor-signed. the referrer table
//! is the generated snowplow referer-db port (`referers.rs`), with assistant
//! referrals kept as a first-class channel: the builtin AI table wins over
//! the snowplow classification (spec: referrer→source engine).

#[path = "referers.rs"]
mod referers;

use lytics_event::EventBody;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub browser: Option<String>,
    pub browser_version: Option<String>,
    pub os: Option<String>,
    pub device: Option<String>,
}

pub fn parse_ua(ua: Option<&str>) -> Device {
    let Some(ua) = ua else {
        return Device { browser: None, browser_version: None, os: None, device: None };
    };
    match woothee::parser::Parser::new().parse(ua) {
        Some(r) => Device {
            browser: Some(r.name.to_string()),
            browser_version: Some(r.version.to_string()),
            os: Some(r.os.to_string()),
            device: Some(r.category.to_string()),
        },
        None => Device { browser: None, browser_version: None, os: None, device: None },
    }
}

/// channel taxonomy. assistant referrals are their own channel.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Direct,
    Internal,
    Search,
    Social,
    Ai,
    Email,
    Paid,
    Referral,
    Campaign,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attribution {
    pub source: Option<String>,
    pub channel: Channel,
}

/// assistant referrals stay first-class: this table wins over the snowplow
/// classification, so chatgpt.com is `Ai` even though snowplow knows it.
const AI: &[&str] = &[
    "chatgpt.com", "chat.openai.com", "perplexity.ai", "claude.ai", "gemini.google.com",
    "copilot.microsoft.com", "you.com", "phind.com", "kagi.com", "poe.com", "grok.com",
];

fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.split('@').next_back()?.split(':').next()?;
    let host = host.strip_prefix("www.").unwrap_or(host);
    if host.is_empty() { None } else { Some(host.to_ascii_lowercase()) }
}

fn hosts_match(host: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('.') {
        // "google." matches google.com, google.de — prefix families
        host == prefix
            || host.starts_with(&format!("{prefix}."))
            || host.contains(&format!(".{prefix}."))
    } else {
        host == pattern || host.ends_with(&format!(".{pattern}"))
    }
}

/// look up a referrer host in the snowplow table: exact domain match first,
/// then walk up parent domains by stripping the leftmost label.
fn referer_lookup(host: &str) -> Option<(&'static str, &'static str)> {
    let mut candidate = host;
    loop {
        if let Ok(i) = referers::REFERERS.binary_search_by_key(&candidate, |&(d, _, _)| d) {
            let (_, source, medium) = referers::REFERERS[i];
            return Some((source, medium));
        }
        match candidate.split_once('.') {
            Some((_, parent)) if parent.contains('.') => candidate = parent,
            _ => return None,
        }
    }
}

/// snowplow medium → channel. `unknown` means "named source, medium unknown" —
/// classified as referral but keeping the source name.
fn medium_channel(medium: &str) -> Channel {
    match medium {
        "search" => Channel::Search,
        "social" => Channel::Social,
        "email" => Channel::Email,
        "paid" => Channel::Paid,
        "chatbot" => Channel::Ai,
        _ => Channel::Referral,
    }
}

/// attribute an event: utm wins, then referrer host, then direct/internal.
pub fn attribute(body: &EventBody) -> Attribution {
    if let Some(src) = body.utm.as_ref().and_then(|utm| utm.source.as_ref()) {
        return Attribution { source: Some(src.clone()), channel: Channel::Campaign };
    }
    let own = body.hostname.to_ascii_lowercase();
    let own = own.strip_prefix("www.").unwrap_or(&own);
    match body.referrer.as_deref().and_then(host_of) {
        None => Attribution { source: None, channel: Channel::Direct },
        Some(host) if hosts_match(&host, own) => {
            Attribution { source: None, channel: Channel::Internal }
        }
        Some(host) => {
            if AI.iter().any(|p| hosts_match(&host, p)) {
                return Attribution { source: Some(host), channel: Channel::Ai };
            }
            match referer_lookup(&host) {
                Some((source, medium)) => Attribution {
                    source: Some(source.to_string()),
                    channel: medium_channel(medium),
                },
                None => Attribution { source: Some(host), channel: Channel::Referral },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lytics_event::{Actor, Kind};

    fn body(referrer: Option<&str>, utm_source: Option<&str>) -> EventBody {
        EventBody {
            neuron: "lytics1x".into(),
            actor: Actor::Human,
            agent: None,
            kind: Kind::Pageview,
            navigation: None,
            hostname: "cyber.page".into(),
            pathname: "/".into(),
            referrer: referrer.map(String::from),
            utm: utm_source.map(|s| lytics_event::event::Utm {
                source: Some(s.into()),
                medium: None,
                campaign: None,
                term: None,
                content: None,
            }),
            attention: None,
            props: None,
            revenue: None,
            timestamp: 0,
        }
    }

    #[test]
    fn assistant_referral_is_ai_channel() {
        let a = attribute(&body(Some("https://chatgpt.com/c/123"), None));
        assert_eq!(a.channel, Channel::Ai);
        assert_eq!(a.source.as_deref(), Some("chatgpt.com"));
    }

    #[test]
    fn google_is_search_even_with_cctld() {
        let a = attribute(&body(Some("https://www.google.de/search?q=x"), None));
        assert_eq!(a.channel, Channel::Search);
    }

    #[test]
    fn own_host_is_internal_and_none_is_direct() {
        assert_eq!(attribute(&body(Some("https://cyber.page/other"), None)).channel, Channel::Internal);
        assert_eq!(attribute(&body(None, None)).channel, Channel::Direct);
    }

    #[test]
    fn gmail_is_email_channel_with_source_name() {
        let a = attribute(&body(Some("https://mail.google.com/mail/u/0"), None));
        assert_eq!(a.channel, Channel::Email);
        assert_eq!(a.source.as_deref(), Some("Gmail"));
    }

    #[test]
    fn parent_domain_walk_resolves_subdomains() {
        let a = attribute(&body(Some("https://l.facebook.com/l.php?u=x"), None));
        assert_eq!(a.channel, Channel::Social);
        assert_eq!(a.source.as_deref(), Some("Facebook"));
    }

    #[test]
    fn utm_wins_over_referrer() {
        let a = attribute(&body(Some("https://x.com/post"), Some("newsletter")));
        assert_eq!(a.channel, Channel::Campaign);
        assert_eq!(a.source.as_deref(), Some("newsletter"));
    }
}
