//! Safe rendering of attacker-controlled Markdown (`description` in every
//! metadata document, `justification` on token requests, mission text).
//!
//! The draft says "MUST sanitize before rendering". We go one step further
//! than sanitizing HTML after the fact: the parser's event stream is rendered
//! through a fixed whitelist of tags, all text is escaped, raw/inline HTML in
//! the source is dropped, images become a placeholder, and links are shown as
//! text plus their URL — **not** as anchors, so nothing on a consent screen
//! can be a phishing link. Input is capped so a hostile document cannot blow
//! up the page.

use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

/// Longest Markdown source we render; the rest is dropped with a marker.
pub const MAX_INPUT: usize = 8 * 1024;

fn escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
}

/// Render Markdown to a restricted HTML fragment. The output is safe to
/// insert unescaped (`| safe`) into a template.
pub fn render(src: &str) -> String {
    let (src, truncated) = if src.len() > MAX_INPUT {
        let mut end = MAX_INPUT;
        while !src.is_char_boundary(end) {
            end -= 1;
        }
        (&src[..end], true)
    } else {
        (src, false)
    };
    let parser = Parser::new_ext(src, Options::empty());
    let mut out = String::with_capacity(src.len() + 64);
    let mut skip_depth = 0usize; // inside an image: swallow content
    let mut link_url: Vec<String> = Vec::new();
    for ev in parser {
        if skip_depth > 0 {
            match ev {
                Event::Start(_) => skip_depth += 1,
                Event::End(_) => skip_depth -= 1,
                _ => {}
            }
            continue;
        }
        match ev {
            Event::Start(tag) => match tag {
                Tag::Paragraph => out.push_str("<p>"),
                Tag::Heading { .. } => out.push_str("<p><strong>"),
                Tag::BlockQuote(_) => out.push_str("<blockquote>"),
                Tag::CodeBlock(_) => out.push_str("<pre><code>"),
                Tag::List(Some(_)) => out.push_str("<ol>"),
                Tag::List(None) => out.push_str("<ul>"),
                Tag::Item => out.push_str("<li>"),
                Tag::Emphasis => out.push_str("<em>"),
                Tag::Strong => out.push_str("<strong>"),
                Tag::Strikethrough => out.push_str("<s>"),
                Tag::Link { dest_url, .. } => {
                    out.push_str("<span class=\"md-link\">");
                    link_url.push(dest_url.to_string());
                }
                Tag::Image { .. } => {
                    out.push_str("[image]");
                    skip_depth = 1;
                }
                // Tables, footnotes, definition lists, metadata blocks, HTML
                // blocks: not enabled or not rendered — treat as plain flow.
                _ => {}
            },
            Event::End(tag) => match tag {
                TagEnd::Paragraph => out.push_str("</p>\n"),
                TagEnd::Heading(_) => out.push_str("</strong></p>\n"),
                TagEnd::BlockQuote(_) => out.push_str("</blockquote>\n"),
                TagEnd::CodeBlock => out.push_str("</code></pre>\n"),
                TagEnd::List(true) => out.push_str("</ol>\n"),
                TagEnd::List(false) => out.push_str("</ul>\n"),
                TagEnd::Item => out.push_str("</li>\n"),
                TagEnd::Emphasis => out.push_str("</em>"),
                TagEnd::Strong => out.push_str("</strong>"),
                TagEnd::Strikethrough => out.push_str("</s>"),
                TagEnd::Link => {
                    if let Some(url) = link_url.pop() {
                        out.push_str(" (");
                        escape(&url, &mut out);
                        out.push(')');
                    }
                    out.push_str("</span>");
                }
                _ => {}
            },
            Event::Text(t) => escape(&t, &mut out),
            Event::Code(t) => {
                out.push_str("<code>");
                escape(&t, &mut out);
                out.push_str("</code>");
            }
            Event::SoftBreak => out.push(' '),
            Event::HardBreak => out.push_str("<br>\n"),
            Event::Rule => out.push_str("<hr>\n"),
            // Raw HTML of any kind is dropped: never emitted, never escaped in.
            Event::Html(_) | Event::InlineHtml(_) => {}
            Event::FootnoteReference(_)
            | Event::TaskListMarker(_)
            | Event::InlineMath(_)
            | Event::DisplayMath(_) => {}
        }
    }
    if truncated {
        out.push_str("<p><em>[description truncated]</em></p>\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_markdown() {
        let html = render("# Title\n\nSome **bold** and _em_ and `code`.\n\n- a\n- b\n\n1. x\n");
        assert!(html.contains("<p><strong>Title</strong></p>"));
        assert!(html.contains("<strong>bold</strong>"));
        assert!(html.contains("<em>em</em>"));
        assert!(html.contains("<code>code</code>"));
        assert!(html.contains("<ul><li>a</li>"), "{html}");
        assert!(html.contains("<ol><li>x</li>"), "{html}");
    }

    #[test]
    fn html_is_dropped_and_text_escaped() {
        let html = render(
            "hi <script>alert(1)</script> there\n\n<div onclick=x>block</div>\n\n<b>bold?</b>",
        );
        assert!(!html.contains("<script"));
        assert!(!html.contains("onclick"));
        assert!(!html.contains("<div"));
        assert!(!html.contains("<b>"));
        assert!(html.contains("hi "));
        let html = render("a < b & c > d \"q\" 'x'");
        assert!(html.contains("a &lt; b &amp; c &gt; d &quot;q&quot; &#x27;x&#x27;"));
    }

    #[test]
    fn links_are_text_not_anchors_and_images_are_placeholders() {
        let html = render("see [our site](https://evil.example/login) now ![alt](https://x/y.png)");
        assert!(!html.contains("<a "));
        assert!(!html.contains("href"));
        assert!(
            html.contains("<span class=\"md-link\">our site (https://evil.example/login)</span>")
        );
        assert!(html.contains("[image]"));
        assert!(!html.contains("alt"));
        // javascript: URLs are just text too, and escaped
        let html = render("[x](javascript:alert('1'))");
        assert!(html.contains("javascript:alert(&#x27;1&#x27;)"));
        assert!(!html.contains("href"));
    }

    #[test]
    fn autolinks_and_raw_urls_are_not_clickable() {
        let html = render("<https://a.example> and https://b.example");
        assert!(!html.contains("<a "));
        assert!(html.contains("https://a.example"));
    }

    #[test]
    fn long_input_is_truncated() {
        let big = "x".repeat(MAX_INPUT + 100);
        let html = render(&big);
        assert!(html.contains("[description truncated]"));
        assert!(html.len() < MAX_INPUT + 200);
    }
}
