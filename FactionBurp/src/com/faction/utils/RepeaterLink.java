package com.faction.utils;

import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringEscapeUtils;

/**
 * Builds and decodes the "Send to Repeater" links shown in the vulnerability
 * details pane.
 *
 * <p>A finding's details HTML can carry an HTTP request in several shapes,
 * depending on who last saved it:
 * <ul>
 *   <li>written by this extension: {@code <pre class='code'><code>…<br/>…</code></pre>}</li>
 *   <li>re-saved in the Faction UI: the same block with {@code <br>}</li>
 *   <li>a fenced code block typed in the UI: {@code <pre><code class="language-…">…\n…</code></pre>}</li>
 *   <li>the UI's table-shaped code block: {@code <table class="code-block">} with one
 *       {@code <td class="code-block-line">} per line</li>
 * </ul>
 * {@link #addLinks} recognises all of them — any {@code <pre>} and any
 * {@code <table>} — extracts the block's text, and treats it as a request when
 * it carries a Host header. For those it inserts a link whose URL host carries
 * the request, URL-encoded base64. The
 * link deliberately uses the host rather than the path: Swing's HTML parser
 * hands the href back verbatim and {@link URL#getHost()} returns it untouched.
 * {@link #decode} reverses it when the link is clicked.
 */
public final class RepeaterLink {

	/** Where the request should be sent, as reconstructed from a clicked link. */
	public record Target(String host, int port, boolean secure, byte[] request) { }

	private static final String LINK_SCHEME = "http://";
	private static final String LINK_PREFIX = "&nbsp;&nbsp;<a class='btn' href='";
	private static final String LINK_SUFFIX = "'>Send to Repeater</a><br/>";

	/** A <pre> block, or any table: the UI's code block (with or without a line-number gutter) or a plain one. */
	private static final Pattern BLOCK = Pattern.compile(
			"(?is)(<pre\\b[^>]*>(.*?)</pre>)|(<table\\b[^>]*>(.*?)</table>)");
	private static final Pattern ROW = Pattern.compile("(?is)<tr\\b([^>]*)>(.*?)</tr>");
	private static final Pattern CELL = Pattern.compile("(?is)<t[dh]\\b[^>]*>(.*?)</t[dh]>");
	private static final Pattern BR = Pattern.compile("(?i)<br\\s*/?>");
	private static final Pattern TAG = Pattern.compile("(?s)<[^>]+>");
	private static final Pattern HOST_HEADER = Pattern.compile("(?im)^host:[ \\t]*([^\\r\\n]+)");

	private RepeaterLink() { }

	/**
	 * Returns {@code html} with a "Send to Repeater" link inserted before every
	 * code block that contains an HTTP request (identified by a Host header).
	 * Blocks without one — responses, ordinary code — are left untouched.
	 */
	public static String addLinks(String html) {
		if (html == null || html.isEmpty()) return html;
		Matcher m = BLOCK.matcher(html);
		StringBuilder out = new StringBuilder();
		while (m.find()) {
			String request = m.group(1) != null ? requestFromPre(m.group(2)) : requestFromTable(m.group(4));
			String replacement = m.group();
			if (HOST_HEADER.matcher(request).find()) {
				replacement = LINK_PREFIX + hrefFor(request) + LINK_SUFFIX + replacement;
			}
			m.appendReplacement(out, Matcher.quoteReplacement(replacement));
		}
		m.appendTail(out);
		return out.toString();
	}

	/**
	 * Decodes a clicked link. Returns null if {@code url} is not one of ours or
	 * carries no Host header.
	 */
	public static Target decode(URL url) {
		if (url == null || url.getHost() == null || url.getHost().isEmpty()) return null;
		String request;
		try {
			byte[] data = Base64.getDecoder().decode(URLDecoder.decode(url.getHost(), StandardCharsets.UTF_8));
			request = new String(data, StandardCharsets.ISO_8859_1);
		} catch (IllegalArgumentException e) {
			return null; // not base64: an ordinary hyperlink in the details
		}
		Matcher host = HOST_HEADER.matcher(request);
		if (!host.find()) return null;
		String authority = host.group(1).trim();
		String hostName = authority;
		int port = 443;
		int colon = authority.lastIndexOf(':');
		if (colon > 0 && colon < authority.length() - 1 && authority.indexOf(']') < colon) {
			try {
				port = Integer.parseInt(authority.substring(colon + 1));
				hostName = authority.substring(0, colon);
			} catch (NumberFormatException ignored) { }
		}
		boolean secure = port != 80;
		return new Target(hostName, port, secure, request.getBytes(StandardCharsets.ISO_8859_1));
	}

	// ── Request text extraction ─────────────────────────────────────────────────

	/** Inner HTML of a <pre> → raw request text with CRLF line endings. */
	static String requestFromPre(String innerHtml) {
		String text = BR.matcher(innerHtml).replaceAll("\n");
		text = TAG.matcher(text).replaceAll("");
		return normalise(StringEscapeUtils.unescapeHtml4(text));
	}

	/** Inner HTML of a UI code-block table → raw request text with CRLF line endings. */
	static String requestFromTable(String innerHtml) {
		List<String> lines = new ArrayList<>();
		Matcher row = ROW.matcher(innerHtml);
		while (row.find()) {
			if (row.group(1).contains("code-block-pad")) continue; // spacer rows are not code
			// The code is the last cell: a gutter of line numbers, if any, comes first.
			String last = null;
			Matcher cell = CELL.matcher(row.group(2));
			while (cell.find()) last = cell.group(1);
			if (last == null) continue;
			String text = BR.matcher(last).replaceAll("\n");
			text = TAG.matcher(text).replaceAll("");
			lines.add(StringEscapeUtils.unescapeHtml4(text));
		}
		return normalise(String.join("\n", lines));
	}

	/** Unifies line endings to CRLF, trims, and terminates the request with a blank line. */
	private static String normalise(String text) {
		String s = text.replace('\u00a0', ' ').replace("\r\n", "\n").replace('\r', '\n');
		StringBuilder sb = new StringBuilder();
		for (String line : s.split("\n", -1)) sb.append(stripTrailing(line)).append('\n');
		s = sb.toString().strip();
		return s.replace("\n", "\r\n") + "\r\n\r\n";
	}

	private static String stripTrailing(String line) {
		int end = line.length();
		while (end > 0 && (line.charAt(end - 1) == ' ' || line.charAt(end - 1) == '\t')) end--;
		return line.substring(0, end);
	}

	private static String hrefFor(String request) {
		String b64 = Base64.getEncoder().encodeToString(request.getBytes(StandardCharsets.ISO_8859_1));
		return LINK_SCHEME + URLEncoder.encode(b64, StandardCharsets.UTF_8);
	}
}
