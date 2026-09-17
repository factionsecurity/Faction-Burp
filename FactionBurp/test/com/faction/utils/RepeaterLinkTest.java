package com.faction.utils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * The details HTML of a finding reaches the extension in several shapes,
 * depending on who last saved it:
 *  - straight from this extension: {@code <pre class='code'><code>…<br/>…</code></pre>}
 *  - after a save in the Faction UI: the same with {@code <br>} (browser-normalised)
 *  - a fenced code block typed in the UI: {@code <pre><code class="language-x">…\n…</code></pre>}
 *  - the UI's table-shaped code block: one {@code <td class="code-block-line">} per line
 * Every one of them must yield a working "Send to Repeater" link.
 */
class RepeaterLinkTest {

	private static final Pattern HREF = Pattern.compile("<a class='btn' href='([^']+)'>Send to Repeater</a>");

	private static RepeaterLink.Target decodeFirstLink(String html) throws Exception {
		Matcher m = HREF.matcher(html);
		assertTrue(m.find(), "expected a Send to Repeater link in: " + html);
		return RepeaterLink.decode(new URL(m.group(1)));
	}

	private static int linkCount(String html) {
		Matcher m = HREF.matcher(html);
		int n = 0;
		while (m.find()) n++;
		return n;
	}

	@Test
	void freshExtensionBlockWithSelfClosingBr() throws Exception {
		String html = "<p>steps</p><br/><b>Request: </b><pre class='code'><code>"
				+ "GET /a?b=1&amp;c=2 HTTP/1.1<br/>Host: target.example.com<br/>User-Agent: x<br/><br/></code></pre>";
		String out = RepeaterLink.addLinks(html);
		assertEquals(1, linkCount(out));
		assertTrue(out.indexOf("Send to Repeater") < out.indexOf("<pre"), "link goes before the block");
		RepeaterLink.Target t = decodeFirstLink(out);
		assertEquals("target.example.com", t.host());
		assertEquals(443, t.port());
		assertTrue(t.secure());
		assertArrayEquals("GET /a?b=1&c=2 HTTP/1.1\r\nHost: target.example.com\r\nUser-Agent: x\r\n\r\n"
				.getBytes(StandardCharsets.ISO_8859_1), t.request());
	}

	@Test
	void uiNormalisedBlockWithPlainBrAndHttp2() throws Exception {
		String html = "<p><b>Request: </b></p><pre class=\"code\"><code>"
				+ "GET /?q=%22%3E HTTP/2<br>Host: lab.web-security-academy.net<br>Cookie: s=1<br><br></code></pre>";
		RepeaterLink.Target t = decodeFirstLink(RepeaterLink.addLinks(html));
		assertEquals("lab.web-security-academy.net", t.host());
		assertEquals("GET /?q=%22%3E HTTP/2\r\nHost: lab.web-security-academy.net\r\nCookie: s=1\r\n\r\n",
				new String(t.request(), StandardCharsets.ISO_8859_1));
	}

	@Test
	void fencedBlockWithBareNewlinesAndLanguageClass() throws Exception {
		String html = "<ol><li><p>Intercept:</p></li></ol><pre><code class=\"language-json\">"
				+ "POST /api/v1/user HTTP/1.1\nHost: app.example.com:8080\nContent-Type: application/json\n\n"
				+ "{\n  &quot;a&quot;: 1\n}\n</code></pre>";
		RepeaterLink.Target t = decodeFirstLink(RepeaterLink.addLinks(html));
		assertEquals("app.example.com", t.host());
		assertEquals(8080, t.port());
		String req = new String(t.request(), StandardCharsets.ISO_8859_1);
		assertTrue(req.startsWith("POST /api/v1/user HTTP/1.1\r\nHost: app.example.com:8080\r\n"), req);
		assertTrue(req.contains("\r\n\r\n{\r\n  \"a\": 1\r\n}"), req);
		assertTrue(req.endsWith("\r\n\r\n"), "request is terminated");
		assertFalse(req.contains("<code"), "no markup leaks into the request");
	}

	@Test
	void uiTableCodeBlockWithGutterAndPadRows() throws Exception {
		String html = "<p>Raw request:</p>"
				+ "<table class=\"code-block language-http\"><tbody>"
				+ "<tr class=\"code-block-pad\"><td class=\"code-block-gutter\" contenteditable=\"false\">&nbsp;</td>"
				+ "<td class=\"code-block-line\" contenteditable=\"false\">&nbsp;</td></tr>"
				+ "<tr><td class=\"code-block-gutter\">1</td><td class=\"code-block-line\">GET /x HTTP/1.1</td></tr>"
				+ "<tr><td class=\"code-block-gutter\">2</td><td class=\"code-block-line\">Host: t.example</td></tr>"
				+ "<tr><td class=\"code-block-gutter\">3</td><td class=\"code-block-line\">&nbsp;</td></tr>"
				+ "<tr class=\"code-block-pad\"><td class=\"code-block-gutter\" contenteditable=\"false\">&nbsp;</td>"
				+ "<td class=\"code-block-line\" contenteditable=\"false\">&nbsp;</td></tr>"
				+ "</tbody></table>";
		String out = RepeaterLink.addLinks(html);
		assertEquals(1, linkCount(out));
		assertTrue(out.indexOf("Send to Repeater") < out.indexOf("<table"), "link goes before the block");
		RepeaterLink.Target t = decodeFirstLink(out);
		assertEquals("t.example", t.host());
		assertEquals("GET /x HTTP/1.1\r\nHost: t.example\r\n\r\n",
				new String(t.request(), StandardCharsets.ISO_8859_1));
	}

	@Test
	void uiTableCodeBlockWithoutGutter() throws Exception {
		String html = "<table class=\"code-block\"><tbody>"
				+ "<tr class=\"code-block-pad\"><td class=\"code-block-line\" contenteditable=\"false\">&nbsp;</td></tr>"
				+ "<tr><td class=\"code-block-line\">GET /payments?q=John+Smith HTTP/1.1</td></tr>"
				+ "<tr><td class=\"code-block-line\">Host: app.example.com</td></tr>"
				+ "<tr class=\"code-block-pad\"><td class=\"code-block-line\" contenteditable=\"false\">&nbsp;</td></tr>"
				+ "</tbody></table>";
		RepeaterLink.Target t = decodeFirstLink(RepeaterLink.addLinks(html));
		assertEquals("app.example.com", t.host());
		assertEquals("GET /payments?q=John+Smith HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
				new String(t.request(), StandardCharsets.ISO_8859_1));
	}

	@Test
	void blocksWithoutHostHeaderAreLeftAlone() {
		String html = "<b>Response: </b><pre class='code'><code>HTTP/1.1 200 OK<br/>Content-Type: text/html<br/></code></pre>"
				+ "<table class=\"code-block\"><tbody><tr><td class=\"code-block-line\">just code</td></tr></tbody></table>"
				+ "<table><tbody><tr><th>Header</th><th>Value</th></tr><tr><td>Server</td><td>nginx</td></tr></tbody></table>";
		assertEquals(html, RepeaterLink.addLinks(html));
	}

	@Test
	void plainTableWithoutCodeBlockClassIsRecognised() throws Exception {
		String html = "<table><tbody>"
				+ "<tr><td>GET /plain HTTP/1.1</td></tr>"
				+ "<tr><td>Host: plain.example</td></tr>"
				+ "<tr><td></td></tr>"
				+ "</tbody></table>";
		RepeaterLink.Target t = decodeFirstLink(RepeaterLink.addLinks(html));
		assertEquals("plain.example", t.host());
		assertEquals("GET /plain HTTP/1.1\r\nHost: plain.example\r\n\r\n",
				new String(t.request(), StandardCharsets.ISO_8859_1));
	}

	@Test
	void leadingBlankLinesAreTrimmed() throws Exception {
		RepeaterLink.Target t = decodeFirstLink(RepeaterLink.addLinks(
				"<pre><code><br/><br/>GET /x HTTP/1.1<br/>Host: h<br/></code></pre>"));
		assertEquals("GET /x HTTP/1.1\r\nHost: h\r\n\r\n", new String(t.request(), StandardCharsets.ISO_8859_1));
	}

	@Test
	void requestAndResponseBlocksYieldOneLink() {
		String html = "<b>Request: </b><pre class='code'><code>GET / HTTP/1.1<br/>Host: h<br/><br/></code></pre>"
				+ "<b>Response: </b><pre class='code'><code>HTTP/1.1 200 OK<br/><br/></code></pre>";
		assertEquals(1, linkCount(RepeaterLink.addLinks(html)));
	}

	@Test
	void port80IsPlainHttp() throws Exception {
		RepeaterLink.Target t = decodeFirstLink(RepeaterLink.addLinks(
				"<pre><code>GET / HTTP/1.1\nHost: h.example:80\n\n</code></pre>"));
		assertEquals("h.example", t.host());
		assertEquals(80, t.port());
		assertFalse(t.secure());
	}

	@Test
	void snipMarkersSurviveAsText() throws Exception {
		RepeaterLink.Target t = decodeFirstLink(RepeaterLink.addLinks(
				"<pre class='code'><code>GET / HTTP/1.1<br/>Host: h<br/>Cookie: <b>[ ...snip... ]</b><br/><br/></code></pre>"));
		assertEquals("GET / HTTP/1.1\r\nHost: h\r\nCookie: [ ...snip... ]\r\n\r\n",
				new String(t.request(), StandardCharsets.ISO_8859_1));
	}

	@Test
	void decodeRejectsUrlsThatAreNotOurs() throws Exception {
		assertNull(RepeaterLink.decode(new URL("https://example.com/page")));
		assertNull(RepeaterLink.decode(null));
	}

	@Test
	void hrefSurvivesJavaUrlParsingWithEveryBase64Character() throws Exception {
		// Base64 of binary-ish bodies contains '+', '/' and '='; all must round-trip through the host.
		String html = "<pre><code>POST /x HTTP/1.1\nHost: h\n\n{\"a\":\"ÿþ??&gt;&gt;~~\"}\n</code></pre>";
		RepeaterLink.Target t = decodeFirstLink(RepeaterLink.addLinks(html));
		assertNotNull(t);
		assertTrue(new String(t.request(), StandardCharsets.ISO_8859_1).contains("{\"a\":\"ÿþ??>>~~\"}"));
	}
}
