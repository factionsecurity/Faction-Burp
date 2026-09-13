package com.faction.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

class CodeBlockHtmlTest {

	private static final String REQ = "GET /a HTTP/1.1\r\nHost: h.example\r\nUser-Agent: x\r\nCookie: s=1\r\n\r\nbody\r\n\r\n";

	@Test
	void wholeMessageStartsAtLineOneWithNoSnips() {
		CodeBlockHtml.Excerpt e = CodeBlockHtml.whole(REQ);
		assertEquals(1, e.startLine());
		assertFalse(e.snipBefore());
		assertFalse(e.snipAfter());
		assertEquals(List.of("GET /a HTTP/1.1", "Host: h.example", "User-Agent: x", "Cookie: s=1", "", "body"), e.lines());
	}

	@Test
	void selectionExpandsToWholeLinesAndRemembersTheFirstSelectedLine() {
		int start = REQ.indexOf("h.example") + 3;   // mid line 2
		int end = REQ.indexOf("s=1") + 1;           // mid line 4
		CodeBlockHtml.Excerpt e = CodeBlockHtml.excerpt(REQ, start, end);
		assertEquals(2, e.startLine());
		assertEquals(List.of("Host: h.example", "User-Agent: x", "Cookie: s=1"), e.lines());
		assertTrue(e.snipBefore());
		assertTrue(e.snipAfter());
	}

	@Test
	void selectionFromTheStartHasNoLeadingSnip() {
		CodeBlockHtml.Excerpt e = CodeBlockHtml.excerpt(REQ, 0, 5);
		assertEquals(1, e.startLine());
		assertEquals(List.of("GET /a HTTP/1.1"), e.lines());
		assertFalse(e.snipBefore());
		assertTrue(e.snipAfter());
	}

	@Test
	void selectionToTheEndHasNoTrailingSnip() {
		CodeBlockHtml.Excerpt e = CodeBlockHtml.excerpt(REQ, REQ.indexOf("body"), REQ.length());
		assertEquals(6, e.startLine());
		assertEquals(List.of("body"), e.lines());
		assertTrue(e.snipBefore());
		assertFalse(e.snipAfter());
	}

	@Test
	void emptySelectionMeansTheWholeMessage() {
		assertEquals(CodeBlockHtml.whole(REQ), CodeBlockHtml.excerpt(REQ, 7, 7));
		assertEquals(CodeBlockHtml.whole(REQ), CodeBlockHtml.excerpt(REQ, -1, -1));
	}

	@Test
	void bareLfLineEndingsCountTheSame() {
		String lf = REQ.replace("\r\n", "\n");
		CodeBlockHtml.Excerpt e = CodeBlockHtml.excerpt(lf, lf.indexOf("User-Agent"), lf.indexOf("User-Agent") + 4);
		assertEquals(3, e.startLine());
		assertEquals(List.of("User-Agent: x"), e.lines());
	}

	@Test
	void renderMatchesThePortalsTableShape() {
		String html = CodeBlockHtml.render(new CodeBlockHtml.Excerpt(List.of("GET /a?b=1&c=<2> HTTP/1.1", "", "\t{ \"k\": 1 }"), 100, false, false));
		assertTrue(html.startsWith("<table class=\"code-block\"><tbody><tr class=\"code-block-pad\">"), html);
		assertTrue(html.contains("<tr><td class=\"code-block-gutter\">100</td><td class=\"code-block-line\">GET /a?b=1&amp;c=&lt;2&gt; HTTP/1.1</td></tr>"), html);
		assertTrue(html.contains("<tr><td class=\"code-block-gutter\">101</td><td class=\"code-block-line\">&nbsp;</td></tr>"), html);
		assertTrue(html.contains("<tr><td class=\"code-block-gutter\">102</td><td class=\"code-block-line\">&nbsp;&nbsp;&nbsp;&nbsp;{ &quot;k&quot;: 1 }</td></tr>"), html);
		assertTrue(html.endsWith("</td></tr></tbody></table>"), html);
		assertEquals(2, html.split("code-block-pad", -1).length - 1, "one pad row top and bottom");
	}

	@Test
	void snipMarkersAreRowsAndTheGutterStartsOneBeforeTheFirstSelectedLine() {
		// Lines 4-5 selected: the leading marker takes 3, the lines keep 4 and 5, the trailing marker takes 6.
		CodeBlockHtml.Excerpt e = CodeBlockHtml.excerpt(REQ, REQ.indexOf("User-Agent"), REQ.indexOf("s=1") + 1);
		assertEquals(3, e.startLine());
		String html = CodeBlockHtml.block("Request", e);
		assertTrue(html.startsWith("<p><b>Request:</b></p><table"), html);
		assertTrue(html.contains("<tr><td class=\"code-block-gutter\">2</td><td class=\"code-block-line\">[ ...snip... ]</td></tr>"
				+ "<tr><td class=\"code-block-gutter\">3</td><td class=\"code-block-line\">User-Agent: x</td></tr>"
				+ "<tr><td class=\"code-block-gutter\">4</td><td class=\"code-block-line\">Cookie: s=1</td></tr>"
				+ "<tr><td class=\"code-block-gutter\">5</td><td class=\"code-block-line\">[ ...snip... ]</td></tr>"), html);
		assertFalse(html.contains("<p><b>[ ...snip... ]"), "no marker outside the table: " + html);
	}

	@Test
	void selectionFromLineOneKeepsLineOneAtOne() {
		String html = CodeBlockHtml.render(CodeBlockHtml.excerpt(REQ, 0, 5));
		assertTrue(html.contains("<tr><td class=\"code-block-gutter\">1</td><td class=\"code-block-line\">GET /a HTTP/1.1</td></tr>"
				+ "<tr><td class=\"code-block-gutter\">2</td><td class=\"code-block-line\">[ ...snip... ]</td></tr>"), html);
	}

	@Test
	void commonIndentationIsStrippedFromAnExcerpt() {
		String body = "HTTP/1.1 200 OK\r\n\r\n<html>\r\n"
				+ "                    <section class=blog-header>\r\n"
				+ "                        <h1>0 search results</h1>\r\n"
				+ "\r\n"
				+ "                        <hr>\r\n"
				+ "                    </section>\r\n"
				+ "</html>\r\n";
		CodeBlockHtml.Excerpt e = CodeBlockHtml.excerpt(body, body.indexOf("<section"), body.indexOf("</section>") + 3);
		assertEquals(List.of("<section class=blog-header>", "    <h1>0 search results</h1>", "", "    <hr>", "</section>"), e.lines());
		assertEquals(4, e.startLine());
	}

	@Test
	void tabIndentationIsStrippedToo() {
		String body = "\t\t<a>\r\n\t\t\t<b/>\r\n\t\t</a>\r\n";
		assertEquals(List.of("<a>", "\t<b/>", "</a>"), CodeBlockHtml.whole(body).lines());
	}

	@Test
	void aLessIndentedLineLimitsTheStrip() {
		String body = "    a\r\n  b\r\n      c\r\n";
		assertEquals(List.of("  a", "b", "    c"), CodeBlockHtml.whole(body).lines());
	}

	@Test
	void blockWithoutSnipsHasNoMarkers() {
		String html = CodeBlockHtml.block("Response", CodeBlockHtml.whole("HTTP/1.1 200 OK\r\n\r\n"));
		assertFalse(html.contains("snip"), html);
	}

	@Test
	void renderedRequestRoundTripsThroughSendToRepeater() throws Exception {
		String html = CodeBlockHtml.block("Request", CodeBlockHtml.whole(REQ));
		Matcher m = Pattern.compile("href='([^']+)'>Send to Repeater").matcher(RepeaterLink.addLinks(html));
		assertTrue(m.find(), "numbered block still gets a link");
		RepeaterLink.Target t = RepeaterLink.decode(new URL(m.group(1)));
		assertEquals("h.example", t.host());
		assertEquals("GET /a HTTP/1.1\r\nHost: h.example\r\nUser-Agent: x\r\nCookie: s=1\r\n\r\nbody\r\n\r\n",
				new String(t.request(), StandardCharsets.ISO_8859_1));
	}
}
