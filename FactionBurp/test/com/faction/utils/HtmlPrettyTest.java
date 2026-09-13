package com.faction.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class HtmlPrettyTest {

	@Test
	void oneLineMarkupIsLaidOutLikeBurpsPrettyView() {
		List<String> out = HtmlPretty.format("<h1>0 search results for '\"><script>alert('hacked');</script>'</h1><hr>");
		assertEquals(List.of(
				"<h1>",
				"    0 search results for '\">",
				"    <script>",
				"        alert('hacked');",
				"    </script>",
				"    '",
				"</h1>",
				"<hr>"), out);
	}

	@Test
	void voidAndSelfClosingTagsDoNotIndent() {
		assertEquals(List.of("<div>", "    <br>", "    <img src=\"x\"/>", "    <input type=text>", "    text", "</div>"),
				HtmlPretty.format("<div><br><img src=\"x\"/><input type=text>text</div>"));
	}

	@Test
	void rawTextElementsKeepTheirLinesIndented() {
		assertEquals(List.of("<style>", "    body {", "    color: red;", "    }", "</style>", "<pre>", "    a", "      b", "</pre>"),
				HtmlPretty.format("<style>\n  body {\n  color: red;\n  }\n</style><pre>a\n  b</pre>"));
	}

	@Test
	void commentsDoctypeAndStrayCloseTagsAreHandled() {
		assertEquals(List.of("<!DOCTYPE html>", "<!-- note -->", "<p>", "    x", "</p>", "</div>"),
				HtmlPretty.format("<!DOCTYPE html><!-- note --><p>x</p></div>"));
	}

	@Test
	void whitespaceInsideTextIsCollapsed() {
		assertEquals(List.of("<p>", "    a b c", "</p>"), HtmlPretty.format("<p>\n   a\n   b   c \n</p>"));
	}

	@Test
	void looksLikeMarkupNeedsARealTag() {
		assertTrue(HtmlPretty.looksLikeMarkup("<div>x</div>"));
		assertTrue(HtmlPretty.looksLikeMarkup("text <br/> more"));
		assertFalse(HtmlPretty.looksLikeMarkup("{\"a\": \"1 < 2\"}"));
		assertFalse(HtmlPretty.looksLikeMarkup("plain text"));
	}

	@Test
	void applyFormatsTheBodyOfAResponseAndLeavesHeadersAlone() {
		CodeBlockHtml.Excerpt e = CodeBlockHtml.whole(
				"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Hi</h1></body></html>\r\n");
		CodeBlockHtml.Excerpt pretty = HtmlPretty.apply(e);
		assertEquals(List.of("HTTP/1.1 200 OK", "Content-Type: text/html", "",
				"<html>", "    <body>", "        <h1>", "            Hi", "        </h1>", "    </body>", "</html>"), pretty.lines());
		assertEquals(e.startLine(), pretty.startLine());
	}

	@Test
	void applyFormatsAMarkupOnlySelection() {
		CodeBlockHtml.Excerpt e = new CodeBlockHtml.Excerpt(List.of("<section><h1>x</h1></section>"), 80, true, true);
		CodeBlockHtml.Excerpt pretty = HtmlPretty.apply(e);
		assertEquals(List.of("<section>", "    <h1>", "        x", "    </h1>", "</section>"), pretty.lines());
		assertEquals(80, pretty.startLine());
		assertTrue(pretty.snipBefore() && pretty.snipAfter());
	}

	@Test
	void applyLeavesNonMarkupUntouched() {
		CodeBlockHtml.Excerpt e = CodeBlockHtml.whole("POST /x HTTP/1.1\r\nHost: h\r\n\r\n{\"a\": 1}\r\n");
		assertSame(e, HtmlPretty.apply(e));
	}
}
