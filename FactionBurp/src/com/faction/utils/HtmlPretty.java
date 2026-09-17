package com.faction.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Lays out markup the way Burp's "Pretty" message view does: every tag and
 * every run of text on its own line, children indented four spaces, raw-text
 * elements ({@code <script>}, {@code <style>}, {@code <pre>}, {@code <textarea>})
 * kept line for line. Burp only formats for display — a selection still maps
 * to the raw, often single-line, bytes — so this reproduces what the tester
 * was looking at when the evidence is posted.
 */
public final class HtmlPretty {

	private static final String INDENT = "    ";
	private static final Set<String> VOID = Set.of("area", "base", "br", "col", "embed", "hr", "img", "input",
			"link", "meta", "param", "source", "track", "wbr");
	private static final Set<String> RAW_TEXT = Set.of("script", "style", "pre", "textarea");
	private static final Pattern TAG = Pattern.compile("<(?:[a-zA-Z][^>]*|/[a-zA-Z][^>]*|!--.*?--|!DOCTYPE[^>]*)>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
	private static final Pattern START_LINE = Pattern.compile("^(?:[A-Z]{3,20} \\S+ HTTP/\\d(?:\\.\\d)?|HTTP/\\d(?:\\.\\d)? \\d{3}.*)$");

	private HtmlPretty() { }

	/** Whether the text contains at least one HTML tag. */
	public static boolean looksLikeMarkup(String text) {
		return text != null && TAG.matcher(text).find();
	}

	/**
	 * Pretty-prints the markup in an excerpt. HTTP headers at the top of a
	 * message are left alone; only the body (or the whole excerpt when it is a
	 * body fragment) is formatted, and only when it contains markup. Returns
	 * the same excerpt when there is nothing to do.
	 */
	public static CodeBlockHtml.Excerpt apply(CodeBlockHtml.Excerpt e) {
		List<String> lines = e.lines();
		if (lines.isEmpty()) return e;
		int bodyStart = 0;
		if (START_LINE.matcher(lines.get(0)).matches()) {
			int blank = lines.indexOf("");
			if (blank < 0) return e; // headers only
			bodyStart = blank + 1;
		}
		String body = String.join("\n", lines.subList(bodyStart, lines.size()));
		if (!looksLikeMarkup(body)) return e;
		List<String> out = new ArrayList<>(lines.subList(0, bodyStart));
		out.addAll(format(body));
		return new CodeBlockHtml.Excerpt(out, e.startLine(), e.snipBefore(), e.snipAfter());
	}

	/** The markup as pretty-printed lines, without trailing whitespace. */
	public static List<String> format(String html) {
		List<String> out = new ArrayList<>();
		int depth = 0;
		int i = 0;
		int n = html.length();
		while (i < n) {
			int lt = html.indexOf('<', i);
			if (lt < 0) { text(out, depth, html.substring(i)); break; }
			text(out, depth, html.substring(i, lt));
			int gt = tagEnd(html, lt);
			if (gt < 0) { text(out, depth, html.substring(lt)); break; }
			String tag = html.substring(lt, gt + 1);
			i = gt + 1;
			String name = tagName(tag);
			if (tag.startsWith("</")) {
				depth = Math.max(0, depth - 1);
				line(out, depth, tag.trim());
			} else if (tag.startsWith("<!") || tag.startsWith("<?") || tag.endsWith("/>") || VOID.contains(name)) {
				line(out, depth, tag.trim());
			} else if (RAW_TEXT.contains(name)) {
				// Content is verbatim, not markup: keep its lines, shifted to sit one level in.
				line(out, depth, tag.trim());
				depth++;
				int close = indexOfIgnoreCase(html, "</" + name, i);
				String raw = close < 0 ? html.substring(i) : html.substring(i, close);
				List<String> rawLines = new ArrayList<>();
				for (String l : raw.replace("\r\n", "\n").replace('\r', '\n').split("\n")) {
					if (!l.isBlank()) rawLines.add(stripTrailing(l));
				}
				for (String l : CodeBlockHtml.dedent(rawLines)) line(out, depth, l);
				i = close < 0 ? n : close; // the closing tag is handled like any other
			} else {
				line(out, depth, tag.trim());
				depth++;
			}
		}
		return out;
	}

	// ── Helpers ─────────────────────────────────────────────────────────────────

	private static void text(List<String> out, int depth, String raw) {
		String t = raw.replaceAll("\\s+", " ").trim();
		if (!t.isEmpty()) line(out, depth, t);
	}

	private static void line(List<String> out, int depth, String s) {
		out.add(INDENT.repeat(depth) + s);
	}

	/** Index of the '>' closing the tag that starts at {@code lt}, honouring quoted attribute values. */
	private static int tagEnd(String html, int lt) {
		if (html.startsWith("<!--", lt)) {
			int end = html.indexOf("-->", lt + 4);
			return end < 0 ? -1 : end + 2;
		}
		char quote = 0;
		for (int i = lt + 1; i < html.length(); i++) {
			char c = html.charAt(i);
			if (quote != 0) { if (c == quote) quote = 0; }
			else if (c == '"' || c == '\'') quote = c;
			else if (c == '>') return i;
		}
		return -1;
	}

	private static String tagName(String tag) {
		int i = tag.startsWith("</") ? 2 : 1;
		int start = i;
		while (i < tag.length() && (Character.isLetterOrDigit(tag.charAt(i)) || tag.charAt(i) == '-' || tag.charAt(i) == ':')) i++;
		return tag.substring(start, i).toLowerCase(Locale.ROOT);
	}

	private static int indexOfIgnoreCase(String s, String needle, int from) {
		return s.toLowerCase(Locale.ROOT).indexOf(needle.toLowerCase(Locale.ROOT), from);
	}

	private static String stripTrailing(String l) {
		int end = l.length();
		while (end > 0 && Character.isWhitespace(l.charAt(end - 1))) end--;
		return l.substring(0, end);
	}
}
