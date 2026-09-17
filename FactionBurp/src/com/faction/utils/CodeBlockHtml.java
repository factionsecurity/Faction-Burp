package com.faction.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.function.UnaryOperator;

import org.apache.commons.lang3.StringEscapeUtils;

/**
 * Renders request/response text as the portal's line-numbered code block.
 *
 * <p>The portal stores a fenced block written as {@code ```start=N} as a table:
 * one row per line, a {@code code-block-gutter} cell holding the line number
 * and a {@code code-block-line} cell holding the text, framed by two short
 * {@code code-block-pad} rows. Writing that shape directly means the block
 * round-trips through the portal's editor, keeps its numbers in the report,
 * and is what {@link RepeaterLink} already reads.
 */
public final class CodeBlockHtml {

	/**
	 * The lines to show (common indentation already stripped), the line number
	 * the first one had in the message, and whether the excerpt was cut from a
	 * longer message at either end. A cut is shown as a {@code [ ...snip... ]}
	 * row inside the block: the leading one takes the gutter number just before
	 * {@code startLine}, so the real lines keep their original numbers.
	 */
	public record Excerpt(List<String> lines, int startLine, boolean snipBefore, boolean snipAfter) {
		public Excerpt withLines(UnaryOperator<String> f) {
			List<String> out = new ArrayList<>(lines.size());
			for (String l : lines) out.add(f.apply(l));
			return new Excerpt(out, startLine, snipBefore, snipAfter);
		}
	}

	public static final String SNIP_MARKER = "[ ...snip... ]";

	private CodeBlockHtml() { }

	/** The whole message, numbered from 1. */
	public static Excerpt whole(String raw) {
		return new Excerpt(dedent(lines(raw)), 1, false, false);
	}

	/**
	 * The lines touched by the character range {@code [selStart, selEnd)},
	 * expanded to whole lines and numbered from the first one's position in
	 * the message. An empty or out-of-range selection yields the whole message.
	 */
	public static Excerpt excerpt(String raw, int selStart, int selEnd) {
		if (raw == null) return whole("");
		int len = raw.length();
		selStart = Math.max(0, Math.min(selStart, len));
		selEnd = Math.max(selStart, Math.min(selEnd, len));
		if (selEnd <= selStart) return whole(raw);

		List<String> all = lines(raw);
		int first = lineIndexAt(raw, selStart);
		int last = lineIndexAt(raw, selEnd - 1);
		if (first >= all.size()) return whole(raw); // selection sits in the trailing blank lines
		last = Math.min(last, all.size() - 1);

		List<String> sub = new ArrayList<>(all.subList(first, last + 1));
		trimTrailingBlank(sub);
		return new Excerpt(dedent(sub), first + 1, first > 0, last < all.size() - 1);
	}

	/** Label and the numbered block. */
	public static String block(String label, Excerpt e) {
		return "<p><b>" + StringEscapeUtils.escapeHtml4(label) + ":</b></p>" + render(e);
	}

	/**
	 * The portal's table shape for the excerpt, with a line-number gutter. Snip
	 * markers are rows of their own; the leading one is numbered one before the
	 * first real line so that line keeps its number from the message.
	 */
	public static String render(Excerpt e) {
		String pad = "<tr class=\"code-block-pad\">"
				+ "<td class=\"code-block-gutter\" contenteditable=\"false\">&nbsp;</td>"
				+ "<td class=\"code-block-line\" contenteditable=\"false\">&nbsp;</td></tr>";
		StringBuilder sb = new StringBuilder("<table class=\"code-block\"><tbody>").append(pad);
		int n = e.startLine() - (e.snipBefore() ? 1 : 0);
		if (e.snipBefore()) row(sb, n++, SNIP_MARKER);
		for (String line : e.lines()) row(sb, n++, line);
		if (e.snipAfter()) row(sb, n++, SNIP_MARKER);
		return sb.append(pad).append("</tbody></table>").toString();
	}

	private static void row(StringBuilder sb, int number, String line) {
		sb.append("<tr><td class=\"code-block-gutter\">").append(number).append("</td>")
		  .append("<td class=\"code-block-line\">").append(cell(line)).append("</td></tr>");
	}

	// ── Helpers ─────────────────────────────────────────────────────────────────

	/** Splits on any line ending and drops trailing blank lines, as the portal's fences do. */
	static List<String> lines(String raw) {
		List<String> out = new ArrayList<>();
		if (raw == null || raw.isEmpty()) return out;
		for (String l : raw.split("\r\n|\n|\r", -1)) out.add(l);
		trimTrailingBlank(out);
		return out;
	}

	/**
	 * Strips the leading whitespace every non-blank line shares — an excerpt
	 * from deep inside a response starts at the margin. Compared character by
	 * character, so tabs and spaces are never confused; a whitespace-only line
	 * becomes empty.
	 */
	static List<String> dedent(List<String> lines) {
		String common = null;
		for (String l : lines) {
			if (l.isBlank()) continue;
			String ws = leadingWhitespace(l);
			common = common == null ? ws : commonPrefix(common, ws);
			if (common.isEmpty()) return lines;
		}
		if (common == null || common.isEmpty()) return lines;
		List<String> out = new ArrayList<>(lines.size());
		for (String l : lines) out.add(l.isBlank() ? "" : l.substring(common.length()));
		return out;
	}

	private static String leadingWhitespace(String l) {
		int i = 0;
		while (i < l.length() && (l.charAt(i) == ' ' || l.charAt(i) == '\t')) i++;
		return l.substring(0, i);
	}

	private static String commonPrefix(String a, String b) {
		int i = 0;
		while (i < a.length() && i < b.length() && a.charAt(i) == b.charAt(i)) i++;
		return a.substring(0, i);
	}

	private static void trimTrailingBlank(List<String> lines) {
		while (!lines.isEmpty() && lines.get(lines.size() - 1).isBlank()) lines.remove(lines.size() - 1);
	}

	/** 0-based index of the line containing character {@code pos}. */
	static int lineIndexAt(String raw, int pos) {
		int line = 0;
		for (int i = 0; i < pos && i < raw.length(); i++) {
			char c = raw.charAt(i);
			if (c == '\n') line++;
			else if (c == '\r') { line++; if (i + 1 < raw.length() && raw.charAt(i + 1) == '\n') i++; }
		}
		return line;
	}

	/**
	 * One line as cell HTML: escaped, leading indentation preserved as
	 * non-breaking spaces (a tab as four), and a blank line as a single
	 * non-breaking space so the row keeps its height.
	 */
	static String cell(String line) {
		if (line == null || line.isEmpty()) return "&nbsp;";
		int i = 0;
		StringBuilder indent = new StringBuilder();
		while (i < line.length() && (line.charAt(i) == ' ' || line.charAt(i) == '\t')) {
			indent.append(line.charAt(i) == '\t' ? "&nbsp;&nbsp;&nbsp;&nbsp;" : "&nbsp;");
			i++;
		}
		String rest = StringEscapeUtils.escapeHtml4(line.substring(i));
		String out = indent + rest;
		return out.isEmpty() ? "&nbsp;" : out;
	}
}
