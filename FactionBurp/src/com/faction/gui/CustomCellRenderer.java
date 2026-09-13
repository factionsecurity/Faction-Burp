package com.faction.gui;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableModel;

/**
 * Colors table cells by the Faction severity enum name
 * (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL). Non-severity cells keep the default
 * look with subtle row striping.
 */
public class CustomCellRenderer extends DefaultTableCellRenderer {

	@Override
	public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
			int row, int col) {
		super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);

		String text = value == null ? "" : value.toString().trim().toUpperCase();
		Color bg = severityColor(text);
		if (bg != null) {
			setBackground(bg);
			setForeground(Color.WHITE);
		} else {
			setBackground(row % 2 == 0 ? table.getBackground() : new Color(0xEE, 0xEE, 0xEE));
			setForeground(isClosedRow(table, row) ? Color.GRAY : table.getForeground());
		}
		return this;
	}

	/** A findings row whose Status column reads "Closed" — history, not open work. */
	private static boolean isClosedRow(JTable table, int viewRow) {
		TableModel model = table.getModel();
		for (int c = 0; c < model.getColumnCount(); c++) {
			if ("Status".equals(model.getColumnName(c))) {
				Object v = model.getValueAt(table.convertRowIndexToModel(viewRow), c);
				return v != null && "Closed".equals(v.toString());
			}
		}
		return false;
	}

	private static Color severityColor(String severity) {
		switch (severity) {
			case "CRITICAL": return Color.decode("#8E44AD");
			case "HIGH": return Color.decode("#DD4B39");
			case "MEDIUM": return Color.decode("#F39C12");
			case "LOW": return Color.decode("#00C0EF");
			case "INFORMATIONAL":
			case "INFORMATION":
			case "INFO": return Color.decode("#95A5A6");
			default: return null;
		}
	}
}
