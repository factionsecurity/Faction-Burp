package com.faction.gui;

import java.awt.Color;
import java.awt.Component;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

public class CustomCellRenderer extends DefaultTableCellRenderer {
	private LinkedHashMap<String, Integer> levelMap = new LinkedHashMap<>();
	public CustomCellRenderer(LinkedHashMap<String, Integer> levelMap) {
		this.levelMap = levelMap;
	}
	@Override
	public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
			int row, int col) {

		super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
		int realRow = table.convertRowIndexToModel(row);
		
		if((row == 4 || row == 5)) {
			Date date = new Date( (long) value); 
			// the format of your date
			SimpleDateFormat sdf = new java.text.SimpleDateFormat("dd-MM-yyyy");
			String formattedDate = sdf.format(date);
			setValue(formattedDate);
		}

		String status = "" + table.getModel().getValueAt(realRow, col);
		Integer sevId = levelMap.get(status.toLowerCase());
		if (sevId == null) {
			if (row % 2 == 0) {
				setBackground(table.getBackground());
			} else {
				setBackground(Color.getColor("EEEEEE"));
			}
			setForeground(table.getForeground());

		} else {
			switch (sevId) {
			case 9:
				setBackground(Color.decode("#8E44AD"));
				setForeground(Color.WHITE);
				break;
			case 8:
				setBackground(Color.decode("#8E44AD"));
				setForeground(Color.WHITE);
				break;
			case 7:
				setBackground(Color.decode("#8E44AD"));
				setForeground(Color.WHITE);
				break;
			case 6:
				setBackground(Color.decode("#8E44AD"));
				setForeground(Color.WHITE);
				break;
			case 5:
				setBackground(Color.decode("#DD4B39"));
				setForeground(Color.WHITE);
				break;
			case 4:
				setBackground(Color.decode("#F39C12"));
				setForeground(Color.WHITE);
				break;
			case 3:
				setBackground(Color.decode("#00C0EF"));
				setForeground(Color.WHITE);
				break;
			case 2:
				setBackground(Color.decode("#39CCCC"));
				setForeground(Color.WHITE);
				break;
			case 1:
				setBackground(Color.decode("#00A65A"));
				setForeground(Color.WHITE);
				break;
			default:
				setBackground(Color.decode("#95A5A6"));
				setForeground(Color.WHITE);
				break;
			}

		}
		return this;
	}

}
