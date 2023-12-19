package com.faction.gui;

import java.awt.Color;

import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;

public class FactionTableModel extends DefaultTableModel{
	
	private String[] columnNames;
	private Object[][] data;
	private boolean isVuln =false;
	
	public FactionTableModel(String [] cNames, boolean isVuln){
		this.columnNames = cNames;
		this.isVuln = isVuln;
	}
	public FactionTableModel(String [] cNames){
		this.columnNames = cNames;
	}
	
	public int getColumnCount() {
	    return columnNames.length;
	}
	
	public boolean isCellEditable(int row, int column){  
        return false;  
    }
	
	public String getColumnName(int col) {
	    return columnNames[col];
	}

}
