package com.faction.utils;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.function.Consumer;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;

import com.faction.api.FactionAPI;

public class FSUtils {

	/**
	 * Populates a severity combo box with the Faction severity names for the configured API version,
	 * preselects the one currently mapped to the given Burp severity, and invokes
	 * the callback whenever the selection changes.
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static void setSeverityComboBoxDefaults(FactionAPI api, JComboBox jbox, String burpSeverityString,
			String[] severityStrings, Consumer<String> callback) {
		jbox.setModel(new DefaultComboBoxModel(severityStrings));
		String sevStr = api.getSevMapping(burpSeverityString);
		for (int j = 0; j < jbox.getItemCount(); j++) {
			if (jbox.getItemAt(j).equals(sevStr)) {
				jbox.setSelectedIndex(j);
				break;
			}
		}
		jbox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				Object sel = jbox.getSelectedItem();
				if (sel != null) callback.accept(sel.toString());
			}
		});
	}

	/** MD5 hash of the given text, used to de-duplicate scan-issue detail blocks. */
	public static String hashText(String text) {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(text.getBytes());
			byte[] digest = md.digest();
			return new String(digest, StandardCharsets.UTF_8);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return "";
	}
}
