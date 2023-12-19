package com.fuse.events;

import java.awt.Component;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Action;
import javax.swing.JMenuItem;

import com.fuse.gui.FactionGUI;
import com.fuse.gui.SendToFaction;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

public class FactionMenuItemsProvider implements ContextMenuItemsProvider {

	private FactionGUI factionUI;
	private List<AuditIssue> auditIssues;
	private ContextMenuEvent contextMenuEvent;

	public FactionMenuItemsProvider(FactionGUI factionUI) {
		this.factionUI = factionUI;
	}

	@Override
	public List<Component> provideMenuItems(ContextMenuEvent event) {
		this.contextMenuEvent = event;
		System.out.println(event.toolType());
		if (event.isFromTool(ToolType.PROXY, ToolType.TARGET, ToolType.REPEATER)) {
			List<Component> menuItemList = new ArrayList<>();

			JMenuItem newItem = new JMenuItem("Add as New Finding");
			JMenuItem addExisting = new JMenuItem("Add to Existing Finding");

			HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent()
					? event.messageEditorRequestResponse().get().requestResponse()
					: event.selectedRequestResponses().get(0);

			newItem.addActionListener(new FactionMenuAction(event, false, true, factionUI.getAppId()));
			addExisting.addActionListener(new FactionMenuAction(event,false, false, factionUI.getAppId()));
			menuItemList.add(newItem);
			menuItemList.add(addExisting);
			return menuItemList;
		}

		return null;
	}

	public List<Component> provideMenuItems(AuditIssueContextMenuEvent event) {
		System.out.println("In Scanner");
		AuditIssueContextMenuEvent scanEvent = (AuditIssueContextMenuEvent) event;
		auditIssues = scanEvent.selectedIssues();
		List<Component> menuItemList = new ArrayList<>();

		JMenuItem sendScanItemsToFaction = new JMenuItem("Send Issues To Faction");
		sendScanItemsToFaction.addActionListener(new FactionMenuAction(event,true, true, factionUI.getAppId()));
		menuItemList.add(sendScanItemsToFaction);
		return menuItemList;
	}

}
