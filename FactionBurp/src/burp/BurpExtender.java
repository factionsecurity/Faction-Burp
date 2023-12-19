package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;

import com.org.faction.events.FactionMenuItemsProvider;
import com.org.faction.gui.FactionGUI;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.core.ToolType;

public class BurpExtender implements BurpExtension, IBurpExtender{
	private FactionGUI factionUI;
	private IBurpExtenderCallbacks legacyCallback;

	@Override
	public void initialize(MontoyaApi api) {
		api.extension().setName("Faction");
		factionUI = new FactionGUI(api, legacyCallback);
		api.userInterface().registerSuiteTab("Faction", factionUI);
		api.userInterface().registerContextMenuItemsProvider(new FactionMenuItemsProvider(factionUI));
	}

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.legacyCallback = callbacks;
	}
}
