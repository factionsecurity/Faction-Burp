package burp;


import com.faction.events.FactionMenuItemsProvider;
import com.faction.gui.FactionGUI;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

public class BurpExtender implements BurpExtension, IBurpExtender{
	private FactionGUI factionUI;
	private IBurpExtenderCallbacks legacyCallback;

	@Override
	public void initialize(MontoyaApi api) {
		api.extension().setName("Faction");
		factionUI = new FactionGUI(api, legacyCallback);
		api.userInterface().registerSuiteTab("Faction", factionUI);
		api.userInterface().registerContextMenuItemsProvider(new FactionMenuItemsProvider(factionUI));
		api.extension().registerUnloadingHandler(factionUI);
	}

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.legacyCallback = callbacks;

	}
}
