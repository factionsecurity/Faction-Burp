package burp;

import com.faction.events.FactionMenuItemsProvider;
import com.faction.gui.FactionGUI;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class BurpExtender implements BurpExtension {

	private FactionGUI factionUI;

	@Override
	public void initialize(MontoyaApi api) {
		api.extension().setName("Faction");
		factionUI = new FactionGUI(api);
		api.userInterface().registerSuiteTab("Faction", factionUI);
		api.userInterface().registerContextMenuItemsProvider(new FactionMenuItemsProvider(factionUI));
		api.extension().registerUnloadingHandler(factionUI);
	}
}
