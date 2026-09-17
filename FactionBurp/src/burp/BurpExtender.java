package burp;

import com.faction.events.FactionMenuItemsProvider;
import com.faction.gui.FactionGUI;
import com.faction.utils.Version;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class BurpExtender implements BurpExtension {

	private FactionGUI factionUI;

	@Override
	public void initialize(MontoyaApi api) {
		api.extension().setName("Faction " + Version.get());
		factionUI = new FactionGUI(api);
		api.userInterface().registerSuiteTab("Faction", factionUI);
		api.userInterface().registerContextMenuItemsProvider(new FactionMenuItemsProvider(factionUI));
		api.extension().registerUnloadingHandler(factionUI);
	}
}
