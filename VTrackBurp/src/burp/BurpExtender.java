package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;

import com.fuse.events.ActionJackson;
import com.fuse.gui.FactionGUI;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ITab;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory{
	private FactionGUI factionUI;
	private IBurpExtenderCallbacks cb;
	


	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		
		this.cb = callbacks;
		callbacks.setExtensionName("FuseSoft Security FACTION");
		callbacks.registerContextMenuFactory(this);
		
		
		SwingUtilities.invokeLater(new Runnable() 
        {
			
			@Override
			public void run() {
				factionUI = new FactionGUI();
				callbacks.customizeUiComponent(factionUI);
				callbacks.addSuiteTab(BurpExtender.this);
			}
		
        });
	}
	
	@Override
	public String getTabCaption() {
		
		return "FACTION";
	}



	@Override
	public Component getUiComponent() {
		
		return factionUI;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation inv) {
		JMenu faction = new JMenu("Faction");
		List<JMenuItem> menus = new ArrayList<JMenuItem>();
		if(isMessageEditor(inv)){
			JMenuItem newVuln = new JMenuItem("Add as New Finding");
			newVuln.addActionListener(new ActionJackson(cb, inv, true));
			
			JMenuItem addExisting = new JMenuItem("Add to Existing Finding");
			addExisting.addActionListener(new ActionJackson(cb, inv, false));
			faction.add(newVuln);
			faction.add(addExisting);
			
			menus.add(faction);
		}else if(isScanItems(inv)){
			JMenuItem newScans = new JMenuItem("Send as New Scan Items");
			newScans.addActionListener(new ActionJackson(cb, inv, true));
			faction.add(newScans);
			menus.add(faction);
		}
		return menus;
	}
	
	
	private boolean isMessageEditor(IContextMenuInvocation inv){
		byte ctx = inv.getInvocationContext();
		if(ctx == inv.CONTEXT_MESSAGE_EDITOR_REQUEST || ctx == inv.CONTEXT_MESSAGE_EDITOR_RESPONSE ||
				ctx == inv.CONTEXT_MESSAGE_VIEWER_REQUEST || ctx == inv.CONTEXT_MESSAGE_VIEWER_RESPONSE 
				){
			return true;
		}else
			return false;
		
	}
	private boolean isScanItems(IContextMenuInvocation inv){
		byte ctx = inv.getInvocationContext();
		if(ctx == inv.CONTEXT_SCANNER_RESULTS){
			return true;
		}else{
			return false;
		}
	}
	private boolean isSiteMap(IContextMenuInvocation inv){
		byte ctx = inv.getInvocationContext();
		if(ctx == inv.CONTEXT_TARGET_SITE_MAP_TABLE || ctx == inv.CONTEXT_TARGET_SITE_MAP_TREE){
			return true;
		}else{
			return false;
		}
	}

}
