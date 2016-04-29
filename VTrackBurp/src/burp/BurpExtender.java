package burp;

import java.awt.Component;
import java.io.PrintWriter;

import javax.swing.SwingUtilities;

import org.vtrack.gui.VTrackGUI;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ITab;

public class BurpExtender implements IBurpExtender, ITab{
	private VTrackGUI vtrack;
	


	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		
		
		callbacks.setExtensionName("Hello world extension");
		
		SwingUtilities.invokeLater(new Runnable() 
        {
			
			@Override
			public void run() {
				vtrack = new VTrackGUI();
				callbacks.customizeUiComponent(new VTrackGUI());
				callbacks.addSuiteTab(BurpExtender.this);
			}
		
        });
	}
	
	@Override
	public String getTabCaption() {
		
		return "FUSE VTrack";
	}



	@Override
	public Component getUiComponent() {
		
		return vtrack;
	}

}
