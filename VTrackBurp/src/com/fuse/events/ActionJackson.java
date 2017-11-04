package com.fuse.events;

import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import com.fuse.gui.SendToFaction;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;

public class ActionJackson implements ActionListener{

	private IBurpExtenderCallbacks cb;
	private IContextMenuInvocation inv;
	private boolean newVuln;
	private String APPID;
	public ActionJackson(IBurpExtenderCallbacks cb, IContextMenuInvocation inv, boolean newVuln, String appid){
		this.cb = cb;
		this.inv = inv;
		this.newVuln = newVuln;
		this.APPID = appid;
		
	}
	@Override
	public void actionPerformed(ActionEvent e) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					SendToFaction window = new SendToFaction(cb, inv, newVuln, APPID);
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
		
	}

}
