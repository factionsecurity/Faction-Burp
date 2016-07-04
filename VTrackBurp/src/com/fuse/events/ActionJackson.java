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
	public ActionJackson(IBurpExtenderCallbacks cb, IContextMenuInvocation inv, boolean newVuln){
		this.cb = cb;
		this.inv = inv;
		this.newVuln = newVuln;
		
	}
	@Override
	public void actionPerformed(ActionEvent e) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					SendToFaction window = new SendToFaction(cb, inv, newVuln);
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
		
	}

}
