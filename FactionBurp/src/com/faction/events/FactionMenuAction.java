package com.faction.events;

import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import com.faction.gui.SendToFaction;

import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;

public class FactionMenuAction implements ActionListener {

    private Object event;
    private AuditIssueContextMenuEvent auditEvent;
    private String appId;
    private boolean isNew;
    private boolean isScan;

    public FactionMenuAction(Object event, boolean isScan, boolean isNew, String appId) {
        this.appId = appId;
        this.isNew = isNew;
        this.event = event;
        this.isScan = isScan;

    }

    @Override
    public void actionPerformed(ActionEvent e) {

        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    SendToFaction window = new SendToFaction(event, isScan, isNew, appId);
                    window.frame.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

    }

}
