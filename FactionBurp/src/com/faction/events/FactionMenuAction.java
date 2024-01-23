package com.faction.events;

import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import com.faction.api.FactionAPI;
import com.faction.gui.SendToFaction;

import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;

public class FactionMenuAction implements ActionListener {

    private Object event;
    private AuditIssueContextMenuEvent auditEvent;
    private String appId;
    private boolean isNew;
    private boolean isScan;
    private FactionAPI factionApi;

    public FactionMenuAction(Object event, boolean isScan, boolean isNew, String appId, FactionAPI factionApi) {
        this.appId = appId;
        this.isNew = isNew;
        this.event = event;
        this.isScan = isScan;
        this.factionApi = factionApi;

    }

    @Override
    public void actionPerformed(ActionEvent e) {

        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    SendToFaction window = new SendToFaction(event, isScan, isNew, appId, factionApi);
                    window.frame.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

    }

}
