package com.faction.gui;

import com.faction.api.FactionAPI;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.imageio.ImageIO;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.Element;
import javax.swing.text.StyleConstants;
import javax.swing.text.View;
import javax.swing.text.ViewFactory;
import javax.swing.text.html.HTML;
import javax.swing.text.html.HTMLEditorKit;

public class Base64HtmlEditor extends HTMLEditorKit {

	    private final FactionAPI factionApi;
	    private HTMLFactory factory = null;

	    /** @param factionApi used to fetch portal-hosted images; null shows only data-URI images */
	    public Base64HtmlEditor(FactionAPI factionApi) {
	        this.factionApi = factionApi;
	    }

	    public Base64HtmlEditor() {
	        this(null);
	    }

	    @Override
	    public ViewFactory getViewFactory() {
	        if (factory == null) {
	            factory = new HTMLFactory() {

	                @Override
	                public View create(Element elem) {
	                    AttributeSet attrs = elem.getAttributes();
	                    Object elementName = attrs.getAttribute(AbstractDocument.ElementNameAttribute);
	                    Object o = (elementName != null) ? null : attrs.getAttribute(StyleConstants.NameAttribute);
	                    if (o instanceof HTML.Tag) {
	                        HTML.Tag kind = (HTML.Tag) o;
	                        if (kind == HTML.Tag.IMG) {
	                            // HERE is the call to the special class...
	                            return new Base64ImageView(elem, factionApi);
	                        }
	                    }
	                    return super.create(elem);
	                }
	            };
	        }
	        return factory;
	    }
}

