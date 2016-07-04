package com.fuse.cli;

import java.io.File;
import java.io.IOException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import com.fuse.cli.burp.BurpImporter;

public class DataImporter {

	public static void main(String[] args) throws SAXException, IOException, ParserConfigurationException {
		File fXmlFile = new File("C:/Users/Josh/test.xml");
		BurpImporter.importXML(fXmlFile);

	}

}
