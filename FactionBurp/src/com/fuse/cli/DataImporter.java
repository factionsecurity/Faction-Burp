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

		CLIOptions cli = new CLIOptions(args);
		cli.parse();
		
		if(cli.getType().equals("burp")){
			File fXmlFile = new File(cli.getFilename());
			BurpImporter.importXML(fXmlFile);
			
		}else if (cli.getType().equals("faction")){
			//ImportFactionXLSX.importXLSX(cli.getFilename());
			//ImportFactionDOCX.importXLSX(cli.getFilename());
			
		}else if (cli.getType().equals("appscan")){
			
		}else{
			System.out.println("Invalid type specified. Must be burp, faction, or appscan");
		}
		

	}

}
