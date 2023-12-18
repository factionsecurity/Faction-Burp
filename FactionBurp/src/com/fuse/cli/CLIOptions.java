package com.fuse.cli;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;

public class CLIOptions {
	private Options options = new Options();
	private String [] args;
	private String filename="";
	private String type = "";
	
	
	public CLIOptions(String[] args){
		this.args = args;
		options.addOption("h","help",false,"Show Help" );
		options.addOption("f","file",true,"File to import into Faction");
		options.addOption("t","type",true,"The type of file. Options are burp, appscan, faction");
		
	}
	
	public void parse(){
		CommandLineParser parser = new BasicParser();
		CommandLine cmd =null;
		try{
			cmd = parser.parse(options, args);
			if(cmd.hasOption("h"))
				help();
			
			if(cmd.hasOption("f"))
				this.filename = cmd.getOptionValue("f");
			
			if(cmd.hasOption("t"))
				this.type = cmd.getOptionValue("t");
			
			if(this.filename.equals("") && this.type.equals("") && !cmd.hasOption("h"))
				System.out.println("Must specify options 'f' and 't'");
	
		}catch(Exception ex){}
	}
	
	private void help(){
		HelpFormatter formater = new HelpFormatter();
		formater.printHelp("Main", options);
		System.exit(0);

	}

	public String getFilename() {
		return filename;
	}

	public String getType() {
		return type;
	}
	

}
