package com.mf;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.opencsv.CSVReader;

public class Runner {
    public static void main(String[] args) throws Exception {

		NessRest nessus = NessRest.Init("https://164.99.175.30:8834","admin","Welcome1-2");

        int id=5102;
        if(args.length>0) {
        	try {
        		id = Integer.parseInt( args[0]);
        		nessus.StartNessusScan(id);
        		nessus.WaitNessusScan(id);
        	}
        	catch(Exception e) {
        		//ignore and move on
        	}
        }
       
        String path = nessus.GetReport(id, true);
        
        System.out.println(path);
	}

	public static String Csv2JsonConvert(String path) {
		JSONArray jArray = new JSONArray();
		
		try ( CSVReader csvReader = new CSVReader(Files.newBufferedReader(Paths.get(path))))
		{
			Iterator<String[]> iterator = csvReader.iterator();
			String[] header = iterator.next();
			
			while(iterator.hasNext()) { 
				String[] row = iterator.next();
				
				JSONObject json = new JSONObject();
				for(int idx=0;idx<header.length;idx++) {
					json.put(header[idx],row[idx]);
				}
				
				JSONObject nvdjson = new JSONObject();
				nvdjson.put("nvdFinding", json);
				nvdjson.put("packages", new JSONArray());
				jArray.add(nvdjson);
			}
		
			csvReader.close();
			
			JSONObject json = new JSONObject();
			json.put("findings", jArray);
			File file = new File("NessusReport.json"); 
			OutputStream outStream = new FileOutputStream(file);
			outStream.write(json.toString().getBytes());
			outStream.close();

			return file.getAbsolutePath();
		}
		catch (Exception e){
			return "";
		}
		

	}
}
