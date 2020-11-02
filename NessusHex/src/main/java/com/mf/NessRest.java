package com.mf;

import io.restassured.RestAssured;
import io.restassured.http.Method;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class NessRest {

    String username ;
    String password;
    String baseUrl ;

    //Default Header Map
    Map<String, String> headers = new HashMap<String, String>() {{
        put("Content-Type", "application/json");
        put("X-API-Token", "40695819-99D2-4FEA-B2AC-E8F3F9C97D77");
    }};

    private  static NessRest _RestUtil;
    private NessRest(String urlStr, String user, String pass) throws MalformedURLException {

        baseUrl = GetBaseUrl(urlStr);

        username = user;
        password = pass ;

    }

    private String GetBaseUrl(String urlStr) throws MalformedURLException {
        URL url = new URL(urlStr);
        return url.getProtocol()+"://"+ url.getAuthority();
    }

    public static NessRest Init(String url, String user, String passwd) throws MalformedURLException {
        if(null == _RestUtil){
            _RestUtil = new NessRest(url, user, passwd);
            _RestUtil.DoLogin();
        }

        return _RestUtil;
    }

   public void DoLogin(){
        JSONObject requestParams = new JSONObject();
        requestParams.put("username", username);
        requestParams.put("password", password);

        String url = "/session";
        Response resp = _RestUtil.DoPost(url, requestParams);

        //Update Token
        headers.put("X-Cookie","token="+resp.jsonPath().getString("token"));

    }

    public boolean StartNessusScan(int projectId){
        String url = "/scans/"+projectId+"/launch";
        Response resp = _RestUtil.DoPost(url, new JSONObject());

        String scanId= resp.jsonPath().getString("scan_uuid");
        System.out.println("Started scan for id: "+projectId);
        return (null != scanId );
    }

    public Response DoGet(String url) { 
    	return DoRestAxn(url, Method.GET, null);
    }

    public Response DoPost(String url) {
		return DoPost(url, new JSONObject());
	}
    
    public Response DoPost(String url, JSONObject requestParams){ 
    	return DoRestAxn(url, Method.POST, requestParams);
    }
    
    public Response DoRestAxn(String url, Method method , JSONObject requestParams){
        //If Relative URL is specified, Use the BaseUrl
        if(url.startsWith("/")){
            RestAssured.baseURI = baseUrl;
        }

        //Ignore HTTPS errors
        RestAssured.useRelaxedHTTPSValidation();

        RequestSpecification request = RestAssured.given();
        request.headers(headers);
        
        if (method != Method.GET) { 
        	request.body(requestParams.toJSONString());
        }

        Response response = null;
        switch(method) {
        case GET:
        	response = request.get(url);
        	break;
        case POST: 
        	response = request.post(url);
        	break;
		default:
			return null;
        }
        
        return  response;
    }

	public boolean StartNessusScan(String project) {
		
		//Scan all the Projects
		String url = "/scans?";
		Response json = DoPost(url);
		
		//TODO: Find the specific ID against given project
		int id = json.jsonPath().getInt("TODO");
		
		return StartNessusScan(id);
		
	}

	public String GetReport(int id, boolean isCsv) {
		String url = "/scans/"+id+"/export?limit=2500";

		String jsonStr = getReportJson(isCsv);

        JSONParser parser = new JSONParser();
        try {
			JSONObject json = (JSONObject) parser.parse(jsonStr); 
			Response response = DoPost(url,json);
			
			String fileToken = response.jsonPath().getString("token");

			
			do {
				url = "/tokens/"+fileToken+"/status"; 
				response = DoGet(url);
				Thread.sleep(100);
			}while(!response.jsonPath().getString("status").contentEquals("ready"));
			
		 
			url = "/tokens/"+fileToken+"/download"; 
			response = DoGet(url); 
			
			File file = new File(new SimpleDateFormat("yyyyMMddHHmm").format(new Date())+"NessusReport_"+id+"."+(isCsv?"csv":"html"));
			
			OutputStream outStream = new FileOutputStream(file);
			outStream.write(response.asByteArray());
			outStream.close();
			
			return file.getAbsolutePath();

		} catch (Exception e) {
			return "  ";
		}

	}

    private String getReportJson(boolean isCsv) {
        String data = "";

        if(isCsv) 
        {
        	data = "{" +
        			"    \"extraFilters\": {" +
        			"        \"host_ids\": [" +
        			"        ]," +
        			"        \"plugin_ids\": [" +
        			"        ]" +
        			"    }," +
        			"    \"format\": \"csv\"," +
        			"    \"reportContents\": {" +
        			"        \"csvColumns\": {" +
        			"            \"cve\": true," +
        			"            \"cvss\": true," +
        			"            \"cvss_temporal_score\": true," +
        			"            \"cvss3_base_score\": true," +
        			"            \"cvss3_temporal_score\": true," +
        			"            \"description\": true," +
        			"            \"exploitable_with\": true," +
        			"            \"hostname\": true," +
        			"            \"id\": true," +
        			"            \"plugin_information\": true," +
        			"            \"plugin_name\": true," +
        			"            \"plugin_output\": true," +
        			"            \"port\": true," +
        			"            \"protocol\": true," +
        			"            \"references\": true," +
        			"            \"risk\": true," +
        			"            \"risk_factor\": true," +
        			"            \"see_also\": true," +
        			"            \"solution\": true," +
        			"            \"stig_severity\": true," +
        			"            \"synopsis\": true" +
        			"        }" +
        			"    }" +
        			"}";
        }
        else
        {
        	data = "{" +
        			"    \"format\": \"" + (isCsv ? "html" : "csv") + "\"," +
        			"    \"chapters\": \"\"," +
        			"    \"reportContents\": {" +
        			"        \"csvColumns\": {}," +
        			"        \"vulnerabilitySections\": {}," +
        			"        \"hostSections\": {}," +
        			"        \"formattingOptions\": {}" +
        			"    }," +
        			"    \"extraFilters\": {" +
        			"        \"host_ids\": []," +
        			"        \"plugin_ids\": []" +
        			"    }" +
        			"}";
        } 

        return  data;
    }

    public void WaitNessusScan(int id) {
    	System.out.println("Wating to finish scan for Id: "+id);
		//Sleep for 5 Sec IF Running
    	for(int cnt = 1;!IsScanCompleted(id);cnt++)
    	{
    		try {
    			//Show something is going on
				for (int i=0; i<cnt; i++){
					System.out.print(".");
				}
				Thread.sleep(5000);
			} catch (Exception e) {
			}
    	}
		
	}

	private boolean IsScanCompleted(int id) {
		String url = "/scans/"+id+"?limit=2500&includeHostDetailsForHostDiscovery=true";
		JsonPath data = DoGet(url).jsonPath();
		
		Map abc =  data.getJsonObject("info");
		return abc.get("status").equals("completed");
	}

}
