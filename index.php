<?php

$ApiKey = "AIzaSyCo6t-OgHgDlYvRc8TzKM_ZUxVr4-o5SHM";


function CheckGoogleSafeBrowsing($url, $key) {
	$parameters = array( 'client' => array('clientId'=>'Evolved Marketing', 'clientVersion'=>'1.5.2'), 'threatInfo' => array('threatTypes'=>array('MALWARE', 'SOCIAL_ENGINEERING', 'THREAT_TYPE_UNSPECIFIED', 'UNWANTED_SOFTWARE'), 'platformTypes'=>array('ANY_PLATFORM'), 'threatEntryTypes'=>array('URL'), 'threatEntries'=>array(array('url'=>$url) )), );
	$json = json_encode($parameters);
	
	$ch = curl_init(); 
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

	curl_setopt($ch, CURLOPT_URL, "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$key");
	curl_setopt($ch, CURLOPT_POST, TRUE);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $json);

	curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-type: application/json'));

	$response = curl_exec($ch);	
	
	$decoded = json_decode($response, true);
	
	if(isset($decoded['matches'][0]['threatType']))
		return 1;
	else
		return 0;
}

	$f = fopen("dst.txt","r");
  
	while(($line = fgets($f)) !== false) {
		if(!CheckGoogleSafeBrowsing($line, $ApiKey)) {
			fclose($f);
			header('Location: '.$line);
			exit();
		}
  }
  
  fclose($f);
?>