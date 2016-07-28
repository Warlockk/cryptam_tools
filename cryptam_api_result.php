<?PHP
/*
 * v2.0
 * cryptam_api_result.php: MalwareTracker.com Cryptam - sample api json report downloader
 * Access a Cryptam report from your internal system. Edit $url for your url.
 */


if (!isset($argv[1])) {
	echo "Specify a hash to receive json results.\n";
	echo "php cryptam_api_result.php <md5>\n";
	exit(0);
}


if (isset($argv[1])) {
	$hash = $argv[1];
	$result = mwtreport($hash);
	echo $result;
}



function mwtreport($hash){
	$curl = curl_init();
	$url =  "http://www.cryptam.com/docapirep.php?hash=$hash";
	curl_setopt($curl, CURLOPT_URL, $url);
	curl_setopt($curl, CURLOPT_POST, 0);
	curl_setopt($curl, CURLOPT_HEADER, 0);
	curl_setopt($curl, CURLOPT_HTTPHEADER, array('Expect:'));
	curl_setopt($curl, CURLOPT_VERBOSE, 0);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, true); 
	curl_setopt($curl, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible;) MWT API 2.0");

	curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1); 
	$result = curl_exec($curl); 
	$err = curl_error($curl); 
	if ($err != '') {
		return "CURLERROR: $err"; 
	}
	curl_close ($curl);
	return $result;
}


?>
