<?PHP
/*
 * v0.1
 * mwtdocreport.php: MalwareTracker.com Cryptam - sample api report downloader
 * Access a Cryptam report from your internal system. Edit $url for your url.
 */


if (!isset($argv[1])) {
	echo "Specify a hash and report type.\n";
	echo "php mwtreport.php <md5> <xml php text json>\n";
	exit(0);
}


if (isset($argv[1])) {
	$hash = $argv[1];
	$type = 'xml';
	if (isset($argv[2]))
		$type = $argv[2];
	$result = mwtreport($hash, $type);
	echo $result;
}



function mwtreport($hash, $type='xml'){
	$curl = curl_init();
	$url =  "http://www.malwaretracker.com/docapirep.php?hash=$hash&type=$type";
	curl_setopt($curl, CURLOPT_URL, $url);
	curl_setopt($curl, CURLOPT_POST, 0);
	curl_setopt($curl, CURLOPT_HEADER, 0);
	curl_setopt($curl, CURLOPT_HTTPHEADER, array('Expect:'));
	curl_setopt($curl, CURLOPT_VERBOSE, 0);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, true); 
	curl_setopt($curl, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible;) MWT API 1.0");

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
