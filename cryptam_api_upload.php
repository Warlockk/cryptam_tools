<?PHP
/*
 * v0.1
 * mwtdocfile.php: MalwareTracker.com Cryptam - sample api uploader
 * Upload docs from the command line. Edit CURLOPT_URL for your internal url.
 */


if (!isset($argv[1])) {
	echo "Specify a file.\n";
	exit(0);
}


//accept a file as input
if (is_file($argv[1])) {
	$file = $argv[1];
	$email = '';
	if (isset($argv[2]))
		$email = $argv[2];
	$result = mwtfile($file, $email);
	echo $result;
}



function mwtfile($file, $email = '', $message = ''){
	$curl = curl_init();
	curl_setopt($curl, CURLOPT_URL, "http://www.malwaretracker.com/docapi.php");
	curl_setopt($curl, CURLOPT_POST, true);
	curl_setopt($curl, CURLOPT_VERBOSE, 0);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1); 
	curl_setopt($curl, CURLOPT_HTTPHEADER, array('Expect:'));
	curl_setopt($curl, CURLOPT_HEADER, 0); 
	curl_setopt($curl, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible;) MWT API 1.0");

	curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1); 
	$data = array( "sample[]"=> "@$file", 'type' => 'xml');
	if ($message != '')
		$data['message'] = $message;
	if ($email != '')
		$data['email'] = $email;

	curl_setopt($curl, CURLOPT_POSTFIELDS, $data); 
	$response = curl_exec($curl);
	$err = curl_error($curl); 
	if ($err != '') {
		return "CURLERROR: $err"; 
	}
	curl_close ($curl);
	return $response;
}


?>
