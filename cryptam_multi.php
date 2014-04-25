<?PHP
/*
 * v0.1.1
 * cryptam_unxor.php: MalwareTracker.com Cryptam - command line script
 * unxor and unrol, get parameters from api, extract embedded exe, docs and pdfs
 */
    

$key = '';
$rol = 0;
$ror = 0;
$tph = 0;
$tp = 0;
$not = 0;
$zero = 0;
$submit = 0;
$api = 0;

$outfile = '';

//accept a file as input
if (isset($argv[1]) && is_file($argv[1])) {
	$outfile = $argv[1].".out";
	for ($i = 2; $i < $argc; $i+=2) {
		if ($argv[$i] == "-xor" && is_file($argv[$i+1]) )
			$key = file_get_contents($argv[$i+1]);
		else if ($argv[$i] == "-xor" || $argv[$i] == "-key")
			$key = $argv[$i+1];
		else if ($argv[$i] == "-rol")
			$rol = $argv[$i+1];
		else if ($argv[$i] == "-ror")
			$ror = $argv[$i+1];
		else if ($argv[$i] == "-out")
			$outfile = $argv[$i+1];
		else if ($argv[$i] == "-zero") { //bitwise not
			$zero = 1;
			$i--;
		} else if ($argv[$i] == "-not") { //bitwise not
			$not = 1;
			$i--;
		} else if ($argv[$i] == "-tph") { //transposition
			$tph = 1;
			$i--;
		} else if ($argv[$i] == "-tp") { //transposition
			$tp = 1;
			$i--;
		} else if ($argv[$i] == "-submit") { //transposition
			$submit = 1;
			$i--;
		} else if ($argv[$i] == "-api") { //transposition
			$api = 1;
			$i--;
		}
	}
	$md5 = md5_file($argv[1]);
} else {
	echo "Cryptam Multi Tool - Decode and extract embedded executables from documents\n";
	echo "php cryptam_unxor.php virus.doc -xor fe85aa -rol 3 -not -out file.out\n";
	echo "php cryptam_unxor.php virus.doc -api [gets decoding params from malwaretracker.com]\n";
	echo "php cryptam_unxor.php virus.doc -submit [upload file to malwaretracker.com, download params]\n";

	echo "Params:
     -xor <key>   XOR key to decode document with
     -rol <int>   bitwise left shift <int> places
     -ror <int>   bitwise right shift <int> places
     -not         use a bitwise not filter
     -zero        don't replace zeros in single byte xor decode
     -tp          transposition cipher filter on file
     -tph         transposition cipher filter on EXE 512 byte header
     -submit      upload file to malwaretracker.com Cryptam analyzer, captures decoding params
                  and extracts EXE/docs/pdfs from file
     -api         queries malwaretracker.com Cryptam api with MD5 hash only, captures decoding params
                  and extracts EXE/docs/pdfs from file
";


	exit(1);
}

if ($submit == 1) {
	echo "Submitting ".$argv[1]." to remote server\n";
	$result = unserialize(mwtdocfile($argv[1]));
	if (isset($result['has_exe']) ) {
		$ror = $result['key_rol'];
		$key = $result['key'];
		$tp = $result['key_tp'];
		$tph = $result['key_tph'];
		$not = $result['key_not'];
		$zero = $result['key_zero'];
	}
}

if ($api == 1) {
	
	echo "Accessing remote API for decoding params for $md5\n";
	$result = unserialize(mwtdocreport($md5));
	if (isset($result['has_exe']) ) {
		$ror = $result['key_rol'];
		$key = $result['key'];
		$tp = $result['key_tp'];
		$tph = $result['key_tph'];
		$not = $result['key_not'];
		$zero = $result['key_zero'];
	}
}


$data = file_get_contents($argv[1]);

if ($key != '') {
	echo "using XOR key $key";
	if ($zero != 0)
		echo " (-zero)";
	echo "\n";
	$data = xorString($data, hex2str($key), $zero);
}

if ($rol != 0 && $rol != '') {
	echo "using ROL $rol\n";
	$data = cipherRol($data, $rol);
}

if ($ror != 0  && $ror != '') {
	echo "using ROR $ror\n";
	$data = cipherRor($data, $ror);
}

if ($not != 0 && $not != '') {
	echo "using bitwise not\n";
	$data = cipherNot($data);
}

if ($tp != 0  && $tp != '') {
	echo "using transposition decoder\n";
	$data = untranspose($data);
}

if ($tph != 0  && $tph != '') {
	echo "note first 512 bytes of EXE may be transpositioned\n";
}

if (md5($data) != $md5) //don't rewrite unfiltered file
	file_put_contents($outfile, $data);


dump_pe($data, $argv[1], $tph);


function hex2str($hex) {
	$str = '';
	for($i = 0; $i<strlen($hex); $i += 2) {
		$str .= chr(hexdec(substr($hex,$i,2)));
	}
	return $str;
}


function cipherRol($string, $x) {
	$newstring = '';
	for ($i = 0; $i < strlen($string); $i++){
		$bin = str_pad(decbin(ord($string[$i])), 8,'0', STR_PAD_LEFT);
		$ro = substr($bin, $x).substr($bin, 0, $x);
 		$newstring .= chr(bindec($ro));
    }
    return $newstring;
}

function cipherRor($string, $x) {
	$newstring = '';
	for ($i = 0; $i < strlen($string); $i++) {
		$bin = str_pad(decbin(ord($string[$i])), 8,'0', STR_PAD_LEFT);
		$ro = substr($bin, -$x).substr($bin, 0, -$x);
		$newstring .= chr(bindec($ro));
	}
	return $newstring;
}


function untranspose($string) {

	$newstring = '';
	for ($i = 0; $i < strlen($string); $i+=2){
 		$newstring .= $string[$i+1].$string[$i];
	}
	return $newstring;
}


function cipherNot($string) {
	$newstring = '';
	for ($i = 0; $i < strlen($string); $i++) {
		$bin = str_pad(decbin(ord($string[$i])), 8,'0', STR_PAD_LEFT);
		$ro = '';
		for ($j = 0; $j < 8; $j++) {
			if ($bin[$j] == 1)
				$ro .= 0;
			else
				$ro .= 1;
		}
		$newstring .= chr(bindec($ro));
	}
	return $newstring;
}

function xorString($data, $key, $zero = 0) {
	$key_len = strlen($key);
	$newdata = '';
 
	for ($i = 0; $i < strlen($data); $i++) {
        	$rPos = $i % $key_len;
		$r = '';
		if ($key_len == 1) {
			if ($zero == 1) {
				if ($data[$i] != "\x00")
					$r = ord($data[$i]) ^ ord($key);
				else
					$r = ord($data[$i]);
			} else 
				$r = ord($data[$i]) ^ ord($key);
		} else
			$r = ord($data[$i]) ^ ord($key[$rPos]);
 
		$newdata .= chr($r);
	}
 
	return $newdata;
}


function mwtdocfile($file, $email = '', $message = ''){
	$curl = curl_init();
	curl_setopt($curl, CURLOPT_URL, "http://www.malwaretracker.com/docapi.php");
	curl_setopt($curl, CURLOPT_POST, true);
	curl_setopt($curl, CURLOPT_VERBOSE, 0);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1); 
	curl_setopt($curl, CURLOPT_HTTPHEADER, array('Expect:'));
	curl_setopt($curl, CURLOPT_HEADER, 0); 
	curl_setopt($curl, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible;) MWT API C 1.0");

	curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1); 
	$data = array( "sample[]"=> "@$file", 'type' => 'cryptam', 'private' => '1');
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


function mwtdocreport($hash, $type='cryptam'){
	$curl = curl_init();
	$url =  "http://www.malwaretracker.com/docapirep.php?hash=$hash&type=$type";
	curl_setopt($curl, CURLOPT_URL, $url);
	curl_setopt($curl, CURLOPT_POST, 0);
	curl_setopt($curl, CURLOPT_HEADER, 0);
	curl_setopt($curl, CURLOPT_HTTPHEADER, array('Expect:'));
	curl_setopt($curl, CURLOPT_VERBOSE, 0);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, true); 
	curl_setopt($curl, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible;) MWT API C 1.0");

	curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1); 
	$result = curl_exec($curl); 
	$err = curl_error($curl); 
	if ($err != '') {
		return "CURLERROR: $err"; 
	}
	curl_close ($curl);
	return $result;
}


function dump_pe($data, $filename, $tph = 0) {
	$file_headers =  array("MZ(.{1,150}?)This program" => "exe",
		"ZM(.{1,150}?)hTsip orrgmac" => "exe",
		"\xCA\xFE\xBA\xBE" => "macho",
		"\xCE\xFA\xED\xFE" => "macho",
		"\x7F\x45\x4C\x46" => "elf",
		"\x25\x50\x44\x46" => "pdf",
		"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" => "doc",
		"\x0A\x25\x25\x45\x4F\x46\x0A" => "eof",
		"\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A" => "eof",
		"\x0D\x25\x25\x45\x4F\x46\x0D" => "eof");

	$addresses = array();		
	$files = array();

	foreach($file_headers as $search => $ext) {
		preg_match_all("/$search/s", $data, $match, PREG_OFFSET_CAPTURE);
		if (isset($match[0][0])) {
			foreach($match[0] as $matches0) {
				if (isset($matches0[1])) {
					$l = $matches0[1];
					if (! stristr($search, '?') &&$ext == 'eof') {
						$ladd = preg_replace("/\\x./", '', $search);
						$l += strlen($ladd);
					}
					if ($l > 5) //skip plaintext full file extraction
						$addresses[$l] = array('loc' => $l, 'searchtype' => 'regex', 'ext' => $ext);
				}
			}

		}

	}

	//back into the right order
	ksort($addresses, SORT_NUMERIC);

	$last = 0;
	$over = 0;
	foreach ($addresses as $loc => $hit) {
		if ($last != '') {
			$addresses[$last]['end'] = $loc;
			
		}
	
		if ($last != '' && $addresses[$last]['ext'] != 'eof' && $hit['ext'] == 'eof') {
		 	unset($addresses[$loc]);
			$over = 1;
		} else {
			$last = $loc;
			$over = 0;
		}
	}
	if ($over == 0) {
		$addresses[$last]['end'] = strlen($data);
	}

	foreach ($addresses as $loc => $hit) {
		if ($hit['ext'] != 'eof' && isset($hit['end'])) {
			//untranspose needed
			$fp = fopen($filename."-".$loc.".".$hit['ext'], "w");
			
			$filedata = substr($data, $loc, $hit['end']-$loc);
			if ($tph == 1 && substr($filedata, 0, 2) == "ZM") {
				echo "untransposing first 512 bytes at $loc\n";
				$filenew = untranspose(substr($filedata, 0, 512)).substr($filedata, 512);
				$filedata = $filenew;
			}
			$fmd5 = md5($filedata);
			fwrite($fp, $filedata);
			fclose($fp);
			echo "wrote ".($hit['end']-$loc)." bytes at $loc as type ".$hit['ext']." $fmd5\n";
		}


	
	}	
}




?>
