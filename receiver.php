<?php
@header("content-Type: text/html; charset=utf-8");
session_start();

$current_time = date('Y-m-d H:i:s');

if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
	$client_IP = $_SERVER['HTTP_X_FORWARDED_FOR'];
}
else {
	$client_IP = $_SERVER['REMOTE_ADDR'];
}

$client_verification = new SQLite3('earcis-server.sqlite');
$client_verification_statement = $client_verification->prepare('SELECT releasetime FROM lockouts WHERE userip = :ip;');
$client_verification_statement->bindvalue(':ip',$client_IP);
$client_verification_result = $client_verification_statement->execute();
$client_numrows = $client_verification_result->numRows();
if ($client_numrows > 1) { #For whatever the reason, if there are two or more rows in the lockout table for the same user, we'll keep the user out for now, waiting for the cron script to clear the mess up.
	http_response_code(403);
	die();
}
else {
	$client_result_array = array();
	$client_result_array_count = 0;
	while ($client_res = $client_verification_result->fetchArray(SQLITE3_ASSOC)) {
		release_time = $client_res['releasetime'];
	}
	if ($client_numrows == 1) {
		if (date('Y-m-d H:i:s') <= release_time) {
			http_response_code(403); #still locked? out.
			die();
		}
		elif (date('Y-m-d H:i:s') > release_time) {
			$client_verification_deletion_statement = $client_verification->prepare('DELETE FROM lockouts WHERE userip = :ip;');
			$client_verification_deletion_statement->bindvalue(':ip',$client_IP);
			if !($client_verification_deletion_statement->execute()) {
				http_response_code(403); #in case the deletion fails for whatever the reason
				die();
		}
	}
}

#all cleared, let's actually accept user's json
$request_json = var_dump(json_decode(file_get_contents("php://input")));

?>