<?php
@header("content-Type: text/html; charset=utf-8");
session_start();

require "config.php";

if (($maximum_messages_every_5minutes < 25) or ($maximum_messages_every_5minutes > 200)) {
	die("Inappropriate 5-minute-limit.");
}
if (($lock_out_minutes < 0) or ($lock_out_minutes > 720)) {
	die("Incorrect locked out minutes.");
}
if ($server_password != ""){
	if ((!ctype_alnum($server_password)) or (strlen($server_password) > 32)) {
		die("Inappropriate server password, number and letters only, maximum 32.");
	}
}

function check_user_hash($userhash) {

	$clienthash_length = 40;
	$clienthash_charset = str_split("abcdefghijklmnopqrstuvwxyz0123456789");
	$userhash_content = str_split($userhash);
	$qualifying_hash = True;
	if (strlen($userhash) != $clienthash_length) {
		$qualifying_hash = False;
	}
	else {
		foreach ($userhash_content as $charkey) {
			if (!(in_array($charkey, $clienthash_charset))) {
				$qualifying_hash = False;
				break;
			}
		}
	}
	unset($userhash_content);
	if ($qualifying_hash == False) {
		return False;
	}
	else {
		return True;
	}
}

function check_message_base64($message) {

	$base64_charset = str_split("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");

	if (strlen($message) > 1000) { #In case someone modifies the client to send an encrypted message longer than 1000.
		return False;
	}
	if (strlen($message) < 1) {
		return False;
	}

	$message_content = str_split($message);
	$qualifying_message = True;
	foreach ($message_content as $charkey) {
		if (!(in_array($charkey, $base64_charset))) {
			$qualifying_message = False;
			break;
		}
	}
	unset($message_content);
	if ($qualifying_message == False) {
		return False;
	}
	else {
		return True;
	}
}

function bad_request() {
	echo "400: Bad Request.";
	header('HTTP/1.0 400 Bad Request');
	session_destroy();
	die();
}

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
$client_numrows = 0;
if (!($client_verification_result->fetchArray())) {
	$client_numrows = 0;
}
else {
	$client_verification_result->reset();
	while ($client_verification_result->fetchArray()) {
		$client_numrows++;
	}
	$client_verification_result->reset();
}

if ($client_numrows > 1) { #For whatever the reason, if there are two or more rows in the lockout table for the same user, we'll keep the user out for now, waiting for the cron script to clear the mess up.
	header('HTTP/1.0 403 Forbidden');
	echo "403: Unknown Request.";
	session_destroy();
	die();
}
else { #all the lockout checks
	$release_time_counter = 0;
	while ($client_res = $client_verification_result->fetchArray(SQLITE3_ASSOC)) {
		if (!isset($client_res)) {
			continue;
		}
		$release_time = $client_res['releasetime'];
		$release_time_counter++;
	}
	$client_verification_statement->close();

	if ($client_numrows == 1) {
		
		if (date('Y-m-d H:i:s') < $release_time) {
			echo "403: Too Many Requests.";
			header('HTTP/1.0 403 Forbidden'); #still locked? out.
			session_destroy();
			die();
		}
		elseif (date('Y-m-d H:i:s') > $release_time) {
			$client_verification_deletion_statement = $client_verification->prepare('DELETE FROM lockouts WHERE userip = :ip;');
			$client_verification_deletion_statement->bindvalue(':ip',$client_IP);
			if (!($client_verification_deletion_statement->execute())) {
				$client_verification_deletion_statement->close();
				echo "403: Unknown Request.";
				header('HTTP/1.0 403 Forbidden'); #in case the deletion fails for whatever the reason
				session_destroy();
				die();
			}
			else {
				$client_verification_deletion_statement->close();
			}
		}
	}
	if ($client_numrows == 0) {
		$client_verification_first50_statement = $client_verification->prepare("SELECT messagetime FROM messages WHERE senderip = :ip AND messagetime > date('now', '-5 minutes');");
		$client_verification_first50_statement->bindvalue(':ip',$client_IP);
		$client_verification_first50_result = $client_verification_first50_statement->execute();
		$client_numrows2 = 0;
		$client_verification_first50_result->reset();
		while ($client_res = $client_verification_first50_result->fetchArray(SQLITE3_ASSOC)) {
			if (!isset($client_res)) {
				continue;
			}
			$last_message_time = $client_res['messagetime'];
			$client_numrows2++;
		}
		$client_verification_first50_statement->close();

		if ($client_numrows2 > $maximum_messages_every_5minutes){
			$client_verification_lockout_statement = $client_verification->prepare('INSERT INTO lockouts(releasetime, userip) VALUES (:time , :ip);');
			$client_verification_lockout_statement->bindvalue(':time',date('Y-m-d H:i:s', time() + $lock_out_minutes));
			$client_verification_lockout_statement->bindvalue(':ip',$client_IP);
			$client_verification_lockout_statement->execute();
			$client_verification_lockout_statement->close();
			echo "403: Too Many Requests.";
			header('HTTP/1.0 403 Forbidden'); #Sent more than $maximum_messages_every_5minutes in 5 minutes, $lock_out_minutes lockout granted.
			session_destroy();
			die();
		}
	}
}

unset($client_verification);
#all cleared, let's actually accept user's json
$request_json = json_decode(file_get_contents("php://input"), true);
if ($server_password != $request_json['serverpass']) {
	echo "403: Bad Password.";
	header('HTTP/1.0 403 Forbidden');
	session_destroy();
	die();
}

#original json: {'recipient':recipienthash, 'sender':clienthash, 'messagebody': clientmessage, 'messageiv': clientiv, 'messagelength': clientmessageOL}


if (check_user_hash($request_json['recipient']) == True) {
	$message_recipient = $request_json['recipient'];
}
else {
	bad_request();
}

if (check_user_hash($request_json['sender']) == True) {
	$message_sender = $request_json['sender'];
}
else {
	bad_request();
}

if (check_message_base64(($request_json['messagebody'])) == True) {
	$message_body = $request_json['messagebody'];
}
else {
	bad_request();
}

if (check_message_base64(($request_json['messageiv'])) == True) {
	$message_iv = $request_json['messageiv'];
}
else {
	bad_request();
}

if (($request_json['messagelength'] < 1001) and ($request_json['messagelength'] > 0)) {
	$message_length = $request_json['messagelength'];
}
else {
	bad_request();
}

$client_submission = new SQLite3('earcis-server.sqlite');
$client_submission_statement = $client_submission->prepare('INSERT INTO messages (senderip, sender, receiver, messagebody, messageIV, messageOL) VALUES (:ip , :sender , :receiver , :body , :iv , :ol);');
$client_submission_statement->bindvalue(':ip',$client_IP);
$client_submission_statement->bindvalue(':sender',$message_sender);
$client_submission_statement->bindvalue(':receiver',$message_recipient);
$client_submission_statement->bindvalue(':body',$message_body);
$client_submission_statement->bindvalue(':iv',$message_iv);
$client_submission_statement->bindvalue(':ol',$message_length);
if ($client_submission_statement->execute()) {
}
else {
	echo "500: Server Unavailable.";
	header('HTTP/1.0 500 Internal Server Error'); 
	session_destroy();
	die();
}
$client_submission_statement->close();
session_destroy();
die();

?>
