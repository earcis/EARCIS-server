<?php

@header("content-Type: text/html; charset=utf-8");
session_start();

require "config.php";

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

$request_json = json_decode(file_get_contents("php://input"), true);

if ($server_password != $request_json['serverpass']) {
	echo "403: Bad Password.";
	header('HTTP/1.0 403 Forbidden');
	session_destroy();
	die();
}
if ((!is_numeric($request_json['lastRequestPosition'])) or ($request_json['lastRequestPosition'] < 0))  {
	echo "400: Bad Request.";
	header('HTTP/1.0 400 Bad Request');
	session_destroy();
	die();
}
if (!check_user_hash($request_json['receiver'])) {
	echo "400: Bad Request.";
	header('HTTP/1.0 400 Bad Request');
	session_destroy();
	die();
}

$receiver = $request_json['receiver'];
$start_position = $request_json['lastRequestPosition'];
$end_position = $start_position + 50;

$client_messages = new SQLite3('earcis-server.sqlite');
$client_messages_statement = $client_messages->prepare("SELECT messagetime,sender,messagebody,messageIV,messageOL FROM messages WHERE receiver = :rc LIMIT $start_position,$end_position;");
$client_messages_statement->bindvalue(':rc',$receiver);
$client_messages_statement_result = $client_messages_statement->execute();
$client_messages_statement_result->reset();
$client_numrows = 0;
$messages = array();
while ($client_res = $client_messages_statement_result->fetchArray(SQLITE3_ASSOC)) {
	if (!isset($client_res)) {
		echo "404: No Message.";
		header('HTTP/1.0 404 Object Not Found');
		session_destroy();
		die();
	}
	$client_res_array = array();
	$client_res_array += array("messagetime"=>$client_res['messagetime']);
	$client_res_array += array("sender"=>$client_res['sender']);
	$client_res_array += array("messagebody"=>$client_res['messagebody']);
	$client_res_array += array("messageiv"=>$client_res['messageIV']);
	$client_res_array += array("messageol"=>$client_res['messageOL']);
	$messages[] = $client_res_array;
	$client_numrows++;
	unset($client_res_array);
}
$client_messages_statement->close();
$client_return = json_encode(array("messagequantity"=>$client_numrows,"messages"=>$messages));
header('Content-type: application/json');
exit($client_return);
?>
