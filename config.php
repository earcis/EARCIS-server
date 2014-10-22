<?
$server_password = ""; // Leave empty if you don't want a password to be required to connect to your server. It is left in clear text, and letters/numbers only.
$maximum_messages_every_5minutes = 100; //How many messages can a client send before being locked out for 5 minutes? This is to prevent abuse.
$lock_out_minutes = 5; //How many minutes will a client be locked out if they trigger the 5-minute-limit?
?>