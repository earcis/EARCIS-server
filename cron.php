<?php

if (php_sapi_name() != 'cli') {
	die("Access Disallowed.");
}

require "config.php";

$cron_sql = new SQLite3('earcis-server.sqlite');

$cron_sql_delmessage_statement = $cron_sql->prepare("DELETE FROM messages WHERE messagetime < date('now', '-1 hour');");
if ($cron_sql_delmessage_statement->execute()) {
}
else {
	error_log("EARCIS Server: Older-than-one-hour Messages Deletion Failure", 0);
}
$cron_sql_delmessage_statement->close();

$cron_sql_dellockout_statement = $cron_sql->prepare("DELETE FROM lockouts WHERE releasetime < date('now', '-3 days');");
if ($cron_sql_dellockout_statement->execute()) {
}
else {
	error_log("EARCIS Server: Older-than-three-days Lockouts Deletion Failure", 0);
}
$cron_sql_dellockout_statement->close();

?>