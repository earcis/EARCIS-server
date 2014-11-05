EARCIS-server
======

Server for Encryption and Relational Communications in Space

EARCIS is an instant messaging tool for secured end-to-end communications through insecure connections.

Version 0.2
--------------
Version 0.2 is released on Nov 4, 2014.
This patch includes security updates and system integrity updates, and is NOT compatible with previous versions of servers and clients.
Please update servers and clients to Version 0.2.

Installation and Running
--------------

EARCIS-server is written in PHP, operates on the combination of a webserver (namely Apache or Nginx), PHP and SQLite3. The choice of SQLite 3 allows easy setup and migrations of servers.

**Your server must have SSL/TLS enabled for EARCIS clients to connect, you can create a self-signed one very easily.**

##### Download zip or git clone the source:

```sh
git clone https://github.com/earcis/EARCIS-server.git EARCIS-server
cd EARCIS-server

```

##### Configure EARCIS-server by editing ```config.php```:

```php
$server_password = ""; 
// Leave empty if you don't want a password to be required to connect to your server. It is left in clear text, and letters/numbers only.

$maximum_messages_every_5minutes = 100; 
//How many messages can a client send before being locked out for 5 minutes? This is to prevent abuse.

$lock_out_minutes = 5; 
//How many minutes will a client be locked out if they trigger the 5-minute-limit?
```

##### Configure your webserver (important!)
Please find the example configurations for Nginx and Apache in the ```configs``` folder.

**You must config your webserver to deny public access to ```.sqlite``` files for security reasons.** Example configurations have already included the necessary measures, but modify them according to your environment if need to.

You can include ```EARCIS-server-nginx.conf``` in your Nginx virtual host configuration directly. For Apache servers, you can rename ```EARCIS-server-apache.htaccess``` to ```.htaccess``` and place it under the document root of virtual host.

##### Configure a cron job

It is highly recommended that you configure a cron job to clear messages more than one hour old and lockouts more than three days old, to keep the database small on size and fast to look up from. You should be able to use a command line PHP interpreter to execute ```cron.php```. 

In ```configs``` folder,```cronjob-example.txt``` provides an example cronjob you can use on web hosting panels or your Unix server's crontab; modify binary and file paths as necessary.

How does it work?
----
EARCIS-server serves as the relay server for secure messaging client EARCIS. See https://github.com/earcis/EARCIS-server for how EARCIS functions.

License
----

EARCIS-server is licensed under The MIT License, you are free to modify and distribute it under restrictions defined by The MIT License. For full license details, see LICENSE.
