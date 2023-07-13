<?php

ini_set('display_errors', 1);
error_reporting(E_ALL);

/*
 * sample code to access the Users and Devices service on an App platform using PHP
 * (c) innovaphone AG 2023
 * @author ckl
 */

@include 'my-pbx-data.php';

require_once './classes/websocket.class.php';


/**
 * sample class for Devices
 */
class DevicesLister extends AppPlatform\Pbx2AppAuthenticator {

    public function ReceiveUserStart(\AppPlatform\Message $msg) {
        $this->sendMessage(new AppPlatform\Message("GetDomains"));
    }

    public function ReceiveUserGetDomainsResult(\AppPlatform\Message $msg) {
        $domain = array_shift($msg->domains);
        $this->log("from {$this->svc->name}: domain: {$domain->name}", "runtime");
        return "Dead";
    }
}

/**
 * sample class for Users
 */
class UsersLister extends AppPlatform\Pbx2AppAuthenticator {

    public function ReceiveUserStart(\AppPlatform\Message $msg) {
        $this->sendMessage(new AppPlatform\Message("UserData",
                                                   "maxID", 9999, "offset", 0, "filter", "%", "update", false, "col", "id", "asc", true));
    }

    public function ReceiveUserUserDataInfo(\AppPlatform\Message $msg) {
        $this->log("from {$this->svc->name}: user: id $msg->id, name $msg->username", "runtime");
        return "Dead";
    }
}

print "<pre>";
// turn on logging
\AppPlatform\Log::clearLogLevel(
        ["" =>
            [
                "runtime" => true,
                "error"   => true,
                "smsg"    => true,
            //     "lmsg"    => true,
            // "debug"   => true
            ]
        ]
);
AppPlatform\Log::logon();

// Login to PBX
$app = new AppPlatform\PbxAppLoginAutomaton($pbxdns, new AppPlatform\AppServiceCredentials($pbxapp, $pbxpw));
$app->run();
if (!$app->getIsLoggedIn()) {
    die("login to the PBX failed - check credentials");
}

\AppPlatform\Log::clearLogLevel(
        ["" =>
            [
                "runtime" => true,
                "error"   => true,
                "smsg"    => true,
            // "lmsg"    => true,
            // "debug"   => true
            ]
        ]
);

// connect to services we need
$authenticators = [$app];

// scan list of available app services for those we are interested in
foreach ($app->getServices() as $svc) {
    /* consider if we need this */
    $logmsg = "service: $svc->name ($svc->type)";
    switch ($svc->type) {
        case "innovaphone-devices-api":
            $authenticators[] = new DevicesLister($svc);
            break;
        case "innovaphone-usersadmin":
            $authenticators[] = new UsersLister($svc);
            break;
        default : 
            $logmsg .= ": can't handle";
    }
    AppPlatform\Log::log($logmsg);
}
// tell class talking to PBX how many authentications we need to do
$app->setNumberOfAuthentications(count($authenticators) - 1);

// and run all our automatons
$tr = new AppPlatform\Transitioner($authenticators);
$tr->run();

Exit;
