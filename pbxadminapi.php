<?php

ini_set('display_errors', 1);
error_reporting(E_ALL);

/*
 * sample code to use the PBX PbxAdminApi API
 * (c) innovaphone AG 2023
 * @author ckl
 */


// end of local pbx data
@include 'my-pbx-data.php';

require_once './classes/websocket.class.php';

/**
 * class to create a new PBX App object just like the one we use for this application
 */
class AppObjectCreator extends AppPlatform\FinitStateAutomaton {

    public function ReceiveInitialStart(AppPlatform\Message $msg) {
        // 
        {
            return "CopyObject";
        }
    }

    /**
     * 
     * @global string $pbxapp h323-name of source App object
     * @param AppPlatform\Message $msg
     */
    public function ReceiveCopyObjectStart(AppPlatform\Message $msg) {
        global $pbxapp;
        $this->sendMessage(new AppPlatform\Message(
                        "GetObject",
                        "api", "PbxAdminApi",
                        "h323", $pbxapp));
    }

    public function ReceiveCopyObjectGetObjectResult(AppPlatform\Message $msg) {
        // patch $msg so it can be used for object creation
        $msg->setMt("UpdateObject");
        // a new one shall be created, no update of the exiting one
        unset($msg->guid);
        // assert unique identifiers
        $msg->h323 .= "-clone";
        $msg->cn   .= " (clone)";
        // we don't want any "Devices" entries
        unset($msg->devices);
        
        $this->sendMessage($msg);
    }

    public function ReceiveCopyObjectUpdateObjectResult(AppPlatform\Message $msg) {
        if (isset($msg->guid)) {
            $this->log("App object clone created with Guid $msg->guid", "runtime");
        } else {
            $this->log("App object clone could not be created: $msg->error", "runtime");
        }
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
                // "lmsg"    => true,
                // "debug"   => true
            ]
        ]
);

// Login to PBX
$app = new AppPlatform\PbxAppLoginAutomaton($pbxdns, new AppPlatform\AppServiceCredentials($pbxapp, $pbxpw));
$app->run();
if (!$app->getIsLoggedIn()) {
    die("login to the PBX failed - check credentials");
}

AppPlatform\Log::logon();
$me = new AppObjectCreator($app->getWs());
$me->run();
Exit;
