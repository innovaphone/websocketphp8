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
class RemoteControlUser extends AppPlatform\FinitStateAutomaton {

    private $myusers = [];
    private $mycalls = [];

    public function ReceiveInitialStart(AppPlatform\Message $msg) {
        // move to Monitoring state
        return "Monitoring";
    }

    public function ReceiveMonitoringStart(AppPlatform\Message $msg) {
        // Initialize RCC Api
        $this->sendMessage(new AppPlatform\Message(
                        "Initialize",
                        "api", "RCC"
        ));
    }

    public function ReceiveMonitoringInitializeResult(AppPlatform\Message $msg) {
        $this->log("end of initial user list", "runtime");
    }

    public function ReceiveMonitoringUserInfo(AppPlatform\Message $msg) {
        // remember UserInfo and do UserInitialize on the user
        if (isset($this->myusers[$msg->h323])) {
            $this->log("user '$msg->h323' updated", "runtime");
        }
        else {
            $this->log("new user '$msg->h323'", "runtime");
            $this->myusers[$msg->h323] = new stdClass();
            $this->sendMessage(new AppPlatform\Message(
                            "UserInitialize",
                            "api", "RCC",
                            "cn", $msg->cn,
                            "src", $msg->h323 // use "src" to be able to associate response
            ));
        }
        $this->myusers[$msg->h323]->info = $msg;
    }

    public function ReceiveMonitoringUserInitializeResult(AppPlatform\Message $msg) {
        // remember local user id returned from UserInitialize (associated by "src")
        $this->myusers[$msg->src]->user = $msg->user;
    }

    public function ReceiveMonitoringCallInfo(AppPlatform\Message $msg) {
        // a call state update
        $this->log("user $msg->user call $msg->call event $msg->msg", "runtime");
        // see if the call is towards the waiting queue "sink" 
        if (isset($msg->peer) && isset($msg->peer->h323) && $msg->peer->h323 == "sink") {
            $this->log("user $msg->user call $msg->call with peer h323=sink (notified with $msg->msg)", "runtime");
            // remember this call for monitoring
            $this->mycalls[$msg->call] = $msg;
        }

        // check if we monitor this call and if we are connected
        if (isset($this->mycalls[$msg->call])) {
            switch ($msg->msg) {
                case "r-conn" :
                    $this->log("call $msg->call connected ($msg->msg) - disconnecting", "runtime");
                    $this->sendMessage(new AppPlatform\Message(
                                    "UserClear",
                                    "api", "RCC",
                                    "call", $msg->call,
                                    "cause", 88, // "Incompatible destination" see https://wiki.innovaphone.com/index.php?title=Reference:ISDN_Cause_Codes
                    ));
                    break;
                case "del" : 
                    $this->log("call $msg->call ended ($msg->msg) - terminating", "runtime");
                    return "Dead";
            }
        }
    }

    public function timeout() {
        $this->log("timeout", "runtime");
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
$me = new RemoteControlUser($app->getWs());
$me->run();
Exit;
