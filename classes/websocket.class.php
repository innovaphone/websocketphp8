<?php

/**
 * class to access our AppPlatform through PHP using WebSockets
 *
 * @author ckl
 */

namespace AppPlatform;

require_once 'textalk.class.php';
require_once 'ntlm.class.php';
require_once 'rc4.php';

/*
 * weird utility
 */

function cast2class($obj, $targetclass) {
    if (!class_exists($targetclass, false)) {
        throw new Exception("cast2class: cannot convert object of type '" . get_class($obj) . "' into class '$targetclass' - class does not exist");
    }
    $sorig = serialize($obj);
    $xsorig = explode(':', $sorig, 4);
    $xsorig[1] = strlen($targetclass);
    $xsorig[2] = "\"$targetclass\"";
    $scv = implode(':', $xsorig);
    return (unserialize($scv));
}

/**
 * fully represents a WebSocket message
 */
class Message {
    // var $api = null;

    /**
     * the only mandatory member, the message type
     * @var string
     */
    var $mt;

    /**
     * get the message type
     * @return string
     */
    public function getMt() {
        return $this->mt;
    }

    /**
     * set the message type
     * @param string $mt
     * @return $this
     */
    public function setMt($mt) {
        $this->mt = $mt;
        return $this;
    }

    /**
     * Constructor
     * @param string $mt message type.  The remainder of the argument lists are name/value pairs which are used to initialize the Message<pre>
     * <code>$m = new Message("MessageType", 
     *     &nbsp;"member1", "value-of-member1", "member2", "value-of-member2", ...);</code>
     */
    function __construct($mt) {
        $na = func_num_args();
        $a = func_get_args();
        if (!($na & 1)) {
            die("Message constructor needs odd number of arguments (got " . print_r($a, true));
            // $this->api = array_shift($a);
        }
        $this->mt = array_shift($a);
        $na--;
        while ($na >= 2) {
            $p = array_shift($a);
            $v = array_shift($a);
            $this->$p = $v;
            $na -= 2;
        }
    }

    /**
     * create a Message from a json encoded WebSocket message
     * @param string $json the json encoded data
     * @param string $defaultType the default message type, used if $json can not be decoded
     * @return Message
     */
    static function fromJSON($json, $defaultType = "ReceiveTimeout") {
        $msg = new Message($defaultType);
        $decoded = json_decode($json);
        if ($decoded !== null) {
            foreach ($decoded as $p => $v) {
                $msg->$p = $v;
            }
        } else {
            Log::log("msg cannot be parsed from JSON ($json)", "runtime", "Message");
        }
        return $msg;
    }

}

/**
 * holds the credential to authenticate to a AppPlatform service using the service credentials
 */
class AppServiceCredentials {

    var $pw, $app, $domain, $sip, $guid, $dn;

    /**
     * 
     * @param string $app
     * @param string $pw
     * @param string $domain
     * @param string $sip
     * @param string $guid
     * @param string $dn
     */
    public function __construct($app, $pw, $domain = "", $sip = "", $guid = "", $dn = "") {
        $this->pw = $pw;
        $this->app = $app;
        $this->domain = $domain;
        $this->sip = $sip;
        $this->guid = $guid;
        $this->dn = $dn;
    }

}

class AppUserSessionCredentials {

    var $usr, $pw;

    public function __construct($sessionusr = null, $sessionpw = null) {
        $this->usr = $sessionusr;
        $this->pw = $sessionpw;
    }

}

/**
 * user credentials to log in to an App Service
 */
class AppUserCredentials {

    private $name;

    /**
     * returns the log-in user name provided
     * @return string
     */
    public function getName() {
        return $this->name;
    }

    private $pw;

    /**
     * returns the log-in password provided
     * @return string
     */
    public function getPw() {
        return $this->pw;
    }

    var $agent;

    /**
     * utility: this function returns a suitable "Agent" to be sent to the PBX to identify the calling agent
     * @return string
     */
    public function getAgent() {
        return $this->agent;
    }

    var $nonce;

    /**
     * utility: this function returns a suitable digest nonce to be sent to the PBX during login
     * @return string
     */
    public function getNonce() {
        return $this->nonce;
    }

    private $challenge;

    /**
     * the challenge received from the PBX during log-in
     * @return string
     */
    public function getChallenge() {
        return $this->challenge;
    }

    /**
     * stores the challenge received by the PBX
     * @param string $challenge
     * @return $this
     */
    public function setChallenge($challenge) {
        $this->challenge = $challenge;
        return $this;
    }

    /**
     * @var AppUserSessionCredentials
     */
    private $sessionkeys;

    /**
     * @var bool
     */
    private $disableSessionkeys = false;

    /**
     * disables the stored session keys
     * @return $this
     */
    public function setDisableSessionkeys() {
        $this->disableSessionkeys = true;
        return $this;
    }

    /**
     * the session keys to be used to ride on an existing session
     * @param bool $force if true, get kes even if disabled
     * @return AppUserSessionCredentials
     */
    public function getSessionkeys($force = true) {
        return $force || !$this->disableSessionkeys ? $this->sessionkeys : new AppUserSessionCredentials();
    }

    /**
     * 
     * @param string $name the user name
     * @param string $pw the user pw
     * @param AppUserSessionCredentials $sessionkeys the session keys to ride on (or null)
     * @param string $agent identifies the calling agent (null is recommended, a suitable default is generated then)
     */
    public function __construct($name, $pw = "", AppUserSessionCredentials $sessionkeys = null, $agent = null) {
        $this->name = $name;
        $this->pw = $pw;
        if ($sessionkeys === null)
            $this->sessionkeys = new AppUserSessionCredentials ();
        else
            $this->sessionkeys = $sessionkeys;

        if ($agent === null) {
            $cs = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
            $agent = basename($cs[0]['file']);
        }
        $this->agent = $agent . " (PHP WebSocket " . gethostname() . ")";
        $this->nonce = bin2hex(openssl_random_pseudo_bytes(8));
        Log::log("agent '{$this->agent}'", "constructor", get_class());
    }

}

/**
 * utility class to facilitate uniform logging
 */
class Log {

    /**
     * hold all log messages.  Useful if logoff() is set
     * @var bool 
     */
    static private $logmsg = array();

    /**
     * log messages are printed out immedeatly if true
     * @var bool
     */
    static private $logdebug = false;

    /**
     * array of active log levels, key = source
     *   each element is an array with key = category
     * @var string[]
     */
    static private $loglevel = array("" => array("" => false, "runtime" => true, "error" => true));

    /**
     * set log level for source and category
     * @param string $source must match $source in log()
     * @param string[] $category or array of categories, must match $category in log()
     * @param bool $on matching messages are output to log
     */
    static function setLogLevel($source, $category, $on) {
        if (!is_array($category))
            $category = array($category);
        foreach ($category as $c) {
            self::$loglevel[$source][$c] = $on;
        }
    }

    /**
     * clear all log levels
     * @param array $new if set, all log levels wil be overridde.  This value is usually retunred from a previousl call
     * @return type
     */
    static function clearLogLevel($new = array()) {
        $ret = self::$loglevel;
        self::$loglevel = $new;
        return $ret;
    }

    private static function dolog($source, $category) {
        if (isset(self::$loglevel[$source])) {
            if (isset(self::$loglevel[$source][$category])) {
                return self::$loglevel[$source][$category];
            } else if (isset(self::$loglevel[$source][""])) {
                return self::$loglevel[$source][""];
            }
        } else {
            if (isset(self::$loglevel[""][$category])) {
                return self::$loglevel[""][$category];
            }
        }
        return isset(self::$loglevel[""][""]) ? self::$loglevel[""][""] : false;
    }

    /**
     * turn on immedeate logging (default)
     */
    static public function logon($mode = true) {
        self::$logdebug = $mode;
    }

    /**
     * turn off immedeate logging (default is on)
     */
    static public function logoff() {
        self::$logdebug = false;
    }

    /**
     * format a log message for printing
     * @param integer $i message index, starting with 0. If left out, the last message is used
     * @return string
     */
    static protected function formatLogEntry($i = null) {
        if ($i === null)
            $i = count(self::$logmsg) - 1;
        $e = self::$logmsg[$i];
        $tl = $i ? self::$logmsg[$i - 1]->t : $e->t;
        $t0 = self::$logmsg[0]->t;
        $td = ((int) (($e->t - $tl) * 1000)) / 1000;
        $t0d = ((int) (($e->t - $t0) * 1000)) / 1000;
        $ms = (int) (($e->t - (int) $e->t) * 10000);
        $msg = strftime("%d.%m.%Y %H:%M:%S.", (int) $e->t);
        $msg .= sprintf("%04d %05.3f %08.3f %s %s", $ms, $td, $t0d, $e->category, $e->class) . ":  " . $e->msg;
        return $msg;
    }

    /**
     * submit a log message, printed out right away if logon() was called
     * @param string $msg
     * @param string $source
     */
    public static function log($msg, $category = "runtime", $source = "script") {
        if (!self::dolog($source, $category))
            return;
        $e = new \stdClass();
        $e->t = microtime(true);
        $e->msg = $msg;
        $e->category = $category;
        $e->class = $source;
        self::$logmsg[] = $e;
        $formattedMsg = self::formatLogEntry();
        if (self::$logdebug === true) {
            print $formattedMsg . "\r\n";
            @ob_flush();
            @flush();
        } else if (is_string(self::$logdebug)) {
            call_user_func(self::$logdebug, $formattedMsg);
        }
        return $formattedMsg;
    }

    /**
     * get all the log messages so far
     * @return string[]
     */
    public static function getLogmsg() {
        return self::$logmsg;
    }

    /**
     * clear all log messages so far
     */
    public function clearLogmsg() {
        self::$logmsg = array();
    }

}

/**
 * a web socjet connection
 */
class WSClient extends \WebSocket\Client {

    /**
     * a nickname used to identify the socket, e.g. in debugging
     * @var string
     */
    private $sourcename = null;
    private $randomid = 0;

    /**
     * get the nickname
     * @return string
     */
    public function getSourcename() {
        return $this->sourcename;
    }

    /**
     * submit a log message, using the nickname as source
     * @param string $msg
     * @param string $category
     */
    public function log($msg, $category = "debug") {
        Log::log("socket#{$this->randomid}: " . $msg, $category, $this->sourcename == null ? get_class($this) : $this->sourcename);
    }

    /**
     * 
     * @param string $sourcename a nickname for the connection
     * @param string $uri
     * @param array $options options based to the base class \WebSocket\Client
     */
    function __construct($sourcename, $uri = null, array $options = array()) {
        static $nextid = 100;
        $this->randomid = ++$nextid;
        // if no context available, turn off peer verification for client
        if (empty($options['context'])) {
            $options['context'] = stream_context_create(array("ssl" => array('verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true)));
        }
        parent::__construct($uri, $options);
        $this->sourcename = "$sourcename";
        if ($uri !== null)
            $this->connect();
        $this->log("$uri" . ($this->is_connected ? "" : " not") . " connected");
    }

    public function setUrl($uri) {
        parent::setUrl($uri);
        $this->log("$uri" . ($this->is_connected ? "" : " not") . " connected");
    }

    public function receive() {
        // $this->log("about to receive");
        $rcv = parent::receive();
        // $this->log("received '$rcv'");
        return $rcv;
    }

}

/**
 * the name says it all :-)
 */
class AutomatonState {

    /**
     * actually the name of the current state
     * @var string
     */
    private $name = null;

    /**
     * @var bool automaton receives events if true
     */
    private $run = false;

    /**



     *
     * @var FinitStateAutomaton backlink to the automaton  
     */
    private $auto = null;

    /**
     * @var string nockname :-) 
     */
    private $nickname = null;

    public function getNickname() {
        return $this->nickname;
    }

    /**
     * @return string the current status 
     */
    public function getName() {
        return $this->name;
    }

    /**
     * @return bool the current run state
     */
    public function getRun() {
        return $this->run;
    }

    /**
     * transition in to a new state
     * @param string $state
     * @return $this
     */
    public function setName($state) {
        if ($state !== null)
            $this->name = $state;
        return $this;
    }

    /**
     * alter the run state
     * @param bool $run new run state
     * @return $this
     */
    public function setRun($run) {
        if ($run && !$this->run)
            $this->auto->getTrans()->addRunnableAuto();
        else if (!$run && $this->run)
            $this->auto->getTrans()->subRunnableAuto();

        $this->run = $run;
        return $this;
    }

    /**
     * 
     * @param FinitStateAutomaton $me
     * @param string $nickname
     */
    public function __construct(FinitStateAutomaton $me, $nickname) {
        $this->auto = $me;
        $this->nickname = $nickname;
    }

}

/**
 * the automaton boilerplate.  This class does nothing, a working automaton must be derived. So this class is abstract
 */
abstract class FinitStateAutomaton {

    /**
     * the automatons state
     * @var AutomatonState
     */
    var $state;

    /**
     * the transitioner which runs this automaton
     * @var Transitioner
     */
    private $transitioner = null;

    /**
     * get the transitioner which executes me
     * @return Transitioner
     */
    protected function getTransitioner() {
        return $this->transitioner;
    }

    /**
     * the websocket connection this automaton talks to 
     * @var WSClient
     */
    private $ws = null;

    /**
     * @var string
     */
    private $nickname = null;

    /**
     * @var string
     */
    private $shortNickname = null;

    /**
     * 
     * @param WSClient $ws
     * @param string $nickname
     */
    public function __construct(WSClient $ws, $nickname = null) {
        $this->ws = $ws;
        if ($nickname === null)
            $nickname = get_class($this);
        $this->nickname = get_class($this) . "($nickname)";
        $this->shortNickname = $nickname;
        $this->state = new AutomatonState($this, "Auto$nickname");
    }

    /**
     * reconnect server (e.g. after disconnect)
     */
    public function reconnect($newws = null) {
        $this->log("setting new WS for " . $this->getNickname());
        $this->ws = $newws;
    }

    /**
     * @return string
     */
    public function getNickname() {
        return $this->nickname;
    }

    /**
     * @return string
     */
    public function getShortNickname() {
        return $this->shortNickname;
    }

    /**
     * initialize the automaton to be run by transitioner
     * @param Transitioner $trans
     */
    public function init(Transitioner $trans) {
        $this->transitioner = $trans;
    }

    /**
     * send a Message through my WebSocket connection
     * @param Message $msg
     */
    public function sendMessage(Message $msg) {
        $this->transitioner->sendMessage($this, $msg);
    }

    /**
     * post an Event to other automatons, this function is synchronous (i.e. Receive*() member functions will be called directly)
     * @param Message $msg
     */
    protected function postEvent(Message $msg, $dst = null) {
        $msg->_sourcename = $this->getShortNickname();
        $this->log("posting {$msg->_sourcename}->$dst: " . self::raw_json_encode($msg), "smsg");
        if (!$this->transitioner->transitions(null, $msg, $dst)) {
            $this->log("failed to post msg to '$dst'", "runtime");
        }
    }

    /**
     * get my WebSocket connection
     * @return WSClient
     */
    public function getWs() {
        return $this->ws;
    }

    /**
     * get my transitioner
     * @return Transitioner
     */
    public function getTrans() {
        return $this->transitioner;
    }

    /**
     * submit a log message
     * @param string $msg
     * @param string $category
     */
    public function log($msg, $category = "debug") {
        Log::log($msg, $category, $this->getNickname());
    }

    /**
     * called on a timeout (no message received). 
     * If this function returns false, then the automaton does not want to tertminate
     * @return boolean true if automaton wants to terminate after a timeout
     */
    public function timeout() {
        return true;
    }

    /**
     * json_encode is by default not compatible with JSON.Stringify().  Since we are dealing with message hashes
     * which are based on encoded JSON data, we must use exact JSON encoding 
     * @param sring $input
     * @param int $flags
     * @return string
     */
    public static function raw_json_encode($input, $flags = 0) {
        if (version_compare(PHP_VERSION, "5.4.0", '<')) {
            $fails = implode('|', array_filter(array(
                '\\\\',
                $flags & JSON_HEX_TAG ? 'u003[CE]' : '',
                $flags & JSON_HEX_AMP ? 'u0026' : '',
                $flags & JSON_HEX_APOS ? 'u0027' : '',
                $flags & JSON_HEX_QUOT ? 'u0022' : '',
            )));
            $pattern = "/\\\\(?:(?:$fails)(*SKIP)(*FAIL)|u([0-9a-fA-F]{4}))/";
            $callback = function ($m) {
                return html_entity_decode("&#x$m[1];", ENT_QUOTES, 'UTF-8');
            };
            return preg_replace_callback($pattern, $callback, json_encode($input, $flags));
        } else {
            return json_encode($input, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
    }

    protected $useWS = false;

    /**
     * true if websockets URLs are fixed to non-encrypted (for debugging)
     * @return bool
     */
    public function getUseWS() {
        return $this->useWS;
    }

    /**
     * set "fix websocket URI to ws://" mode (for debuging)
     * @param bool $useWS if true, websocket URIs are fixed from wss:// to ws:// 
     * @return $this
     */
    public function setUseWS($useWS) {
        $this->useWS = $useWS;
        return $this;
    }

    public function makeWebSocketUri($weburl) {
        // $weburl is something like
        //   https://apps.sample.dom/sample.dom/reporting/$innovaphone-reporting
        // or
        //   https://apps.sample.dom/gartenzwerg.com/meine-schoenen-devices/$innovaphone-devices
        // we strip the trailing component and change http to ws to create the WS uri
        // special case: it is a PBX URL, then don't strip the trailing part

        $parts = explode('/', $weburl);
        if (strpos($weburl, "/PBX0/APPS/websocket" /* PBX websocket path */) === false && count($parts) > 0) {
            unset($parts[count($parts) - 1]);
        }
        $wsuri = 'ws' . substr(implode('/', $parts), strlen('http'));
        if ($this->useWS) {
            $wsuri = str_replace("wss://", "ws://", $wsuri);
        }
        return $wsuri;
    }

    // this function at least must be overriden by any derived class
    abstract public function ReceiveInitialStart(Message $msg);

    /**
     * this is a strange helper function that creates a stream context which works with the App Platform
     * background: the app platform does not support HTTP 1.0 (it requires 1.1).  Many PHP functions however use HTTP 1.0 implicitly.
     * The "solution" is to fake a stream context that lets a client look like a 1.1 version and the server behave like 1.0
     * @param array $opts your default options for the new context
     * @return resource a stream_context with some HTTP options set
     */
    public function createPseudo11StreamContext(array $opts = array()) {
        if (!isset($opts['http']))
            $opts['http'] = array();
        foreach (
        array(
            'protocol_version' => '1.1',
            'method' => 'GET',
            'header' => array(
                'Connection: close'
            )
        )
        as $key => $setting) {
            $opts['http'][$key] = $setting;
        }
        return stream_context_create($opts);
    }

    /**
     * utility function for the simple case you want to run a single (i.e. this) automaton only
     */
    public function run($sockettimeout = 5) {
        $auto = new Transitioner($this);
        $auto->run($sockettimeout);
    }

}

/**
 * class to create and use a WebSocket connection to a service on an AppPlatform
 * Executes a number of FinitStateAutomaton
 */
class Transitioner {

    /**
     * submit a log message
     * @param string $msg
     * @param string $category 
     * @param string $source
     */
    public function log($msg, $category = "debug", $source = null) {
        Log::log($msg, $category, $source === null ? get_class($this) : $source);
    }

    /**
     * encode and send a Message to my WebSocket connection
     * @param FinitStateAutomaton $auto
     * @param Message $msg
     */
    public function sendMessage(FinitStateAutomaton $auto, Message $msg) {
        $ws = $auto->getWs();
        if (!$ws->isConnected()) {
            throw new \Exception("cannot sendMessage when socket is not connected");
        }
        $ws->send($coded = FinitStateAutomaton::raw_json_encode($msg));
        $this->log("sent->{$ws->getSourcename()} $coded", "smsg");
        $this->log("sent->{$ws->getSourcename()} from " . $auto->getNickname() . ": " . print_r($msg, true), "lmsg");
    }

    /**
     * list of automatons this transitioner runs (including idle ones)
     * @var FinitStateAutomaton[]
     */
    private $autos = array();

    /**
     * number of runnable automatons
     * @var int
     */
    private $nRunnableAutos = 0;

    public function addRunnableAuto() {
        $this->nRunnableAutos++;
    }

    public function subRunnableAuto() {
        $this->nRunnableAutos--;
    }

    /**
     * timeout in seconds to wait for input during select
     * @var int
     */
    private $selectTimeout;

    public function getSelectTimeout() {
        return $this->selectTimeout;
    }

    /**
     * add another FinitStateAutomaton to be run by this transitioner
     * @param FinitStateAutomaton $auto
     */
    public function addAutomaton(FinitStateAutomaton $auto) {
        $this->autos[] = $auto;
        $auto->init($this);
    }

    /**
     * 
     * @param FinitStateAutomaton $_ actually an argument list of automatons or an array of automatons
     */
    public function __construct(FinitStateAutomaton $_) {
        $args = func_get_args();
        // arguments are automatons
        while (count($args)) {
            $auto = array_shift($args);
            if (!is_array($auto))
                $auto = array($auto);
            foreach ($auto as $a)
                $this->addAutomaton($a);
        }
    }

    /**
     * start the given automaton, sends to pseudo "Start" Message to te automaton
     * @param FinitStateAutomaton $auto
     */
    public function startAutomaton(FinitStateAutomaton $auto) {
        $auto->state->setName("Initial");
        $auto->state->setRun(true);
        return $this->transition("", $auto, new Message("Start", "_sourcename", $auto->getShortNickname()));
    }

    /**
     * transition $auto with Event $msg
     * @param string $sourcename nickname of the WSClient the Message came from, can be empty if Message originates from an automaton
     * @param FinitStateAutomaton $auto
     * @param Message $msg
     * @return string the new state for this $auto
     */
    private function transition($sourcename, FinitStateAutomaton $auto, Message $msg) {
        $callable = array($auto, $handler = "Receive" . ($state = $auto->state->getName()) . $msg->getMt());
        $newstate = $state;
        $nickname = $auto->getNickname();
        if (!is_callable($callable)) {
            // $this->mylog("No event handler '{$callable[1]}' for $class - message not sent");
            $this->log("  no event func in " . get_class($auto) . ", implement 'public function $handler(\\AppPlatform\\Message \$msg) {}' for " . $auto->getShortNickname() . "?", "override");
        } else {
            $this->log("  transitioning $nickname from " . $state
                    . " via $handler");
            $auto->state->setName($xcufr = call_user_func($callable, $msg));
            $this->log("callable '" . get_class($auto) . "::" . $callable[1] . "' returns '$xcufr'");
            $newstate = $auto->state->getName();
            if ($newstate != $state) {
                $this->log("$nickname state $state->$newstate", "state");
                if ($newstate != "Dead") {
                    $newstate = $this->transition($sourcename, $auto, new Message("Start", "_sourcename", $auto->getShortNickname()));
                }
            }
        }
        return $newstate;
    }

    private $transitionsLevel = 0;

    /**
     * execute all transitions for an event (that is, a Message). Sent to all automatons that use the 
     * WebSocket identified by $sourcename 
     * @param string $sourcename the nickname of the originating WebSocket connection, or null if it is not from a socekt (a post)
     * @param Message $msg
     * @param string $dst optional nickname of target automaton (if null, event is posted to all automatons)
     * @return boolean false if there were no running automatons
     */
    public function transitions($sourcename, Message $msg, $dst = null) {
        // send msg to all automatons
        $this->transitionsLevel++;
        $this->log("transitions#{$this->transitionsLevel}($sourcename, " . $msg->getMt() . ") from '$sourcename' with msg from $sourcename:" . print_r($msg, true), "lmsg");
        $done = false;
        foreach ($this->autos as $auto) {
            // $this->log(" " . $auto->getShortNickname() . " " . ($auto->state->getRun() ? "" : "not ") . "runnable, socket " . $auto->getWs()->getSourcename());
            if ($auto->state->getRun()) {
                if ($dst === null)
                    $done = true;
                if (($sourcename === null ||
                        $auto->getWs()->getSourcename() == $sourcename) &&
                        ($dst === null ||
                        $auto->getShortNickname() == $dst)) {
                    $done = true;
                    if ($this->transition($sourcename, $auto, $msg) == "Dead") {
                        $auto->state->setRun(false);
                    }
                } else {
                    // $this->log($auto->getWs()->getSourcename() . "!= $sourcename");
                }
            } else {
                // $this->mylog(" not runnable");
            }
        }
        $this->log("done transitions#{$this->transitionsLevel}($sourcename, " . $msg->getMt() . ")");
        $this->transitionsLevel--;
        return $done;
    }

    /**
     * run all the automatons.  Used like<pre>
     * <code>$a = new FinitstateAutomaton;
     * $t = new Transitioner($a);
     * $t->run();</code>
     * @param int $sockettimeout number of seconds after which socket receive times out, default 5
     */
    public function run($sockettimeout = 5) {
        $this->selectTimeout = $sockettimeout;

        // start all automatons
        foreach ($this->autos as $auto) {
            if ($this->startAutomaton($auto) == "Dead")
                $auto->state->setRun(false);
        }

        // do the transitions until no running automaton is available any more
        $effect = false;
        do {
            $rstreams = array();
            $null = null;

            // gather streams with available input
            foreach ($this->autos as $auto) {
                if ($auto->state->getRun()) {
                    if ($auto->getWs()->isConnected()) {
                        $stream = $auto->getWs()->getSocket();
                        if (!in_array($stream, $rstreams, true) && $auto->getWs()->available() > 0) {
                            $rstreams[] = $auto->getWs()->getSocket();
                        }
                    }
                }
            }

            if (!count($rstreams)) {
                // gather streams we can select from
                foreach ($this->autos as $auto) {
                    if ($auto->state->getRun()) {
                        if ($auto->getWs()->isConnected()) {
                            $stream = $auto->getWs()->getSocket();
                            if (!in_array($stream, $rstreams, true)) {
                                $rstreams[] = $stream;
                            }
                        }
                    }
                }

                if (count($rstreams) == 0) {
                    $this->log("no selectable streams");
                    break;
                }

                $s = @stream_select($rstreams, $null, $null, $sockettimeout);
                if ($s === 0) {
                    // see if any automaton wants to recover from a timeout
                    $tryagain = false;
                    foreach ($this->autos as $auto) {
                        if ($auto->state->getRun()) {
                            if (!$auto->timeout()) {
                                $name = $auto->getShortNickname();
                                $this->log("socket select timeout, but '$name' wants to recover");
                                $tryagain = true;
                            }
                        }
                    }
                    // select again
                    if ($tryagain)
                        continue;
                    $this->log("socket select timeout");
                    break;
                }
            }

            // here we have only streams in rstreams which have buffered input or have been selected
            foreach ($rstreams as $rs) {
                // need to search for matching auto
                foreach ($this->autos as $auto) {
                    if ($auto->state->getRun()) {
                        $ws = $auto->getWs();
                        if ($ws->getSocket() === $rs) {
                            try {
                                $this->log("receiving from {$ws->getSourcename()}...");
                                $rcv = $ws->receive();
                                $sourcename = $ws->getSourcename();
                            } catch (Exception $e) {
                                $this->log("Exception: " . $e->getMessage(), "runtime");
                                break;  // from while
                            }
                            if ($rcv === false) {
                                $this->log("received<-$sourcename nothing", "smsg");
                                $ws->close();
                                $this->log("closed WS");

                                // give user a chance to handle EOF condition
                                $this->transitions($sourcename, $msg = new Message("EOF"));
                                $ws = $auto->getWs();
                                if ($ws->isConnected()) {
                                    $this->log("socket was reconnected after EOF");
                                } else {
                                    $this->log("socket still disconnected after EOF - terminating automaton");
                                    $auto->state->setRun(false);
                                    $effect = true;
                                }

                                continue;
                            }
                            if ($rcv !== null) {
                                $this->log("received<-$sourcename $rcv", "smsg");
                                $msg = Message::fromJSON($rcv);
                                $msg->_sourcename = $auto->getShortNickname();
                                if ($this->transitions($sourcename, $msg)) {
                                    $effect = true;
                                }
                            }
                            // we do not need to read again from this socket for another automaton
                            continue;
                        }
                    }
                }
            }
        } while ($effect);
        $this->log("all " . ($this->nRunnableAutos ? "but {$this->nRunnableAutos} " : "") . "automatons finished - end", $this->nRunnableAutos ? "error" : "debug");
    }

}

/**
 * This automaton will log you in to a specific AppService using the PBX's shared secret for the App
 * (provided as AppServiceCredentials)
 */
class AppLoginAutomaton extends FinitStateAutomaton {

    /**
     * did we log in OK?
     * @var boolean
     */
    protected $isLoggedIn = false;

    /**
     * the Message sent to login
     * @var Message 
     */
    protected $loginData = null;

    /**
     * the credentials to log in to the AppService
     * @var AppServiceCredentials 
     */
    protected $cred = null;

    /**
     * used if no credentials we given/known during constructor call time
     * @param AppServiceCredentials $cred
     * @return $this
     */
    public function setCred(AppServiceCredentials $cred) {
        $this->cred = $cred;
        return $this;
    }

    /**
     * get the credentials used for log-in
     * @return AppServiceCredentials
     */
    public function getCred() {
        return $this->cred;
    }

    /**
     * the session key of the websocket connection to the AppService (for encryption)
     * @var string 
     */
    protected $sessionKey = null;

    /**
     * the salt of the websocket connection to the AppService (unclear what for)
     * @var string
     */
    protected $sessionSalt = null;

    /**
     * 
     * @param WSClient $ws the WebSocket connection to use
     * @param AppServiceCredentials $cred the credentials to log in
     * @param string $nickname identifies this automaton (if you instantiate it twice), defailt is "Login"
     */
    public function __construct(WSClient $ws = null, AppServiceCredentials $cred = null, $nickname = null) {
        $this->cred = $cred;
        $this->loginData = new Message("");
        parent::__construct($ws, $nickname === null ? "Login" : $nickname);
    }

    /**
     * @return bool
     */
    public function getIsLoggedIn() {
        return $this->isLoggedIn;
    }

    /**
     * handles initial (pseudo) message, that is, starts the finite state machine
     * @param Message $msg
     */
    public function ReceiveInitialStart(Message $msg) {
        if ($this->getWs()->isConnected()) {
            $this->log("requesting challenge");
            $this->sendMessage(new Message("AppChallenge"));
        } else {
            $this->log("deferred - websocket not yet connected");
        }
    }

    /**
     * process the challenge received from the AppService
     * @param Message $msg
     */
    public function ReceiveInitialAppChallengeResult(Message $msg) {
        $infoObj = new \stdClass();
        $infoHashString = json_encode($infoObj, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $hashcode = hash('sha256', $sha = "{$this->cred->app}:::::{$infoHashString}:{$msg->challenge}:{$this->cred->pw}");
        $this->log("computed challenge $sha", "debug");  // do not output in any other category than "debug" coz it includes the password
        $this->sessionKey = hash('sha256', "innovaphoneAppSessionKey:{$msg->challenge}:{$this->cred->pw}");
        $this->sendMessage($this->loginData = new Message("AppLogin", "digest", $hashcode, "domain", "", "sip", "", "guid", "", "dn", "", "app", $this->cred->app, "info", $infoObj));
    }

    /**
     * process the login result
     * @param Message $msg
     * @return string the new state
     */
    public function ReceiveInitialAppLoginResult(Message $msg) {
        $response = clone $this->loginData;
        if ((isset($msg->ok) ? $msg->ok : false) != "true") {
            $this->log("login failed", "error");
            $response->setMt("AppLoginFailure");
            $this->isLoggedIn = false;
        } else {
            $this->log("successfully logged in");
            $response->setMt("AppLoginSuccess");
            $this->isLoggedIn = true;
        }
        $this->postEvent($response);
        return "Dead";
    }

    /**
     * encrypt data to send to the AppService
     * @param string $seed seed
     * @param string $data data to encrypt
     * @return string the new state
     */
    public function encrypt($seed, $data) {
        $key = $seed . ':' . $this->sessionKey;
        $cipher = rc4Encrypt($key, $data);
        return bin2hex($cipher);
    }

}

class UserPBXLoginResults {

    /**
     * @var Message Login message
     */
    public $loginMsg = null;

    /**
     * @var Message LoginResult message
     */
    public $loginResultMsg = null;

    /**
     * @var Message UpdateApps message
     */
    public $UpdateAppsMsg = null;
    public $updateAppsComplete = false;

    public function __construct() {
        $this->UpdateAppsMsg = new \stdClass();
        $this->UpdateAppsMsg->apps = array();
    }

}

/**
 * this automaton logs you in to the PBX using a PBX user 
 * you can use this logged-in session with any AppService later on
 */
class UserPBXLoginAutomaton extends FinitStateAutomaton {

    /**
     * @var AppUserCredentials
     */
    private $cred;

    /**
     * the number of seconds we shall wait for login confirmation (if 2 factor is enabled)
     * @var int
     */
    private $confirmTimeout;
    private $loginMsg = null;
    private $loginResultMsg = null;

    /**
     *
     * @var UserPBXLoginResults collection of various PBX result messages
     */
    private $results = null;

    /**
     * access the PBX login results
     * @return UserPBXLoginResults
     */
    public function getResults() {
        return $this->results;
    }

    /**
     *
     * @var AppUserSessionCredentials
     */
    private $sessionCredentials = null;

    /**
     * get the session keys which were created (when logging in with user/password)
     * @return AppUserSessionCredentials
     */
    public function getSessionkeys() {
        return $this->sessionCredentials;
    }

    /**
     * true if login succeeded
     * @var bool
     */
    private $isLoggedIn = false;

    /**
     * true if login succeeded
     * @return bool
     */
    public function getIsLoggedIn() {
        return $this->isLoggedIn;
    }

    /**
     * create an automaton which logs in to the PBX
     * @param WSClient $ws WebSocket connection to the PBX
     * @param AppUserCredentials $cred credentials, if session keys are present, we try to resume this session
     * @param int $confirmTimeout number of seconds we wait for 2 factor confirmation (if enabled on the PBX)
     * @param string $nickname just for logging
     */
    public function __construct(WSClient $ws, AppUserCredentials $cred, $confirmTimeout = 60, $nickname = null) {
        $this->cred = $cred;
        $this->confirmTimeout = $confirmTimeout;
        $this->isLoggedIn = false;
        $this->sessionCredentials = null;
        $this->results = new UserPBXLoginResults;
        parent::__construct($ws, $nickname === null ? "UserPBXLogin" : $nickname);
    }

    public function ReceiveInitialStart(Message $msg) {
        $this->sendMessage(new Message("Login", "type", empty($this->cred->getSessionkeys(false)->usr) ? "user" : "session", "userAgent", $this->cred->agent));
    }

    public function ReceiveInitialAuthenticate(Message $msg) {

        $login = new Message("Login");
        $login->method = $msg->method;

        if (empty($this->cred->getSessionkeys(false)->usr)) {
            $login->type = "user";
            $password = $this->cred->getPw();
            $login->username = $this->cred->getName();
        } else {
            $login->type = "session";
            $password = $this->cred->getSessionkeys()->pw;
            $login->username = $this->cred->getSessionkeys()->usr;
        }
        $login->nonce = $this->cred->nonce;
        $login->userAgent = $this->cred->getAgent();
        $this->cred->setChallenge($msg->challenge);

        switch ($msg->method) {
            case "digest" :
                $digestInput = "innovaphoneAppClient:{$msg->type}:{$msg->domain}:{$login->username}:$password:{$login->nonce}:{$msg->challenge}";
                $digest = hash("sha256", $digestInput);
                $login->response = $digest;
                $login->password = $password;
                break;
            case 'ntlm' :
                $login->response = \NTLM\ntlmResponse($password, $msg->challenge);
                $login->password = bin2hex(mhash(MHASH_MD4, (mhash(MHASH_MD4, iconv('UTF-8', 'UTF-16LE', $password)))));
                break;
            default :
                $this->log("unknown/unsupported login method '{$msg->method}'");
                return "Dead";
        }
        $this->results->loginMsg = clone $login;
        unset($login->password);
        $this->sendMessage($login);
    }

    /**
     * number of timeout intervals we want to wait before giving up on 2 factor auth
     * @var int
     */
    private $authWaitCount = 0;

    public function ReceiveInitialAuthorize(Message $msg) {
        $this->authWaitCount = $this->confirmTimeout / $this->getTransitioner()->getSelectTimeout();
        $this->log("  Waiting for Authorization Code {$msg->code} ...");
    }

    /**
     * called upon WebSocket receive timeout
     * @return boolean false if we want to continue to wait for messages
     */
    public function timeout() {
        $this->log("  Waiting timeout (#{$this->authWaitCount})...");
        if (--$this->authWaitCount > 0) {
            return false;
        } else {
            $this->log("Too many waiting timeouts, give up :-(", "error");
            return true;
        }
    }

    public function ReceiveInitialLoginResult(Message $msg) {
        $this->authWaitCount = 0;
        $this->results->loginResultMsg = $msg;
        if (empty($msg->error)) {
            // verify PBX
            $check = hash("sha256", $secret = "innovaphoneAppClient:loginresult:" . $msg->info->user->domain . ":" . $this->results->loginMsg->username . ":" . $this->results->loginMsg->password . ":" . $this->cred->getNonce() . ":" . $this->cred->getChallenge() . ":" . self::raw_json_encode($msg->info));
            if ($msg->digest != $check) {
                $this->log("DIGEST ERROR($secret)");
                $msg->error = 99999;
                $msg->errorText = "Fake PBX - wrong digest";
            }
        }
        if (!empty($msg->error)) {
            $this->log("Login failed: {$msg->errorText}", "error");
            $msg->setMt("UserPBXLoginFailure");
            $this->isLoggedIn = false;
            $this->sessionCredentials = null;
        } else {
            $this->isLoggedIn = true;
            $this->log("Successfully logged-in to PBX " . parse_url($this->getWs()->getUrl(), PHP_URL_HOST) . " as {$this->cred->getName()}");

            if (!empty($msg->info->session)) {
                $sessionUsername = (rc4Encrypt($usrx = "innovaphoneAppClient:usr:" . $this->cred->nonce . ":" . $this->results->loginMsg->password, \NTLM\hex2bin($msg->info->session->usr)));
                $sessionPassword = (rc4Encrypt($pwdx = "innovaphoneAppClient:pwd:" . $this->cred->nonce . ":" . $this->results->loginMsg->password, \NTLM\hex2bin($msg->info->session->pwd)));
                $msg->sessionkeys = $this->sessionCredentials = new AppUserSessionCredentials($sessionUsername, $sessionPassword);
            } else {
                $msg->sessionkeys = $this->sessionCredentials = null;
            }
            // request user apps
            $this->sendMessage(new Message("SubscribeApps"));
            return;
        }
        // can we recover?
        if (!$this->isLoggedIn) {
            if (($this->results->loginMsg->type == "session") &&
                    // we tried a session login, retry with user credentials if available
                    ($this->cred->getName() != "")) {
                $this->log("session login failed, retrying with user credentials", "runtime");
                // so do not use session keys on next round
                $this->cred->setDisableSessionkeys();
                $this->ReceiveInitialStart(new Message("Start"));
                return;
            } else {
                $this->log("session login failed with user credentials", "error");
                return "Dead";
            }
        }
        return $this->tryLoginComplete();
    }

    /**
     * this message seems to be obsoleted by a sequence of UpdateAppsInfo
     * @param \AppPlatform\Message $msg
     * @return string new state
     */
    public function ReceiveInitialUpdateApps(Message $msg) {

        $this->results->UpdateAppsMsg = $msg;
        $ok = new Message("UserPBXLoginSuccess", "results", $this->results);
        $this->postEvent($ok);
        return "Dead";
    }

    public function ReceiveInitialUpdateAppsInfo(Message $msg) {
        $this->results->UpdateAppsMsg->apps[] = $msg->app;
    }

    public function ReceiveInitialUpdateAppsComplete(Message $msg) {
        $this->results->updateAppsComplete = true;
        return $this->tryLoginComplete();
    }

    private function tryLoginComplete() {
        $this->log("tryLoginComplete called");
        if ($this->results->updateAppsComplete && $this->results->loginResultMsg !== null) {
            $this->log("posting PBX login final result type '{$this->results->loginResultMsg->mt}'");
            $this->postEvent($this->results->loginResultMsg);

            $ok = new Message("UserPBXLoginSuccess", "results", $this->results);
            $this->postEvent($ok);
            return "Dead";
        } else {
            $this->log("tryLoginComplete not yet Dead (updateAppsComplete=" . ($this->results->updateAppsComplete ? "true" : "false") . ", loginResultMsg=" . ($this->results->loginResultMsg === null ? "null" : $this->results->loginResultMsg->mt) . ")");
        }
    }

}

/**
 * an automaton which allows to log in to an AppService using a PBX user account
 * 
 * derived from UserPBXLoginAutomaton so it must override all Receive functions which might transition to "Dead" before this automaton is finished
 */
class UserPBXLoginWithAppAutomaton extends UserPBXLoginAutomaton {

    /**
     * @var int number of outstanding AppGetLoginResilt messages
     */
    protected $nclients = 0;

    /**
     * set the number of app services we shall authenticate towards the PBX
     * @param int $nclients
     * @return $this
     */
    public function setNclients($nclients) {
        $this->nclients = $nclients;
        return $this;
    }

    /**
     * calls parent function but supresses the transition to "Dead"
     * @param Message $msg
     */
    public function ReceiveInitialUpdateApps(Message $msg) {
        parent::ReceiveInitialUpdateApps($msg);
        // return nothing, so this automaton will not transition to "Dead" here
    }

    /**
     * calls parent function but supresses the transition to "Dead"
     * @param Message $msg
     */
    public function ReceiveInitialUpdateAppsComplete(Message $msg) {
        parent::ReceiveInitialUpdateAppsComplete($msg);
        // return nothing, so this automaton will not transition to "Dead" here
    }

    /**
     * when the PBX user login is cancelled, no app login based on this login will work. So we can termibate right away
     * @param Message $msg
     * @return string new state
     */
    public function ReceiveInitialUserPBXLoginCancel(Message $msg) {
        $this->log("UserPBXLogin cancelled");
        return "Dead";
    }

    /**
     * an app client automaton needs an AppGetlogin from the PBX
     * @param Message $msg
     */
    public function ReceiveInitialUserPBXLoginNeedGetLogin(Message $msg) {
        // "$msg->challenge" below is to cast an int to string.  we receive it as int from PBX but must send it as string to app
        // this has been fixed in later builds of the PBX
        $gl = new Message("AppGetLogin", "app", $msg->app->name, "challenge", "$msg->challenge", "src", $msg->_sourcename);
        $this->sendMessage($gl);
    }

    public function ReceiveInitialAppGetLoginResult(Message $msg) {
        $this->postEvent($msg->setMt("GotAppGetLoginResult"), $msg->src);
        if (--$this->nclients <= 0) {
            $this->log("nclients is 0 now, exiting");
            return "Dead";
        }
    }

}

/**
 * specifies an AppService instance to connect to
 */
class AppServiceSpec {

    var $app;
    var $service;
    var $domain;

    /**
     * AppService specification
     * @param string $service service name, must match the last part of the instance URI 
     * @param string $name instance name, must match the name as configured in the PBX
     * @param string $domain domain name, must match the first part of the instance URI 
     */
    public function __construct($service, $name = null, $domain = null) {
        $this->app = $service;
        $this->service = $name;
        $this->domain = $domain;
    }

}

/**
 * this is an AppLoginAutomaton that starts only after a UserPBXLoginSuccess was received, so it works in 
 * tandem with an UserPBXLoginAutomaton
 * it takes the authenticated PBX user session and creates an authenticated session to an AppService based on this
 */
class AppLoginViaPBXAutomaton extends AppLoginAutomaton {

    /**
     *
     * @var AppServiceSpec specifies app to connect to
     */
    private $sSpec;

    /**
     * the selected websocket app instance
     * @var stdClass
     */
    private $selectedApp = null;

    /**
     * array of maps: FQDN to passthrough URL (via Devices)
     * @var string[]
     */
    private $passthrough = array();

    /**
     * the app info for the selected AppService instance
     * @return \stdClass
     */
    public function getSelectedApp() {
        return $this->selectedApp;
    }

    /**
     * constructor
     * @param WSClient $ws WebSocket to devices, this is usually not (yet) connected, as we only learn the AppService URI 
     *      later in the process
     * @param string $service name of the service type.  This is what the PBX will announce as last part of the apps[]->uri member
     * @param string $name name of the service instance (given by the PBX as apps[]->name).  If left null, the first instance is used
     * @param string $nickname nick name for the automaton (only for logging)
     * @param string[] $passthrough array of maps: FQDN to passthrough-URL (via Devices)
     */
    public function __construct(WSClient $ws, AppServiceSpec $spec, $nickname = "AppLoginViaPBXA", $passthrough = array()) {
        $this->sSpec = $spec;
        $this->passthrough = $passthrough;
        parent::__construct($ws, null, $nickname);
    }

    /**
     * selects the first app assigned to the user that matches the criteria
     * derived classes can override this for more sophisticated selection 
     * @param AppServiceSpec $spec to select the AppService instance we want to connect to
     * @param array $apps apps member of UpdateAppsMsg received from PBX
     * @return stdClass matching apps array member in UpdateAppsMsg received from PBX
     */
    protected function selectInstance(AppServiceSpec $spec, array $apps) {

        foreach ($apps as $app) {
            if (!isset($app->url))
                continue;
            $components = explode('/', $app->url);
            $nc = count($components);
            $thisapp = $components[$nc - 1];
            $thisservice = $components[$nc - 2];
            $thisdomain = $components[$nc - 3];
            $this->log("found instance app=$thisapp service=$thisservice domain=$thisdomain vs. $spec->app/$spec->service/$spec->domain");
            if ($spec->domain !== null && $thisdomain != $spec->domain)
                continue;
            if ($spec->service !== null && $thisservice != $spec->service)
                continue;
            if ($spec->app !== null && $thisapp != $spec->app)
                continue;
            return $app;
        }
        $this->log("no matching AppService for '{$spec->app}/{$spec->service}/{$spec->domain}'", "runtime");
        return null;
    }

    /**
     * receive the UserPBXLoginAutomaton automaton's indication that login to the PBX succeeded
     * selects the AppService instance to use, connects to the AppService 
     *   and starts the parent class (by sending an "InitialStart" message to itself)
     * @param Message $msg
     * @return string new state (only changes on failure)
     */
    function ReceiveInitialUserPBXLoginSuccess(Message $msg) {

        if (($app = $this->selectInstance($this->sSpec, $msg->results->UpdateAppsMsg->apps)) === null) {
            $this->log("no suitable AppServices instance ({$this->sSpec->app}/{$this->sSpec->service})");
            // allow PBX automaton to terminate
            $this->postEvent(new Message("UserPBXLoginCancel"));
            return parent::ReceiveInitialAppLoginResult(new Message("AppLoginResult"));
        }
        $this->selectedApp = $app;
        $urlhost = parse_url($app->url, PHP_URL_HOST);
        if (isset($this->passthrough[strtolower($urlhost)])) {
            $useUrl = (preg_replace("@^[^:]*:\/\/$urlhost\/@", $this->passthrough[strtolower($urlhost)] . "/", $app->url));
        } else {
            $useUrl = $app->url;
        }
        $wsuri = $this->makeWebSocketUri($useUrl);

        $this->getWs()->setUrl($wsuri);
        $this->log("starting app login now for $wsuri ($app->title), " . ($this->getWs()->isConnected() ? "" : " not") . " connected");

        $this->ReceiveInitialStart(new Message("Start"));
    }

    /**
     * receive challenge from the app service, passes this information to the UserPBXLoginAutomaton automaton
     * @param Message $msg
     */
    function ReceiveInitialAppChallengeResult(Message $msg) {
        $this->postEvent(new Message("UserPBXLoginNeedGetLogin", "app", $this->selectedApp, "challenge", $msg->challenge));
    }

    /**
     * receive the AppGetLogin result from the UserPBXLoginAutomaton automaton 
     * @param Message $msg
     */
    public function ReceiveInitialGotAppGetLoginResult(Message $msg) {
        // send AppLogin to app
        $this->sendMessage(
                $this->loginData = new Message(
                "AppLogin", "app", $msg->app, "domain", $msg->domain, "sip", $msg->sip, "guid", $msg->guid, "dn", $msg->dn, "info", $msg->info, "digest", $msg->digest, "pbxObj", $msg->pbxObj
        ));
        // save session key for encryption
        $this->sessionKey = $msg->key;
        $this->log("got session key {$msg->key}");
    }

}

/**
 * a class that logs in to a PBX and creates authenticated websocket connections to a number of AppServices
 */
class AppServiceLogin {

    /**
     * @var string PBX websocket URL, may be abbreviated to plain domain name or IP address (e.g. "pbx.mydomain.tld")
     */
    private $pbxUrl = null;

    /**
     * @var WSClient websocket connection to PBX
     */
    private $pbxWS = null;

    /**
     * @var UserPBXLoginWithAppAutomaton PBX Login Automaton
     */
    private $pbxA = null;

    /**
     * @return WSClient the WebSocket to the PBX
     */
    public function getPbxWS() {
        return $this->pbxWS;
    }

    /**
     * @return UserPBXLoginWithAppAutomaton the automaton used to log in to the PBX
     */
    public function getPbxA() {
        return $this->pbxA;
    }

    /**
     * @var AppUserSessionCredentials PBX session credentials used initially
     */
    private $pbxOldSessionKey = null;

    /**
     * @var AppServiceSpec[] the service specification given to the constructor
     */
    private $appServiceSpec = array();

    /**
     * @var AppLoginViaPBXAutomaton[] array of automatons used to log in to the AppServices
     */
    private $appServiceAS = array();

    /**
     * @var WSClient[] array of WebSockets 
     */
    private $appServiceWS = array();

    /**
     * array of maps: FQDN to passthrough URL (via Devices)
     * @var string[] 
     */
    private $passthrough = array();

    /**
     * get the WSClient for the app that matched $spec
     * @param AppServiceSpec $spec
     * @return WSClient
     */
    public function getAppWebSocket(AppServiceSpec $spec) {
        $sspec = serialize($spec);
        return isset($this->appServiceWS[$sspec]) ? $this->appServiceWS[$sspec] : null;
    }

    /**
     * get the Automaton for the app that matched $spec
     * @param AppServiceSpec $spec
     * @return AppLoginViaPBXAutomaton
     */
    public function getAppAutomaton(AppServiceSpec $spec) {
        $sspec = serialize($spec);
        return isset($this->appServiceAS[$sspec]) ? $this->appServiceAS[$sspec] : null;
    }

    /**
     * PBX user credentials
     * @var AppUserCredentials 
     */
    private $credentials = null;

    /**
     * @var bool create ws:// instead of wss:// sockets if set
     */
    private $useWS = false;

    protected function log($msg, $category = "debug") {
        Log::log($msg, $category, get_class());
    }

    protected $sessionFn = null;

    /**
     * setup the class to authenticate and connect to the AppServices
     * @param string $pbx WebSocekt URI to PBX, either pure FQDN/IP or the full URI
     * @param AppUserCredentials $credentials to log in to the PBX
     * @param AppServiceSpec[] $appServiceSpec specifies the services to connect to
     * @param bool $useWS if true, ws:// instead of wss:// is used
     * @param string[] $passthrough array of maps: FQDN to passthrough URL (via Devices)
     */
    function __construct($pbx, AppUserCredentials $credentials, $appServiceSpec = array(), $useWS = false, $passthrough = array()) {

        $this->useWS = $useWS;
        $this->passthrough = $passthrough;
        $this->pbxUrl = (strpos($pbx, "s://") !== false) ? $pbx :
                $this->pbxUrl = ($useWS ? "ws" : "wss") . "://$pbx/PBX0/APPCLIENT/130000/websocket";
        $this->pbxOldSessionKey = new AppUserSessionCredentials();
        $this->credentials = $credentials;
        if (!is_array($appServiceSpec))
            $appServiceSpec = array($appServiceSpec);
        $this->appServiceSpec = $appServiceSpec;

        // create hopefully uniq session kex file name
        $pbxid = parse_url($this->pbxUrl, PHP_URL_HOST);
        if (strpos($this->pbxUrl, "/passthrough/") !== false &&
                preg_match('@/passthrough/([^/]*)/@', $this->pbxUrl, $matches)) {
            $pbxid = "{$matches[1]}.$pbxid";
        }
        $this->sessionFn = ("session-" . $this->credentials->getName() . "-" . $pbxid . ".sessioninfo");
    }

    /**
     * connect all the requested AppService instances and the PBX
     * @return bool true if PBX login was OK
     */
    public function connect() {
        $keys = $this->getSessionkey();

        // create websocket towards the well known PBX URI
        $this->pbxWS = new WSClient("PBXWS", $this->pbxUrl);

        // create automaton which logs in to an AppService via PBX
        $this->pbxA = new UserPBXLoginWithAppAutomaton($this->pbxWS, new AppUserCredentials($this->credentials->getName(), $this->credentials->getPw(), $keys));
        $this->pbxA->setUseWS($this->useWS);
        // create websocket for the AppService, not yet connected 
        $napps = 0;
        foreach ($this->appServiceSpec as $spec) {
            $sspec = serialize($spec);
            $id = strtoupper("{$spec->app}-{$spec->service}");
            $this->appServiceAS[$sspec] = new AppLoginViaPBXAutomaton($this->appServiceWS[$sspec] = new WSClient("$id-WS"), $spec, "$id-A", $this->passthrough);
            $this->appServiceAS[$sspec]->setUseWS($this->useWS);
            $napps++;
        }
        // tell class it needs to authenticate $napps app services
        $this->pbxA->setNclients($napps);

        // run all automatons
        $auto = new Transitioner($this->pbxA, $this->appServiceAS);
        $auto->run();

        // save the session key we received (if encessary)
        $this->putSessionKey();

        return $this->pbxA->getIsLoggedIn();
    }

    private function getSessionkey() {
        $keys = false;
        if (($sk = $this->readSessionKey()) !== false) {
            $this->log("Using saved session keys");
            $this->pbxOldSessionKey = $keys = @unserialize($sk);
        }
        if ($keys === false) {
            $keys = new AppUserSessionCredentials();
        }
        return $keys;
    }

    private function putSessionKey() {
        $sc = $this->pbxA->getSessionkeys();
        if (
                $this->pbxA->getIsLoggedIn() &&
                $sc !== null &&
                (
                !$this->pbxOldSessionKey ||
                $sc->pw != $this->pbxOldSessionKey->pw ||
                $sc->usr != $this->pbxOldSessionKey->usr
                )
        ) {
            if ($this->writeSessionKey(serialize($sc)))
                $this->log("Session keys saved");
            else
                $this->log("Failed to save session keys");
        }
    }

    /**
     * save session key to persistent memory.  May be overriden by derived class
     * @param string $sk
     * @return bool false on error
     */
    protected function writeSessionKey($sk) {
        return @file_put_contents($this->sessionFn, $sk);
    }

    /**
     * read session key from persistent memory.  May be overriden by derived class
     * @return string retrieved session key data, false on error
     */
    protected function readSessionKey() {
        return @file_get_contents($this->sessionFn);
    }

}

/**
 * a class to get access to the AdminUI of a device which is registered with Devices
 * you will need an authenticated WebSocket towards the Devices instance
 * you could use something like
 *  $apc = new AppServiceLogin("sindelfingen.sample.dom", new AppUserCredentials("ckl", "pwd"), new AppServiceSpec("\$innovaphone-devices"));
 *  $apc->connect();
 * for this
 */
class DevicesGetAdminAccess extends FinitStateAutomaton {

    protected $GetUserInfoResult = null;

    /**
     * @var \stdClass[] list of known (or requested) macs
     */
    protected $macs = null;

    /**
     * @var bool true if we want all devices known to Devices
     */
    protected $getAllDevices = false;

    /**
     * @var \stdClass domain info received from devices
     */
    protected $domains = array();
    private $gotDomains = false, $gotDevices = 0, $gotKey = false;
    protected $searchDomains = array();
    private $searchDomainSpec = array();

    /**
     * @var string base uri of the APP PlatForm
     */
    protected $apppfUri = null;

    /**
     * get a config file from a device, with standard pw is $standard is true
     * @param string $serial mac address
     * @param $type device type, like IP811
     * @param $fn recommended file name for config file
     * @param bool $standard if true, config with standard passwords is retrieved
     * @return string the config file
     */
    public function getConfigDump($serial, $type, /* out */ &$fn, $standard = false) {

        if (($pturl = $this->getDeviceAccessURL($serial)) === false)
            return false;
        $pturl .= $standard ? "/cfg-standard.txt" /* cd=standard-IP811-41-00-04.txt" */ : "/cfg.txt" /*  ?cd=complete-IP811-41-00-04.txt" */;
        $fn = ($standard ? "standard-" : "complete-") . "$type-" . implode("-", array_slice(str_split($serial, 2), 3)) . ".txt";
        // var_dump($pturl, $fn);

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT_MS, 5000);
        curl_setopt($curl, CURLOPT_TIMEOUT_MS, 30000);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_URL, $pturl);
        $cfg = curl_exec($curl);
        $this->log("reading config file from $type ($serial)", "runtime");
        return ($cfg !== false && (curl_getinfo($curl, CURLINFO_RESPONSE_CODE) == 200)) ? $cfg : false;
    }

    /**
     * get the passthrough URL to the device (so you can do a GET request to it)
     * @param string $mac mac address
     * @return string|false 
     */
    public function getDeviceAccessURL($mac) {
        $mac = $this->fixmac($mac);
        if (!isset($this->macs[$mac]) || !isset($this->macs[$mac]->hwId)) {
            $this->log("getDeviceAccessURL($mac): not found (" . count($this->macs) . " entries in this->macs)");
            return false;
        }
        $dev = $this->macs[$mac];
        $rurl = $this->getKey();
        $dev->deviceAccessURL = "http" . substr($this->getWs()->getUrl(), 2) . "/passthrough/$dev->hwId/$rurl";
        $this->log("getDeviceAccessURL($mac): " . $dev->deviceAccessURL);
        return $dev->deviceAccessURL;
    }

    /**
     * get device info
     * @param string $mac
     * @return boolean|\stdClass device info as returned from Devices, either for a dedicated device or all
     */
    public function getDeviceInfo($mac = null) {
        if ($mac !== null) {
            $mac = $this->fixmac($mac);
            if (isset($this->macs[$mac]) && isset($this->macs[$mac]->hwId)) {
                $this->getDeviceAccessURL($mac);
                return $this->macs[$mac];
            }
            return false;
        }
        foreach (array_keys($this->macs) as $mac) {
            $this->getDeviceAccessURL($mac);
        }
        return $this->macs;
    }

    private function nextState() {
        if ($this->gotDomains && ($this->gotDevices <= 0) && $this->gotKey) {
            // compute device access URL
            $this->apppfUri = parse_url($this->getWs()->getUrl(), PHP_URL_HOST);
            return "Dead";
        }
        return null;
    }

    /**
     * this key authenticates a plain HTTP request, valid until the WebSocket dies
     * @return string
     */
    public function getKey() {
        return $this->GetUserInfoResult !== null ? $this->GetUserInfoResult->key : null;
    }

    public function ReceiveInitialStart(Message $msg) {
        $this->sendMessage(new Message("GetDomains", "recvUpdates", false));
        $this->sendMessage(new Message("GetUserInfo"));
    }

    public function ReceiveInitialGetDevicesResult(Message $msg) {
        if (isset($msg->devices))
            foreach ($msg->devices as $d) {
                $fmac = $this->fixmac($d->hwId);
                if ($this->getAllDevices || isset($this->macs[$fmac])) {
                    $this->macs[$fmac] = $d;
                    $this->gotDevices--;
                    if (!$this->getAllDevices && $this->gotDevices <= 0) {
                        break;
                    }
                }
            }
        if (isset($msg->last) && $msg->last) {
            $this->gotDevices = 0;
        }
        return $this->nextState();
    }

    public function ReceiveInitialGetDomainsResult($msg) {
        foreach ($msg->domains as $domain) {
            $this->domains[$domain->id] = $domain;
            if (isset($domain->name) && in_array($domain->name, $this->searchDomains)) {
                $this->searchDomainSpec[] = $domain->id;
                $this->log("domain($domain->id, $domain->name)");
            }
        }
        if (isset($msg->last) && $msg->last) {
            $this->gotDomains = true;
            // kick off search devices
            $this->sendMessage(new Message("GetDevices", "recvUpdates", false, "domainIds", implode(',', $this->searchDomainSpec), "unassigned", false));
        }
        return $this->nextState();
    }

    public function ReceiveInitialGetUserInfoResult(Message $msg) {
        $this->GetUserInfoResult = $msg;
        $this->gotKey = true;
        return $this->nextState();
    }

    /**
     * setup the class
     * @param WSClient $ws authenticated websocket towards the Devices instance
     * @param string[] $macs list of device macs we are interested (or null, so we get all known)
     * @param string $nickname
     * @param string[] $searchDomains optional list of domains to search macs in
     */
    public function __construct(WSClient $ws, $macs = null, $nickname = null, $searchDomains = array()) {

        if (is_null($nickname))
            $nickname = "DevAccess";
        parent::__construct($ws, $nickname);

        if (!is_array($searchDomains))
            $searchDomains = array($searchDomains);
        foreach ($searchDomains as $sd)
            $this->searchDomains[] = strtolower($sd);

        if ($macs !== null) {
            if (!is_array($macs))
                $macs = array($macs);
            foreach ($macs as $mac) {
                $this->macs[$this->fixmac($mac)] = new \stdClass();
            }
            $this->gotDevices = count($macs);
        } else {
            $this->getAllDevices = true;
            $this->gotDevices = 999999;
        }
    }

    private function fixmac($mac) {
        return strtolower(str_replace("-", "", $mac));
    }

}

/**
 * a class that pulls an XML dump from an appservice (through the manager)
 */
class ManagerDumpAppService extends FinitStateAutomaton {

    protected $httpkey = null;
    protected $managerUri = null;

    /**
     * get the HTTP URL pseudo auth key to access devices
     * @return string 
     */
    public function getHttpkey() {
        return $this->httpkey;
    }

    /**
     * get the manager's URI
     * @return string URI
     */
    public function getManagerUri() {
        return $this->managerUri;
    }

    /**
     * event function for the InitialLoginSuccess message
     * this event is generated by the AppLoginAutomaton that does the login for us
     * when this is received, we start our activity
     * @param Message $msg
     */
    public function ReceiveInitialStart(Message $msg) {
        $this->httpkey = null;
        $this->sendMessage(new Message("RequestHttpKey"));
    }

    /**
     * event function for the RequestHttpKeyResult message (received from the Devices app service)
     * @param Message $msg
     * @return string the new state.  We always tranistion to "Dead" when we received this message. On success, we post the 
     * HttpKeySuccess message (which can be received with a ReceiveInitialHttpKeySuccess function in other automatons
     */
    public function ReceiveInitialRequestHttpKeyResult(Message $msg) {
        if (isset($msg->key)) {
            $this->httpkey = $msg->key;
            $this->log("HTTP Key received: {$msg->key}");
            $this->managerUri = $this->getWs()->getUrl();
        } else {
            $this->log("no HTTP key returned");
        }
        return "Dead";
    }

    /**
     * get AppPlattform state text dump for instance $instance of App  $app
     * @param string $instance the instance short name (??)
     * @param string[] $exclude list of tabls to exclude
     * @return string
     */
    public function getHTTPKeyUrlText($domain = null, $instance = null) {
        if ($this->httpkey == null)
            return null;
        $uri = dirname($this->managerUri) . "/backup?key={$this->httpkey}&uncompressed=1";
        if ($instance != null) {
            $uri .= "&appName=" . rawurlencode($instance) . "&appDomain=" . rawurlencode($domain);
        } else {
            $uri .= "&manager=true&ignoreStatistics=true";
        }
        switch (parse_url($uri, PHP_URL_SCHEME)) {
            case "ws" : $uri = str_replace("ws://", "http://", $uri);
                break;
            case "wss" : $uri = str_replace("wss://", "https://", $uri);
        }
        if ($this->getUseWS())
            $uri = str_replace("https://", "http://", $uri);
        return $uri;
    }

    public function getHTTPKeyUrlRestore($instance = null) {
        if ($this->httpkey == null)
            return null;
        $uri = dirname($this->managerUri) . "/restore?src=restore-instance-" . rawurlencode($instance) . "&key={$this->httpkey}";

        switch (parse_url($uri, PHP_URL_SCHEME)) {
            case "ws" : $uri = str_replace("ws://", "http://", $uri);
                break;
            case "wss" : $uri = str_replace("wss://", "https://", $uri);
        }
        if ($this->getUseWS())
            $uri = str_replace("https://", "http://", $uri);
        return $uri;
    }

    /**
     * get AppPlattform state XML dump for App $app
     * @param string $app the instance short name (??)
     * @param string[] $exclude list of tables to exclude
     * @return string
     */
    public function getHTTPKeyUrl($app = null, $exclude = array()) {
        if ($this->httpkey == null)
            return null;
        $uri = dirname($this->managerUri) . "/dbdump?key={$this->httpkey}";
        if ($app != null) {
            $uri .= "&app=" . rawurlencode($app);
        }
        if (count($exclude)) {
            $uri .= "&exclude=" . implode(",", $exclude);
        }
        switch (parse_url($uri, PHP_URL_SCHEME)) {
            case "ws" : $uri = str_replace("ws://", "http://", $uri);
                break;
            case "wss" : $uri = str_replace("wss://", "https://", $uri);
        }
        if ($this->getUseWS())
            $uri = str_replace("https://", "http://", $uri);
        // var_dump("DUMP URI=$uri");
        return $uri;
    }

    /**
     * get the XML dump for all instances of an app.  Each instance is a separate db and we can not limit to a single instance
     * however, we can exclude certain tables (given in $exclude) in each of the instance databases
     * @param string $app name of app instance
     * @param string[] $exclude array of tables to exclude
     * @return string XML dump of databases
     */
    public function GetAppDump($app, $exclude = array()) {
        if (($dumpurl = $this->getHTTPKeyUrl($app, $exclude)) != null) {
            $curl = curl_init();
            curl_setopt($curl, CURLOPT_CONNECTTIMEOUT_MS, 5000);
            curl_setopt($curl, CURLOPT_TIMEOUT_MS, 30000);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_URL, $dumpurl);
            $dbdump = curl_exec($curl);
            // print "<pre>"; var_dump($app, $exclude, htmlspecialchars($dbdump)); print "</pre>";

            return $dbdump;
        }
    }

    /**
     * get the text dump of an instance of an app (or the manager).
     * @param string $domain name of app instance, manager will be dumped if $app is empty
     * @param string $instance name (that is, AppDomain) of the instance, ignored if $app is empty
     * @param ressource $outfile output file (must be open already, such as from fopen())
     * @return bool true if succeeded
     */
    public function GetAppInstanceTextDump($domain, $instance, $outfile) {
        if ($outfile === null)
            die("outputfile is null on GetAppInstanceTextDump");
        if (($dumpurl = $this->getHTTPKeyUrlText($domain, $instance)) != null) {
            $curl = curl_init();
            curl_setopt($curl, CURLOPT_CONNECTTIMEOUT_MS, 5000);
            curl_setopt($curl, CURLOPT_TIMEOUT_MS, 5 /* minutes */ * 60 * 1000);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, false);
            curl_setopt($curl, CURLOPT_FILE, $outfile);
            curl_setopt($curl, CURLOPT_URL, $dumpurl);
            $cresult = curl_exec($curl);

            $rcode = $cresult && (curl_getinfo($curl, CURLINFO_RESPONSE_CODE) == 200);
            if (!$rcode) {
                print "<pre>GetAppInstanceTextDump: domain, instance, url, curl-result, HTTP response code:<br>";
                var_dump($domain, $instance, $dumpurl, $cresult, curl_getinfo($curl, CURLINFO_RESPONSE_CODE));
                print "</pre>";
                die("abort");
            }
            return $rcode;
        } else {
            die("dumpurl for $domain/$instance is null");
        }
    }

    /**
     * restore an instance dump to an AP
     * @param string  $instance instance id
     * @param string $file filename of dump or dump itself, depending on $fileiscontent
     * @param bool $fileiscontent
     * @return bool true if OK
     */
    public function RestoreAppInstance($instance, $file, $fileiscontent = false) {
        if (($dumpurl = $this->getHTTPKeyUrlRestore($instance)) != null) {
            $curl = curl_init($dumpurl);

            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false); // stop verifying certificate
            if ($fileiscontent) {
                curl_setopt($curl, CURLOPT_POST, 1);
                curl_setopt($curl, CURLOPT_POSTFIELDS, $file);
            } else {
                // we need to set PUT mode so that the raw file is sent, but then ...
                curl_setopt($curl, CURLOPT_PUT, 1);
                // use custom request method POST cause that is what the AP expects
                curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST"); // enable posting 
                curl_setopt($curl, CURLOPT_INFILESIZE, $fs = filesize($file));
                curl_setopt($curl, CURLOPT_INFILE, ($in = fopen($file, 'r')));
            }
            curl_setopt($curl, CURLOPT_HTTPHEADER, [ 'Content-Type: application/text']);

            $cresult = curl_exec($curl);
            $rcode = $cresult && (curl_getinfo($curl, CURLINFO_RESPONSE_CODE) == 200);
            if (!$fileiscontent)
                fclose($in);
            if (!$rcode) {
                print "<pre>RestoreAppInstance: instance, file, size, url, curl-result, HTTP response code:<br>";
                var_dump($instance, $file, $fs, $dumpurl, $cresult, curl_getinfo($curl, CURLINFO_RESPONSE_CODE));
                print "</pre>";
                if (!$rcode) {
                    die("abort");
                }
            }
            curl_close($curl);
            return $rcode;
        } else {
            die("dumpurl for $domain/$instance is null");
        }
    }

}
