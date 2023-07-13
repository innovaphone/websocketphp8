<?php

/*
 * Paul Tero, July 2001
 * http://www.tero.co.uk/des/
 * 
 * Optimised for performance with large blocks by Michael Hayworth, November 2001
 * http://www.netdealing.com
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Code translated to PHP by innovaphone
 */

namespace NTLM;

/**
 * A collection of open source crypto functions
 */


function get7Bits($input, $startBit) {
    $word = 0;
    $word = ord(@$input[$startBit / 8]) << 8;
    if ((($startBit / 8) + 1) < strlen($input))
        $word |= ord($input[($startBit / 8) + 1]);
    $word >>= 15 - (($startBit % 8) + 7);
    $ret = chr($word & 0xfe);
    return $ret;
}

function makeKey($input) {
    $ret = get7Bits($input, 0) .
            get7Bits($input, 7) .
            get7Bits($input, 14) .
            get7Bits($input, 21) .
            get7Bits($input, 28) .
            get7Bits($input, 35) .
            get7Bits($input, 42) .
            get7Bits($input, 49);
    return $ret;
}

function ntlmResponse($password, $challenge) {
    $challenge = hex2bin($x = $challenge);
    $ntKey = (mhash(MHASH_MD4, iconv('UTF-8', 'UTF-16LE', $password)));  // OK
    $key1 = makeKey(substr($ntKey, 0, 7));
    $key2 = makeKey(substr($ntKey, 7, 7));
    $key3 = makeKey(substr($ntKey, 14, 2) . "\0\0\0\0\0");

    return bin2hex(des($key1, $challenge, true) . des($key2, $challenge, true) . des($key3, $challenge, true));
}

if (!function_exists('hex2bin')) {

    function hex2bin($str) {
        $map = array(
            '00' => "\x00", '10' => "\x10", '20' => "\x20", '30' => "\x30", '40' => "\x40", '50' => "\x50", '60' => "\x60", '70' => "\x70",
            '01' => "\x01", '11' => "\x11", '21' => "\x21", '31' => "\x31", '41' => "\x41", '51' => "\x51", '61' => "\x61", '71' => "\x71",
            '02' => "\x02", '12' => "\x12", '22' => "\x22", '32' => "\x32", '42' => "\x42", '52' => "\x52", '62' => "\x62", '72' => "\x72",
            '03' => "\x03", '13' => "\x13", '23' => "\x23", '33' => "\x33", '43' => "\x43", '53' => "\x53", '63' => "\x63", '73' => "\x73",
            '04' => "\x04", '14' => "\x14", '24' => "\x24", '34' => "\x34", '44' => "\x44", '54' => "\x54", '64' => "\x64", '74' => "\x74",
            '05' => "\x05", '15' => "\x15", '25' => "\x25", '35' => "\x35", '45' => "\x45", '55' => "\x55", '65' => "\x65", '75' => "\x75",
            '06' => "\x06", '16' => "\x16", '26' => "\x26", '36' => "\x36", '46' => "\x46", '56' => "\x56", '66' => "\x66", '76' => "\x76",
            '07' => "\x07", '17' => "\x17", '27' => "\x27", '37' => "\x37", '47' => "\x47", '57' => "\x57", '67' => "\x67", '77' => "\x77",
            '08' => "\x08", '18' => "\x18", '28' => "\x28", '38' => "\x38", '48' => "\x48", '58' => "\x58", '68' => "\x68", '78' => "\x78",
            '09' => "\x09", '19' => "\x19", '29' => "\x29", '39' => "\x39", '49' => "\x49", '59' => "\x59", '69' => "\x69", '79' => "\x79",
            '0a' => "\x0a", '1a' => "\x1a", '2a' => "\x2a", '3a' => "\x3a", '4a' => "\x4a", '5a' => "\x5a", '6a' => "\x6a", '7a' => "\x7a",
            '0b' => "\x0b", '1b' => "\x1b", '2b' => "\x2b", '3b' => "\x3b", '4b' => "\x4b", '5b' => "\x5b", '6b' => "\x6b", '7b' => "\x7b",
            '0c' => "\x0c", '1c' => "\x1c", '2c' => "\x2c", '3c' => "\x3c", '4c' => "\x4c", '5c' => "\x5c", '6c' => "\x6c", '7c' => "\x7c",
            '0d' => "\x0d", '1d' => "\x1d", '2d' => "\x2d", '3d' => "\x3d", '4d' => "\x4d", '5d' => "\x5d", '6d' => "\x6d", '7d' => "\x7d",
            '0e' => "\x0e", '1e' => "\x1e", '2e' => "\x2e", '3e' => "\x3e", '4e' => "\x4e", '5e' => "\x5e", '6e' => "\x6e", '7e' => "\x7e",
            '0f' => "\x0f", '1f' => "\x1f", '2f' => "\x2f", '3f' => "\x3f", '4f' => "\x4f", '5f' => "\x5f", '6f' => "\x6f", '7f' => "\x7f",
            '80' => "\x80", '90' => "\x90", 'a0' => "\xa0", 'b0' => "\xb0", 'c0' => "\xc0", 'd0' => "\xd0", 'e0' => "\xe0", 'f0' => "\xf0",
            '81' => "\x81", '91' => "\x91", 'a1' => "\xa1", 'b1' => "\xb1", 'c1' => "\xc1", 'd1' => "\xd1", 'e1' => "\xe1", 'f1' => "\xf1",
            '82' => "\x82", '92' => "\x92", 'a2' => "\xa2", 'b2' => "\xb2", 'c2' => "\xc2", 'd2' => "\xd2", 'e2' => "\xe2", 'f2' => "\xf2",
            '83' => "\x83", '93' => "\x93", 'a3' => "\xa3", 'b3' => "\xb3", 'c3' => "\xc3", 'd3' => "\xd3", 'e3' => "\xe3", 'f3' => "\xf3",
            '84' => "\x84", '94' => "\x94", 'a4' => "\xa4", 'b4' => "\xb4", 'c4' => "\xc4", 'd4' => "\xd4", 'e4' => "\xe4", 'f4' => "\xf4",
            '85' => "\x85", '95' => "\x95", 'a5' => "\xa5", 'b5' => "\xb5", 'c5' => "\xc5", 'd5' => "\xd5", 'e5' => "\xe5", 'f5' => "\xf5",
            '86' => "\x86", '96' => "\x96", 'a6' => "\xa6", 'b6' => "\xb6", 'c6' => "\xc6", 'd6' => "\xd6", 'e6' => "\xe6", 'f6' => "\xf6",
            '87' => "\x87", '97' => "\x97", 'a7' => "\xa7", 'b7' => "\xb7", 'c7' => "\xc7", 'd7' => "\xd7", 'e7' => "\xe7", 'f7' => "\xf7",
            '88' => "\x88", '98' => "\x98", 'a8' => "\xa8", 'b8' => "\xb8", 'c8' => "\xc8", 'd8' => "\xd8", 'e8' => "\xe8", 'f8' => "\xf8",
            '89' => "\x89", '99' => "\x99", 'a9' => "\xa9", 'b9' => "\xb9", 'c9' => "\xc9", 'd9' => "\xd9", 'e9' => "\xe9", 'f9' => "\xf9",
            '8a' => "\x8a", '9a' => "\x9a", 'aa' => "\xaa", 'ba' => "\xba", 'ca' => "\xca", 'da' => "\xda", 'ea' => "\xea", 'fa' => "\xfa",
            '8b' => "\x8b", '9b' => "\x9b", 'ab' => "\xab", 'bb' => "\xbb", 'cb' => "\xcb", 'db' => "\xdb", 'eb' => "\xeb", 'fb' => "\xfb",
            '8c' => "\x8c", '9c' => "\x9c", 'ac' => "\xac", 'bc' => "\xbc", 'cc' => "\xcc", 'dc' => "\xdc", 'ec' => "\xec", 'fc' => "\xfc",
            '8d' => "\x8d", '9d' => "\x9d", 'ad' => "\xad", 'bd' => "\xbd", 'cd' => "\xcd", 'dd' => "\xdd", 'ed' => "\xed", 'fd' => "\xfd",
            '8e' => "\x8e", '9e' => "\x9e", 'ae' => "\xae", 'be' => "\xbe", 'ce' => "\xce", 'de' => "\xde", 'ee' => "\xee", 'fe' => "\xfe",
            '8f' => "\x8f", '9f' => "\x9f", 'af' => "\xaf", 'bf' => "\xbf", 'cf' => "\xcf", 'df' => "\xdf", 'ef' => "\xef", 'ff' => "\xff",
        );
        $strlen = strlen($str);
        if ($strlen % 2 !== 0) {
            user_error('Hexadecimal input string must have an even length', E_USER_WARNING);
            return false;
        }
        if (strspn($str, '0123456789ABCDEFabcdef') !== $strlen) {
            return false;
        }
        return strtr(strtolower($str), $map);
    }

} else {
    function hex2bin($str) { return \hex2bin($str); }
}

function usrs($a, $b) {
    if ($b >= 32 || $b < -32) {
        $m = (int) ($b / 32);
        $b = $b - ($m * 32);
    }

    if ($b < 0) {
        $b = 32 + $b;
    }

    if ($b == 0) {
        return (($a >> 1) & 0x7fffffff) * 2 + (($a >> $b) & 1);
    }

    if ($a < 0) {
        $a = ($a >> 1);
        $a &= 2147483647;
        $a |= 0x40000000;
        $a = ($a >> ($b - 1));
    } else {
        $a = ($a >> $b);
    }
    return $a;
}

function des($key, $message, $encrypt, $mode = 0, $iv = "", $padding = 0) {
    $spfunction1 = array(0x1010400, 0, 0x10000, 0x1010404, 0x1010004, 0x10404, 0x4, 0x10000, 0x400, 0x1010400, 0x1010404, 0x400, 0x1000404, 0x1010004, 0x1000000, 0x4, 0x404, 0x1000400, 0x1000400, 0x10400, 0x10400, 0x1010000, 0x1010000, 0x1000404, 0x10004, 0x1000004, 0x1000004, 0x10004, 0, 0x404, 0x10404, 0x1000000, 0x10000, 0x1010404, 0x4, 0x1010000, 0x1010400, 0x1000000, 0x1000000, 0x400, 0x1010004, 0x10000, 0x10400, 0x1000004, 0x400, 0x4, 0x1000404, 0x10404, 0x1010404, 0x10004, 0x1010000, 0x1000404, 0x1000004, 0x404, 0x10404, 0x1010400, 0x404, 0x1000400, 0x1000400, 0, 0x10004, 0x10400, 0, 0x1010004);
    $spfunction2 = array(-0x7fef7fe0, -0x7fff8000, 0x8000, 0x108020, 0x100000, 0x20, -0x7fefffe0, -0x7fff7fe0, -0x7fffffe0, -0x7fef7fe0, -0x7fef8000, -0x80000000, -0x7fff8000, 0x100000, 0x20, -0x7fefffe0, 0x108000, 0x100020, -0x7fff7fe0, 0, -0x80000000, 0x8000, 0x108020, -0x7ff00000, 0x100020, -0x7fffffe0, 0, 0x108000, 0x8020, -0x7fef8000, -0x7ff00000, 0x8020, 0, 0x108020, -0x7fefffe0, 0x100000, -0x7fff7fe0, -0x7ff00000, -0x7fef8000, 0x8000, -0x7ff00000, -0x7fff8000, 0x20, -0x7fef7fe0, 0x108020, 0x20, 0x8000, -0x80000000, 0x8020, -0x7fef8000, 0x100000, -0x7fffffe0, 0x100020, -0x7fff7fe0, -0x7fffffe0, 0x100020, 0x108000, 0, -0x7fff8000, 0x8020, -0x80000000, -0x7fefffe0, -0x7fef7fe0, 0x108000);
    $spfunction3 = array(0x208, 0x8020200, 0, 0x8020008, 0x8000200, 0, 0x20208, 0x8000200, 0x20008, 0x8000008, 0x8000008, 0x20000, 0x8020208, 0x20008, 0x8020000, 0x208, 0x8000000, 0x8, 0x8020200, 0x200, 0x20200, 0x8020000, 0x8020008, 0x20208, 0x8000208, 0x20200, 0x20000, 0x8000208, 0x8, 0x8020208, 0x200, 0x8000000, 0x8020200, 0x8000000, 0x20008, 0x208, 0x20000, 0x8020200, 0x8000200, 0, 0x200, 0x20008, 0x8020208, 0x8000200, 0x8000008, 0x200, 0, 0x8020008, 0x8000208, 0x20000, 0x8000000, 0x8020208, 0x8, 0x20208, 0x20200, 0x8000008, 0x8020000, 0x8000208, 0x208, 0x8020000, 0x20208, 0x8, 0x8020008, 0x20200);
    $spfunction4 = array(0x802001, 0x2081, 0x2081, 0x80, 0x802080, 0x800081, 0x800001, 0x2001, 0, 0x802000, 0x802000, 0x802081, 0x81, 0, 0x800080, 0x800001, 0x1, 0x2000, 0x800000, 0x802001, 0x80, 0x800000, 0x2001, 0x2080, 0x800081, 0x1, 0x2080, 0x800080, 0x2000, 0x802080, 0x802081, 0x81, 0x800080, 0x800001, 0x802000, 0x802081, 0x81, 0, 0, 0x802000, 0x2080, 0x800080, 0x800081, 0x1, 0x802001, 0x2081, 0x2081, 0x80, 0x802081, 0x81, 0x1, 0x2000, 0x800001, 0x2001, 0x802080, 0x800081, 0x2001, 0x2080, 0x800000, 0x802001, 0x80, 0x800000, 0x2000, 0x802080);
    $spfunction5 = array(0x100, 0x2080100, 0x2080000, 0x42000100, 0x80000, 0x100, 0x40000000, 0x2080000, 0x40080100, 0x80000, 0x2000100, 0x40080100, 0x42000100, 0x42080000, 0x80100, 0x40000000, 0x2000000, 0x40080000, 0x40080000, 0, 0x40000100, 0x42080100, 0x42080100, 0x2000100, 0x42080000, 0x40000100, 0, 0x42000000, 0x2080100, 0x2000000, 0x42000000, 0x80100, 0x80000, 0x42000100, 0x100, 0x2000000, 0x40000000, 0x2080000, 0x42000100, 0x40080100, 0x2000100, 0x40000000, 0x42080000, 0x2080100, 0x40080100, 0x100, 0x2000000, 0x42080000, 0x42080100, 0x80100, 0x42000000, 0x42080100, 0x2080000, 0, 0x40080000, 0x42000000, 0x80100, 0x2000100, 0x40000100, 0x80000, 0, 0x40080000, 0x2080100, 0x40000100);
    $spfunction6 = array(0x20000010, 0x20400000, 0x4000, 0x20404010, 0x20400000, 0x10, 0x20404010, 0x400000, 0x20004000, 0x404010, 0x400000, 0x20000010, 0x400010, 0x20004000, 0x20000000, 0x4010, 0, 0x400010, 0x20004010, 0x4000, 0x404000, 0x20004010, 0x10, 0x20400010, 0x20400010, 0, 0x404010, 0x20404000, 0x4010, 0x404000, 0x20404000, 0x20000000, 0x20004000, 0x10, 0x20400010, 0x404000, 0x20404010, 0x400000, 0x4010, 0x20000010, 0x400000, 0x20004000, 0x20000000, 0x4010, 0x20000010, 0x20404010, 0x404000, 0x20400000, 0x404010, 0x20404000, 0, 0x20400010, 0x10, 0x4000, 0x20400000, 0x404010, 0x4000, 0x400010, 0x20004010, 0, 0x20404000, 0x20000000, 0x400010, 0x20004010);
    $spfunction7 = array(0x200000, 0x4200002, 0x4000802, 0, 0x800, 0x4000802, 0x200802, 0x4200800, 0x4200802, 0x200000, 0, 0x4000002, 0x2, 0x4000000, 0x4200002, 0x802, 0x4000800, 0x200802, 0x200002, 0x4000800, 0x4000002, 0x4200000, 0x4200800, 0x200002, 0x4200000, 0x800, 0x802, 0x4200802, 0x200800, 0x2, 0x4000000, 0x200800, 0x4000000, 0x200800, 0x200000, 0x4000802, 0x4000802, 0x4200002, 0x4200002, 0x2, 0x200002, 0x4000000, 0x4000800, 0x200000, 0x4200800, 0x802, 0x200802, 0x4200800, 0x802, 0x4000002, 0x4200802, 0x4200000, 0x200800, 0, 0x2, 0x4200802, 0, 0x200802, 0x4200000, 0x800, 0x4000002, 0x4000800, 0x800, 0x200002);
    $spfunction8 = array(0x10001040, 0x1000, 0x40000, 0x10041040, 0x10000000, 0x10001040, 0x40, 0x10000000, 0x40040, 0x10040000, 0x10041040, 0x41000, 0x10041000, 0x41040, 0x1000, 0x40, 0x10040000, 0x10000040, 0x10001000, 0x1040, 0x41000, 0x40040, 0x10040040, 0x10041000, 0x1040, 0, 0, 0x10040040, 0x10000040, 0x10001000, 0x41040, 0x40000, 0x41040, 0x40000, 0x10041000, 0x1000, 0x40, 0x10040040, 0x1000, 0x41040, 0x10001000, 0x40, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x40000, 0x10001040, 0, 0x10041040, 0x40040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0, 0x10041040, 0x41000, 0x41000, 0x1040, 0x1040, 0x40040, 0x10000000, 0x10041000);

    $keys = desCreateKeys($key);
    $m = 0;
    $len = strlen($message);
    $chunk = 0;
    $iterations = count($keys) == 32 ? 3 : 9;
    if ($iterations == 3) {
        $looping = $encrypt ? array(0, 32, 2) : array(30, -2, -2);
    } else {
        $looping = $encrypt ? array(0, 32, 2, 62, 30, -2, 64, 96, 2) : array(94, 62, -2, 32, 64, 2, 30, -2, -2);
    }
    if ($padding == 2)
        $message .= "        ";
    else if ($padding == 1) {
        $temp = 8 - ($len % 8);
        $message .= chr($temp) . chr($temp) . chr($temp) . chr($temp) . chr($temp) . chr($temp) . chr($temp) . chr($temp);
        if ($temp == 8)
            $len += 8;
    }
    else if (!$padding)
        $message .= "\0\0\0\0\0\0\0\0";
    $result = "";
    $tempresult = "";
    if ($mode == 1) {
        $cbcleft = (($iv . charCodeAt($m++)) << 24) | (($iv . charCodeAt($m++)) << 16) | (($iv . charCodeAt($m++)) << 8) | ($iv . charCodeAt($m++));
        $cbcright = (($iv . charCodeAt($m++)) << 24) | (($iv . charCodeAt($m++)) << 16) | (($iv . charCodeAt($m++)) << 8) | ($iv . charCodeAt($m++));
        $m = 0;
    }
    while ($m < $len) {
        $left = (ord($message[$m++]) << 24) | (ord($message[$m++]) << 16) | (ord($message[$m++]) << 8) | ord($message[$m++]);
        $right = (ord($message[$m++]) << 24) | (ord($message[$m++]) << 16) | (ord($message[$m++]) << 8) | ord($message[$m++]);
        if ($mode == 1) {
            if ($encrypt) {
                $left ^= $cbcleft;
                $right ^= $cbcright;
            } else {
                $cbcleft2 = $cbcleft;
                $cbcright2 = $cbcright;
                $cbcleft = $left;
                $cbcright = $right;
            }
        }
        $temp = (usrs($left, 4) ^ $right) & 0x0f0f0f0f;
        $right ^= $temp;
        $left ^= ($temp << 4);
        $temp = (usrs($left, 16) ^ $right) & 0x0000ffff;
        $right ^= $temp;
        $left ^= ($temp << 16);
        $temp = (usrs($right, 2) ^ $left) & 0x33333333;
        $left ^= $temp;
        $right ^= ($temp << 2);
        $temp = (usrs($right, 8) ^ $left) & 0x00ff00ff;
        $left ^= $temp;
        $right ^= ($temp << 8);
        $temp = (usrs($left, 1) ^ $right) & 0x55555555;
        $right ^= $temp;
        $left ^= ($temp << 1);
        $left = (($left << 1) | usrs($left, 31));
        $right = (($right << 1) | usrs($right, 31));
        for ($j = 0; $j < $iterations; $j += 3) {
            $endloop = $looping[$j + 1];
            $loopinc = $looping[$j + 2];
            for ($i = $looping[$j]; $i != $endloop; $i += $loopinc) {
                $right1 = $right ^ $keys[$i];
                $right2 = (usrs($right, 4) | ($right << 28)) ^ $keys[$i + 1];
                $temp = $left;
                $left = $right;
                $right = $temp ^ ($spfunction2[usrs($right1, 24) & 0x3f] | $spfunction4[usrs($right1, 16) & 0x3f] | $spfunction6[usrs($right1, 8) & 0x3f] | $spfunction8[$right1 & 0x3f] | $spfunction1[usrs($right2, 24) & 0x3f] | $spfunction3[usrs($right2, 16) & 0x3f] | $spfunction5[usrs($right2, 8) & 0x3f] | $spfunction7[$right2 & 0x3f]);
            }
            $temp = $left;
            $left = $right;
            $right = $temp;
        }
        $left = (usrs($left, 1) | ($left << 31));
        $right = (usrs($right, 1) | ($right << 31));
        $temp = (usrs($left, 1) ^ $right) & 0x55555555;
        $right ^= $temp;
        $left ^= ($temp << 1);
        $temp = (usrs($right, 8) ^ $left) & 0x00ff00ff;
        $left ^= $temp;
        $right ^= ($temp << 8);
        $temp = (usrs($right, 2) ^ $left) & 0x33333333;
        $left ^= $temp;
        $right ^= ($temp << 2);
        $temp = (usrs($left, 16) ^ $right) & 0x0000ffff;
        $right ^= $temp;
        $left ^= ($temp << 16);
        $temp = (usrs($left, 4) ^ $right) & 0x0f0f0f0f;
        $right ^= $temp;
        $left ^= ($temp << 4);
        if ($mode == 1) {
            if ($encrypt) {
                $cbcleft = $left;
                $cbcright = $right;
            } else {
                $left ^= $cbcleft2;
                $right ^= $cbcright2;
            }
        }
        $tempresult .= chr(usrs($left, 24)) .
                chr(usrs($left, 16) & 0xff) .
                chr(usrs($left, 8) & 0xff) .
                chr($left & 0xff) .
                chr(usrs($right, 24)) .
                chr(usrs($right, 16) & 0xff) .
                chr(usrs($right, 8) & 0xff) .
                chr($right & 0xff);
        $chunk += 8;
        if ($chunk == 512) {
            $result .= $tempresult;
            $tempresult = "";
            $chunk = 0;
        }
    }
    $result .= $tempresult;
    // $result = $result.replace(/\0*$/g, "");
    preg_replace('/\0*$/', "$result", $result);
    return $result;
}

function desCreateKeys($key) {
    $pc2bytes0 = array(0, 0x4, 0x20000000, 0x20000004, 0x10000, 0x10004, 0x20010000, 0x20010004, 0x200, 0x204, 0x20000200, 0x20000204, 0x10200, 0x10204, 0x20010200, 0x20010204);
    $pc2bytes1 = array(0, 0x1, 0x100000, 0x100001, 0x4000000, 0x4000001, 0x4100000, 0x4100001, 0x100, 0x101, 0x100100, 0x100101, 0x4000100, 0x4000101, 0x4100100, 0x4100101);
    $pc2bytes2 = array(0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808, 0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808);
    $pc2bytes3 = array(0, 0x200000, 0x8000000, 0x8200000, 0x2000, 0x202000, 0x8002000, 0x8202000, 0x20000, 0x220000, 0x8020000, 0x8220000, 0x22000, 0x222000, 0x8022000, 0x8222000);
    $pc2bytes4 = array(0, 0x40000, 0x10, 0x40010, 0, 0x40000, 0x10, 0x40010, 0x1000, 0x41000, 0x1010, 0x41010, 0x1000, 0x41000, 0x1010, 0x41010);
    $pc2bytes5 = array(0, 0x400, 0x20, 0x420, 0, 0x400, 0x20, 0x420, 0x2000000, 0x2000400, 0x2000020, 0x2000420, 0x2000000, 0x2000400, 0x2000020, 0x2000420);
    $pc2bytes6 = array(0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002, 0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002);
    $pc2bytes7 = array(0, 0x10000, 0x800, 0x10800, 0x20000000, 0x20010000, 0x20000800, 0x20010800, 0x20000, 0x30000, 0x20800, 0x30800, 0x20020000, 0x20030000, 0x20020800, 0x20030800);
    $pc2bytes8 = array(0, 0x40000, 0, 0x40000, 0x2, 0x40002, 0x2, 0x40002, 0x2000000, 0x2040000, 0x2000000, 0x2040000, 0x2000002, 0x2040002, 0x2000002, 0x2040002);
    $pc2bytes9 = array(0, 0x10000000, 0x8, 0x10000008, 0, 0x10000000, 0x8, 0x10000008, 0x400, 0x10000400, 0x408, 0x10000408, 0x400, 0x10000400, 0x408, 0x10000408);
    $pc2bytes10 = array(0, 0x20, 0, 0x20, 0x100000, 0x100020, 0x100000, 0x100020, 0x2000, 0x2020, 0x2000, 0x2020, 0x102000, 0x102020, 0x102000, 0x102020);
    $pc2bytes11 = array(0, 0x1000000, 0x200, 0x1000200, 0x200000, 0x1200000, 0x200200, 0x1200200, 0x4000000, 0x5000000, 0x4000200, 0x5000200, 0x4200000, 0x5200000, 0x4200200, 0x5200200);
    $pc2bytes12 = array(0, 0x1000, 0x8000000, 0x8001000, 0x80000, 0x81000, 0x8080000, 0x8081000, 0x10, 0x1010, 0x8000010, 0x8001010, 0x80010, 0x81010, 0x8080010, 0x8081010);
    $pc2bytes13 = array(0, 0x4, 0x100, 0x104, 0, 0x4, 0x100, 0x104, 0x1, 0x5, 0x101, 0x105, 0x1, 0x5, 0x101, 0x105);
    $iterations = strlen($key) > 8 ? 3 : 1;
    $keys = array(32 * $iterations);
    $shifts = array(0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0);
    $m = 0;
    $n = 0;
    $temp;
    for ($j = 0; $j < $iterations; $j++) {
        $left = (ord($key[$m++]) << 24) | (ord($key[$m++]) << 16) | (ord($key[$m++]) << 8) | ord($key[$m++]);
        $right = (ord($key[$m++]) << 24) | (ord($key[$m++]) << 16) | (ord($key[$m++]) << 8) | ord($key[$m++]);
        $temp = (usrs($left, 4) ^ $right) & 0x0f0f0f0f;
        $right ^= $temp;
        $left ^= ($temp << 4);
        $temp = (usrs($right, -16) ^ $left) & 0x0000ffff;
        $left ^= $temp;
        $right ^= ($temp << -16);
        $temp = (usrs($left, 2) ^ $right) & 0x33333333;
        $right ^= $temp;
        $left ^= ($temp << 2);
        $temp = (usrs($right, -16) ^ $left) & 0x0000ffff;
        $left ^= $temp;
        $right ^= ($temp << -16);
        $temp = (usrs($left, 1) ^ $right) & 0x55555555;
        $right ^= $temp;
        $left ^= ($temp << 1);
        $temp = (usrs($right, 8) ^ $left) & 0x00ff00ff;
        $left ^= $temp;
        $right ^= ($temp << 8);
        $temp = (usrs($left, 1) ^ $right) & 0x55555555;
        $right ^= $temp;
        $left ^= ($temp << 1);
        $temp = ($left << 8) | (usrs($right, 20) & 0x000000f0);
        $left = ($right << 24) | (($right << 8) & 0xff0000) | (usrs($right, 8) & 0xff00) | (usrs($right, 24) & 0xf0);
        $right = $temp;
        for ($i = 0; $i < count($shifts); $i++) {
            if ($shifts[$i]) {
                $left = ($left << 2) | usrs($left, 26);
                $right = ($right << 2) | usrs($right, 26);
            } else {
                $left = ($left << 1) | usrs($left, 27);
                $right = ($right << 1) | usrs($right, 27);
            }
            $left &= -0xf;
            $right &= -0xf;
            $lefttemp = $pc2bytes0[usrs($left, 28)] | $pc2bytes1[usrs($left, 24) & 0xf] | $pc2bytes2[usrs($left, 20) & 0xf] | $pc2bytes3[usrs($left, 16) & 0xf] | $pc2bytes4[usrs($left, 12) & 0xf] | $pc2bytes5[usrs($left, 8) & 0xf] | $pc2bytes6[usrs($left, 4) & 0xf];
            $righttemp = $pc2bytes7[usrs($right, 28)] | $pc2bytes8[usrs($right, 24) & 0xf] | $pc2bytes9[usrs($right, 20) & 0xf] | $pc2bytes10[usrs($right, 16) & 0xf] | $pc2bytes11[usrs($right, 12) & 0xf] | $pc2bytes12[usrs($right, 8) & 0xf] | $pc2bytes13[usrs($right, 4) & 0xf];
            $temp = (usrs($righttemp, 16) ^ $lefttemp) & 0x0000ffff;
            $keys[$n++] = $lefttemp ^ $temp;
            $keys[$n++] = $righttemp ^ ($temp << 16);
        }
    }
    return $keys;
}

?>
