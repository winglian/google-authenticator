<?php
namespace Auth\Multifactor;

/**
 * Generate and validate codes compatable with Google Authenticator
 * 
 * See https://tools.ietf.org/html/rfc6238
 *
 */
class GoogleAuthenticator {

    /**
     *
     */
    private $secret;

    private $timeStep = 30;

    private $window = 4;

    private $tokenLength = 6;

    private $lookupTable;

    public function __construct()
    {
        $this->buildLookupTable();
    }

    public function buildLookupTable()
    {
        $lookup = array_combine(
            array_merge(range('A', 'Z'), range(2, 7)),
            range(0, 31)
        );
        $this->setLookupTable($lookup);
    }

    public function getLookupTable()
    {
        return $this->lookupTable;
    }

    public function setLookupTable($lookup)
    {
        $this->lookupTable = $lookup;
    }

    public function convertTimestampToCounter($ts = null)
    {
        if ($ts == null) {
            $ts = microtime(true);
        }

        return floor($ts/$this->timeStep);
    }

    public function convertTimestampToBinaryCounter($ts = null)
    {
        $counter = $this->convertTimestampToCounter($ts);
        return pack('NN', 0, $counter);
    }

    public function generateNewSecret($length = 16)
    {
        $lookupTable = $this->getLookupTable();
        $pool = preg_split('//', implode('', array_keys($lookupTable)), -1, PREG_SPLIT_NO_EMPTY);
        shuffle($pool);
        $secret = '';
        foreach(array_slice($pool, 0, $length) as $word) {
            $secret .= $word;
        }

        return $secret;
    }

    protected function getSecret()
    {
        return $this->secret;
    }

    protected function getBinarySecret()
    {
        $secret = $this->getSecret();
        return $this->base32Decode($secret);
    }

    public function setSecret($secret)
    {
        if (strlen($secret) < 8) {
            throw new \InvalidArgumentException('Secret key is too short');
        }
        $this->secret = $secret;
    }

    public function base32Decode($hash)
    {
        $lookupTable = $this->getLookupTable();
        $str = strtoupper($hash);
        $buffer = 0;
        $length = 0;
        $binary = '';

        for ($i = 0; $i < strlen($hash); $i++) {
            $buffer = $buffer << 5;
            $buffer += $lookupTable[$hash[$i]];
            $length += 5;
            if ($length >= 8) {
                $length -= 8;
                $binary .= chr(($buffer & (0xFF << $length)) >> $length);
            }
        }

        return $binary;
    }

    public function getTimeStep()
    {
        return $this->timeStep;
    }

    public function setTimeStep($timeStep = 30)
    {
        if (!is_numeric($timeStep)) {
            throw new \InvalidArgumentException('Time Step must be numeric');
        }
        $this->timeStep = $timeStep;
    }

    public function getWindow()
    {
        return $this->window;
    }

    public function setWindow($window = 4)
    {
        if (!is_numeric($window)) {
            throw new \InvalidArgumentException('Window size must be numeric');
        }
        $this->window = $window;
        return $this;
    }

    public function getTokenLength()
    {
        return $this->tokenLength;
    }

    public function setTokenLength($tokenLength = 6) {
        if (!is_numeric($tokenLength)) {
            throw new \InvalidArgumentException('Token Length must be numeric');
        }
        $this->tokenLength = $tokenLength;
        return $this;
    }

    public function generateTOTP($timestamp = null)
    {
        $binary_counter = $this->convertTimestampToBinaryCounter($timestamp);
        $hash = hash_hmac('sha1', $binary_counter, $this->getBinarySecret(), true);
        return $this->truncateHash($hash);
    }

    public function verifyTOTP($totp, $timestamp = null)
    {
        $window = $this->getWindow();
        for ($ts = $timestamp - ($window * $this->getTimeStep()), $end_ts = $timestamp + ($window * $this->getTimeStep()); $ts <= $end_ts; $ts += $this->getTimeStep()) {
            if ($this->generateTOTP($ts) == $totp) {
                return true;
            }
        }
        return false;
    }

    public function truncateHash($hash)
    {
        $offset = ord($hash[19]) & 0xf;

        return (
            ((ord($hash[$offset+0]) & 0x7f) << 24 ) |
            ((ord($hash[$offset+1]) & 0xff) << 16 ) |
            ((ord($hash[$offset+2]) & 0xff) << 8 ) |
            (ord($hash[$offset+3]) & 0xff)
        ) % pow(10, $this->getTokenLength());
    }

}
