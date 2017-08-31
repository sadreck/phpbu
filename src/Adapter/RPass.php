<?php
namespace phpbu\App\Adapter;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use phpbu\App\Adapter;

class RPass implements Adapter
{
    /** @var string */
    private $gpgPath = '';

    /**
     * Setup the adapter.
     *
     * @param  array $conf
     * @return void
     */
    public function setup(array $conf)
    {
        $this->gpgPath = isset($conf['gpgPath']) ? $conf['gpgPath'] : '';
    }

    /**
     * Return a value for a given path.
     *
     * @param  string $path
     * @return string
     */
    public function getValue(string $path): string
    {
        $tokenData = $this->getTokenData($path);
        if (empty($tokenData['token'])) {
            return '';
        }

        $gpgString = $this->fetchGPGString($tokenData['token']);
        if (empty($tokenData['gpg'])) {
            return $gpgString;
        }

        return $this->decryptString($gpgString, $tokenData['gpg']);
    }

    /**
     * @param $data
     * @param $gpgShortKey
     * @return string
     */
    private function decryptString($data, $gpgShortKey)
    {
        $data = escapeshellarg($data);
        $gpgShortKey = escapeshellarg($gpgShortKey);

        $commandLine = "echo {$data} | {$this->gpgPath} --decrypt -r {$gpgShortKey} 2>/dev/null";
        $result = shell_exec($commandLine);
        return empty($result) ? '' : $result;
    }

    /**
     * @param $data
     * @return array
     */
    private function getTokenData($data)
    {
        $returnData = [
            'token' => '',
            'gpg' => ''
        ];

        $data = explode('|', $data);
        if (count($data) == 0) {
            // Something went wrong. Don't throw an exception as we don't want the whole thing to stop.
            return $returnData;
        }

        $returnData['token'] = trim($data[0]);
        if (count($data) == 2) {
            $returnData['gpg'] = trim($data[1]);
        }

        return $returnData;
    }

    /**
     * @param $token
     * @return string
     */
    private function fetchGPGString($token)
    {
        $firstPart = substr($token, 0, 32);
        $secondPart = substr($token, 32, 32);
        $sha256Hash = substr($token, -64);

        $remoteURL = "https://www.remotepassword.com/password/{$firstPart}/{$secondPart}";
        $gpgString = $this->getRequest($remoteURL);
        if (hash('sha256', $gpgString) != $sha256Hash) {
            return '';
        }

        return base64_decode($gpgString);
    }

    /**
     * @param $url
     * @return string
     */
    private function getRequest($url)
    {
        $client = new Client();
        try {
            $response = $client->send(new Request('GET', $url));
            $return = $response->getBody()->getContents();
        } catch (\Exception $e) {
            $return = '';
        }

        return $return;
    }
}