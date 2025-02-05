<?php
// From https://github.com/opnsense/core/issues/5776#issuecomment-2140902486
function generateRandomBase64($length = 60) {
    return base64_encode(random_bytes($length));
}

function generateApiSecret($secret) {
    return crypt($secret, '$6$');
}

$xml = new DOMDocument();
$xml->load('/conf/config.xml');

$xpath = new DOMXPath($xml);

$homenetQuery = "/opnsense/OPNsense/IDS[@version='1.0.9']/general/homenet";
$homenetNode = $xpath->query($homenetQuery)->item(0);

if ($homenetNode) {
    $homenetNode->nodeValue = "192.168.56.0/26,192.168.56.64/26,192.168.56.128/26";
    echo "Updated IDS <homenet> successfully.\n";
} else {
    echo "IDS <homenet> tag not found.\n";
}

$query = "/opnsense/system/user[name='root']";
$rootUser = $xpath->query($query)->item(0);

if ($rootUser) {
    $apikeys = $rootUser->getElementsByTagName('apikeys')->item(0);
    if (!$apikeys) {
        $apikeys = $xml->createElement('apikeys');
        $rootUser->appendChild($apikeys);
    }

    $newApiKey = generateRandomBase64();
    $newApiSecret = generateRandomBase64();

    $item = $xml->createElement('item');
    $key = $xml->createElement('key', $newApiKey);
    $secret = $xml->createElement('secret', generateApiSecret($newApiSecret));

    $item->appendChild($key);
    $item->appendChild($secret);
    $apikeys->appendChild($item);

    echo "API key and secret added successfully.\n";
    echo "API Key: $newApiKey\n";
    echo "API Secret: $newApiSecret\n";

    file_put_contents('./apikey', "APIKEY='$newApiKey'\nAPISECRET='$newApiSecret'\n");
} else {
    echo "Root user not found.\n";
}

$xml->save('/conf/config.xml');

sleep(5);

function makeOpnsenseRequest(string $endpoint, array $data): array {
    global $newApiKey, $newApiSecret;
    $opnsense_ip = "192.168.56.2";
    $api_key = $newApiKey;
    $api_secret = $newApiSecret;

    $url = "https://$opnsense_ip/api/$endpoint";
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ["Content-Type: application/json"],
        CURLOPT_USERPWD => "$api_key:$api_secret",
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($data),
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_SSL_VERIFYPEER => 0,
    ]);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    return [
        "http_code" => $http_code,
        "response" => $response,
        "error" => $error
    ];
}

$aliases = [
    [
        "name" => "RFC1918",
        "type" => "network",
        "content" => "192.168.0.0/16\n172.16.0.0/12\n10.0.0.0/8",
        "description" => "RFC1918",
        "proto" => "",
        "categories" => "",
        "updatefreq" => "",
        "interface" => "",
        "counters" => "0"
    ],
    [
        "name" => "WebPorts",
        "type" => "port",
        "content" => "80\n443",
        "description" => "WebPorts",
        "proto" => "",
        "categories" => "",
        "updatefreq" => "",
        "interface" => "",
        "counters" => "0"
    ],
    [
        "name" => "Services",
        "type" => "port",
        "content" => "53\n123",
        "description" => "Services",
        "proto" => "",
        "categories" => "",
        "updatefreq" => "",
        "interface" => "",
        "counters" => "0"
    ],
    [
        "name" => "Monitoring",
        "type" => "port",
        "content" => "8220\n9200",
        "description" => "Monitoring",
        "proto" => "",
        "categories" => "",
        "updatefreq" => "",
        "interface" => "",
        "counters" => "0"
    ],
    [
        "name" => "DHCP_Ports",
        "type" => "port",
        "content" => "67\n68",
        "description" => "DHCP_Ports",
        "proto" => "",
        "categories" => "",
        "updatefreq" => "",
        "interface" => "",
        "counters" => "0"
    ]
];

$rules = [
    [
        "action" => "pass",
        "description" => "Allow DNS and NTP traffic",
        "interface" => "opt1,opt3",
        "ipprotocol" => "inet",
        "statetype" => "keep state",
        "direction" => "in",
        "quick" => "1",
        "source_net" => "any",
        "protocol" => "UDP",
        "destination_net" => "(self)",
        "destination_port" => "Services"
    ],
    [
        "action" => "pass",
        "description" => "Allow Elasticsearch traffic",
        "interface" => "opt1,opt2",
        "ipprotocol" => "inet",
        "statetype" => "keep state",
        "direction" => "in",
        "quick" => "1",
        "source" => "any",
        "protocol" => "TCP",
        "destination_net" => "lan",
        "destination_port" => "Monitoring"
    ],
    [
        "action" => "block",
        "description" => "Block all traffic to RFC1918",
        "interface" => "opt1,opt2",
        "ipprotocol" => "inet",
        "statetype" => "keep state",
        "direction" => "in",
        "quick" => "0",
        "source_net" => "any",
        "destination_net" => "RFC1918",
        "log" => "1"
    ],
    [
        "action" => "pass",
        "description" => "Allow DHCP traffic",
        "interface" => "opt2",
        "ipprotocol" => "inet",
        "statetype" => "keep state",
        "direction" => "in",
        "quick" => "1",
        "source" => "any",
        "protocol" => "UDP",
        "destination_net" => "(self)",
        "destination_port" => "DHCP_Ports"
    ],
    [
        "action" => "pass",
        "description" => "Allow web traffic",
        "interface" => "opt1,opt3",
        "ipprotocol" => "inet",
        "statetype" => "keep state",
        "direction" => "in",
        "quick" => "0",
        "source" => "any",
        "protocol" => "TCP",
        "destination_net" => "any",
        "destination_port" => "WebPorts"
    ],
    [
        "action" => "pass",
        "description" => "Allow SSH traffic",
        "interface" => "opt3",
        "ipprotocol" => "inet",
        "statetype" => "keep state",
        "direction" => "in",
        "quick" => "0",
        "source" => "any",
        "protocol" => "TCP",
        "destination_net" => "opt1",
        "destination_port" => "22"
    ]
];

$syslog = [
            [
                "enabled" => "1",
                "certificate" => "",
                "transport" => "udp4",
                "hostname" => "192.168.56.10",
                "facility" => "",
                "level" => "",
                "port" => "5514",
                "rfc5424" => "0",
                "program" => "",
                "description" => "Remote Syslog Server"
            ]
];

// Output responses
foreach ($aliases as $alias) {
    $response = makeOpnsenseRequest("firewall/alias/addItem", ["alias" => $alias], $api_key, $api_secret);
    echo "Response: " . json_encode($response) . "\n";
}

foreach ($rules as $rule) {
    $response = makeOpnsenseRequest("firewall/filter/addRule", ["rule" => $rule], $api_key, $api_secret);
    echo "Response: " . json_encode($response) . "\n";
}

foreach ($syslog as $syslog) {
    $response = makeOpnsenseRequest("syslog/settings/addDestination", ["destination" => $syslog], $api_key, $api_secret);
    echo "Response: " . json_encode($response) . "\n";
}

?>