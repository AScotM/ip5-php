#!/usr/bin/php
<?php

class NetworkMonitor {
    private $colorReset = "\033[0m";
    private $colorGrey = "\033[38;5;245m";
    private $colorBlue = "\033[34m";
    private $colorGreen = "\033[32m";
    private $colorRed = "\033[31m";
    private $colorYellow = "\033[33m";
    private $colorCyan = "\033[36m";
    private $colorMagenta = "\033[35m";
    private $clearScreen = "\033[H\033[J";

    private $config;
    private $shouldExit = false;
    private $debug = false;
    private $ipCache = null;
    private $cacheTime = null;
    private $prevStats = [];
    private $statCache = null;
    private $statCacheTime = null;
    private $stateCache = [];
    private $rateHistory = [];
    private $interfaceDetailsCache = [];
    private $gatewayCache = null;
    private $gatewayCacheTime = null;

    private const MAX_HISTORY = 5;
    private const MAX_INTERVAL = 3600;
    private const MIN_INTERVAL = 0.1;
    private const MAX_INTERFACES = 1000;
    private const DEFAULT_CACHE_TTL = 5;
    private const MAX_FILE_SIZE = 8192;
    private const MAX_RETRIES = 3;
    private const RETRY_DELAY = 100000;

    public function __construct(array $config = []) {
        $this->config = array_merge([
            'interval' => 1.0,
            'show_loopback' => false,
            'show_inactive' => false,
            'max_interfaces' => 50,
            'units' => 'binary',
            'cache_ips_seconds' => 5,
            'cache_stats_seconds' => 1,
            'show_errors' => true,
            'show_averages' => true,
            'sort_by' => 'rx_rate',
            'alert_threshold' => 0.01,
            'show_details' => false,
            'show_gateway' => true
        ], $config);
        
        $this->validateConfig();
        $this->enforceResourceLimits();
    }

    private function validateConfig() {
        $validators = [
            'interval' => fn($v) => $v >= self::MIN_INTERVAL && $v <= self::MAX_INTERVAL,
            'max_interfaces' => fn($v) => $v > 0 && $v <= self::MAX_INTERFACES,
            'units' => fn($v) => in_array($v, ['binary', 'decimal']),
            'sort_by' => fn($v) => in_array($v, ['rx_rate', 'tx_rate', 'name'])
        ];
        
        foreach ($validators as $key => $validator) {
            if (isset($this->config[$key]) && !$validator($this->config[$key])) {
                throw new InvalidArgumentException("Invalid value for configuration '$key': " . $this->config[$key]);
            }
        }
    }

    private function enforceResourceLimits() {
        ini_set('memory_limit', '64M');
        
        if (function_exists('setrlimit') && defined('RLIMIT_NOFILE')) {
            setrlimit(RLIMIT_NOFILE, 1024, 1024);
        }
    }

    private function safeFileRead($path) {
        if (!file_exists($path)) {
            throw new RuntimeException("File does not exist: $path");
        }
        
        if (!is_readable($path)) {
            throw new RuntimeException("File is not readable: $path");
        }
        
        $content = @file_get_contents($path, false, null, 0, self::MAX_FILE_SIZE);
        if ($content === false) {
            throw new RuntimeException("Failed to read file: $path");
        }
        
        return $content;
    }

    private function safeShellExec($command) {
        $escapedCommand = escapeshellcmd($command);
        return @shell_exec($escapedCommand);
    }

    private function validateAndBuildPath($ifaceName, $filename) {
        $this->validateInterfaceName($ifaceName);
        $safeFilename = basename($filename);
        return "/sys/class/net/" . $ifaceName . "/" . $safeFilename;
    }

    private function log($message, $level = 'INFO') {
        if ($this->debug) {
            file_put_contents('php://stderr', 
                date('Y-m-d H:i:s') . " [$level] $message\n", FILE_APPEND);
        }
    }

    private function error($message) {
        echo $this->colorRed . "Error: " . $message . $this->colorReset . "\n";
    }

    private function validateNumericValue($value, $fieldName) {
        if (!is_numeric($value) || $value < 0) {
            throw new InvalidArgumentException("Invalid value for $fieldName: $value");
        }
        return (float)$value;
    }

    private function validateInterfaceName($ifaceName) {
        if (!preg_match('/^[a-zA-Z0-9:_\.-]+$/', $ifaceName)) {
            throw new InvalidArgumentException("Invalid interface name: $ifaceName");
        }
        return $ifaceName;
    }

    private function getDefaultGateway() {
        $now = time();
        if ($this->gatewayCache !== null && $this->gatewayCacheTime !== null && 
            ($now - $this->gatewayCacheTime) < $this->config['cache_ips_seconds']) {
            return $this->gatewayCache;
        }

        $gateway = null;
        
        $result = $this->safeShellExec('/sbin/ip route show default');
        if ($result) {
            foreach (explode("\n", $result) as $line) {
                if (preg_match('/default via (\S+) dev (\S+)/', $line, $matches)) {
                    $gateway = [
                        'ip' => $matches[1],
                        'interface' => $matches[2]
                    ];
                    break;
                }
            }
        }

        if (!$gateway) {
            $result = $this->safeShellExec('netstat -rn');
            if ($result) {
                foreach (explode("\n", $result) as $line) {
                    if (preg_match('/^0\.0\.0\.0\s+(\S+)\s+.*?(\S+)$/', $line, $matches)) {
                        $gateway = [
                            'ip' => $matches[1],
                            'interface' => $matches[2]
                        ];
                        break;
                    }
                }
            }
        }

        $this->gatewayCache = $gateway;
        $this->gatewayCacheTime = $now;
        return $gateway;
    }

    private function getInterfaceIPs() {
        $now = time();
        if ($this->ipCache !== null && $this->cacheTime !== null && 
            ($now - $this->cacheTime) < $this->config['cache_ips_seconds']) {
            return $this->ipCache;
        }

        $ips = [];
        $result = $this->safeShellExec('/sbin/ip -o -4 addr show');
        if ($result) {
            foreach (explode("\n", $result) as $line) {
                if (preg_match('/^\d+:\s+(\S+)\s+inet\s+(\S+)/', $line, $matches)) {
                    $iface = $matches[1];
                    $ip = $matches[2];
                    $ips[$iface][] = explode('/', $ip)[0];
                }
            }
        } else {
            $interfaces = @net_get_interfaces();
            if (!$interfaces) {
                $this->log('Failed to get network interfaces');
                return $ips;
            }

            foreach ($interfaces as $ifaceName => $ifaceData) {
                if (!$this->config['show_loopback'] && $this->isLoopbackInterface($ifaceName, $ifaceData)) {
                    continue;
                }

                if (!isset($ifaceData['unicast'])) {
                    continue;
                }
                
                $ipList = [];
                foreach ($ifaceData['unicast'] as $addr) {
                    if (isset($addr['address']) && !$this->isLoopback($addr['address'])) {
                        $ipList[] = $addr['address'];
                    }
                }
                
                if (!empty($ipList)) {
                    $ips[$ifaceName] = $ipList;
                }
            }
        }

        $this->ipCache = $ips;
        $this->cacheTime = $now;
        return $ips;
    }

    private function isLoopback($ip) {
        return substr($ip, 0, 4) === '127.' || $ip === '::1';
    }

    private function isLoopbackInterface($ifaceName, $ifaceData) {
        if ($ifaceName === 'lo') {
            return true;
        }
        
        if (isset($ifaceData['flags']) && in_array('loopback', $ifaceData['flags'])) {
            return true;
        }
        
        $operstatePath = $this->validateAndBuildPath($ifaceName, 'operstate');
        if (file_exists($operstatePath)) {
            $operstate = trim($this->safeFileRead($operstatePath));
            if ($operstate === 'unknown' || $operstate === 'down') {
                $carrierPath = $this->validateAndBuildPath($ifaceName, 'carrier');
                if (file_exists($carrierPath)) {
                    $carrier = trim($this->safeFileRead($carrierPath));
                    if ($carrier === '1') {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }

    private function isInterfaceInactive($stats) {
        return $stats['rxBytes'] == 0 && $stats['txBytes'] == 0 &&
               $stats['rxPackets'] == 0 && $stats['txPackets'] == 0;
    }

    private function shouldShowInterface($ifaceName, $stats) {
        if (!$this->config['show_loopback'] && $this->isLoopbackInterface($ifaceName, [])) {
            return false;
        }
        if (!$this->config['show_inactive'] && $this->isInterfaceInactive($stats)) {
            return false;
        }
        return true;
    }

    private function getInterfaceState($ifaceName) {
        $operstatePath = $this->validateAndBuildPath($ifaceName, 'operstate');
        try {
            return trim($this->safeFileRead($operstatePath));
        } catch (Exception $e) {
            return 'unknown';
        }
    }

    private function getInterfaceStateCached($ifaceName) {
        if (isset($this->stateCache[$ifaceName])) {
            return $this->stateCache[$ifaceName];
        }
        
        $state = $this->getInterfaceState($ifaceName);
        $this->stateCache[$ifaceName] = $state;
        
        if (count($this->stateCache) > 100) {
            $this->stateCache = array_slice($this->stateCache, -50, null, true);
        }
        
        return $state;
    }

    private function getInterfaceDetails($ifaceName) {
        if (isset($this->interfaceDetailsCache[$ifaceName])) {
            return $this->interfaceDetailsCache[$ifaceName];
        }
        
        $details = [];
        
        $speedPath = $this->validateAndBuildPath($ifaceName, 'speed');
        if (file_exists($speedPath)) {
            $speed = trim($this->safeFileRead($speedPath));
            if (is_numeric($speed) && $speed > 0) {
                $details['speed'] = $speed;
            }
        }
        
        $mtuPath = $this->validateAndBuildPath($ifaceName, 'mtu');
        if (file_exists($mtuPath)) {
            $mtu = trim($this->safeFileRead($mtuPath));
            if (is_numeric($mtu)) {
                $details['mtu'] = $mtu;
            }
        }

        $duplexPath = $this->validateAndBuildPath($ifaceName, 'duplex');
        if (file_exists($duplexPath)) {
            $duplex = trim($this->safeFileRead($duplexPath));
            if ($duplex) {
                $details['duplex'] = $duplex;
            }
        }
        
        $this->interfaceDetailsCache[$ifaceName] = $details;
        return $details;
    }

    private function getInterfaceFlags($ifaceName) {
        $flags = [];
        
        if ($this->isLoopbackInterface($ifaceName, [])) {
            $flags[] = 'LOOPBACK';
        }
        
        $gateway = $this->getDefaultGateway();
        if ($gateway && $gateway['interface'] === $ifaceName) {
            $flags[] = 'GATEWAY';
        }
        
        $state = $this->getInterfaceStateCached($ifaceName);
        if ($state === 'up') {
            $flags[] = 'UP';
        } else {
            $flags[] = 'DOWN';
        }
        
        return $flags;
    }

    private function cleanupCaches() {
        $now = time();
        $maxCacheAge = 300;
        
        if ($this->statCacheTime && ($now - $this->statCacheTime) > $maxCacheAge) {
            $this->statCache = null;
            $this->statCacheTime = null;
        }
        
        foreach ($this->rateHistory as $iface => &$history) {
            if (count($history['rx']) > 60) {
                $history['rx'] = array_slice($history['rx'], -60);
                $history['tx'] = array_slice($history['tx'], -60);
            }
        }
    }

    private function getCachedStats() {
        $now = time();
        $cacheTtl = $this->config['cache_stats_seconds'];
        
        if ($this->statCache !== null && 
            ($now - $this->statCacheTime) < $cacheTtl) {
            return $this->statCache;
        }
        
        $this->statCache = $this->parseProcNetDev();
        $this->statCacheTime = $now;
        return $this->statCache;
    }

    private function parseProcNetDev() {
        for ($attempt = 1; $attempt <= self::MAX_RETRIES; $attempt++) {
            try {
                return $this->doParseProcNetDev();
            } catch (Exception $e) {
                if ($attempt === self::MAX_RETRIES) {
                    throw new RuntimeException("Failed to parse /proc/net/dev after " . self::MAX_RETRIES . " attempts: " . $e->getMessage());
                }
                usleep(self::RETRY_DELAY);
            }
        }
        
        throw new RuntimeException("Unexpected error in parseProcNetDev");
    }

    private function doParseProcNetDev() {
        $stats = [];
        
        if (!file_exists('/proc/net/dev')) {
            throw new RuntimeException('/proc/net/dev does not exist');
        }

        $handle = fopen('/proc/net/dev', 'r');
        if (!$handle) {
            throw new RuntimeException('Failed to open /proc/net/dev');
        }

        fgets($handle);
        fgets($handle);

        $interfaceCount = 0;

        while (($line = fgets($handle)) !== false && $interfaceCount < $this->config['max_interfaces']) {
            $line = trim($line);
            if (empty($line)) continue;

            if (preg_match('/^(\S+?):\s*(.*)$/', $line, $matches)) {
                $iface = $this->validateInterfaceName($matches[1]);
                $data = preg_split('/\s+/', trim($matches[2]));
                
                if (count($data) >= 16) {
                    try {
                        $stats[$iface] = [
                            'name' => $iface,
                            'rxBytes' => $this->validateNumericValue($data[0], 'rxBytes'),
                            'rxPackets' => $this->validateNumericValue($data[1], 'rxPackets'),
                            'rxErrs' => $this->validateNumericValue($data[2], 'rxErrs'),
                            'rxDrop' => $this->validateNumericValue($data[3], 'rxDrop'),
                            'txBytes' => $this->validateNumericValue($data[8], 'txBytes'),
                            'txPackets' => $this->validateNumericValue($data[9], 'txPackets'),
                            'txErrs' => $this->validateNumericValue($data[10], 'txErrs'),
                            'txDrop' => $this->validateNumericValue($data[11], 'txDrop')
                        ];
                        $interfaceCount++;
                    } catch (InvalidArgumentException $e) {
                        $this->log("Invalid data for interface $iface: " . $e->getMessage());
                    }
                }
            }
        }

        fclose($handle);

        if (empty($stats)) {
            throw new RuntimeException('No valid interface data found in /proc/net/dev');
        }

        return $stats;
    }

    private function formatBytes($bytes) {
        if ($this->config['units'] === 'decimal') {
            $units = ['B', 'KB', 'MB', 'GB', 'TB'];
            $divisor = 1000;
        } else {
            $units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
            $divisor = 1024;
        }
        
        $i = 0;
        $val = $bytes;
        
        while ($val >= $divisor && $i < count($units) - 1) {
            $val /= $divisor;
            $i++;
        }
        
        return sprintf('%.1f%s', $val, $units[$i]);
    }

    private function formatRate($rate) {
        if ($this->config['units'] === 'decimal') {
            $units = ['B/s', 'KB/s', 'MB/s', 'GB/s', 'TB/s'];
            $divisor = 1000;
        } else {
            $units = ['B/s', 'KiB/s', 'MiB/s', 'GiB/s', 'TiB/s'];
            $divisor = 1024;
        }
        
        $i = 0;
        $val = $rate;
        
        while ($val >= $divisor && $i < count($units) - 1) {
            $val /= $divisor;
            $i++;
        }
        
        return sprintf('%.1f%s', $val, $units[$i]);
    }

    private function convertUnits($bytes, $from = 'bytes', $to = 'auto') {
        $units = [
            'bytes' => 1,
            'kilobits' => 125,
            'megabits' => 125000,
            'kilobytes' => 1000,
            'megabytes' => 1000000,
        ];
        
        if ($to === 'auto') {
            $abs = abs($bytes);
            if ($abs >= $units['megabytes']) {
                return [$bytes / $units['megabytes'], 'MB'];
            } elseif ($abs >= $units['kilobytes']) {
                return [$bytes / $units['kilobytes'], 'KB'];
            } else {
                return [$bytes, 'B'];
            }
        }
        
        if (isset($units[$from]) && isset($units[$to])) {
            return $bytes * ($units[$to] / $units[$from]);
        }
        
        throw new InvalidArgumentException("Invalid units: $from or $to");
    }

    private function formatFlags($flags) {
        $formatted = [];
        foreach ($flags as $flag) {
            switch ($flag) {
                case 'UP':
                    $formatted[] = $this->colorGreen . $flag . $this->colorReset;
                    break;
                case 'DOWN':
                    $formatted[] = $this->colorRed . $flag . $this->colorReset;
                    break;
                case 'LOOPBACK':
                    $formatted[] = $this->colorMagenta . $flag . $this->colorReset;
                    break;
                case 'GATEWAY':
                    $formatted[] = $this->colorCyan . $flag . $this->colorReset;
                    break;
                default:
                    $formatted[] = $this->colorGrey . $flag . $this->colorReset;
            }
        }
        return '[' . implode(' ', $formatted) . ']';
    }

    private function header($gatewayInfo = null) {
        echo $this->clearScreen;
        echo $this->colorBlue . "Network Interface Monitor" . $this->colorReset;
        
        if ($this->config['show_gateway'] && $gatewayInfo) {
            echo " | Gateway: " . $this->colorCyan . $gatewayInfo['ip'] . 
                 $this->colorReset . " via " . $this->colorGreen . $gatewayInfo['interface'] . $this->colorReset;
        }
        
        echo "\n";
        echo $this->colorGrey . "Monitoring interface statistics..." . $this->colorReset . "\n\n";
    }

    private function signalHandler($signo) {
        $this->log("Received signal $signo, shutting down");
        $this->shouldExit = true;
    }

    private function setupSignalHandlers() {
        if (!extension_loaded('pcntl')) {
            $this->log('PCNTL extension not available, signal handling disabled');
            return;
        }
        
        if (!function_exists('pcntl_async_signals')) {
            $this->log('pcntl_async_signals not available, using legacy signal handling');
            declare(ticks=1);
        } else {
            pcntl_async_signals(true);
        }
        
        $signals = [SIGINT, SIGTERM, SIGHUP];
        foreach ($signals as $signal) {
            if (!pcntl_signal($signal, [$this, 'signalHandler'])) {
                $this->log("Failed to set handler for signal $signal");
            }
        }
    }

    private function manageHistory($current) {
        $this->prevStats[] = $current;
        if (count($this->prevStats) > self::MAX_HISTORY) {
            array_shift($this->prevStats);
        }
    }

    private function calculateDelta($prev, $curr, $interval) {
        $deltas = [];
        
        foreach ($curr as $name => $now) {
            if (!isset($prev[$name]) || !$this->shouldShowInterface($name, $now)) {
                continue;
            }
            
            $pr = $prev[$name];
            
            $rxDelta = $this->calculateCounterDelta($pr['rxBytes'], $now['rxBytes']);
            $txDelta = $this->calculateCounterDelta($pr['txBytes'], $now['txBytes']);

            $deltas[$name] = [
                'name' => $name,
                'rxRate' => $rxDelta / $interval,
                'txRate' => $txDelta / $interval,
                'rxBytes' => $now['rxBytes'],
                'txBytes' => $now['txBytes'],
                'rxErrs' => $now['rxErrs'],
                'txErrs' => $now['txErrs'],
                'rxDrop' => $now['rxDrop'],
                'txDrop' => $now['txDrop'],
                'rxPackets' => $now['rxPackets'],
                'txPackets' => $now['txPackets']
            ];
        }
        
        return $deltas;
    }

    private function calculateCounterDelta($prev, $curr) {
        $maxValue = PHP_INT_MAX;
        
        if ($curr >= $prev) {
            return $curr - $prev;
        } else {
            return ($maxValue - $prev) + $curr;
        }
    }

    private function updateRateHistory($ifaceName, $rxRate, $txRate) {
        if (!isset($this->rateHistory[$ifaceName])) {
            $this->rateHistory[$ifaceName] = [
                'rx' => [],
                'tx' => []
            ];
        }

        $this->rateHistory[$ifaceName]['rx'][] = $rxRate;
        $this->rateHistory[$ifaceName]['tx'][] = $txRate;

        if (count($this->rateHistory[$ifaceName]['rx']) > 60) {
            array_shift($this->rateHistory[$ifaceName]['rx']);
            array_shift($this->rateHistory[$ifaceName]['tx']);
        }
    }

    private function getAverageRates($ifaceName) {
        if (!isset($this->rateHistory[$ifaceName])) {
            return ['rx' => 0, 'tx' => 0];
        }

        $rxRates = $this->rateHistory[$ifaceName]['rx'];
        $txRates = $this->rateHistory[$ifaceName]['tx'];

        if (empty($rxRates)) return ['rx' => 0, 'tx' => 0];

        $rxAvg = array_sum($rxRates) / count($rxRates);
        $txAvg = array_sum($txRates) / count($txRates);

        return ['rx' => $rxAvg, 'tx' => $txAvg];
    }

    private function calculateAdvancedMetrics($deltas) {
        $metrics = [
            'total_rx_rate' => 0,
            'total_tx_rate' => 0,
            'peak_rx_rate' => 0,
            'peak_tx_rate' => 0,
            'interface_count' => count($deltas),
            'active_interfaces' => 0
        ];

        foreach ($deltas as $name => $data) {
            $metrics['total_rx_rate'] += $data['rxRate'];
            $metrics['total_tx_rate'] += $data['txRate'];
            $metrics['peak_rx_rate'] = max($metrics['peak_rx_rate'], $data['rxRate']);
            $metrics['peak_tx_rate'] = max($metrics['peak_tx_rate'], $data['txRate']);
            
            if ($data['rxRate'] > 0 || $data['txRate'] > 0) {
                $metrics['active_interfaces']++;
            }
            
            $this->updateRateHistory($name, $data['rxRate'], $data['txRate']);
        }

        return $metrics;
    }

    private function detectNetworkIssues($deltas) {
        $issues = [];
        
        foreach ($deltas as $name => $data) {
            $totalPackets = $data['rxPackets'] + $data['txPackets'];
            $totalErrors = $data['rxErrs'] + $data['txErrs'];
            
            if ($totalPackets > 1000 && $totalPackets > 0 && ($totalErrors / $totalPackets) > $this->config['alert_threshold']) {
                $errorRate = round(($totalErrors / $totalPackets) * 100, 2);
                $issues[] = "High error rate on $name: {$errorRate}%";
            }
            
            $state = $this->getInterfaceStateCached($name);
            if ($state !== 'up' && ($data['rxBytes'] > 0 || $data['txBytes'] > 0)) {
                $issues[] = "Interface $name is down but previously had traffic";
            }
        }
        
        return $issues;
    }

    private function sortDeltas(&$deltas) {
        switch ($this->config['sort_by']) {
            case 'tx_rate':
                uasort($deltas, function($a, $b) {
                    return $b['txRate'] <=> $a['txRate'];
                });
                break;
            case 'name':
                ksort($deltas);
                break;
            case 'rx_rate':
            default:
                uasort($deltas, function($a, $b) {
                    return $b['rxRate'] <=> $a['rxRate'];
                });
                break;
        }
    }

    private function displayEnhancedDeltas($deltas) {
        $ipMap = $this->getInterfaceIPs();
        $metrics = $this->calculateAdvancedMetrics($deltas);
        $gateway = $this->getDefaultGateway();
        
        $this->sortDeltas($deltas);

        foreach ($deltas as $name => $data) {
            $ips = $ipMap[$name] ?? [];
            $ipInfo = !empty($ips) ? " [" . implode(', ', $ips) . "]" : "";
            
            $flags = $this->getInterfaceFlags($name);
            $flagsDisplay = $this->formatFlags($flags);
            
            $avgRates = $this->getAverageRates($name);
            $avgInfo = $this->config['show_averages'] ? 
                sprintf(" [Avg: %s/%s]", $this->formatRate($avgRates['rx']), $this->formatRate($avgRates['tx'])) : "";

            $details = $this->getInterfaceDetails($name);
            $detailsInfo = "";
            if ($this->config['show_details'] && !empty($details)) {
                $detailParts = [];
                if (isset($details['speed'])) $detailParts[] = $details['speed'] . ' Mbps';
                if (isset($details['mtu'])) $detailParts[] = 'MTU:' . $details['mtu'];
                if (isset($details['duplex'])) $detailParts[] = $details['duplex'];
                if (!empty($detailParts)) {
                    $detailsInfo = " (" . implode(', ', $detailParts) . ")";
                }
            }

            printf("%s%12s%s %s%s%s%s\n",
                $this->colorBlue, $name, $this->colorReset, $flagsDisplay, $ipInfo, $detailsInfo, $avgInfo);
            
            printf("  RX: %s%-12s%s TX: %s%-12s%s\n",
                $this->colorGreen, $this->formatRate($data['rxRate']), $this->colorReset,
                $this->colorYellow, $this->formatRate($data['txRate']), $this->colorReset);
            
            if ($this->config['show_errors'] && ($data['rxErrs'] > 0 || $data['txErrs'] > 0)) {
                printf("  %sErrors: RX%.0f TX%.0f Drop: RX%.0f TX%.0f%s\n",
                    $this->colorRed, $data['rxErrs'], $data['txErrs'], 
                    $data['rxDrop'], $data['txDrop'], $this->colorReset);
            }
            
            echo "\n";
        }
        
        $this->displaySummary($metrics, count($deltas), $gateway);
    }

    private function displaySummary($metrics, $interfaceCount, $gateway) {
        echo $this->colorGrey . str_repeat("─", 60) . $this->colorReset . "\n";
        printf("Summary: %d interfaces (%d active) | Total: %s/s RX, %s/s TX\n",
            $interfaceCount, $metrics['active_interfaces'],
            $this->formatRate($metrics['total_rx_rate']),
            $this->formatRate($metrics['total_tx_rate']));
        
        printf("Peak: %s/s RX, %s/s TX",
            $this->formatRate($metrics['peak_rx_rate']),
            $this->formatRate($metrics['peak_tx_rate']));
        
        if ($this->config['show_gateway'] && $gateway) {
            printf(" | Gateway: %s%s%s",
                $this->colorCyan, $gateway['ip'], $this->colorReset);
        }
        
        printf(" | %s\n", date('H:i:s'));
        
        echo $this->colorGrey . "[ctrl+c to stop]" . $this->colorReset . "\n";
    }

    private function getSystemLoad() {
        if (file_exists('/proc/loadavg')) {
            $load = $this->safeFileRead('/proc/loadavg');
            return floatval(explode(' ', $load)[0]);
        }
        return 0.0;
    }

    private function adaptiveSleep($interval, $startTime) {
        $elapsed = microtime(true) - $startTime;
        $sleepTime = ($interval - $elapsed) * 1000000;
        
        if ($sleepTime > 1000) {
            $load = $this->getSystemLoad();
            if ($load > 2.0) {
                $sleepTime = max(1000, $sleepTime * 0.5);
            }
            usleep((int)$sleepTime);
        }
    }

    private function adaptiveSleepWithProgress($interval) {
        $sleepSteps = 10;
        $stepDuration = ($interval * 1000000) / $sleepSteps;
        
        for ($i = 0; $i < $sleepSteps; $i++) {
            if ($this->shouldExit) break;
            
            $progress = str_repeat('█', $i + 1) . str_repeat('░', $sleepSteps - $i - 1);
            echo "\r" . $this->colorGrey . "[" . $progress . "] " . 
                 round(($i + 1) * (100 / $sleepSteps)) . "%" . $this->colorReset;
            usleep((int)$stepDuration);
        }
        echo "\r" . str_repeat(' ', 50) . "\r";
    }

    public function watch($interval) {
        $this->log("Starting watch mode with interval: {$interval}s");
        
        $this->setupSignalHandlers();
        $iteration = 0;
        $startTime = time();
        $gateway = $this->getDefaultGateway();

        try {
            $prev = $this->parseProcNetDev();
        } catch (Exception $e) {
            throw new RuntimeException("Failed to initialize monitoring: " . $e->getMessage());
        }

        while (!$this->shouldExit) {
            $iteration++;
            $currentTime = time();
            $uptime = $currentTime - $startTime;
            
            $this->header($gateway);
            printf("Uptime: %ds | Iteration: %d | %s\n\n", 
                   $uptime, $iteration, date('Y-m-d H:i:s'));

            try {
                $this->cleanupCaches();
                $curr = $this->getCachedStats();
                $deltas = $this->calculateDelta($prev, $curr, $interval);
                
                $issues = $this->detectNetworkIssues($deltas);
                if (!empty($issues)) {
                    echo $this->colorRed . "Network Issues:\n";
                    foreach ($issues as $issue) {
                        echo "  ⚠ $issue\n";
                    }
                    echo $this->colorReset . "\n";
                }
                
                $this->displayEnhancedDeltas($deltas);
                $prev = $curr;
            } catch (Exception $e) {
                $this->log("Monitoring error: " . $e->getMessage());
                echo $this->colorRed . "Read error: " . $e->getMessage() . $this->colorReset . "\n";
            }

            if ($this->shouldExit) break;

            $this->adaptiveSleepWithProgress($interval);
        }

        echo "\n" . $this->colorGrey . "Exiting after $iteration iterations..." . $this->colorReset . "\n";
    }

    private function singleShotMode() {
        $this->log("Running in single shot mode");
        
        $gateway = $this->getDefaultGateway();
        $this->header($gateway);
        
        try {
            $stats = $this->parseProcNetDev();
        } catch (Exception $e) {
            throw new RuntimeException("Failed to read network statistics: " . $e->getMessage());
        }
        
        $ipMap = $this->getInterfaceIPs();
        $displayed = 0;
        
        foreach ($stats as $s) {
            if (!$this->shouldShowInterface($s['name'], $s)) {
                continue;
            }

            if ($displayed >= $this->config['max_interfaces']) {
                break;
            }

            $ips = $ipMap[$s['name']] ?? [];
            $ipInfo = "";
            if (!empty($ips)) {
                $ipInfo = " - " . $this->colorGrey . implode(', ', $ips) . $this->colorReset;
            }
            
            $flags = $this->getInterfaceFlags($s['name']);
            $flagsDisplay = $this->formatFlags($flags);
            
            $details = $this->getInterfaceDetails($s['name']);
            $detailsInfo = "";
            if (!empty($details)) {
                $detailParts = [];
                if (isset($details['speed'])) $detailParts[] = $details['speed'] . ' Mbps';
                if (isset($details['mtu'])) $detailParts[] = 'MTU:' . $details['mtu'];
                if (isset($details['duplex'])) $detailParts[] = $details['duplex'];
                $detailsInfo = " (" . implode(', ', $detailParts) . ")";
            }
            
            echo $this->colorBlue . $s['name'] . $this->colorReset . " " . $flagsDisplay . $detailsInfo . $ipInfo . "\n";
            printf("    RX: %s%s%s (%.0f pkts, %.0f errs, %.0f drop)\n",
                $this->colorGreen, $this->formatBytes($s['rxBytes']), $this->colorReset,
                $s['rxPackets'], $s['rxErrs'], $s['rxDrop']);
            printf("    TX: %s%s%s (%.0f pkts, %.0f errs, %.0f drop)\n\n",
                $this->colorYellow, $this->formatBytes($s['txBytes']), $this->colorReset,
                $s['txPackets'], $s['txErrs'], $s['txDrop']);
            
            $displayed++;
        }
        
        if ($displayed === 0) {
            echo $this->colorGrey . "No active interfaces found." . $this->colorReset . "\n";
        }
        
        if ($this->config['show_gateway'] && $gateway) {
            printf("%sDefault Gateway: %s via %s%s\n",
                $this->colorCyan, $gateway['ip'], $gateway['interface'], $this->colorReset);
        }
        
        echo $this->colorGrey . "Invoke with --watch for live view." . $this->colorReset . "\n";
    }

    private function handleOptions($options) {
        if (isset($options['debug'])) {
            $this->debug = true;
        }

        if (isset($options['interval'])) {
            $this->config['interval'] = $this->validateNumericValue($options['interval'], 'interval');
        }

        if (isset($options['no-loopback'])) {
            $this->config['show_loopback'] = false;
        }
    }

    public function run() {
        try {
            $options = getopt('', ['watch', 'interval:', 'debug', 'no-loopback', 'show-inactive', 'units:', 'sort-by:', 'show-details', 'show-gateway']);
            
            $this->handleOptions($options);
            
            if (isset($options['show-inactive'])) {
                $this->config['show_inactive'] = true;
            }

            if (isset($options['units']) && in_array($options['units'], ['binary', 'decimal'])) {
                $this->config['units'] = $options['units'];
            }

            if (isset($options['sort-by']) && in_array($options['sort-by'], ['rx_rate', 'tx_rate', 'name'])) {
                $this->config['sort_by'] = $options['sort-by'];
            }

            if (isset($options['show-details'])) {
                $this->config['show_details'] = true;
            }

            if (isset($options['show-gateway'])) {
                $this->config['show_gateway'] = true;
            }

            $this->validateConfig();

            if (isset($options['watch'])) {
                set_time_limit(0);
                $this->watch($this->config['interval']);
            } else {
                $this->singleShotMode();
            }
        } catch (Exception $e) {
            $this->error($e->getMessage());
            exit(1);
        }
    }

    public function setDebug($debug) {
        $this->debug = (bool)$debug;
        return $this;
    }

    public function __destruct() {
        if ($this->debug) {
            $this->log("NetworkMonitor shutting down");
        }
    }
}

try {
    error_reporting(E_ALL);
    $monitor = new NetworkMonitor();
    $monitor->run();
} catch (Throwable $e) {
    error_log("Fatal error: " . $e->getMessage());
    echo "Fatal Error: " . $e->getMessage() . "\n";
    exit(1);
}
