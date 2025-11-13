#!/usr/bin/php
<?php

class NetworkMonitorConfig {
    public $interval = 1.0;
    public $show_loopback = false;
    public $show_inactive = false;
    public $max_interfaces = 50;
    public $units = 'binary';
    public $cache_ips_seconds = 5;
    public $cache_stats_seconds = 1;
    public $show_errors = true;
    public $show_averages = true;
    public $sort_by = 'rx_rate';
    public $alert_threshold = 0.01;
    public $show_details = false;
    public $show_gateway = true;
    
    public function __construct(array $options = []) {
        foreach ($options as $key => $value) {
            if (property_exists($this, $key)) {
                $this->$key = $value;
            }
        }
    }
}

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
        $this->config = new NetworkMonitorConfig($config);
        $this->validateConfig();
        $this->enforceResourceLimits();
    }

    private function validateConfig() {
        $validators = [
            'interval' => fn($v) => $v >= self::MIN_INTERVAL && $v <= self::MAX_INTERVAL,
            'max_interfaces' => fn($v) => $v > 0 && $v <= self::MAX_INTERFACES,
            'units' => fn($v) => in_array($v, ['binary', 'decimal']),
            'sort_by' => fn($v) => in_array($v, ['rx_rate', 'tx_rate', 'name']),
            'alert_threshold' => fn($v) => $v >= 0 && $v <= 1,
            'cache_ips_seconds' => fn($v) => $v > 0 && $v <= 300,
            'cache_stats_seconds' => fn($v) => $v > 0 && $v <= 60
        ];
        
        foreach ($validators as $key => $validator) {
            $value = $this->config->$key;
            if (!$validator($value)) {
                throw new InvalidArgumentException("Invalid value for configuration '$key': $value");
            }
        }
    }

    private function enforceResourceLimits() {
        ini_set('memory_limit', '64M');
        
        if (function_exists('set_time_limit')) {
            set_time_limit(0);
        }
        
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
        
        if (is_dir($path)) {
            throw new RuntimeException("Path is a directory: $path");
        }
        
        $size = filesize($path);
        if ($size > self::MAX_FILE_SIZE) {
            throw new RuntimeException("File too large: $path");
        }
        
        $content = @file_get_contents($path, false, null, 0, self::MAX_FILE_SIZE);
        if ($content === false) {
            throw new RuntimeException("Failed to read file: $path");
        }
        
        return $content;
    }

    private function safeShellExec($command) {
        $allowedCommands = [
            '/sbin/ip -o -4 addr show',
            '/sbin/ip route show default',
            'netstat -rn'
        ];
        
        $isAllowed = false;
        foreach ($allowedCommands as $allowed) {
            if (strpos($command, $allowed) === 0) {
                $isAllowed = true;
                break;
            }
        }
        
        if (!$isAllowed) {
            throw new InvalidArgumentException("Command not allowed: $command");
        }
        
        $escapedCommand = escapeshellcmd($command);
        return @shell_exec($escapedCommand);
    }

    private function validateInterfaceName($ifaceName) {
        if (!preg_match('/^[a-zA-Z0-9:_\.\-]{1,15}$/', $ifaceName)) {
            throw new InvalidArgumentException("Invalid interface name: $ifaceName");
        }
        return $ifaceName;
    }

    private function validateAndBuildPath($ifaceName, $filename) {
        $this->validateInterfaceName($ifaceName);
        
        $safeFilename = basename($filename);
        $allowedFiles = [
            'tx_bytes', 'rx_bytes', 'tx_packets', 'rx_packets',
            'tx_errors', 'rx_errors', 'tx_dropped', 'rx_dropped',
            'operstate', 'carrier', 'speed', 'mtu', 'duplex'
        ];
        
        if (!in_array($safeFilename, $allowedFiles)) {
            throw new InvalidArgumentException("Invalid filename: $filename");
        }
        
        $path = "/sys/class/net/" . $ifaceName . "/" . $safeFilename;
        
        $normalizedPath = str_replace('//', '/', $path);
        if (strpos($normalizedPath, '/sys/class/net/') !== 0) {
            throw new InvalidArgumentException("Invalid path construction");
        }
        
        return $path;
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

    private function getDefaultGateway() {
        $now = time();
        if ($this->gatewayCache !== null && $this->gatewayCacheTime !== null && 
            ($now - $this->gatewayCacheTime) < $this->config->cache_ips_seconds) {
            return $this->gatewayCache;
        }

        $gateway = null;
        
        try {
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
        } catch (Exception $e) {
            $this->log("Failed to get gateway via ip command: " . $e->getMessage());
        }

        if (!$gateway) {
            try {
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
            } catch (Exception $e) {
                $this->log("Failed to get gateway via netstat: " . $e->getMessage());
            }
        }

        $this->gatewayCache = $gateway;
        $this->gatewayCacheTime = $now;
        return $gateway;
    }

    private function getInterfaceIPs() {
        $now = time();
        if ($this->ipCache !== null && $this->cacheTime !== null && 
            ($now - $this->cacheTime) < $this->config->cache_ips_seconds) {
            return $this->ipCache;
        }

        $ips = [];
        
        try {
            $result = $this->safeShellExec('/sbin/ip -o -4 addr show');
            if ($result) {
                foreach (explode("\n", $result) as $line) {
                    if (preg_match('/^\d+:\s+(\S+)\s+inet\s+(\S+)/', $line, $matches)) {
                        try {
                            $iface = $this->validateInterfaceName($matches[1]);
                            $ip = $matches[2];
                            $ips[$iface][] = explode('/', $ip)[0];
                        } catch (InvalidArgumentException $e) {
                            continue;
                        }
                    }
                }
            }
        } catch (Exception $e) {
            $this->log("Failed to get IPs via ip command: " . $e->getMessage());
        }

        if (empty($ips)) {
            $interfaces = @net_get_interfaces();
            if (!$interfaces) {
                $this->log('Failed to get network interfaces via net_get_interfaces');
                return $ips;
            }

            foreach ($interfaces as $ifaceName => $ifaceData) {
                try {
                    $ifaceName = $this->validateInterfaceName($ifaceName);
                } catch (InvalidArgumentException $e) {
                    continue;
                }
                
                if (!$this->config->show_loopback && $this->isLoopbackInterface($ifaceName, $ifaceData)) {
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
        
        try {
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
        } catch (Exception $e) {
            $this->log("Failed to check loopback status for $ifaceName: " . $e->getMessage());
        }
        
        return false;
    }

    private function isInterfaceInactive($stats) {
        return $stats['rxBytes'] == 0 && $stats['txBytes'] == 0 &&
               $stats['rxPackets'] == 0 && $stats['txPackets'] == 0;
    }

    private function shouldShowInterface($ifaceName, $stats) {
        if (!$this->config->show_loopback && $this->isLoopbackInterface($ifaceName, [])) {
            return false;
        }
        if (!$this->config->show_inactive && $this->isInterfaceInactive($stats)) {
            return false;
        }
        return true;
    }

    private function getInterfaceState($ifaceName) {
        try {
            $operstatePath = $this->validateAndBuildPath($ifaceName, 'operstate');
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
        
        $filesToCheck = [
            'speed' => 'speed',
            'mtu' => 'mtu',
            'duplex' => 'duplex'
        ];
        
        foreach ($filesToCheck as $key => $filename) {
            try {
                $path = $this->validateAndBuildPath($ifaceName, $filename);
                if (file_exists($path)) {
                    $value = trim($this->safeFileRead($path));
                    if ($key === 'speed' && is_numeric($value) && $value > 0) {
                        $details[$key] = (int)$value;
                    } elseif ($key === 'mtu' && is_numeric($value)) {
                        $details[$key] = (int)$value;
                    } elseif ($key === 'duplex' && !empty($value)) {
                        $details[$key] = $value;
                    }
                }
            } catch (Exception $e) {
                $this->log("Failed to read $key for $ifaceName: " . $e->getMessage());
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
        } elseif ($state === 'down') {
            $flags[] = 'DOWN';
        } else {
            $flags[] = strtoupper($state);
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
        
        if (count($this->interfaceDetailsCache) > 100) {
            $this->interfaceDetailsCache = array_slice($this->interfaceDetailsCache, -50, null, true);
        }
    }

    private function getCachedStats() {
        $now = time();
        $cacheTtl = $this->config->cache_stats_seconds;
        
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

        while (($line = fgets($handle)) !== false && $interfaceCount < $this->config->max_interfaces) {
            $line = trim($line);
            if (empty($line)) continue;

            if (preg_match('/^(\S+?):\s*(.*)$/', $line, $matches)) {
                try {
                    $iface = $this->validateInterfaceName($matches[1]);
                } catch (InvalidArgumentException $e) {
                    continue;
                }
                
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
        if ($this->config->units === 'decimal') {
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
        if ($this->config->units === 'decimal') {
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
        
        if ($this->config->show_gateway && $gatewayInfo) {
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
        
        if (function_exists('pcntl_async_signals')) {
            pcntl_async_signals(true);
        } else {
            declare(ticks=1);
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
            
            if ($totalPackets > 1000 && $totalPackets > 0 && ($totalErrors / $totalPackets) > $this->config->alert_threshold) {
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
        switch ($this->config->sort_by) {
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
            $avgInfo = $this->config->show_averages ? 
                sprintf(" [Avg: %s/%s]", $this->formatRate($avgRates['rx']), $this->formatRate($avgRates['tx'])) : "";

            $details = $this->getInterfaceDetails($name);
            $detailsInfo = "";
            if ($this->config->show_details && !empty($details)) {
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
            
            if ($this->config->show_errors && ($data['rxErrs'] > 0 || $data['txErrs'] > 0)) {
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
        
        if ($this->config->show_gateway && $gateway) {
            printf(" | Gateway: %s%s%s",
                $this->colorCyan, $gateway['ip'], $this->colorReset);
        }
        
        printf(" | %s\n", date('H:i:s'));
        
        echo $this->colorGrey . "[ctrl+c to stop]" . $this->colorReset . "\n";
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
                        echo "  ALERT: $issue\n";
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

            if ($displayed >= $this->config->max_interfaces) {
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
        
        if ($this->config->show_gateway && $gateway) {
            printf("%sDefault Gateway: %s via %s%s\n",
                $this->colorCyan, $gateway['ip'], $gateway['interface'], $this->colorReset);
        }
        
        echo $this->colorGrey . "Invoke with --watch for live view." . $this->colorReset . "\n";
    }

    private function handleOptions($options) {
        $configUpdates = [];
        
        if (isset($options['debug'])) {
            $this->debug = true;
        }

        if (isset($options['interval'])) {
            $configUpdates['interval'] = $this->validateNumericValue($options['interval'], 'interval');
        }

        if (isset($options['no-loopback'])) {
            $configUpdates['show_loopback'] = false;
        }

        if (isset($options['show-inactive'])) {
            $configUpdates['show_inactive'] = true;
        }

        if (isset($options['units']) && in_array($options['units'], ['binary', 'decimal'])) {
            $configUpdates['units'] = $options['units'];
        }

        if (isset($options['sort-by']) && in_array($options['sort-by'], ['rx_rate', 'tx_rate', 'name'])) {
            $configUpdates['sort_by'] = $options['sort-by'];
        }

        if (isset($options['show-details'])) {
            $configUpdates['show_details'] = true;
        }

        if (isset($options['show-gateway'])) {
            $configUpdates['show_gateway'] = true;
        }

        if (!empty($configUpdates)) {
            $this->config = new NetworkMonitorConfig(array_merge(get_object_vars($this->config), $configUpdates));
            $this->validateConfig();
        }
    }

    public function run() {
        try {
            $options = getopt('', ['watch', 'interval:', 'debug', 'no-loopback', 'show-inactive', 'units:', 'sort-by:', 'show-details', 'show-gateway']);
            
            $this->handleOptions($options);

            if (isset($options['watch'])) {
                $this->watch($this->config->interval);
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
