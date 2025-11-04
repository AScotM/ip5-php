#!/usr/bin/php
<?php

class NetworkMonitor {
    private $colorReset = "\033[0m";
    private $colorGrey = "\033[38;5;245m";
    private $colorBlue = "\033[34m";
    private $colorGreen = "\033[32m";
    private $colorRed = "\033[31m";
    private $colorYellow = "\033[33m";
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

    private const MAX_HISTORY = 5;
    private const MAX_INTERVAL = 3600;
    private const MIN_INTERVAL = 0.1;
    private const MAX_INTERFACES = 1000;
    private const DEFAULT_CACHE_TTL = 5;

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
            'alert_threshold' => 0.01
        ], $config);
        
        $this->validateConfig();
    }

    private function validateConfig() {
        if ($this->config['interval'] < self::MIN_INTERVAL || $this->config['interval'] > self::MAX_INTERVAL) {
            throw new InvalidArgumentException(
                "Interval must be between " . self::MIN_INTERVAL . " and " . self::MAX_INTERVAL
            );
        }
        
        if ($this->config['max_interfaces'] > self::MAX_INTERFACES) {
            throw new InvalidArgumentException(
                "Max interfaces cannot exceed " . self::MAX_INTERFACES
            );
        }
    }

    private function safeFileRead($path) {
        if (!file_exists($path)) {
            throw new RuntimeException("File does not exist: $path");
        }
        
        if (!is_readable($path)) {
            throw new RuntimeException("File is not readable: $path");
        }
        
        $content = file_get_contents($path);
        if ($content === false) {
            throw new RuntimeException("Failed to read file: $path");
        }
        
        return $content;
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

    private function getInterfaceIPs() {
        $now = time();
        if ($this->ipCache !== null && $this->cacheTime !== null && 
            ($now - $this->cacheTime) < $this->config['cache_ips_seconds']) {
            return $this->ipCache;
        }

        $ips = [];
        $result = @shell_exec('/sbin/ip -o -4 addr show 2>/dev/null');
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
        return $ifaceName === 'lo' || 
               (isset($ifaceData['flags']) && in_array('loopback', $ifaceData['flags']));
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
        $operstatePath = "/sys/class/net/$ifaceName/operstate";
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
        $details = [];
        
        $speedPath = "/sys/class/net/$ifaceName/speed";
        if (file_exists($speedPath)) {
            $speed = trim(file_get_contents($speedPath));
            if (is_numeric($speed) && $speed > 0) {
                $details['speed'] = $speed . ' Mbps';
            }
        }
        
        $mtuPath = "/sys/class/net/$ifaceName/mtu";
        if (file_exists($mtuPath)) {
            $mtu = trim(file_get_contents($mtuPath));
            if (is_numeric($mtu)) {
                $details['mtu'] = $mtu;
            }
        }
        
        return $details;
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

    private function header() {
        echo $this->clearScreen;
        echo $this->colorBlue . "Network Interface Monitor" . $this->colorReset . "\n";
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
        
        declare(ticks=1);
        pcntl_signal(SIGINT, [$this, 'signalHandler']);
        pcntl_signal(SIGTERM, [$this, 'signalHandler']);
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
        $max32 = 4294967295;
        $max64 = 18446744073709551615;
        
        if ($curr >= $prev) {
            return $curr - $prev;
        } else {
            if ($prev > $max32) {
                return ($max64 - $prev) + $curr + 1;
            } else {
                return ($max32 - $prev) + $curr + 1;
            }
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

        $rxAvg = array_sum($this->rateHistory[$ifaceName]['rx']) / 
                 count($this->rateHistory[$ifaceName]['rx']);
        $txAvg = array_sum($this->rateHistory[$ifaceName]['tx']) / 
                 count($this->rateHistory[$ifaceName]['tx']);

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

        foreach ($deltas as $data) {
            $metrics['total_rx_rate'] += $data['rxRate'];
            $metrics['total_tx_rate'] += $data['txRate'];
            $metrics['peak_rx_rate'] = max($metrics['peak_rx_rate'], $data['rxRate']);
            $metrics['peak_tx_rate'] = max($metrics['peak_tx_rate'], $data['txRate']);
            
            if ($data['rxRate'] > 0 || $data['txRate'] > 0) {
                $metrics['active_interfaces']++;
            }
            
            $this->updateRateHistory($data['name'], $data['rxRate'], $data['txRate']);
        }

        return $metrics;
    }

    private function detectNetworkIssues($deltas) {
        $issues = [];
        
        foreach ($deltas as $name => $data) {
            $totalPackets = $data['rxPackets'] + $data['txPackets'];
            $totalErrors = $data['rxErrs'] + $data['txErrs'];
            
            if ($totalPackets > 1000 && ($totalErrors / $totalPackets) > $this->config['alert_threshold']) {
                $issues[] = "High error rate on $name: " . 
                           round(($totalErrors / $totalPackets) * 100, 2) . "%";
            }
            
            $state = $this->getInterfaceStateCached($name);
            if ($state !== 'up' && ($data['rxBytes'] > 0 || $data['txBytes'] > 0)) {
                $issues[] = "Interface $name is down but previously had traffic";
            }
        }
        
        return $issues;
    }

    private function displayEnhancedDeltas($deltas) {
        $ipMap = $this->getInterfaceIPs();
        $metrics = $this->calculateAdvancedMetrics($deltas);
        
        uasort($deltas, function($a, $b) {
            return $b['rxRate'] <=> $a['rxRate'];
        });

        foreach ($deltas as $name => $data) {
            $ips = $ipMap[$name] ?? [];
            $ipInfo = !empty($ips) ? " [" . implode(', ', $ips) . "]" : "";
            
            $state = $this->getInterfaceStateCached($name);
            $stateColor = $state === 'up' ? $this->colorGreen : $this->colorRed;
            $stateDisplay = $state !== 'unknown' ? " $stateColor$state$this->colorReset" : "";
            
            $avgRates = $this->getAverageRates($name);
            $avgInfo = sprintf(" [Avg: %s/%s]", 
                $this->formatRate($avgRates['rx']),
                $this->formatRate($avgRates['tx'])
            );

            printf("%s%12s%s%s%s\n",
                $this->colorBlue, $name, $this->colorReset, $ipInfo, $stateDisplay);
            
            printf("  RX: %s%-12s%s TX: %s%-12s%s%s\n",
                $this->colorGreen, $this->formatRate($data['rxRate']), $this->colorReset,
                $this->colorYellow, $this->formatRate($data['txRate']), $this->colorReset,
                $this->colorGrey . $avgInfo . $this->colorReset);
            
            if ($this->config['show_errors'] && ($data['rxErrs'] > 0 || $data['txErrs'] > 0)) {
                printf("  %sErrors: RX%.0f TX%.0f Drop: RX%.0f TX%.0f%s\n",
                    $this->colorRed, $data['rxErrs'], $data['txErrs'], 
                    $data['rxDrop'], $data['txDrop'], $this->colorReset);
            }
            
            echo "\n";
        }
        
        $this->displaySummary($metrics, count($deltas));
    }

    private function displaySummary($metrics, $interfaceCount) {
        echo $this->colorGrey . str_repeat("─", 60) . $this->colorReset . "\n";
        printf("Summary: %d interfaces (%d active) | Total: %s/s RX, %s/s TX\n",
            $interfaceCount, $metrics['active_interfaces'],
            $this->formatRate($metrics['total_rx_rate']),
            $this->formatRate($metrics['total_tx_rate']));
        
        printf("Peak: %s/s RX, %s/s TX | %s\n",
            $this->formatRate($metrics['peak_rx_rate']),
            $this->formatRate($metrics['peak_tx_rate']),
            date('H:i:s'));
        
        echo $this->colorGrey . "[ctrl+c to stop]" . $this->colorReset . "\n";
    }

    private function getSystemLoad() {
        if (file_exists('/proc/loadavg')) {
            $load = file_get_contents('/proc/loadavg');
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
                $sleepTime *= 0.5;
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
                 ($i + 1) * (100 / $sleepSteps) . "%" . $this->colorReset;
            usleep((int)$stepDuration);
        }
        echo "\r" . str_repeat(' ', 50) . "\r";
    }

    public function watch($interval) {
        $this->log("Starting watch mode with interval: {$interval}s");
        
        $this->setupSignalHandlers();
        $iteration = 0;
        $startTime = time();

        try {
            $prev = $this->parseProcNetDev();
        } catch (Exception $e) {
            throw new RuntimeException("Failed to initialize monitoring: " . $e->getMessage());
        }

        while (!$this->shouldExit) {
            $iteration++;
            $currentTime = time();
            $uptime = $currentTime - $startTime;
            
            $this->header();
            printf("Uptime: %ds | Iteration: %d | %s\n\n", 
                   $uptime, $iteration, date('Y-m-d H:i:s'));

            try {
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
        
        $this->header();
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
            
            $state = $this->getInterfaceStateCached($s['name']);
            $stateColor = $state === 'up' ? $this->colorGreen : $this->colorRed;
            $stateDisplay = $state !== 'unknown' ? " [$stateColor$state$this->colorReset]" : "";
            
            $details = $this->getInterfaceDetails($s['name']);
            $detailsInfo = "";
            if (!empty($details)) {
                $detailsInfo = " (" . implode(', ', $details) . ")";
            }
            
            echo $this->colorBlue . $s['name'] . $this->colorReset . $stateDisplay . $detailsInfo . $ipInfo . "\n";
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
            $options = getopt('', ['watch', 'interval:', 'debug', 'no-loopback', 'show-inactive', 'units:', 'sort-by:']);
            
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

            $this->validateConfig();

            if (isset($options['watch'])) {
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
    $monitor = new NetworkMonitor();
    $monitor->run();
} catch (Exception $e) {
    echo "Fatal Error: " . $e->getMessage() . "\n";
    exit(1);
}
