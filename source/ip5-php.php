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
    private const MAX_HISTORY = 5;

    public function __construct(array $config = []) {
        $this->config = array_merge([
            'interval' => 1.0,
            'show_loopback' => false,
            'show_inactive' => false,
            'max_interfaces' => 50,
            'units' => 'binary',
            'cache_ips_seconds' => 5
        ], $config);
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
        if (file_exists($operstatePath)) {
            return trim(file_get_contents($operstatePath));
        }
        return 'unknown';
    }

    private function parseProcNetDev() {
        $stats = [];
        
        if (!file_exists('/proc/net/dev')) {
            throw new RuntimeException('/proc/net/dev does not exist');
        }

        if (!is_readable('/proc/net/dev')) {
            throw new RuntimeException('/proc/net/dev is not readable');
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
                'txErrs' => $now['txErrs']
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

    private function displayDeltas($deltas) {
        $ipMap = $this->getInterfaceIPs();
        
        foreach ($deltas as $name => $data) {
            $ips = $ipMap[$name] ?? [];
            $ipInfo = "";
            if (!empty($ips)) {
                $ipInfo = " [" . implode(', ', $ips) . "]";
            }

            $state = $this->getInterfaceState($name);
            $stateColor = $state === 'up' ? $this->colorGreen : $this->colorRed;
            $stateDisplay = $state !== 'unknown' ? " $stateColor$state$this->colorReset" : "";

            printf("%s%10s%s%s%s :: RX %s%-12s%s TX %s%-12s%s\n",
                $this->colorBlue, $name, $this->colorReset, $ipInfo, $stateDisplay,
                $this->colorGreen, $this->formatRate($data['rxRate']), $this->colorReset,
                $this->colorYellow, $this->formatRate($data['txRate']), $this->colorReset);
        }
        
        echo "\n";
        echo $this->colorGrey . "[ctrl+c to stop]" . $this->colorReset . "\n";
    }

    public function watch($interval) {
        $this->log("Starting watch mode with interval: {$interval}s");
        
        $this->setupSignalHandlers();
        $intervalMicros = (int)($interval * 1000000);

        try {
            $prev = $this->parseProcNetDev();
            $this->manageHistory($prev);
        } catch (Exception $e) {
            throw new RuntimeException("Failed to initialize monitoring: " . $e->getMessage());
        }

        $this->header();

        while (!$this->shouldExit) {
            $start = microtime(true);
            
            try {
                $curr = $this->parseProcNetDev();
                $deltas = $this->calculateDelta($prev, $curr, $interval);
                $this->manageHistory($curr);
                $this->header();
                $this->displayDeltas($deltas);
                $prev = $curr;
            } catch (Exception $e) {
                $this->log("Monitoring error: " . $e->getMessage());
                echo $this->colorRed . "Read error: " . $e->getMessage() . $this->colorReset . "\n";
            }

            if ($this->shouldExit) break;

            $this->adaptiveSleep($interval, $start);
        }

        echo "\n" . $this->colorGrey . "Exiting..." . $this->colorReset . "\n";
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
            
            $state = $this->getInterfaceState($s['name']);
            $stateColor = $state === 'up' ? $this->colorGreen : $this->colorRed;
            $stateDisplay = $state !== 'unknown' ? " [$stateColor$state$this->colorReset]" : "";
            
            echo $this->colorBlue . $s['name'] . $this->colorReset . $stateDisplay . $ipInfo . "\n";
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
            $options = getopt('', ['watch', 'interval:', 'debug', 'no-loopback', 'show-inactive', 'units:']);
            
            $this->handleOptions($options);
            
            if (isset($options['show-inactive'])) {
                $this->config['show_inactive'] = true;
            }

            if (isset($options['units']) && in_array($options['units'], ['binary', 'decimal'])) {
                $this->config['units'] = $options['units'];
            }

            if ($this->config['interval'] <= 0) {
                throw new InvalidArgumentException("Interval must be positive");
            }

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
