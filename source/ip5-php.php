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

    private function getInterfaceIPs() {
        $now = time();
        if ($this->ipCache !== null && $this->cacheTime !== null && 
            ($now - $this->cacheTime) < $this->config['cache_ips_seconds']) {
            return $this->ipCache;
        }

        $ips = [];
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

    private function parseProcNetDev() {
        $stats = [];
        
        if (!file_exists('/proc/net/dev')) {
            throw new RuntimeException('/proc/net/dev does not exist');
        }

        if (!is_readable('/proc/net/dev')) {
            throw new RuntimeException('/proc/net/dev is not readable');
        }

        $content = file_get_contents('/proc/net/dev');
        if ($content === false) {
            throw new RuntimeException('Failed to read /proc/net/dev');
        }

        $lines = explode("\n", $content);
        $interfaceCount = 0;

        for ($i = 2; $i < count($lines); $i++) {
            if ($interfaceCount >= $this->config['max_interfaces']) {
                break;
            }

            $line = trim($lines[$i]);
            if (empty($line)) {
                continue;
            }

            $parts = preg_split('/\s+/', $line);
            if (count($parts) < 12) {
                continue;
            }

            $iface = rtrim($parts[0], ':');
            
            try {
                $stats[$iface] = [
                    'name' => $iface,
                    'rxBytes' => $this->validateNumericValue($parts[1], 'rxBytes'),
                    'rxPackets' => $this->validateNumericValue($parts[2], 'rxPackets'),
                    'rxErrs' => $this->validateNumericValue($parts[3], 'rxErrs'),
                    'txBytes' => $this->validateNumericValue($parts[9], 'txBytes'),
                    'txPackets' => $this->validateNumericValue($parts[10], 'txPackets'),
                    'txErrs' => $this->validateNumericValue($parts[11], 'txErrs')
                ];
                $interfaceCount++;
            } catch (InvalidArgumentException $e) {
                $this->log("Invalid data for interface $iface: " . $e->getMessage());
                continue;
            }
        }

        if (empty($stats)) {
            throw new RuntimeException('No valid interface data found in /proc/net/dev');
        }

        return $stats;
    }

    private function formatBytes($bytes) {
        $units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
        $i = 0;
        $val = $bytes;
        
        while ($val >= 1024 && $i < count($units) - 1) {
            $val /= 1024;
            $i++;
        }
        
        return sprintf('%.1f%s', $val, $units[$i]);
    }

    private function formatRate($rate) {
        $units = ['B/s', 'KiB/s', 'MiB/s', 'GiB/s', 'TiB/s'];
        $i = 0;
        $val = $rate;
        
        while ($val >= 1024 && $i < count($units) - 1) {
            $val /= 1024;
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
                'txBytes' => $now['txBytes']
            ];
        }
        
        return $deltas;
    }

    private function calculateCounterDelta($prev, $curr) {
        if ($curr >= $prev) {
            return $curr - $prev;
        } else {
            return (PHP_FLOAT_MAX - $prev) + $curr;
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

            printf("%s%10s%s%s :: RX %s%-12s%s TX %s%-12s%s\n",
                $this->colorBlue, $name, $this->colorReset, $ipInfo,
                $this->colorGreen, $this->formatRate($data['rxRate']), $this->colorReset,
                $this->colorYellow, $this->formatRate($data['txRate']), $this->colorReset);
        }
        
        echo "\n";
        echo $this->colorGrey . "[ctrl+c to stop]" . $this->colorReset . "\n";
    }

    public function watch($interval) {
        $this->log("Starting watch mode with interval: {$interval}s");
        
        declare(ticks=1);
        pcntl_signal(SIGINT, [$this, 'signalHandler']);
        pcntl_signal(SIGTERM, [$this, 'signalHandler']);

        $intervalMicros = (int)($interval * 1000000);

        try {
            $prev = $this->parseProcNetDev();
        } catch (Exception $e) {
            throw new RuntimeException("Failed to initialize monitoring: " . $e->getMessage());
        }

        $this->header();

        while (!$this->shouldExit) {
            $start = microtime(true);
            
            try {
                $curr = $this->parseProcNetDev();
                $deltas = $this->calculateDelta($prev, $curr, $interval);
                $this->header();
                $this->displayDeltas($deltas);
                $prev = $curr;
            } catch (Exception $e) {
                $this->log("Monitoring error: " . $e->getMessage());
                echo $this->colorRed . "Read error: " . $e->getMessage() . $this->colorReset . "\n";
            }

            if ($this->shouldExit) break;

            $elapsed = microtime(true) - $start;
            $sleepTime = $intervalMicros - ($elapsed * 1000000);
            
            if ($sleepTime > 0) {
                usleep((int)$sleepTime);
            }
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
            
            echo $this->colorBlue . $s['name'] . $this->colorReset . $ipInfo . "\n";
            printf("    RX: %s%s%s (%.0f pkts, %.0f errs)\n",
                $this->colorGreen, $this->formatBytes($s['rxBytes']), $this->colorReset,
                $s['rxPackets'], $s['rxErrs']);
            printf("    TX: %s%s%s (%.0f pkts, %.0f errs)\n\n",
                $this->colorYellow, $this->formatBytes($s['txBytes']), $this->colorReset,
                $s['txPackets'], $s['txErrs']);
            
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
            $options = getopt('', ['watch', 'interval:', 'debug', 'no-loopback', 'show-inactive']);
            
            $this->handleOptions($options);
            
            if (isset($options['show-inactive'])) {
                $this->config['show_inactive'] = true;
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
}

try {
    $monitor = new NetworkMonitor();
    $monitor->run();
} catch (Exception $e) {
    echo "Fatal Error: " . $e->getMessage() . "\n";
    exit(1);
}
