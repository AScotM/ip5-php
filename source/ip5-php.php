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

    private function getInterfaceIPs() {
        $ips = [];
        $interfaces = @net_get_interfaces();
        if (!$interfaces) {
            return $ips;
        }

        foreach ($interfaces as $ifaceName => $ifaceData) {
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
        return $ips;
    }

    private function isLoopback($ip) {
        return substr($ip, 0, 4) === '127.' || $ip === '::1';
    }

    private function parseProcNetDev() {
        $stats = [];
        
        if (!file_exists('/proc/net/dev')) {
            return $stats;
        }

        $lines = file('/proc/net/dev', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) {
            return $stats;
        }

        for ($i = 2; $i < count($lines); $i++) {
            $line = trim($lines[$i]);
            if (empty($line)) {
                continue;
            }

            $parts = preg_split('/\s+/', $line);
            if (count($parts) < 12) {
                continue;
            }

            $iface = rtrim($parts[0], ':');
            $stats[$iface] = [
                'name' => $iface,
                'rxBytes' => (float)$parts[1],
                'rxPackets' => (float)$parts[2],
                'rxErrs' => (float)$parts[3],
                'txBytes' => (float)$parts[9],
                'txPackets' => (float)$parts[10],
                'txErrs' => (float)$parts[11]
            ];
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

    private function delta($prev, $curr, $interval) {
        $ipMap = $this->getInterfaceIPs();
        
        foreach ($curr as $name => $now) {
            if (!isset($prev[$name])) {
                continue;
            }
            
            $pr = $prev[$name];
            
            if ($now['rxBytes'] >= $pr['rxBytes']) {
                $rxDelta = $now['rxBytes'] - $pr['rxBytes'];
            } else {
                $rxDelta = (PHP_INT_MAX - $pr['rxBytes']) + $now['rxBytes'] + 1;
            }
            
            if ($now['txBytes'] >= $pr['txBytes']) {
                $txDelta = $now['txBytes'] - $pr['txBytes'];
            } else {
                $txDelta = (PHP_INT_MAX - $pr['txBytes']) + $now['txBytes'] + 1;
            }

            $rxRate = $rxDelta / $interval;
            $txRate = $txDelta / $interval;

            $ipInfo = "";
            if (isset($ipMap[$name]) && !empty($ipMap[$name])) {
                $ipInfo = " [" . implode(', ', $ipMap[$name]) . "]";
            }

            printf("%s%10s%s%s :: RX %s%-12s%s TX %s%-12s%s\n",
                $this->colorBlue, $name, $this->colorReset, $ipInfo,
                $this->colorGreen, $this->formatRate($rxRate), $this->colorReset,
                $this->colorYellow, $this->formatRate($txRate), $this->colorReset);
        }
        
        echo "\n";
        echo $this->colorGrey . "[ctrl+c to stop]" . $this->colorReset . "\n";
    }

    public function watch($interval) {
        declare(ticks=1);
        pcntl_signal(SIGINT, function() {
            echo "\n" . $this->colorGrey . "Exiting..." . $this->colorReset . "\n";
            exit(0);
        });

        $prev = $this->parseProcNetDev();
        if (empty($prev)) {
            echo $this->colorRed . "Failed to read /proc/net/dev" . $this->colorReset . "\n";
            exit(1);
        }

        $this->header();

        while (true) {
            sleep($interval);
            $curr = $this->parseProcNetDev();
            if (empty($curr)) {
                echo $this->colorRed . "Read error" . $this->colorReset . "\n";
                continue;
            }
            
            $this->header();
            $this->delta($prev, $curr, $interval);
            $prev = $curr;
        }
    }

    public function run() {
        $options = getopt('', ['watch', 'interval:']);
        $watchMode = isset($options['watch']);
        $interval = isset($options['interval']) ? (float)$options['interval'] : 1.0;

        if ($interval <= 0) {
            echo $this->colorRed . "Interval must be positive" . $this->colorReset . "\n";
            exit(1);
        }

        if (!$watchMode) {
            $this->header();
            $stats = $this->parseProcNetDev();
            if (empty($stats)) {
                echo $this->colorRed . "Failed to read network statistics" . $this->colorReset . "\n";
                exit(1);
            }
            
            $ipMap = $this->getInterfaceIPs();
            
            foreach ($stats as $s) {
                $ipInfo = "";
                if (isset($ipMap[$s['name']]) && !empty($ipMap[$s['name']])) {
                    $ipInfo = " - " . $this->colorGrey . implode(', ', $ipMap[$s['name']]) . $this->colorReset;
                }
                
                echo $this->colorBlue . $s['name'] . $this->colorReset . $ipInfo . "\n";
                printf("    RX: %s%s%s (%.0f pkts, %.0f errs)\n",
                    $this->colorGreen, $this->formatBytes($s['rxBytes']), $this->colorReset,
                    $s['rxPackets'], $s['rxErrs']);
                printf("    TX: %s%s%s (%.0f pkts, %.0f errs)\n\n",
                    $this->colorYellow, $this->formatBytes($s['txBytes']), $this->colorReset,
                    $s['txPackets'], $s['txErrs']);
            }
            
            echo $this->colorGrey . "Invoke with --watch for live view." . $this->colorReset . "\n";
            return;
        }
        
        $this->watch($interval);
    }
}

$monitor = new NetworkMonitor();
$monitor->run();
