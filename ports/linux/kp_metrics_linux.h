#pragma once

// Test hook of the Linux metrics port. Not installed.

// Read /proc and /sys below `root` instead of "/". Resets the CPU baseline.
void kp_linux_metrics_set_root(const char* root);
