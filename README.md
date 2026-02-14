# Log Analyzer (Failed Login Detection)



## Overview

This project analyzes an authentication log and flags IP addresses that exceed a failed-login threshold. Simulating basic SOC-style alerting workflow.



## Features

- Parses a log file (`sample\_auth.log`)

- Counts failed login attempts per IP

- Flags suspicious IPs at a configurable threshold



## What I Learned

- Parsing text logs safely

- Counting events with `collections.Counter`

- Building detection logic with thresholds



## Notes

This is a learning project using a sample log format. A real implementation would support multiple log formats and include timestamps, users, and alert export.



