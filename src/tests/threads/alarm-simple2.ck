# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(alarm-simple2) begin
(alarm-simple2) Creating 1 threads to sleep 7 times each.
(alarm-simple2) Thread 0 sleeps 10 ticks each time,
(alarm-simple2) thread 1 sleeps 20 ticks each time, and so on.
(alarm-simple2) If successful, product of iteration count and
(alarm-simple2) sleep duration will appear in nondescending order.
(alarm-simple2) thread 0: duration=10, iteration=1, product=10
(alarm-simple2) thread 0: duration=10, iteration=2, product=20
(alarm-simple2) thread 0: duration=10, iteration=3, product=30
(alarm-simple2) thread 0: duration=10, iteration=4, product=40
(alarm-simple2) thread 0: duration=10, iteration=5, product=50
(alarm-simple2) thread 0: duration=10, iteration=6, product=60
(alarm-simple2) thread 0: duration=10, iteration=7, product=70
(alarm-simple2) end
EOF
pass;
