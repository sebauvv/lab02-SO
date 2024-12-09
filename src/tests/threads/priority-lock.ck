# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(priority-lock) begin
(priority-lock) main thread acquires the lock.
(priority-lock) Thread priority 23 starting.
(priority-lock) Thread priority 22 starting.
(priority-lock) Thread priority 21 starting.
(priority-lock) Thread priority 30 starting.
(priority-lock) Thread priority 29 starting.
(priority-lock) Thread priority 28 starting.
(priority-lock) Thread priority 27 starting.
(priority-lock) Thread priority 26 starting.
(priority-lock) Thread priority 25 starting.
(priority-lock) Thread priority 24 starting.
(priority-lock) main thread releases the lock.
(priority-lock) Thread priority 30 acquires the lock.
(priority-lock) Thread priority 29 acquires the lock.
(priority-lock) Thread priority 28 acquires the lock.
(priority-lock) Thread priority 27 acquires the lock.
(priority-lock) Thread priority 26 acquires the lock.
(priority-lock) Thread priority 25 acquires the lock.
(priority-lock) Thread priority 24 acquires the lock.
(priority-lock) Thread priority 23 acquires the lock.
(priority-lock) Thread priority 22 acquires the lock.
(priority-lock) Thread priority 21 acquires the lock.
(priority-lock) end
EOF
pass;
