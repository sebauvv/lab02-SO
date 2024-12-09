# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(good-stack) begin
(good-stack) end
good-stack: exit(0)
EOF
pass;
