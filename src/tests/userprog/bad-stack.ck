# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(bad-stack) begin
bad-stack: exit(-1)
EOF
pass;
