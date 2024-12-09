# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(good-stack-2) begin
(good-stack-2) end
good-stack-2: exit(0)
EOF
pass;
