--TEST--
Redefine a constant
--FILE--
<?php
const A = 'foo';

var_dump(\A);
try {
    var_dump(\B);
} catch (Throwable $t) {
    echo "Class B is not defined\n\n";
}

redefine_constant('A', 'bar');
redefine_constant('A', 'bat');

var_dump(A);
var_dump(A);
--EXPECT--
string(3) "foo"
Class B is not defined

string(3) "bat"
string(3) "bat"
