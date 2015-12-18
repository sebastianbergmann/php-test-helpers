--TEST--
Redefine a class constant
--FILE--
<?php
class A {
    const A = 'foo';
}

var_dump(A::A);
try {
    var_dump(A::B);
} catch (Throwable $t) {
    echo "Class Constant B is not defined\n\n";
}

redefine_constant('A::A', 'bar');
redefine_constant('A::B', 'bat');

var_dump(A::A);
var_dump(A::B);
--EXPECT--
string(3) "foo"
Class Constant B is not defined

string(3) "bar"
string(3) "bat"
