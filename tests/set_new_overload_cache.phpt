--TEST--
set_new_overload() make sure that when overloading new we don't return the wrong class after unsetting
--SKIPIF--
<?php
if (!extension_loaded('test_helpers')) die('skip test_helpers extension not loaded');
?>
--FILE--
<?php
class X { }
class Y { }

function returnX() {
    return new X;
}

echo get_class(returnX())  . PHP_EOL;
set_new_overload(function($class) {
    return 'Y';
});
echo get_class(returnX())  . PHP_EOL;
unset_new_overload();
echo get_class(returnX())  . PHP_EOL;
--EXPECT--
X
Y
X
