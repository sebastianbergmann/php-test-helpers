--TEST--
set_new_overload() should be able to handle dynamic class names during creation
--SKIPIF--
<?php
if (!extension_loaded('test_helpers')) die('skip test_helpers extension not loaded');
?>
--FILE--
<?php

class X { }
class Y { }

set_new_overload(function() {
    return 'Y';
});

$x = 'X';
echo get_class(new X())  . PHP_EOL;
echo get_class(new $x()) . PHP_EOL;
--EXPECTF--
Y
Y
