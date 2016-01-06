--TEST--
set_new_overload() should be able to handle static class names during creation
--SKIPIF--
<?php
if (!extension_loaded('test_helpers')) die('skip test_helpers extension not loaded');
?>
--FILE--
<?php

class X {
    public static function create() {
	$var = new static();
	var_dump($var);
    }
}

class Y extends X { }

set_new_overload(function($classname) {
    var_dump($classname);
    return $classname;
});

X::create();
Y::create();
--EXPECT--
string(1) "X"
object(X)#2 (0) {
}
string(1) "Y"
object(Y)#2 (0) {
}
