--TEST--
set_class_overload() overloads instantiation of existing and nonexisting classes
--SKIPIF--
<?php 
if (!extension_loaded('test_helpers')) die('skip test_helpers extension not loaded');
?>
--FILE--
<?php

class MyTest { }
class MyClass { }

// Regular instantiation, existing class
$c = new MyClass;
echo get_class($c), PHP_EOL;

// Overloaded instantiation, existing class
function test_overload() { return 'MyTest'; }
set_class_overload('test_overload');

$c = new MyClass;
echo get_class($c), PHP_EOL;

// Overloaded instantiation, nonexisting class
$c = new IDontExist;
echo get_class($c), PHP_EOL;

--EXPECT--
MyClass
MyTest
MyTest