--TEST--
set_class_overload() overloads work when accessing class constants
--SKIPIF--
<?php 
if (!extension_loaded('test_helpers')) die('skip test_helpers extension not loaded');
?>
--FILE--
<?php

class MyTest { const MY_CLASS_CONSTANT = "test constant"; }
class MyClass { const MY_CLASS_CONSTANT = "class constant"; }

// Regular constant 
echo MyClass::MY_CLASS_CONSTANT, PHP_EOL;

// Overloaded
function test_overload() { return 'MyTest'; }
set_class_overload('test_overload');

echo MyClass::MY_CLASS_CONSTANT;
--EXPECT--
class constant
test constant