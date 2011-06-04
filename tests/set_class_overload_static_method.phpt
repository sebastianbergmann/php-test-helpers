--TEST--
set_class_overload() overloads calling of static methods
--SKIPIF--
<?php 
if (!extension_loaded('test_helpers')) die('skip test_helpers extension not loaded');
?>
--FILE--
<?php

class MyTest {
	public static function testMethod() { echo "I am MyTest::testMethod()", PHP_EOL; }
}
class MyClass {
	public static function testMethod() { echo "I am MyClass::testMethod()", PHP_EOL;}
}

// Regular static method call
MyClass::testMethod();

// Overloaded call, existing class
function test_overload() { return 'MyTest'; }
set_class_overload('test_overload');

MyClass::testMethod();

// Overloaded dynamic call, existing class
$x = 'MyClass';
$x::testMethod();

--EXPECT--
I am MyClass::testMethod()
I am MyTest::testMethod()
I am MyTest::testMethod()
