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

// Overloaded instantiation, existing class
function test_overload() { return 'MyTest'; }
set_class_overload('test_overload');

MyClass::testMethod();

// Reset behaviour
unset_class_overload();

MyClass::testMethod();

--EXPECT--
I am MyClass::testMethod()
I am MyTest::testMethod()
I am MyClass::testMethod()
