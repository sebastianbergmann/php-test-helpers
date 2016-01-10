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

echo get_class(returnX()) . ' was created' . PHP_EOL;
set_new_overload(function($class) {
    echo $class . ' was passed' . PHP_EOL;
    return 'Y';
});
echo get_class(returnX()) . ' was created' . PHP_EOL;
echo get_class(returnX()) . ' was created' . PHP_EOL;
unset_new_overload();
echo get_class(returnX()) . ' was created' . PHP_EOL;
--EXPECT--
X was created
X was passed
Y was created
X was passed
Y was created
X was created
