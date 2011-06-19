--TEST--
restore_internal_functions() resets internal functions after renaming an internal function
--SKIPIF--
<?php 
if (!extension_loaded('test_helpers')) die('skip test_helpers extension not loaded');
?>
--FILE--
<?php

function my_date($format, $time=NULL)
{
	return "FORMAT: $format";
}

rename_function('date', 'date_old');
rename_function('my_date', 'date');

echo date('Y-m-d'), PHP_EOL;

restore_internal_functions();

echo date('Y-m-d', strtotime("2011-02-14 12:00")), PHP_EOL;

--EXPECT--
FORMAT: Y-m-d
2011-02-14
