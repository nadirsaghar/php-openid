<?php

error_reporting(E_STRICT | E_ALL);

require_once('PHPUnit.php');
require_once('PHPUnit/GUI/HTML.php');

/**
 * Load the tests that are defined in the named modules.
 *
 * @param test_dir: The root of the test hierarchy. Must end with a /
 *
 * @param test_names: The names of the modules in which the tests are
 *     defined. This should not include the root of the test hierarchy.
 *
 * If you have Tests/Foo.php which defines a test class called Tests_Foo, the
 * call would look like:
 *
 * loadTests('Tests/', array('Foo'))
 */
function loadTests($test_dir, $test_names) {
    $suites = array();

    foreach ($test_names as $filename) {
        $filename = $test_dir . $filename . '.php';
        $class_name = str_replace(DIRECTORY_SEPARATOR, '_', $filename);
        $class_name = basename($class_name, '.php');
        include_once($filename);
        $test = new $class_name($class_name);
        if (is_a($test, 'PHPUnit_TestCase')) {
            $test = new PHPUnit_TestSuite($class_name);
        }
        $suites[] = $test;
    }

    return $suites;
}

$_test_dir = 'Tests/Net/OpenID/';
$_test_names = array(
    'KVForm',
    'CryptUtil',
    'DiffieHellman',
    'HMACSHA1',
    );

// Load OpenID library tests
function loadSuite() {
    global $_test_names;
    global $_test_dir;
    return loadTests($_test_dir, $_test_names);
}
?>