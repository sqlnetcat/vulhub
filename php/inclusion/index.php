<?php
$a = @$_GET['file'];
echo 'include $_GET[\'file\']';
if (strpos($a,'flag')!==false) {
die('_POST');
}
include $a;
?>
