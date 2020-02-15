<?php
$a = @$_GET['dir'];
if(!$a){
$a = '/tmp';
}
var_dump(scandir($a));
