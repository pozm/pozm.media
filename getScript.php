<?php


    $sent = null;
    if (array_key_exists('script',$_GET)) $sent = $_GET['script'];

    if (!$sent) {return;}

    $exists = glob('./'. $sent . '.*');

    $whiteList = ['.txt','.lua','.js'];

    if ($exists && in_array( substr($exists[0], strrpos($exists[0],'.')),$whiteList) ) {

        //echo $exists[0]
        readfile($exists[0]);

    }

?>