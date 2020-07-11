<?php


    $sent = null;
    if (array_key_exists('script',$_GET)) $sent = $_GET['script'];

    if (!$sent) {return;}

    $exists = glob('./'. $sent . '.*');

    $whiteList = ['JSON','json'];

    if ($exists && in_array( substr($exists[0], strrpos($exists[0],'.')),$whiteList) ) {

        echo file_get_contents($exists[0]);

    } else echo 'Bad request';

?>