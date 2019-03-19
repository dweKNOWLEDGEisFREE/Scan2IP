<?php

// ipc4iTop - collector

printf ("php: ipc4c.: main.php ...\n");

Orchestrator::AddRequirement('5.4.0');

require_once(APPROOT.'collectors/ipc4srcIpAddrCollector.class.inc.php');

$iRank = 1;
Orchestrator::AddCollector($iRank++, 'ipc4srcIpAddrCollector');
