<?php

class ipc4srcIpAddrCollector extends SQLCollector
{
    protected $idx;

    public function Prepare()
    {
        printf ("php: ipc4c.: prepare\n");
        $bResult = parent::Prepare();
        $this->idx = 0;
        return $bResult;
    }

    public function Fetch()
    {
    //  printf("php: ipc4c.: fetch %d\n", $this->idx);
        $aData = parent::Fetch();

        if ($aData !== false)
        {
            // Then process each collected brand
        }
        return $aData;

//        if ($this->idx < 1)
//        {
//            $this->idx++;
//            return array('primary_key' => $this->idx,
//                'org_id'  => '37',
//            //  'ip_list' => '',
//                'fqdn'    => 'HalloTestX',
//                'ip'      => '172.16.0.222');
//        }
//        return false;
    }
}
