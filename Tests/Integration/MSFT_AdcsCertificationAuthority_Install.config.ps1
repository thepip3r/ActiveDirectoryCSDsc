configuration MSFT_AdcsCertificationAuthority_Install_Config {
    Import-DscResource -ModuleName AdcsDeploymentDsc

    node localhost {
        AdcsCertificationAuthority Integration_Test {
            CAType     = 'StandaloneRootCA'
            Credential = $Node.AdminCred
            Ensure     = 'Present'
        }
    }
}
