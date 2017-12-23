configuration MSFT_AdcsCertificationAuthority_Uninstall_Config {
    Import-DscResource -ModuleName AdcsDeploymentDsc

    node localhost {
        AdcsCertificationAuthority Integration_Test {
            CAType     = 'StandaloneRootCA'
            Credential = $Node.AdminCred
            Ensure     = 'Absent'
        }
    }
}
