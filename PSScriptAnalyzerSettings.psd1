@{
    # PSScriptAnalyzer configuration.
    #
    # Two rules are excluded deliberately; everything else is on.
    ExcludeRules = @(
        # The interop wrappers are named for what they wrap, and several of those
        # verbs (Enable-, Set-) are correct PowerShell verbs used on private
        # functions that are never exported. The exported surface uses approved
        # verbs, which is what the rule exists to protect.
        'PSUseSingularNouns',

        # Write-Host is used only in the deploy script and the smoke-test runner,
        # both of which are interactive tools whose entire output is for a human
        # at a terminal, not objects for a pipeline.
        'PSAvoidUsingWriteHost'
    )

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable = $true
            # The module has to run on Windows PowerShell 5.1, which is what
            # ships on the Azure Local hosts, as well as on PowerShell 7.
            TargetVersions = @('5.1', '7.0')
        }
    }
}
