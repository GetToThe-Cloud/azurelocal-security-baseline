#requires -Version 5.1

function New-AzLocalSecurityReport {
    <#
        .SYNOPSIS
            Turns audit results into a self-contained HTML report and a JSON
            sidecar suitable for an auditor or a SIEM.

        .DESCRIPTION
            The HTML file has no external dependencies, so it can be attached to a
            change record or an audit response and still render years later on a
            machine with no internet access.

            The JSON sidecar is written next to it with the same base name. That
            is the artifact to ship to a SIEM or to diff between runs.

        .PARAMETER Result
            Audit results from Test-AzLocalSecurityBaseline.

        .PARAMETER Path
            Output path for the HTML report. The JSON sidecar is written beside it.

        .PARAMETER Title
            Report heading. Defaults to the system name and scope.

        .PARAMETER NoJson
            Write only the HTML file.

        .PARAMETER PassThru
            Emit the summary object as well as writing the files.

        .EXAMPLE
            Test-AzLocalSecurityBaseline -Scope Cluster |
                New-AzLocalSecurityReport -Path C:\Reports\baseline.html

        .EXAMPLE
            $summary = Test-AzLocalSecurityBaseline -Scope Cluster |
                New-AzLocalSecurityReport -Path .\baseline.html -PassThru
            if ($summary.CriticalFindings -gt 0) { exit 1 }

            The shape to use in a pipeline that should fail the build.

        .OUTPUTS
            AzLocal.ReportSummary when -PassThru is supplied.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject[]] $Result,

        [Parameter(Mandatory)]
        [string] $Path,

        [string] $Title,

        [switch] $NoJson,

        [switch] $PassThru
    )

    begin {
        $collected = New-Object System.Collections.Generic.List[object]
    }

    process {
        foreach ($item in $Result) { $collected.Add($item) }
    }

    end {
        $results = $collected.ToArray()

        if ($results.Count -eq 0) {
            Write-AzLocalLog -Level Warning -Message 'No results supplied. Nothing to report.'
            return
        }

        $summary = Get-AzLocalResultSummary -Result $results

        if (-not $Title) {
            $Title = "Azure Local security baseline: $($results[0].ComputerName)"
        }

        $html = ConvertTo-AzLocalHtmlReport -Result $results -Summary $summary -Title $Title

        $directory = Split-Path -Path $Path -Parent
        if ($directory -and -not (Test-Path -LiteralPath $directory)) {
            if ($PSCmdlet.ShouldProcess($directory, 'Create report directory')) {
                New-Item -Path $directory -ItemType Directory -Force | Out-Null
            }
        }

        if ($PSCmdlet.ShouldProcess($Path, 'Write HTML report')) {
            Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
            Write-AzLocalLog -Message "HTML report written to $Path"
        }

        if (-not $NoJson) {
            $jsonPath = [System.IO.Path]::ChangeExtension($Path, '.json')
            $payload = [pscustomobject]@{
                summary = $summary
                results = $results
            }

            if ($PSCmdlet.ShouldProcess($jsonPath, 'Write JSON sidecar')) {
                $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
                Write-AzLocalLog -Message "JSON sidecar written to $jsonPath"
            }
        }

        if ($PassThru) { return $summary }
    }
}

function Get-AzLocalResultSummary {
    <#
        .SYNOPSIS
            Counts and scores a set of audit results.

        .DESCRIPTION
            The compliance score deliberately counts only Compliant and
            NonCompliant. Unknown results are reported separately and never
            inflate the score, because a control that could not be read is not a
            control that passed.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [psobject[]] $Result
    )

    $compliant = @($Result | Where-Object Status -eq 'Compliant').Count
    $nonCompliant = @($Result | Where-Object Status -eq 'NonCompliant').Count
    $unknown = @($Result | Where-Object Status -eq 'Unknown').Count
    $notApplicable = @($Result | Where-Object Status -eq 'NotApplicable').Count
    $skipped = @($Result | Where-Object Status -eq 'Skipped').Count

    $scored = $compliant + $nonCompliant
    $score = if ($scored -gt 0) { [math]::Round(($compliant / $scored) * 100, 1) } else { $null }

    $findings = @($Result | Where-Object Status -eq 'NonCompliant')

    return [pscustomobject]@{
        PSTypeName        = 'AzLocal.ReportSummary'
        TimestampUtc      = (Get-Date).ToUniversalTime()
        ComputerName      = $Result[0].ComputerName
        TargetComputerName = if ($Result[0].PSObject.Properties['TargetComputerName']) { $Result[0].TargetComputerName } else { $Result[0].ComputerName }
        Scope             = $Result[0].Scope
        Profile           = $Result[0].Profile
        ModuleVersion     = if ($Result[0].PSObject.Properties['ModuleVersion']) { $Result[0].ModuleVersion } else { $script:ModuleVersion }
        Transport         = if ($Result[0].PSObject.Properties['Transport']) { $Result[0].Transport } else { 'Local' }
        ExecutionId        = if ($Result[0].PSObject.Properties['ExecutionId']) { $Result[0].ExecutionId } else { $null }
        EvaluationStatus   = if ($unknown -eq 0) { 'Complete' } elseif ($scored -eq 0) { 'Incomplete' } else { 'Partial' }
        Total             = $Result.Count
        Compliant         = $compliant
        NonCompliant      = $nonCompliant
        Unknown           = $unknown
        NotApplicable     = $notApplicable
        Skipped           = $skipped
        ComplianceScore   = $score
        CriticalFindings  = @($findings | Where-Object Severity -eq 'Critical').Count
        HighFindings      = @($findings | Where-Object Severity -eq 'High').Count
        MediumFindings    = @($findings | Where-Object Severity -eq 'Medium').Count
        LowFindings       = @($findings | Where-Object Severity -eq 'Low').Count
        RemediableFindings = @($findings | Where-Object Remediable).Count
    }
}

function ConvertTo-AzLocalHtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [psobject[]] $Result,
        [Parameter(Mandatory)] $Summary,
        [Parameter(Mandatory)] [string] $Title
    )

    $severityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $statusRank = @{ NonCompliant = 0; Unknown = 1; Compliant = 2; NotApplicable = 3; Skipped = 4 }

    $sorted = $Result | Sort-Object `
        @{ Expression = { $statusRank[$_.Status] } },
        @{ Expression = { $severityRank[$_.Severity] } },
        Id

    $rows = New-Object System.Text.StringBuilder
    $currentCategory = $null

    foreach ($item in $sorted) {
        $statusClass = switch ($item.Status) {
            'Compliant'     { 'ok' }
            'NonCompliant'  { 'bad' }
            'Unknown'       { 'unknown' }
            default         { 'muted' }
        }

        # The object keeps the machine-readable status; only the cell is humanised.
        $statusLabel = switch ($item.Status) {
            'NonCompliant'  { 'Non-compliant' }
            'NotApplicable' { 'Not applicable' }
            default         { $item.Status }
        }

        $flags = @()
        if ($item.Remediable) { $flags += 'auto-remediable' }
        if ($item.RequiresReboot) { $flags += 'reboot' }
        if ($item.RequiresMaintenanceWindow) { $flags += 'maintenance window' }

        [void] $rows.Append(@"
<tr class="r-$statusClass">
  <td class="c-id"><a href="$(ConvertTo-AzLocalHtmlEncoded $item.Reference)" target="_blank" rel="noopener">$(ConvertTo-AzLocalHtmlEncoded $item.Id)</a></td>
  <td><span class="sev sev-$($item.Severity.ToLowerInvariant())">$(ConvertTo-AzLocalHtmlEncoded $item.Severity)</span></td>
  <td><span class="status status-$statusClass">$(ConvertTo-AzLocalHtmlEncoded $statusLabel)</span></td>
  <td>
    <div class="t">$(ConvertTo-AzLocalHtmlEncoded $item.Title)</div>
    <div class="d">$(ConvertTo-AzLocalHtmlEncoded $item.Detail)</div>
    $(if ($flags.Count) { '<div class="flags">' + (($flags | ForEach-Object { '<span class="flag">' + (ConvertTo-AzLocalHtmlEncoded $_) + '</span>' }) -join '') + '</div>' })
  </td>
  <td class="c-val">$(ConvertTo-AzLocalHtmlEncoded (ConvertTo-AzLocalDisplayValue -Value $item.Expected))</td>
  <td class="c-val">$(ConvertTo-AzLocalHtmlEncoded (ConvertTo-AzLocalDisplayValue -Value $item.Actual))</td>
</tr>
"@)
    }

    $scoreText = if ($null -eq $Summary.ComplianceScore) { 'n/a' } else { "$($Summary.ComplianceScore)%" }
    $scoreClass = if ($null -eq $Summary.ComplianceScore) { 'unknown' }
        elseif ($Summary.ComplianceScore -ge 95) { 'ok' }
        elseif ($Summary.ComplianceScore -ge 80) { 'warn' }
        else { 'bad' }

    return @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(ConvertTo-AzLocalHtmlEncoded $Title)</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 32px; font-family: 'Segoe UI', -apple-system, system-ui, sans-serif;
         background: #f4f7fb; color: #12243a; font-size: 14px; line-height: 1.5; }
  .wrap { max-width: 1180px; margin: 0 auto; }
  header { background: linear-gradient(120deg, #0b3d86, #0078d4); color: #fff;
           border-radius: 14px; padding: 28px 32px; }
  header h1 { margin: 0 0 6px; font-size: 25px; letter-spacing: -.4px; }
  header .meta { opacity: .88; font-size: 13.5px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
           gap: 14px; margin: 22px 0; }
  .card { background: #fff; border: 1px solid #dde6f0; border-radius: 12px; padding: 18px 20px; }
  .card .n { font-size: 30px; font-weight: 700; letter-spacing: -1px; }
  .card .l { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #5b6b7f;
             font-weight: 600; margin-top: 4px; }
  .n.ok { color: #0b6a3c; } .n.bad { color: #b3261e; }
  .n.warn { color: #9a6700; } .n.unknown { color: #5b6b7f; }
  table { width: 100%; border-collapse: collapse; background: #fff;
          border: 1px solid #dde6f0; border-radius: 12px; overflow: hidden; }
  th { background: #0b3d86; color: #fff; text-align: left; padding: 11px 14px;
       font-size: 11.5px; text-transform: uppercase; letter-spacing: .8px; }
  td { padding: 12px 14px; border-top: 1px solid #eef2f7; vertical-align: top; }
  tr.r-bad td { background: #fdf4f3; }
  tr.r-unknown td { background: #fbf9f2; }
  .c-id { font-family: Consolas, monospace; font-size: 12px; white-space: nowrap; }
  .c-id a { color: #0b5cad; text-decoration: none; }
  .c-id a:hover { text-decoration: underline; }
  .c-val { font-family: Consolas, monospace; font-size: 12px; color: #40506a; max-width: 190px;
           word-break: break-word; }
  .t { font-weight: 600; }
  .d { color: #5b6b7f; font-size: 13px; margin-top: 3px; }
  .flags { margin-top: 6px; }
  .flag { display: inline-block; font-size: 10.5px; font-weight: 700; text-transform: uppercase;
          letter-spacing: .6px; background: #eef2f7; color: #40506a; border-radius: 4px;
          padding: 3px 7px; margin-right: 5px; }
  .sev, .status { display: inline-block; font-size: 11px; font-weight: 700; border-radius: 5px;
                  padding: 4px 9px; text-transform: uppercase; letter-spacing: .5px; white-space: nowrap; }
  .sev-critical { background: #fde8e6; color: #93190f; }
  .sev-high { background: #fdf0e0; color: #8a4b00; }
  .sev-medium { background: #eef5fd; color: #0b5cad; }
  .sev-low { background: #eef2f7; color: #40506a; }
  .status-ok { background: #e3f6ec; color: #0b6a3c; }
  .status-bad { background: #fde8e6; color: #93190f; }
  .status-unknown { background: #fdf6e3; color: #8a6d00; }
  .status-muted { background: #eef2f7; color: #5b6b7f; }
  footer { margin-top: 22px; color: #5b6b7f; font-size: 12.5px; }
  @media (prefers-color-scheme: dark) {
    body { background: #0e1621; color: #e6edf5; }
    .card, table { background: #16202e; border-color: #26374d; }
    td { border-top-color: #22303f; }
    tr.r-bad td { background: #2a1a1a; }
    tr.r-unknown td { background: #262218; }
    .c-val { color: #a9bdd6; } .d, .card .l, footer { color: #94a8c0; }
    .flag { background: #22303f; color: #a9bdd6; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>$(ConvertTo-AzLocalHtmlEncoded $Title)</h1>
    <div class="meta">
      Profile: $(ConvertTo-AzLocalHtmlEncoded $Summary.Profile) &middot;
      Target: $(ConvertTo-AzLocalHtmlEncoded $Summary.TargetComputerName) &middot;
      Transport: $(ConvertTo-AzLocalHtmlEncoded $Summary.Transport) &middot;
      Scope: $(ConvertTo-AzLocalHtmlEncoded $Summary.Scope) &middot;
      Evaluation: $(ConvertTo-AzLocalHtmlEncoded $Summary.EvaluationStatus) &middot;
      Generated: $($Summary.TimestampUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC
    </div>
  </header>

  <div class="cards">
    <div class="card"><div class="n $scoreClass">$scoreText</div><div class="l">Compliance</div></div>
    <div class="card"><div class="n ok">$($Summary.Compliant)</div><div class="l">Compliant</div></div>
    <div class="card"><div class="n bad">$($Summary.NonCompliant)</div><div class="l">Non-compliant</div></div>
    <div class="card"><div class="n unknown">$($Summary.Unknown)</div><div class="l">Unknown</div></div>
    <div class="card"><div class="n bad">$($Summary.CriticalFindings)</div><div class="l">Critical findings</div></div>
    <div class="card"><div class="n warn">$($Summary.RemediableFindings)</div><div class="l">Auto-remediable</div></div>
  </div>

  <table>
    <thead>
      <tr><th>Control</th><th>Severity</th><th>Status</th><th>Finding</th><th>Expected</th><th>Actual</th></tr>
    </thead>
    <tbody>
$($rows.ToString())
    </tbody>
  </table>

  <footer>
    Unknown results are controls whose state could not be read, usually a missing cmdlet, a CredSSP
    refusal or an unreachable node. They are excluded from the compliance score rather than counted
    as passes. A report with only Unknown results is incomplete, not compliant. Generated by
    AzLocalSecurityBaseline $($script:ModuleVersion) through
    $(ConvertTo-AzLocalHtmlEncoded $Summary.Transport) on
    $(ConvertTo-AzLocalHtmlEncoded $Summary.TargetComputerName).
  </footer>
</div>
</body>
</html>
"@
}

function ConvertTo-AzLocalHtmlEncoded {
    <#
        .SYNOPSIS
            Minimal HTML encoding that does not depend on System.Web being loaded.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        $Value
    )

    if ($null -eq $Value) { return '' }

    return ([string] $Value).
        Replace('&', '&amp;').
        Replace('<', '&lt;').
        Replace('>', '&gt;').
        Replace('"', '&quot;').
        Replace("'", '&#39;')
}
