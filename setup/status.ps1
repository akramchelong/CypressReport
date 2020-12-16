$ServiceName = 'OIDC-IAM'
$PluginService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($PluginService) {
  if ($PluginService.Status -eq "Running") {
    exit 0
  }
}
exit 1
