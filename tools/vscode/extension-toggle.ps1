Param(
  [Parameter(Mandatory=$true)][ValidateSet('disable','enable')][string]$Action,
  [string[]]$Extensions = @(
    'bradlc.vscode-tailwindcss',
    'ms-vscode.powershell',
    'vscjava.vscode-gradle',
    'ms-vscode-remote.remote-containers',
    'ms-azuretools.vscode-containers',
    'ritwickdey.liveserver',
    'ms-python.python',
    'ms-python.vscode-pylance',
    'ms-python.debugpy',
    'ms-python.vscode-python-envs'
  )
)

Write-Output "Action: $Action"
foreach ($ext in $Extensions) {
  try {
    if ($Action -eq 'disable') {
      code --disable-extension $ext | Out-Null
      Write-Output "Disabled: $ext"
    } else {
      code --enable-extension $ext | Out-Null
      Write-Output "Enabled: $ext"
    }
  } catch {
    Write-Warning "Failed toggling $ext: $_"
  }
}
Write-Output "Done."