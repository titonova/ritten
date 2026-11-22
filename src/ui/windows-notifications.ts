import { spawn } from 'node:child_process';

export interface WindowsApprovalNotice {
  id: string;
  client: string;
  tool: string;
  details: string;
  expires: number;
  ownerPort: number;
}

export interface WindowsApprovalPrompt {
  done: Promise<void>;
  close: () => void;
}

/** WPF approval popup. Only the original Node parent may interpret its stdout choice. */
export function notifyWindowsApproval(
  notice: WindowsApprovalNotice,
  onDecision: (decision: 'approve' | 'deny') => Promise<void>,
): WindowsApprovalPrompt | null {
  if (process.platform !== 'win32' || notice.expires <= Date.now()) return null;
  const script = [
    "$ErrorActionPreference = 'Stop'",
    'Add-Type -AssemblyName PresentationFramework',
    'Add-Type -AssemblyName PresentationCore',
    'Add-Type -AssemblyName WindowsBase',
    "[xml]$layout = @'",
    '<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Ritten Control - Approval" Width="500" Height="390" ResizeMode="NoResize" WindowStartupLocation="CenterScreen" ShowInTaskbar="True" Topmost="True" Background="#111B28" Foreground="#E6F1F5" FontFamily="Segoe UI">',
    '  <Border Padding="24" BorderBrush="#355266" BorderThickness="1"><StackPanel>',
    '    <TextBlock Text="RITTEN  //  CONTROL" Foreground="#77D5D4" FontSize="13" FontWeight="Bold"/>',
    '    <TextBlock Text="Approval required" FontSize="23" FontWeight="SemiBold" Margin="0,12,0,6"/>',
    '    <TextBlock Name="tool" Foreground="#C4D6E1" FontSize="14" TextWrapping="Wrap"/>',
    '    <TextBlock Name="client" Foreground="#8FA5B8" FontSize="12" Margin="0,8,0,0" TextWrapping="Wrap"/>\n    <TextBox Name="details" Margin="0,12,0,0" Height="102" Background="#0B1420" Foreground="#C4D6E1" BorderBrush="#355266" FontFamily="Consolas" FontSize="11" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" Padding="8"/>',
    '    <TextBlock Name="remaining" Foreground="#F3C083" FontSize="12" Margin="0,14,0,0"/>',
    '    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,18,0,0">',
    '      <Button Name="deny" Content="DENY" Width="110" Height="36" Margin="0,0,10,0" Background="#304355" Foreground="White" BorderThickness="0"/>',
    '      <Button Name="approve" Content="APPROVE" Width="120" Height="36" Background="#197C6F" Foreground="White" BorderThickness="0" FontWeight="SemiBold"/>',
    '    </StackPanel></StackPanel></Border>',
    '</Window>',
    "'@",
    '$reader = New-Object System.Xml.XmlNodeReader($layout)',
    '$window = [Windows.Markup.XamlReader]::Load($reader)',
    "$window.FindName('tool').Text = $env:RITTEN_PROMPT_TOOL",
    "$window.FindName('client').Text = 'Client: ' + $env:RITTEN_PROMPT_CLIENT",
    "$window.FindName('details').Text = $env:RITTEN_PROMPT_DETAILS",
    '$expiry = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$env:RITTEN_PROMPT_EXPIRES)',
    "$choice = ''",
    "$window.FindName('approve').Add_Click({ $script:choice = 'APPROVE'; $window.Close() })",
    "$window.FindName('deny').Add_Click({ $script:choice = 'DENY'; $window.Close() })",
    '$timer = New-Object System.Windows.Threading.DispatcherTimer',
    '$timer.Interval = [TimeSpan]::FromMilliseconds(200)',
    '$timer.Add_Tick({',
    '  $left = [Math]::Ceiling(($expiry - [DateTimeOffset]::UtcNow).TotalSeconds)',
    '  if ($left -le 0) { $timer.Stop(); $window.Close() }',
    '  else { $window.FindName("remaining").Text = "Expires in $left seconds" }',
    '})',
    '$timer.Start()',
    'try { $window.ShowDialog() | Out-Null } finally { $timer.Stop() }',
    "if ($choice -ne '') { [Console]::Out.WriteLine($choice) }",
  ].join('\n');
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const child = spawn(
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    ['-NoProfile', '-NonInteractive', '-STA', '-EncodedCommand', encoded],
    {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        RITTEN_PROMPT_TOOL: notice.tool.slice(0, 130),
        RITTEN_PROMPT_CLIENT: notice.client.slice(0, 100),
        RITTEN_PROMPT_DETAILS: notice.details.slice(0, 3000),
        RITTEN_PROMPT_EXPIRES: String(notice.expires),
      },
    },
  );
  let stderr = '';
  let stdout = '';
  let responded = false;
  let closedByParent = false;
  const done = new Promise<void>((resolve, reject) => {
    child.stderr.on('data', (data: Buffer) => {
      stderr = (stderr + data.toString('utf8')).slice(-4096);
    });
    child.stdout.on('data', (data: Buffer) => {
      stdout = (stdout + data.toString('utf8')).slice(-128);
      if (responded) return;
      const response = stdout.trim();
      if (response === 'APPROVE' || response === 'DENY') {
        responded = true;
        void onDecision(response === 'APPROVE' ? 'approve' : 'deny').catch(reject);
      }
    });
    child.once('error', reject);
    child.once('close', (code) => {
      if (closedByParent || code === 0) resolve();
      else reject(new Error('WPF popup exited ' + code + ': ' + stderr));
    });
  });
  return {
    done,
    close: () => {
      if (child.exitCode === null && !child.killed) {
        closedByParent = true;
        child.kill();
      }
    },
  };
}
