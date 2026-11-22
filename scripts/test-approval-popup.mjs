import os from 'node:os';
import { notifyWindowsApproval } from '../dist/ui/windows-notifications.js';

if (process.platform !== 'win32') {
  console.error('This popup test requires Windows.');
  process.exitCode = 1;
} else {
  const prompt = notifyWindowsApproval(
    {
      id: 'local-preview-only',
      client: 'Local popup preview',
      tool: 'process.run (TEST ONLY â€” no command will execute)',
      details: JSON.stringify(
        {
          executable: 'powershell.exe',
          args: ['-NoProfile', '-Command', "Write-Output 'Ritten test'"],
          cwd: os.tmpdir(),
        },
        null,
        2,
      ),
      expires: Date.now() + 30000,
      ownerPort: 7338,
    },
    async (choice) => {
      console.log('You clicked:', choice);
      console.log('Preview only; no Ritten authorization changed.');
    },
  );
  if (!prompt) throw Error('Could not create Windows popup');
  try {
    await prompt.done;
    console.log('Preview finished.');
  } catch (error) {
    console.error('Popup failed:', error);
    process.exitCode = 1;
  }
}
