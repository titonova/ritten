import path from 'node:path';
import os from 'node:os';

export interface RittenPaths {
  config: string;
  data: string;
  logs: string;
  toolsets: string;
}

export function getPaths(
  platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
  home = os.homedir(),
): RittenPaths {
  let configDir: string;
  let data: string;
  if (platform === 'win32') {
    configDir = path.join(env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Ritten');
    data = path.join(env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'Ritten');
  } else if (platform === 'darwin') {
    configDir = path.join(home, 'Library', 'Application Support', 'Ritten');
    data = configDir;
  } else {
    configDir = path.join(env.XDG_CONFIG_HOME || path.join(home, '.config'), 'ritten');
    data = path.join(env.XDG_DATA_HOME || path.join(home, '.local', 'share'), 'ritten');
  }
  data = env.RITTEN_DATA_DIR || data;
  return {
    config: env.RITTEN_CONFIG || path.join(configDir, 'config.yaml'),
    data,
    logs: path.join(data, 'logs'),
    toolsets: path.join(configDir, 'toolsets'),
  };
}
