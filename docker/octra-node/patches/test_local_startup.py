"""Run only inside a disposable network-disabled native-node container."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--node', type=Path, required=True)
parser.add_argument('--compose', type=Path, required=True)
parser.add_argument('--out', type=Path)
parser.add_argument('--isolated-network-namespace', action='store_true',
                    help='explicitly confirm this disposable Linux namespace has no external network')
args = parser.parse_args()
# BuildKit RUN --network=none omits /.dockerenv; require an explicit test opt-in
# and inspect the actual route table before starting any process.
assert args.isolated_network_namespace, 'requires --isolated-network-namespace'
assert Path('/proc/net/route').is_file(), 'requires an isolated Linux network namespace'
assert not any(line.split()[1] == '00000000' for line in Path('/proc/net/route').read_text().splitlines()[1:]), 'external default route forbidden'
node = args.node.resolve()
assert node.is_file() and node.with_name('octra_pvac_worker.exe').is_file()
base = {key: value for key, value in os.environ.items() if not key.startswith('OCTRA_')}
base.update(OCTRA_CHAIN_ID='octra-local-foundry-regression', OCTRA_LOCAL_TEST_MODE='1', OCTRA_CONSENSUS_PORT='0', OCTRA_P2P_PORT='0', OCTRA_API_PORT='19080')
cases = [
    ('public_chain', {'OCTRA_CHAIN_ID': 'octra-devnet-9871-cluster'}, [], [], 'isolated_single_required'),
    ('bft', {'OCTRA_CONSENSUS_MODE': 'bft'}, [], [], 'isolated_single_required'),
    ('observer_env', {'OCTRA_CONSENSUS_MODE': 'observer'}, [], [], 'isolated_single_required'),
    ('observer_flag', {}, ['--observer'], [], 'isolated_single_required'),
    ('publisher_flag', {}, ['--state-sync-publisher'], [], 'isolated_single_required'),
    ('legacy_publisher_flag', {}, ['--publisher'], [], 'isolated_single_required'),
    ('peer_environment', {'OCTRA_PEERS': '127.0.0.1:19000'}, [], [], 'isolated_single_required'),
    ('peer_file', {}, [], ['forbidden'], 'isolated_single_required'),
    ('consensus_port', {'OCTRA_CONSENSUS_PORT': '19000'}, [], [], 'isolated_single_required'),
    ('default_private_refusal', {'OCTRA_LOCAL_TEST_MODE': None}, [], [], 'unsupported_chain'),
    ('recovery_role', {}, [], [], 'consensus_enabled'),
]
report = {'refusals': [], 'private_rpc_ready': False, 'public_effects': False}
with tempfile.TemporaryDirectory(prefix='octra-startup-regression-') as directory:
    root = Path(directory)
    for name, changes, flags, peers, reason in cases:
        work = root / name
        data = work / 'data'
        data.mkdir(parents=True)
        (work / 'nodes.config').write_text(json.dumps(peers) + '\n')
        env = dict(base, OCTRA_DATA_DIR=str(data))
        for key, value in changes.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        if name == 'recovery_role':
            (data / 'recovery').mkdir()
            (data / 'recovery/sync_need.json').write_text(json.dumps({'schema': 'octra_sync_need_v2', 'chain_id': base['OCTRA_CHAIN_ID'], 'cause': 'root', 'epoch': 1, 'head': 0, 'target': None}) + '\n')
        result = subprocess.run([str(node), *flags], cwd=work, env=env, capture_output=True, text=True, timeout=20)
        assert result.returncode != 0 and reason in result.stdout + result.stderr, (name, result.returncode, result.stdout[-2000:], result.stderr[-2000:])
        assert not (data / 'wallet.json').exists() and not (data / 'HEAD.json').exists(), name
        report['refusals'].append({'case': name, 'exit_code': result.returncode, 'reason': reason})
    work = root / 'positive'
    data = work / 'data'
    data.mkdir(parents=True)
    (work / 'nodes.config').write_text('[]\n')
    env = dict(base, OCTRA_DATA_DIR=str(data))
    for key in ['OCTRA_VALIDATORS', 'OCTRA_DEV_WALLET_JSON']:
        line = next(line.strip() for line in args.compose.read_text().splitlines() if line.strip().startswith(key + ':'))
        value = line.split(':', 1)[1].strip()
        env[key] = json.loads(value) if value.startswith('"') else value[1:-1]
    (data / 'wallet.json').write_text(env.pop('OCTRA_DEV_WALLET_JSON') + '\n')
    (data / 'wallet.json').chmod(0o600)
    with (work / 'node.log').open('w') as stream:
        process = subprocess.Popen([str(node)], cwd=work, env=env, stdout=stream, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 60
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            while time.monotonic() < deadline:
                assert process.poll() is None, (work / 'node.log').read_text()[-2000:]
                try:
                    request = urllib.request.Request('http://127.0.0.1:19080/rpc', data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'octra_runtimeVersion', 'params': []}).encode(), headers={'Content-Type': 'application/json'})
                    with opener.open(request, timeout=2) as response:
                        value = json.loads(response.read(65536))
                    if value.get('result', {}).get('chain_id') == base['OCTRA_CHAIN_ID']:
                        report['private_rpc_ready'] = True
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(.2)
            assert report['private_rpc_ready'], (work / 'node.log').read_text()[-2000:]
        finally:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
if args.out:
    args.out.write_text(json.dumps(report, indent=2) + '\n')
print('native private startup regression PASS: 11 refusals and private RPC')
