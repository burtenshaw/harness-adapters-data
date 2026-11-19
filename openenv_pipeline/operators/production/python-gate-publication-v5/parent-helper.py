"""Capture admitted tasks, then append them privately with optimistic parent CAS."""
import base64
import hashlib
import importlib.util
import json
import re
import stat
import tempfile
from collections import Counter
from pathlib import Path

import yaml
from dotenv import dotenv_values
from huggingface_hub import CommitOperationAdd, HfApi, hf_hub_download

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
REPO = 'harness-hub/agentic-coding-envs'
PREFIX = 'scale800_v1/20261112'
CONFIG = 'scale800_gate_v1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def scan(files, values):
    needles = [x for value in values if value for x in (value.encode(), base64.b64encode(value.encode()))]
    for path, raw in files.items():
        # Public chi TLS test fixture, pinned to its original Git blob and public
        # immutable-source readback. Credential-value checks always precede it.
        public_fixture = bool(re.fullmatch(r'scale800_v1/20261112/tasks/[0-9a-f]{24}/tests/frozen/testdata/key\.pem', path)) and sha(raw) == 'fecae623b5a0ae0a1110285c66e3e0e7f6019f49fd540ed3d9b85f65b9054f6c'
        # Exact public OAuthlib test fixtures, verified at immutable source URLs.
        # This only exempts the PEM pattern; actual credentials still fail below.
        oauth_fixtures = {
            'tests/trusted/tests/oauth1/rfc5849/test_client.py': '7ca99bfe6ee6a59ca18ea75572051401d280796c8015632e5bf2a08f832906f3',
            'tests/trusted/tests/oauth1/rfc5849/test_signatures.py': '8873fd8233d2fd8d4633a778e21da3734a0c21ffc1c9cf6285ce6adb5524e41c',
            'tests/trusted/tests/oauth2/rfc6749/clients/test_service_application.py': '533004e7664b09032f803e6cf8d591eec6c2d3630121d8f9075cd8027d3969ba',
            'tests/trusted/tests/oauth2/rfc6749/test_server.py': '7f7b32adc6b6c7e8d8d533b8223bbbee66e1833a008a49ffe721bc3feba0b5d0',
        }
        match = re.fullmatch(r'scale800_py_v1/20261112/tasks/[0-9a-f]{24}/(tests/trusted/.+)', path)
        public_fixture = public_fixture or bool(match and oauth_fixtures.get(match[1]) == sha(raw))
        if any(x in path.encode() + raw for x in needles) or re.search(rb'hf_[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9_-]{16,}', raw) or (not public_fixture and re.search(rb'BEGIN (?:RSA |OPENSSH )?PRIVATE KEY', raw)):
            raise ValueError('Credential scan failed at ' + path)


def canonical_repo(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value):
        raise ValueError('Explicit canonical upstream repository required')
    return value.casefold()


def tree(source):
    captured, inventory = {}, {}
    for path in sorted(source.rglob('*')):
        if path.is_symlink():
            raise ValueError('Publication links are unsupported')
        if path.is_file():
            name = path.relative_to(source).as_posix()
            raw = path.read_bytes()
            captured[name] = raw
            inventory[name] = {'sha256':sha(raw), 'size':len(raw), 'mode':oct(stat.S_IMODE(path.stat().st_mode))}
    return captured, inventory


def capture(rows, destination, batch_id):
    if destination.exists():
        raise FileExistsError('Capture is immutable; use existing receipt or a new batch')
    runner = module(HERE.parent / 'hf-check-gate-v1/run.py', 'published_reviewed_runner')
    files, index = {}, []
    for row in rows:
        plan_path = Path(row['plan_path'])
        plan, fingerprint = runner.prepared(plan_path, row['plan_sha256'])
        result = plan_path.parent / 'execution-run'
        task_bytes, task_inventory = tree(plan_path.parent/'task')
        evidence, _ = tree(result)
        plan_bytes = plan_path.read_bytes()
        image_bytes = (plan_path.parent/'image-receipt.json').read_bytes()
        if task_inventory != plan['task_files'] or sha(plan_bytes) != fingerprint or sha(image_bytes) != plan['image_receipt_sha256']:
            raise ValueError('Captured source, modes, plan or image receipt changed')
        expected_evidence = {}
        for line in evidence['SHA256SUMS'].decode().splitlines():
            digest, path = line.split('  ', 1)
            expected_evidence[path] = digest
        if {name:sha(raw) for name,raw in evidence.items() if name != 'SHA256SUMS'} != expected_evidence:
            raise ValueError('Captured evidence differs from its checksum inventory')
        report = json.loads(evidence['report.json'])
        if report.get('admitted') is not True or report['profile'] != 'harbor-semantic-jobs-v1':
            continue
        assert report['task_inventory_sha256'] == plan['task_inventory_sha256']
        trials = []
        for number, role in enumerate(plan['roles']):
            folder = f'trials/{number:04d}/'
            trial = json.loads(evidence[folder+'trial.json'])
            trial['raw_reward'] = evidence[folder+'reward.raw']
            trials.append(trial)
        with tempfile.TemporaryDirectory(prefix='scale800-publication-') as directory:
            frozen = Path(directory)
            for name,raw in task_bytes.items():
                target=frozen/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(int(task_inventory[name]['mode'],8))
            assessed = runner.load_module('gate').assess(frozen, trials, plan['task_digest'], plan['execution']['agent_image'])
        assert assessed['admitted'] is True
        def stable(value):
            copied = json.loads(json.dumps(value))
            copied['manifest'].pop('name', None)
            for check in copied['results']:
                check.pop('duration_s', None)
            return copied
        assert stable(assessed) == stable(report)
        key = sha(row['task_id'].encode())[:24]
        task_root = f'{PREFIX}/tasks/{key}'
        files.update({task_root+'/'+name:raw for name,raw in task_bytes.items()})
        files.update({f'{PREFIX}/gate-evidence/{key}/'+name:raw for name,raw in evidence.items()})
        provenance = json.loads(task_bytes['provenance.json'])
        source = provenance['source_record']
        if row['task_id'] != source['task_id'] or canonical_repo(row['upstream_repo']) != canonical_repo(source['upstream_repo']):
            raise ValueError('Caller task/repository identity differs from frozen source')
        row = dict(row, upstream_repo=canonical_repo(source['upstream_repo']))
        execution = dict(plan['execution'])
        execution['expected_task_inventory_sha256'] = plan['task_inventory_sha256']
        execution['public_source_files'] = {name.removeprefix('environment/source/'):{'sha256':entry['sha256'],'bytes':entry['size'],'mode':int(entry['mode'],8)} for name,entry in plan['task_files'].items() if name.startswith('environment/source/')}
        execution_path = f'{PREFIX}/execution/{key}.json'
        inventory_path = f'{PREFIX}/inventories/{key}.json'
        receipt_path = f'{PREFIX}/images/{key}.json'
        files[execution_path] = encode(execution)
        files[inventory_path] = encode(plan['task_files'])
        files[receipt_path] = image_bytes
        files[f'{PREFIX}/plans/{key}.json'] = plan_bytes
        index.append({'task_id':row['task_id'],'task_path':task_root,'instruction':task_bytes['instruction.md'].decode(),'source_repo':source['source_repo'],'upstream_repo':row['upstream_repo'],'source_dataset':source['source_dataset'],'source_revision':source['source_revision'],'source_split':source['source_split'],'source_commit':source['source_commit'],'source_license_spdx':source['license_evidence']['source_code']['spdx'],'usage':source['usage'],'evaluation_only':source['source_split'] != 'train','semantic_nonoverlap_established':source['semantic_nonoverlap_established'],'provenance_path':task_root+'/provenance.json','task_file_inventory_path':inventory_path,'task_inventory_sha256':plan['task_inventory_sha256'],'task_source_sha256':plan['task_digest'],'execution_path':execution_path,'image_receipt_path':receipt_path,'gate_report_path':f'{PREFIX}/gate-evidence/{key}/report.json','validation_profile':'harbor-semantic-jobs-v1','gate_passed':True,'provided_reference':True,'generated_reference':False,'language':'go','image_pull_qualified':True,'cloud_launch_ready':True,'target_model':'Qwen/Qwen3.8-27B','target_model_calibrated':False,'difficulty_status':'unmeasured','rfc008_complete':False,'trainability_established':False,'training_admissible':False,'verified':False})
    assert index and len({r['task_id'] for r in index}) == len(index)
    assert all(count <= 40 for count in Counter(r['upstream_repo'] for r in index).values())
    split = f'splits/{CONFIG}-{batch_id}.jsonl'
    files[split] = b''.join((json.dumps(row, sort_keys=True)+'\n').encode() for row in index)
    summary = {'profile':'harbor-semantic-jobs-v1','tasks':len(index),'per_repository':dict(Counter(r['upstream_repo'] for r in index)),'per_language':{'go':len(index)},'qwen_measured':0,'full_rfc008_qualified':0,'training_admissible':0,'split_path':split,'per_repository_accepted_cap':40}
    files[f'{PREFIX}/batches/{batch_id}/summary.json'] = encode(summary)
    for name in ('gate.py','backend.py','run.py','RUNNER.md'):
        files[f'{PREFIX}/gate-implementation/{name}'] = (HERE.parent/'hf-check-gate-v1'/name).read_bytes()
    manifest = {name:{'sha256':sha(raw),'size':len(raw)} for name,raw in sorted(files.items())}
    files[f'{PREFIX}/batches/{batch_id}/file-sha256.json'] = encode(manifest)
    destination.mkdir(mode=0o700,parents=True)
    for name,raw in files.items():
        p=destination/'files'/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);p.write_bytes(raw)
    plan={'schema':'scale800-private-gate-publication-v1','batch_id':batch_id,'config':CONFIG,'split_path':split,'files':{name:sha(raw) for name,raw in files.items()},'summary':summary}
    (destination/'plan.json').write_bytes(encode(plan))
    return plan


def publish(destination, expected_plan_sha256):
    raw=(destination/'plan.json').read_bytes()
    if sha(raw)!=expected_plan_sha256:raise ValueError('Reviewed publication plan changed')
    plan=json.loads(raw);files={name:(destination/'files'/name).read_bytes() for name in plan['files']}
    if {name:sha(data) for name,data in files.items()}!=plan['files']:raise ValueError('Captured publication bytes changed')
    values=dotenv_values(ROOT/'.env');scan(files,values.values())
    receipt_path=destination/'publication.json'
    if receipt_path.exists():raise FileExistsError('Reconcile existing publication attempt before retry')
    api=HfApi(token=values['HF_TOKEN']);info=api.dataset_info(REPO)
    if info.private is not True:raise ValueError('Dataset must be private')
    previous=set(api.list_repo_files(REPO,repo_type='dataset',revision=info.sha))
    # Shared implementation files must remain byte-identical; task/index/evidence paths are append-only.
    for name in set(files)&previous:
        old=Path(hf_hub_download(REPO,name,repo_type='dataset',revision=info.sha,token=values['HF_TOKEN'])).read_bytes()
        if old!=files[name]:raise ValueError('Existing private path would change: '+name)
    oldcard=Path(hf_hub_download(REPO,'README.md',repo_type='dataset',revision=info.sha,token=values['HF_TOKEN'])).read_bytes()
    header,body=oldcard.decode().split('\n---\n',1)
    assert header.startswith('---\n')
    metadata=yaml.safe_load(header[4:]);before=json.loads(json.dumps(metadata));configs=metadata.setdefault('configs',[])
    config=next((c for c in configs if c['config_name']==CONFIG),None)
    if config is None:
        config={'config_name':CONFIG,'data_files':[]};configs.append(config)
    existing_paths=[]
    for c in configs:
        if c['config_name']==CONFIG:
            for d in c['data_files']:
                paths=d['path'] if isinstance(d['path'],list) else [d['path']]
                existing_paths.extend(paths)
    # Validate cumulative canonical-repository cap and task identities against all previous gate rows.
    counts=Counter();ids=set()
    for path in existing_paths:
        original=Path(hf_hub_download(REPO,path,repo_type='dataset',revision=info.sha,token=values['HF_TOKEN'])).read_bytes()
        for line in original.splitlines():
            row=json.loads(line);assert row['task_id'] not in ids;ids.add(row['task_id']);counts[canonical_repo(row['upstream_repo'])]+=1
    for line in files[plan['split_path']].splitlines():
        row=json.loads(line);assert row['task_id'] not in ids;ids.add(row['task_id']);counts[canonical_repo(row['upstream_repo'])]+=1
    assert all(count<=40 for count in counts.values())
    match=next((d for d in config['data_files'] if d['split']=='accepted'),None)
    if match is None:config['data_files'].append({'split':'accepted','path':[plan['split_path']]})
    elif isinstance(match['path'],str):match['path']=[match['path'],plan['split_path']]
    else:match['path'].append(plan['split_path'])
    # Preserve every old config value and body exactly; only append paths to this owned config.
    for c in before.get('configs',[]):
        if c['config_name']!=CONFIG:assert c in configs
    card=('---\n'+yaml.safe_dump(metadata,sort_keys=False,allow_unicode=True)+'---\n'+body).encode()
    scan({'README.md':card},values.values());files['README.md']=card
    receipt={'status':'commit_uncertain','parent':info.sha,'plan_sha256':expected_plan_sha256,'expected_paths':sorted(files),'card_before_sha256':sha(oldcard)}
    (destination/'publication.json').write_bytes(encode(receipt))
    commit=api.create_commit(REPO,repo_type='dataset',parent_commit=info.sha,commit_message='Append HF Jobs semantic-gated task batch '+plan['batch_id'],operations=[CommitOperationAdd(path_in_repo=name,path_or_fileobj=data) for name,data in sorted(files.items())])
    receipt.update(status='committed_readback_pending',revision=commit.oid);receipt_path.write_bytes(encode(receipt))
    current=set(api.list_repo_files(REPO,repo_type='dataset',revision=commit.oid));assert current==previous|set(files)
    for name,data in files.items():
        check=Path(hf_hub_download(REPO,name,repo_type='dataset',revision=commit.oid,token=values['HF_TOKEN'])).read_bytes();assert check==data
    assert card.decode().split('\n---\n',1)[1]==body
    receipt.update(status='immutable_readback_verified',files=len(files),config=CONFIG,split='accepted',split_path=plan['split_path'],summary=plan['summary']);receipt_path.write_bytes(encode(receipt));return receipt
