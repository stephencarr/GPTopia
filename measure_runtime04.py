"""Local synthetic Node/Python runtime probe; no container/provider/live pilot."""
import json
import os
from pathlib import Path
import subprocess
import shutil
import signal
import tempfile
import time
ROOT=Path(__file__).resolve().parent

def usage(pid):
    try:
        status=Path(f'/proc/{pid}/status').read_text()
        rss=int(next(line.split()[1] for line in status.splitlines() if line.startswith('VmRSS:')))*1024
        fields=Path(f'/proc/{pid}/stat').read_text().split()
        cpu=(int(fields[13])+int(fields[14]))/os.sysconf('SC_CLK_TCK')
        return rss,cpu
    except (OSError,StopIteration):return 0,0

with tempfile.TemporaryDirectory(prefix='gptopia04-runtime-') as temp:
    env={'PATH':os.environ['PATH'],'NODE_OPTIONS':'--max-old-space-size=96','TMPDIR':temp,'PYTHONDONTWRITEBYTECODE':'1'}
    start=time.monotonic()
    proc=subprocess.Popen(['node','measure04.mjs'],cwd=ROOT/'mcp_adapter',env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
    try:
        ready=json.loads(proc.stdout.readline());pids=[ready['node_pid'],ready['worker_pid']]
        peak=0;last_cpu=[0,0];samples=0
        while proc.poll() is None:
            readings=[usage(pid) for pid in pids];peak=max(peak,sum(r[0] for r in readings));last_cpu=[max(old,r[1]) for old,r in zip(last_cpu,readings)];samples+=1
            if time.monotonic()-start>30:raise TimeoutError('local probe timeout')
            time.sleep(.01)
        output=proc.stdout.read();error=proc.stderr.read()
        if proc.returncode:raise RuntimeError(error+'\n'+output)
        completed=json.loads(output.strip().splitlines()[-1])
        result={'mode':'local synthetic Node + Python child, fixture JWTs in memory only','container_measured':False,'docker_available':bool(shutil.which('docker')),'podman_available':bool(shutil.which('podman')),'heap_cap_mib':96,'sampled_combined_peak_rss_bytes':peak,'node_cpu_seconds':last_cpu[0],'python_cpu_seconds':last_cpu[1],'elapsed_seconds':round(time.monotonic()-start,4),'samples':samples,'workload':completed,'no_external_services_or_live_data':True,'limitations':['10ms RSS sampling can miss peaks','host runtime is not Railway container sizing proof','initialization is excluded before first ready sample','no production identity provider or real-agent proof']}
        print(json.dumps(result,indent=2))
    finally:
        try:os.killpg(proc.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        proc.wait()
        proc.stdout.close();proc.stderr.close()
