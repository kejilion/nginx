#!/usr/bin/env python3
"""Sign an immutable, already tested Git revision. Private key is never bundled."""
import argparse,base64,hashlib,json,pathlib,re,subprocess,tempfile,time

FILES=('configure.py','policy.py','nginx_edit.py','ban.py','example-policy.json','cloudflare-ips.json','legacy-jails.local')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--revision',required=True)
    parser.add_argument('--sequence',type=int,required=True)
    parser.add_argument('--private-key',type=pathlib.Path,required=True)
    parser.add_argument('--output',type=pathlib.Path,required=True)
    parser.add_argument('--openssl',default='openssl')
    args=parser.parse_args()
    repo=pathlib.Path(__file__).resolve().parents[1]
    revision=subprocess.check_output(['git','rev-parse',args.revision+'^{commit}'],cwd=repo,text=True).strip()
    if not re.fullmatch('[a-f0-9]{40}',revision) or not 1<=args.sequence<=2**53:raise ValueError('Invalid release identity')
    if args.output.exists():
        previous=json.loads(base64.b64decode(json.loads(args.output.read_text())['payload']))
        if args.sequence<=previous['sequence']:raise ValueError('Sequence must increase; never replace a published sequence')
    files={}
    for name in FILES:
        data=subprocess.check_output(['git','show',revision+':waf/'+name],cwd=repo)
        if len(data)>2097152:raise ValueError('Package file exceeds budget')
        files[name]=hashlib.sha256(data).hexdigest()
    now=int(time.time())
    payload=json.dumps(dict(schema=1,api=1,channel='stable',sequence=args.sequence,revision=revision,
                            files=files,issued=now,expires=now+90*86400),sort_keys=True,separators=(',',':')).encode()
    with tempfile.TemporaryDirectory() as tmp:
        source=pathlib.Path(tmp)/'payload';signature=pathlib.Path(tmp)/'signature'
        source.write_bytes(payload)
        subprocess.run([args.openssl,'dgst','-sha256','-sign',str(args.private_key),'-out',str(signature),str(source)],check=True)
        subprocess.run([args.openssl,'dgst','-sha256','-verify',str(repo/'waf/release-public.pem'),'-signature',str(signature),str(source)],check=True)
        signed=signature.read_bytes()
    if len(signed)!=384:raise ValueError('Expected RSA-3072 signature')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps({'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode(signed).decode()},sort_keys=True)+'\n')
    print('Signed stable API 1 sequence',args.sequence,'revision',revision)

if __name__=='__main__':main()
