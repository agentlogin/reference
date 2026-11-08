import assert from 'node:assert/strict';
import {readFileSync,readdirSync,writeFileSync} from 'node:fs';
import {join,dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
const out=dirname(fileURLToPath(import.meta.url));
const root=resolve(process.argv[2]??join(out,'../../..'));
const rehearsal=join(root,'.private-launch-20261106/main-recovery');
const artifact=join(root,'releases/2026-11-03-security/identity');
const deployment=JSON.parse(readFileSync(join(root,'releases/2026-11-03-security/identity-deployment.json')));
const readback=JSON.parse(readFileSync(join(root,'releases/2026-11-08-trusted-providers/identity-deployment-readback.json')));
const recorded=JSON.parse(readFileSync(join(artifact,'release-manifest.json')));
const receipt=JSON.parse(readFileSync(join(rehearsal,'verified-baseline-v3.json')));
const manifest=JSON.parse(readFileSync(join(rehearsal,'source-manifest.json')));
const recovered=JSON.parse(readFileSync(join(rehearsal,'independent-review-result-v3.json')));
const sha=b=>createHash('sha256').update(b).digest('hex');
const git=(repo,...args)=>execFileSync('git',['-C',repo,...args]);
const mailRepo=join(root,'acceptance-20261106/mail-current-release'),refRepo=join(root,'reference');
assert.equal(sha(readFileSync(join(artifact,'release-manifest.json'))),deployment.artifactProof.artifactManifestSha256);
for(const [name,digest] of Object.entries(recorded.sha256))assert.equal(sha(readFileSync(join(artifact,name))),digest,name);
for(const [name,digest] of Object.entries(receipt.inputHashes))assert.equal(sha(readFileSync(join(rehearsal,name))),digest,name);
for(const [name,digest] of Object.entries(manifest.files))assert.equal(sha(readFileSync(join(rehearsal,name))),digest,name);
assert.equal(sha(readFileSync(join(rehearsal,'independent-review-result-v3.json'))),receipt.independentRecoveryResultSha256);
assert.equal(readback.deployments[0].id,deployment.deployment.id);assert.equal(readback.deployments[0].meta.imageDigest,deployment.imageDigest);assert.equal(readback.deployments[0].status,'SUCCESS');
const ts=createRequire(join(refRepo,'package.json'))('typescript');
const sourceChecks=[],emissionChecks=[];
for(const name of readdirSync(join(rehearsal,'source/mail/packages/identity/src')).filter(n=>n.endsWith('.ts'))){
 const relative='packages/identity/src/'+name,tested=readFileSync(join(rehearsal,'source/mail',relative));
 assert.ok(tested.equals(git(mailRepo,'show',deployment.source+':'+relative)),relative);
 sourceChecks.push({package:'identity',path:'src/'+name,sha256:sha(tested),matchesDeployedSource:true});
 const emitted=ts.transpileModule(tested.toString(),{fileName:name,compilerOptions:{target:ts.ScriptTarget.ES2023,module:ts.ModuleKind.ESNext,strict:true}}).outputText;
 const runtime='dist/'+name.replace(/\.ts$/,'.js'),built=readFileSync(join(artifact,runtime));
 emissionChecks.push({package:'identity',path:runtime,sourceEmissionSha256:sha(emitted),artifactSha256:sha(built),byteIdentical:Buffer.from(emitted).equals(built)});
}
for(const pkg of ['issuer','store-postgres']){
 const archive=join(artifact,`vendor/agentlogin-${pkg}-0.2.0-beta.1.tgz`);
 const entries=JSON.parse(execFileSync('python3',['-c',"import tarfile,json,base64,sys; t=tarfile.open(sys.argv[1]); print(json.dumps({m.name:base64.b64encode(t.extractfile(m).read()).decode() for m in t.getmembers() if m.isfile() and m.name.startswith('package/dist/') and m.name.endswith('.js')}))",archive]));
 for(const [path,encoded] of Object.entries(entries)){
  const name=path.replace('package/dist/','src/').replace(/\.js$/,'.ts'),relative=`packages/${pkg}/${name}`,tested=readFileSync(join(rehearsal,'source/reference',relative));
  assert.ok(tested.equals(git(refRepo,'show',deployment.referenceSource+':'+relative)),relative);
  sourceChecks.push({package:pkg,path:name,sha256:sha(tested),matchesDeployedSource:true});
  const emitted=ts.transpileModule(tested.toString(),{fileName:name.split('/').at(-1),compilerOptions:{target:ts.ScriptTarget.ES2023,module:ts.ModuleKind.ESNext,strict:true,noImplicitOverride:true,sourceMap:true}}).outputText;
  const built=Buffer.from(encoded,'base64');emissionChecks.push({package:pkg,path:path.replace('package/',''),sourceEmissionSha256:sha(emitted),artifactSha256:sha(built),byteIdentical:Buffer.from(emitted).equals(built)});
 }
}
assert.ok(emissionChecks.every(x=>x.byteIdentical),'first_party_emission_differs_from_deployed_artifact');
const delta=git(mailRepo,'diff','--name-only',deployment.source,manifest.mailRevision,'--','packages/identity').toString().trim().split('\n').filter(Boolean);
const report={assessmentDate:'2026-11-08',issuer:'https://identity.sentfrom.ai',deployedImageDigest:deployment.imageDigest,identitySource:deployment.source,referenceSource:deployment.referenceSource,rehearsalMailSource:manifest.mailRevision,observationDate:readback.observedAt,artifactManifestSha256:sha(readFileSync(join(artifact,'release-manifest.json'))),artifactFilesVerified:Object.keys(recorded.sha256).length,sourceManifestFilesVerified:Object.keys(manifest.files).length,rehearsalInputsVerified:Object.keys(receipt.inputHashes).length,recoveryResultSha256:receipt.independentRecoveryResultSha256,recoveryObservedAt:recovered.checkedAt,independentAgentCheckpoints:recovered.checks.length,typescriptVersion:ts.version,sourceChecks,emissionChecks,nonRuntimeIdentityDelta:delta,newTestsExecuted:false,emissionOnlyNoRuntimeExecuted:true,productionAccess:false};
writeFileSync(join(out,'binding-verification.json'),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({artifactFiles:report.artifactFilesVerified,sourceFiles:sourceChecks.length,emittedFiles:emissionChecks.length,allEmissionsMatch:emissionChecks.every(x=>x.byteIdentical),mismatches:emissionChecks.filter(x=>!x.byteIdentical).map(x=>({package:x.package,path:x.path})),delta}));
