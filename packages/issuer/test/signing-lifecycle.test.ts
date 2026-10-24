import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeProtectedHeader, exportJWK, generateKeyPair } from 'jose';
import { createIssuer, MemoryStore, ownerAddressKey, validateSigningConfiguration, reloadSigningConfiguration } from '../src/index.js';
import { mintIdToken } from '../src/tokens.js';

const jwk=async()=>exportJWK((await generateKeyPair('ES256',{extractable:true})).privateKey);
test('shared JWKS stages rotation, preserves old tokens, and withdraws compromised keys from every instance',async()=>{
  let now=1700000000;
  const store=new MemoryStore(),first=await jwk(),second=await jwk();
  const a=await createIssuer({issuer:'https://issuer.example',handleDomains:['example.test'],store,signingJwk:first,now:()=>now,jwksCacheSeconds:10});
  const b=await createIssuer({issuer:'https://issuer.example',handleDomains:['example.test'],store,signingJwk:first,now:()=>now,jwksCacheSeconds:10});
  const claims={agent:{handle:'bot@example.test',local:'bot',domain:'example.test',sub:'agent',ownerId:'owner',preferredUsername:'bot',enabled:true,authorizationVersion:0,createdAt:now},owner:{id:'owner',ownerSub:'owner-sub',email:'owner@example.test',emailVerified:true,verifiedVia:'passkey' as const,createdAt:now},client:{clientId:'client',type:'open' as const,redirectUris:['https://rp.example/cb'],requireReview:false,tokenEndpointAuthMethod:'none' as const},scopes:['openid'] as ['openid'],nonce:'nonce',authTime:now};
  const old=await mintIdToken(a.ctx,claims);
  const [next]=await a.publishSigningKeys([second]);
  assert.equal((await (await b.app.request('/.well-known/jwks.json')).json()).keys.length,2);
  assert.equal(await a.activateSigningKey(next!),false);
  now++;
  assert.equal(await a.activateSigningKey(next!),true);
  await assert.rejects(mintIdToken(b.ctx,claims),/No active/);
  await b.publishSigningKeys([second]);
  assert.equal(decodeProtectedHeader(await mintIdToken(b.ctx,claims)).kid,next);
  assert.equal(await a.removeSigningKey(decodeProtectedHeader(old).kid!),false);
  assert.equal(await a.removeSigningKey(next!,true),true);
  await assert.rejects(mintIdToken(b.ctx,claims),/No active/);
  assert.equal((await (await b.app.request('/.well-known/jwks.json')).json()).keys.some((key:{kid:string})=>key.kid===next),false);
});
test('signing configuration rejects wrong algorithms, inconsistent private keys, duplicate material and invalid reloads before publication',async()=>{
  const first=await jwk(),second=await jwk();
  await assert.rejects(createIssuer({issuer:'https://issuer.example',handleDomains:[],signingJwk:{...first,alg:'HS256'}}),/ES256/);
  await assert.rejects(createIssuer({issuer:'https://issuer.example',handleDomains:[],signingJwk:{...first,d:second.d}}));
  await assert.rejects(validateSigningConfiguration({keys:[first,first]}),/Duplicate/);
  const issuer=await createIssuer({issuer:'https://issuer.example',handleDomains:[],signingJwk:first});
  await assert.rejects(reloadSigningConfiguration(issuer,{keys:[second],activateKid:'absent'}),/Activation/);
  assert.equal((await issuer.ctx.store.listSigningKeys()).length,1);
});
test('a replica serving longer JWKS freshness protects keys staged by another replica',async()=>{
  let now=1700000000;
  const store=new MemoryStore(),first=await jwk(),second=await jwk();
  const options={issuer:'https://issuer.example',handleDomains:['example.test'],store,signingJwk:first,now:()=>now};
  const longer=await createIssuer({...options,jwksCacheSeconds:3600});
  const shorter=await createIssuer({...options,jwksCacheSeconds:0});
  const [kid]=await shorter.publishSigningKeys([second]);
  const response=await longer.app.request('/.well-known/jwks.json');
  assert.equal(response.headers.get('cache-control'),'public, max-age=3600');
  assert.ok((await response.json()).keys.some((key:{kid:string})=>key.kid===kid));
  assert.equal((await store.listSigningKeys()).find((key)=>key.kid===kid)?.cacheLifetime,3600);
  now++;
  assert.equal(await shorter.removeSigningKey(kid!),false);
});
test('Owner address identity preserves local-part octets and normalizes quoted forms and A-label domains',()=>{
  assert.equal(ownerAddressKey('Person@EXAMPLE.COM'),ownerAddressKey('"Person"@example.com'));
  assert.notEqual(ownerAddressKey('Person@example.com'),ownerAddressKey('person@example.com'));
  assert.equal(ownerAddressKey('Person@bücher.example'),ownerAddressKey('Person@xn--bcher-kva.example'));
  for(const invalid of ['no-at','a@@example.com','a@bad..example','a\n@example.com','a@-bad.example']) assert.throws(()=>ownerAddressKey(invalid));
});
