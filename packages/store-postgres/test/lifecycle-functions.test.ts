import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isAssertionSubjectError } from '../../issuer/src/store.js';
import { asserted, deferred, eventually, fixture, pending, prepareAgent, quote, skipPostgres } from './helpers.js';

const options = { skip: skipPostgres, timeout: 30_000 };

for (const lifecycle of ['invalidate_agent','retire_agent'] as const) {
  test(`READ COMMITTED ${lifecycle} fences a stale first assertion before acceptance`, options, async(t)=>{
    let armed=false;
    const waiting=deferred(),resume=deferred();
    const f=await fixture(t,{async onCheckpoint(event){
      if(armed && event.operation==='updateTransaction' && event.phase==='before_agent_lock'){
        armed=false; waiting.resolve(); await resume.promise;
      }
    }});
    const {agent}=await prepareAgent(f.store,f.now(),'assertion');
    const tx=await pending(f.store,f.now(),'stale-assertion');
    armed=true;
    const accepting=f.store.updateTransaction(asserted(tx,'assertion',f.now()),0,{now:f.now(),maxSignups:1});
    const outcome=accepting.then(value=>({value}),error=>({error}));
    await waiting.promise;
    try {
      // Deliberately autocommit READ COMMITTED, as an ordinary hosting trigger can run.
      assert.equal((await f.admin.query(`SELECT ${quote(f.schema)}.${lifecycle}($1,$2,$3) AS changed`,[agent.handle,agent.sub,f.now()])).rows[0].changed,true);
    } finally {resume.resolve();}
    const result=await outcome;
    assert.ok('error' in result && isAssertionSubjectError(result.error));
    assert.deepEqual(await f.store.getTransaction(tx.id),tx,'a stale assertion must not establish identity, consent, or a quota claim');
    assert.equal((await f.admin.query(`SELECT count(*) AS count FROM ${quote(f.schema)}.reservations`)).rows[0].count,'0');
  });
}

test('READ COMMITTED retirement prevents an enrollment from committing after its Agent was removed',options,async(t)=>{
  let armed=false;
  const waiting=deferred(),resume=deferred();
  const f=await fixture(t,{async onCheckpoint(event){
    if(armed && event.operation==='insertKey' && event.phase==='before_agent_lock'){
      armed=false; waiting.resolve(); await resume.promise;
    }
  }});
  const subject=await prepareAgent(f.store,f.now(),'enrollment');
  const key={...subject.key,kid:'new-key',enrollment:'new-enrollment'};
  armed=true;
  const insertion=f.store.insertKey(key,f.now(),subject.authorization);
  await waiting.promise;
  try {
    await f.admin.query(`SELECT ${quote(f.schema)}.retire_agent($1,$2,$3)`,[subject.agent.handle,subject.agent.sub,f.now()]);
  } finally {resume.resolve();}
  assert.equal(await insertion,'unauthorized');
  assert.equal(await f.store.getKey(key.kid),undefined);
});

test('READ COMMITTED invalidation waits for accepted authority and uses time after the Agent lock wait',options,async(t)=>{
  let armed=false;
  const accepted=deferred(),resume=deferred();
  const f=await fixture(t,{async onCheckpoint(event){
    if(armed && event.operation==='updateTransaction' && event.phase==='beforeCommit'){
      armed=false; accepted.resolve(); await resume.promise;
    }
  }});
  const {agent}=await prepareAgent(f.store,f.now(),'accepted');
  const tx=await pending(f.store,f.now(),'accepted-assertion');
  armed=true;
  const accepting=f.store.updateTransaction(asserted(tx,'accepted',f.now()),0,{now:f.now(),maxSignups:1});
  await accepted.promise;
  const lifecycle=await f.admin.connect();
  let invalidating:Promise<unknown>|undefined;
  try {
    const pid=Number((await lifecycle.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
    invalidating=lifecycle.query(`SELECT ${quote(f.schema)}.invalidate_agent($1,$2,$3)`,[agent.handle,agent.sub,f.now()]);
    await eventually(async()=>(await f.admin.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1',[pid])).rows[0]?.wait_event_type==='Lock','invalidation did not wait for the Agent fence');
    await f.advance(10);
    resume.resolve();
    assert.equal((await accepting)?.status,'ready');
    await invalidating;
    const denied=await f.store.readTransaction(tx.id,{now:f.now(),retainFor:300});
    assert.equal(denied?.status,'denied');
    assert.equal(denied?.terminalAt,f.now(),'the time captured before the lock wait must not shorten retention');
    assert.equal((await f.admin.query(`SELECT count(*) AS count FROM ${quote(f.schema)}.reservations`)).rows[0].count,'0');
    await f.advance(301);
    assert.equal(await f.store.readTransaction(tx.id,{now:f.now(),retainFor:300}),undefined);
  } finally {
    resume.resolve();
    await accepting.catch(()=>{});
    await invalidating?.catch(()=>{});
    lifecycle.release();
  }
});
