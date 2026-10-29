import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ban
import configure as manage
import policy

ZONE='a'*32
OTHER='b'*32
OWNER='c'*32
RULESET='d'*32
RULE='e'*32


class Edge:
    def __init__(self):
        self.sets={}
        self.calls=[]

    def request(self,method,path,body=None,missing=False):
        self.calls.append((method,path,copy.deepcopy(body)))
        zone=path.split('/')[2]
        if method=='GET':
            return {'result':copy.deepcopy(self.sets[zone])} if zone in self.sets else None
        if method=='POST' and path.endswith('/rulesets'):
            self.sets[zone]={'id':RULESET,'rules':[]}
        elif method=='POST':
            self.sets[zone]['rules'].append(dict(body,id=RULE))
        elif method=='PATCH':
            self.sets[zone]['rules']=[dict(body,id=RULE) if r['id']==RULE else r for r in self.sets[zone]['rules']]
        elif method=='DELETE':
            self.sets[zone]['rules']=[r for r in self.sets[zone]['rules'] if r['id']!=RULE]
        return {'result':copy.deepcopy(self.sets[zone])}


class BanTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.addCleanup(patch.stopall)
        patch.object(manage,'safe_parent').start()
        patch.object(manage,'locked',side_effect=lambda *a,**k:contextlib.nullcontext()).start()
        self.execute=patch.object(manage,'execute',return_value='[]').start()
        self.reload=patch.object(manage,'reload_nginx').start()
        self.f2b=self.root/'f2b'
        patch.object(ban,'F2B',self.f2b).start()
        self.config=json.loads((manage.BUNDLE/'example-policy.json').read_text())
        self.config.update(mode='on',banBackend='existing',cdn='mixed')
        self.write(self.root/'config/waf/policy.json',self.config)
        self.write(self.root/'config/waf/cloudflare-ips.json',json.loads((manage.BUNDLE/'cloudflare-ips.json').read_text()))
        path=self.root/'conf.d/site.conf';path.parent.mkdir(parents=True)
        path.write_text('server { server_name one.example.com www.example.com; }\nserver { server_name two.example.com; }')
        path=self.root/'conf.d/waf/blocked.map';path.parent.mkdir()
        path.write_text(policy.render_bans({},int(time.time())))
        self.cf={'mode':'cloudflare','auth':{'email':'','key':'x'*40},
                 'targets':{'one.example.com':[{'host':'one.example.com','zone':ZONE},
                                               {'host':'www.example.com','zone':ZONE}]},'zones':[ZONE]}
        self.value={'owner':OWNER,'records':{'one.example.com|8.8.8.8':{'attack':int(time.time())+600}}}

    def write(self,path,data):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(data));path.chmod(0o600)

    def event(self,ip='8.8.8.8',site='one.example.com',source='attack',seconds=600,started=None):
        ban.change(self.root,'ban',site+'|'+ip,source,seconds,started=time.time() if started is None else started)

    def test_missing_actions_restart_only_affected_jail(self):
        actions={'waf-attack':['waf-unified'],'waf-rate':[],'waf-api-invalid':['waf-unified-api']}
        calls=[]
        def execute(*args):
            calls.append(args)
            if args[1:3]==('get','waf-rate'):
                return '\n'.join(actions['waf-rate'])
            if args[1]=='get':
                return '\n'.join(actions[args[2]])
            if args[1:3]==('reload','--restart'):
                actions[args[3]]=['waf-unified']
            return ''
        with patch.object(manage,'execute',side_effect=execute):
            ban.ensure_jail_actions({'apiJailEnabled':True,'apiSite':'one.example.com'})
        self.assertEqual([c for c in calls if c[1]=='reload'],[('fail2ban-client','reload','--restart','waf-rate')])

    def test_failed_action_recovery_is_an_error(self):
        def execute(*args):
            return 'No actions for jail' if args[1:2]==('get',) and args[-1]=='actions' else ''
        with patch.object(manage,'execute',side_effect=execute):
            with self.assertRaisesRegex(ValueError,'Fail2Ban action not loaded'):
                ban.ensure_jail_actions({})

    def test_recovery_refuses_to_drop_tickets_when_database_is_disabled(self):
        def execute(*args):
            if args[1:]==('get','waf-attack','banip'):return 'one.example.com|8.8.8.8'
            if args[1:]==('get','dbfile'):return 'Current database file is:\n`- None\n'
            return ''
        with patch.object(manage,'execute',side_effect=execute) as execute_mock:
            with self.assertRaisesRegex(ValueError,'without a Fail2Ban database'):
                ban.ensure_jail_actions({})
        self.assertFalse(any(c.args[1:3]==('reload','--restart') for c in execute_mock.call_args_list))

    def test_status_rejects_jails_without_live_actions(self):
        jail=self.f2b/'jail.d/zz-waf-managed.local';jail.parent.mkdir(parents=True)
        jail.write_text(ban.MARKER)
        with patch.object(manage,'execute',return_value='No actions for jail'):
            result=ban.status(self.root)
        self.assertFalse(result['running'])
        self.assertFalse(result['healthy'])

    def test_site_isolation_and_origin_hook(self):
        self.event()
        text=(self.root/'conf.d/waf/blocked.map').read_text()
        self.assertIn('"one.example.com|8.8.8.8" 1;',text)
        self.assertNotIn('two.example.com',text)
        self.reload.assert_called_once()

    def test_independent_attack_rate_expiry(self):
        self.event();self.event(source='rate')
        ban.change(self.root,'unban','one.example.com|8.8.8.8','attack')
        self.assertEqual(set(ban.state(self.root)['records']['one.example.com|8.8.8.8']),{'rate'})
        ban.change(self.root,'unban','one.example.com|8.8.8.8','rate')
        self.assertNotIn('8.8.8.8',(self.root/'conf.d/waf/blocked.map').read_text())

    def test_restarted_ticket_keeps_original_expiry(self):
        start=time.time()-100
        self.event(started=start)
        self.assertEqual(ban.state(self.root)['records']['one.example.com|8.8.8.8']['attack'],int(start)+600)

    def test_expired_replay_does_not_reban(self):
        self.event(started=time.time()-1000)
        self.assertEqual(ban.state(self.root)['records'],{})

    def test_invalid_durations_and_future_time(self):
        for seconds in [0,59,86401]:
            with self.assertRaises(ValueError):self.event(seconds=seconds)
        self.event(seconds=3601)
        with self.assertRaises(ValueError):self.event(started=time.time()+100)

    def test_proxy_private_unknown_and_allowlisted_rejected(self):
        self.config['banIgnore']=['9.9.9.9/32']
        self.write(self.root/'config/waf/policy.json',self.config)
        for ip in ['127.0.0.1','10.1.2.3','173.245.48.1','9.9.9.9','2606:4700::1']:
            with self.subTest(ip=ip),self.assertRaises(ValueError):self.event(ip=ip)
        with self.assertRaises(ValueError):self.event(site='unknown.example.com')

    def test_local_interface_address_rejected(self):
        self.execute.return_value='[{"addr_info":[{"local":"8.8.8.8"}]}]'
        with self.assertRaises(ValueError):self.event()

    def test_ipv6_normalized(self):
        self.event(ip='2001:4860:4860:0000::8888')
        self.assertIn('one.example.com|2001:4860:4860::8888',ban.state(self.root)['records'])

    def test_origin_failure_preserves_desired_and_marks_unhealthy(self):
        self.reload.side_effect=RuntimeError('bad reload')
        with self.assertRaises(RuntimeError):self.event()
        self.assertIn('one.example.com|8.8.8.8',ban.state(self.root)['records'])
        self.assertFalse(ban.read(self.root,'ban-health.json',{})['ok'])
        self.assertNotIn('8.8.8.8',(self.root/'conf.d/waf/blocked.map').read_text())

    def test_busy_install_still_persists_ticket_for_cron(self):
        def locking(path,**_):
            if path.name=='install.lock':raise RuntimeError('busy')
            return contextlib.nullcontext()
        with patch.object(manage,'locked',side_effect=locking):
            with self.assertRaises(RuntimeError):self.event()
        self.assertTrue(ban.state(self.root)['records'])
        ban.change(self.root,'sync')
        self.assertIn('8.8.8.8',(self.root/'conf.d/waf/blocked.map').read_text())

    def test_pending_does_not_reset_failed_edge_health(self):
        ban.save(self.root,'bans.json',self.value)
        ban.save(self.root,'ban-cf.json',self.cf)
        ban.save(self.root,'ban-health.json',{'ok':False,'checked':123})
        self.event()
        health=ban.read(self.root,'ban-health.json',{})
        self.assertEqual(health['checked'],123);self.assertFalse(health['ok'])

    def test_expiry_and_clear_remove_origin(self):
        self.event()
        value=ban.state(self.root)
        value['records']['one.example.com|8.8.8.8']['attack']=1
        ban.save(self.root,'bans.json',value)
        ban.change(self.root,'sync')
        self.assertEqual(ban.state(self.root)['records'],{})
        self.event();ban.change(self.root,'clear')
        self.assertEqual(ban.state(self.root)['records'],{})

    def test_edge_scopes_aliases_and_preserves_other_rules(self):
        edge=Edge()
        custom={'id':'f'*32,'ref':'user-rule','action':'skip'}
        edge.sets[ZONE]={'id':RULESET,'rules':[custom]}
        ban.sync_edge(self.cf,self.value,edge)
        rules=edge.sets[ZONE]['rules']
        self.assertEqual(rules[0],custom)
        expression=rules[1]['expression']
        self.assertIn('lower(http.host) eq "one.example.com"',expression)
        self.assertIn('www.example.com',expression)
        self.assertNotIn('two.example.com',expression)
        ban.sync_edge(dict(self.cf,mode='local'),self.value,edge)
        self.assertEqual(edge.sets[ZONE]['rules'],[custom])

    def test_edge_enable_empty_checks_write_permissions(self):
        edge=Edge();value=dict(self.value,records={})
        ban.sync_edge(self.cf,value,edge)
        self.assertEqual(edge.sets[ZONE]['rules'][0]['expression'],ban.CF_NEVER_MATCH)
        self.assertEqual(edge.sets[ZONE]['rules'][0]['position'],{'before':''})

    def test_edge_drift_refuses_overwrite(self):
        edge=Edge();ban.sync_edge(self.cf,self.value,edge)
        edge.sets[ZONE]['rules'][0]['action']='skip'
        with self.assertRaises(ValueError):ban.sync_edge(self.cf,self.value,edge)

    def test_historical_zone_is_cleaned(self):
        edge=Edge();ban.sync_edge(self.cf,self.value,edge)
        cf=dict(self.cf,targets={},zones=[ZONE])
        ban.sync_edge(cf,dict(self.value,records={}),edge)
        self.assertEqual(edge.sets[ZONE]['rules'],[])

    def test_inventory_drift_cleans_before_reporting_error(self):
        edge=Edge();ban.sync_edge(self.cf,self.value,edge)
        (self.root/'conf.d/site.conf').write_text('server { server_name two.example.com; }')
        with patch.object(ban,'Cloudflare',return_value=edge),self.assertRaisesRegex(ValueError,'inventory changed'):
            ban.reconcile(self.root,self.config,self.value,self.cf)
        self.assertEqual(edge.sets[ZONE]['rules'],[])

    def test_capacity_overflow_clears_old_edge_projection(self):
        edge=Edge();ban.sync_edge(self.cf,self.value,edge)
        with patch.object(ban,'MAX_EXPRESSION',1),self.assertRaisesRegex(ValueError,'capacity'):
            ban.sync_edge(self.cf,self.value,edge)
        self.assertEqual(edge.sets[ZONE]['rules'][0]['expression'],ban.CF_NEVER_MATCH)

    def test_cf_off_works_when_fail2ban_is_stopped(self):
        edge=Edge();value=ban.state(self.root)
        ban.save(self.root,'bans.json',value)
        ban.save(self.root,'ban-cf.json',self.cf)
        ban.sync_edge(self.cf,value,edge)
        with patch.object(ban,'Cloudflare',return_value=edge):
            result=ban.configure_cf(self.root,disable=True)
        self.assertEqual(result['mode'],'local')
        self.assertEqual(ban.read(self.root,'ban-cf.json',{}),{'mode':'local'})
        self.assertEqual(edge.sets[ZONE]['rules'],[])

    def test_cf_off_failure_keeps_credentials_for_retry(self):
        ban.save(self.root,'bans.json',self.value)
        ban.save(self.root,'ban-cf.json',self.cf)
        with patch.object(ban,'sync_edge',side_effect=RuntimeError('API unavailable')):
            with self.assertRaises(RuntimeError):ban.configure_cf(self.root,disable=True)
        self.assertEqual(ban.read(self.root,'ban-cf.json',{})['auth'],self.cf['auth'])

    def test_cf_on_requires_running_jails(self):
        with self.assertRaisesRegex(ValueError,'start unified'):
            ban.configure_cf(self.root,{'email':'','key':'x'*40})

    def test_credentials_and_state_are_private(self):
        self.event()
        self.assertEqual((self.root/'config/waf/bans.json').stat().st_mode&0o777,0o600)

    def test_invalid_identity_cannot_reach_action_shell(self):
        for value in ['one.example.com|8.8.8.8;id','$(id)|8.8.8.8','one.example.com|1|2']:
            with self.assertRaises(ValueError):ban.stage(self.root,'ban',value,'attack',600,time.time())

    def test_zone_mapping_excludes_direct_sites_and_longest_zone_wins(self):
        self.config['sites']={'two.example.com':{'cdn':'direct'}}
        mapping=ban.targets(self.root,self.config,{'example.com':ZONE,'one.example.com':OTHER})
        self.assertNotIn('two.example.com',mapping)
        self.assertEqual(mapping['one.example.com'][0]['zone'],OTHER)

    def test_wildcard_and_missing_zone_fail_explicitly(self):
        with self.assertRaisesRegex(ValueError,'No accessible'):
            ban.targets(self.root,self.config,{})
        (self.root/'conf.d/site.conf').write_text('server { server_name *.example.com; }')
        with self.assertRaisesRegex(ValueError,'explicit DNS'):
            ban.targets(self.root,self.config,{'example.com':ZONE})

    def test_map_byte_budget_rejects_growth_without_losing_previous_state(self):
        self.event();before=(self.root/'config/waf/bans.json').read_bytes()
        with patch.object(policy,'render_bans',return_value='x'*(2*1024*1024+1)):
            with self.assertRaisesRegex(ValueError,'byte budget'):self.event(ip='9.9.9.9')
        self.assertEqual((self.root/'config/waf/bans.json').read_bytes(),before)

    def test_missing_cf_owner_refuses_cleanup_and_keeps_credentials(self):
        ban.save(self.root,'ban-cf.json',self.cf)
        with self.assertRaisesRegex(ValueError,'owner state is missing'):
            ban.configure_cf(self.root,disable=True)
        self.assertEqual(ban.read(self.root,'ban-cf.json',{})['auth'],self.cf['auth'])

    def test_conflicting_alias_is_rejected(self):
        (self.root/'conf.d/site.conf').write_text('server { server_name one.example.com shared.example.com; } server { server_name two.example.com shared.example.com; }')
        with self.assertRaisesRegex(ValueError,'Conflicting site alias'):
            ban.inventory(self.root)

    def test_busy_configuration_queues_successfully_after_persisting(self):
        def locking(path,**_):
            if path.name=='install.lock':raise RuntimeError('Configuration is busy; retry later')
            return contextlib.nullcontext()
        with patch.object(manage,'locked',side_effect=locking):self.event()
        self.assertTrue(ban.state(self.root)['records'])

    def test_cf_off_without_integration_is_noop(self):
        ban.configure_cf(self.root,disable=True)
        self.assertFalse((self.root/'config/waf/bans.json').exists())

    def test_remove_already_removed_is_noop(self):
        self.config['banBackend']='none';self.write(self.root/'config/waf/policy.json',self.config)
        ban.save(self.root,'bans.json',dict(self.value,records={}))
        ban.save(self.root,'ban-cf.json',{'mode':'local'})
        self.assertEqual(ban.remove(self.root),{'updated':False})

    def test_full_cf_switch_preserves_origin_bans_and_modes(self):
        jail=self.f2b/'jail.d/zz-waf-managed.local';jail.parent.mkdir(parents=True)
        jail.write_text(ban.MARKER)
        edge=Edge();edge.zones=lambda:{'example.com':ZONE}
        before=(self.root/'config/waf/policy.json').read_bytes()
        with patch.object(ban,'Cloudflare',return_value=edge),patch.object(ban,'jail_action_loaded',return_value=True):
            ban.configure_cf(self.root,{'email':'','key':'x'*40})
            self.event()
            self.assertEqual(edge.sets[ZONE]['rules'][0]['expression'],ban.CF_NEVER_MATCH)
            ban.change(self.root,'sync')
            self.assertIn('8.8.8.8',edge.sets[ZONE]['rules'][0]['expression'])
            ban.configure_cf(self.root,disable=True)
        self.assertEqual(edge.sets[ZONE]['rules'],[])
        self.assertIn('8.8.8.8',(self.root/'conf.d/waf/blocked.map').read_text())
        self.assertEqual((self.root/'config/waf/policy.json').read_bytes(),before)

    def test_cf_cleanup_pending_is_reported_after_failed_disable(self):
        ban.save(self.root,'bans.json',self.value)
        ban.save(self.root,'ban-cf.json',self.cf)
        with patch.object(ban,'sync_edge',side_effect=RuntimeError('unavailable')):
            with self.assertRaises(RuntimeError):ban.configure_cf(self.root,disable=True)
        self.assertTrue(ban.status(self.root)['cleanupPending'])

    def test_failed_cf_enable_preserves_reentry_requirement(self):
        ban.save(self.root,'ban-migration.json',{'state':'legacy-imported','cfReentryRequired':True})
        edge=Edge();edge.zones=lambda:{'example.com':ZONE}
        with patch.object(ban,'status',return_value={'running':True}), \
             patch.object(ban,'Cloudflare',return_value=edge), \
             patch.object(ban,'sync_edge',side_effect=RuntimeError('unavailable')):
            with self.assertRaises(RuntimeError):
                ban.configure_cf(self.root,{'email':'','key':'x'*40})
        self.assertTrue(ban.read(self.root,'ban-migration.json',{})['cfReentryRequired'])
        with patch.object(ban,'sync_edge',return_value=None):
            ban.change(self.root,'sync')
        self.assertFalse(ban.read(self.root,'ban-migration.json',{})['cfReentryRequired'])

    def test_ticket_reconciliation_repairs_orphaned_manual_unban(self):
        value=copy.deepcopy(self.value)
        ban.reconcile_tickets(value,{'generation':0,'sources':{'attack':set(),'rate':set()}})
        self.assertEqual(value['records']['one.example.com|8.8.8.8'],{})

    def test_jail_unavailable_does_not_remove_persisted_ticket(self):
        value=copy.deepcopy(self.value)
        ban.reconcile_tickets(value,None)
        self.assertEqual(value,self.value)

    def test_ticket_list_keeps_active_sources(self):
        value=copy.deepcopy(self.value)
        ban.reconcile_tickets(value,{'generation':0,'sources':{'attack':{'one.example.com|8.8.8.8'},'rate':set()}})
        self.assertEqual(value,self.value)

    def test_stale_ticket_snapshot_cannot_cancel_new_event(self):
        value=dict(copy.deepcopy(self.value),generation=2)
        before=copy.deepcopy(value)
        ban.reconcile_tickets(value,{'generation':1,'sources':{'attack':set(),'rate':set()}})
        self.assertEqual(value,before)

    def test_ticket_reconciliation_keeps_other_source(self):
        value=copy.deepcopy(self.value)
        value['records']['one.example.com|8.8.8.8']['rate']=int(time.time())+600
        ban.reconcile_tickets(value,{'generation':0,'sources':{'attack':set(),'rate':{'one.example.com|8.8.8.8'}}})
        self.assertEqual(set(value['records']['one.example.com|8.8.8.8']),{'rate'})

    def test_incomplete_rpc_snapshot_is_not_used(self):
        with patch.object(ban,'query_tickets',side_effect=[set(),RuntimeError('busy')]):
            self.assertIsNone(ban.ticket_snapshot(self.root))

    def test_cf_zone_budget_failure_preserves_previous_configuration(self):
        ban.save(self.root,'bans.json',self.value)
        previous=dict(self.cf,zones=[ZONE]+[f'{i:032x}' for i in range(1,20)])
        ban.save(self.root,'ban-cf.json',previous)
        before=(self.root/'config/waf/ban-cf.json').read_bytes()
        edge=Edge();edge.zones=lambda:{'example.com':OTHER}
        with patch.object(ban,'status',return_value={'running':True}),patch.object(ban,'Cloudflare',return_value=edge):
            with self.assertRaisesRegex(ValueError,'zone budget'):
                ban.configure_cf(self.root,self.cf['auth'])
        self.assertEqual((self.root/'config/waf/ban-cf.json').read_bytes(),before)

    def test_legacy_state_import_keeps_unexpired_bans_until_original_expiry(self):
        expiry=int(time.time())+420
        identity='one.example.com|8.8.8.8'
        mapped=policy.render_bans({identity:{'expires':expiry}},int(time.time()))
        (self.root/'conf.d/waf/blocked.map').write_text(mapped)
        state={'schemaVersion':1,'bans':{identity:{'expires':expiry,'sources':{'rate':expiry-30}}},
               'appliedDigest':hashlib.sha256(mapped.encode()).hexdigest(),'lastReload':int(time.time())}
        self.write(self.root/'config/waf/state.json',state)
        result=ban.legacy_state(self.root)
        self.assertEqual(result['records'],{identity:{'legacy':expiry}})
        self.assertEqual(result['importedRecords'],1)

    def test_read_only_status_reports_legacy_migration_pending(self):
        expiry=int(time.time())+420
        identity='one.example.com|8.8.8.8'
        mapped=policy.render_bans({identity:{'expires':expiry}},int(time.time()))
        (self.root/'conf.d/waf/blocked.map').write_text(mapped)
        state={'schemaVersion':1,'bans':{identity:{'expires':expiry,'sources':{'manual':expiry}}},
               'appliedDigest':hashlib.sha256(mapped.encode()).hexdigest(),'lastReload':int(time.time())}
        self.write(self.root/'config/waf/state.json',state)
        self.assertEqual(ban.status(self.root)['migration']['state'],'legacy-pending')
        self.assertEqual(ban.status(self.root)['migration']['importedRecords'],1)

    def test_legacy_state_digest_mismatch_refuses_migration(self):
        expiry=int(time.time())+420
        identity='one.example.com|8.8.8.8'
        mapped=policy.render_bans({identity:{'expires':expiry}},int(time.time()))
        (self.root/'conf.d/waf/blocked.map').write_text(mapped)
        state={'schemaVersion':1,'bans':{identity:{'expires':expiry,'sources':{'rate':expiry}}},
               'appliedDigest':'0'*64,'lastReload':int(time.time())}
        self.write(self.root/'config/waf/state.json',state)
        with self.assertRaisesRegex(ValueError,'map changed'):
            ban.legacy_state(self.root)

    def test_unknown_legacy_source_refuses_migration(self):
        expiry=int(time.time())+420
        identity='one.example.com|8.8.8.8'
        mapped=policy.render_bans({identity:{'expires':expiry}},int(time.time()))
        (self.root/'conf.d/waf/blocked.map').write_text(mapped)
        state={'schemaVersion':1,'bans':{identity:{'expires':expiry,'sources':{'custom':expiry}}},
               'appliedDigest':hashlib.sha256(mapped.encode()).hexdigest(),'lastReload':int(time.time())}
        self.write(self.root/'config/waf/state.json',state)
        with self.assertRaisesRegex(ValueError,'Unknown legacy ban source'):
            ban.legacy_state(self.root)

    def test_legacy_expiry_beyond_supported_day_is_rejected(self):
        now=int(time.time());expiry=now+ban.MAX_LEGACY_EXPIRY+1
        identity='one.example.com|8.8.8.8'
        mapped=policy.render_bans({identity:{'expires':expiry}},now)
        (self.root/'conf.d/waf/blocked.map').write_text(mapped)
        state={'schemaVersion':1,'bans':{identity:{'expires':expiry,'sources':{'rate':expiry}}},
               'appliedDigest':hashlib.sha256(mapped.encode()).hexdigest(),'lastReload':now}
        self.write(self.root/'config/waf/state.json',state)
        with self.assertRaisesRegex(ValueError,'Invalid legacy ban expiry'):
            ban.legacy_state(self.root)

    def test_legacy_import_merges_without_replacing_current_sources(self):
        expiry=int(time.time())+420
        value={'owner':OWNER,'generation':4,'records':{
            'one.example.com|8.8.8.8':{'attack':expiry+30},
            'two.example.com|9.9.9.9':{'rate':expiry+60},}}
        legacy={'one.example.com|8.8.8.8':{'legacy':expiry}}
        self.assertEqual(ban.merge_legacy_records(value,legacy),{
            'owner':OWNER,'generation':5,'records':{
                'one.example.com|8.8.8.8':{'attack':expiry+30,'legacy':expiry},
                'two.example.com|9.9.9.9':{'rate':expiry+60},}})

    def test_legacy_jail_actions_migrate_and_keep_thresholds(self):
        previous=ban.LEGACY_MARKER+'[waf-attack]\nenabled = true\nmaxretry = 23\nfindtime = 300\nbantime = 700\naction = waf-local[reason=attack]\n[waf-rate]\nenabled = true\nmaxretry = 140\nfindtime = 300\nbantime = 800\naction = waf-local[reason=rate]\n'
        content=ban.managed_jail_content(previous,{'enabled':True})
        self.assertTrue(content.startswith(ban.MARKER))
        self.assertIn('maxretry = 23',content)
        self.assertIn('bantime = 800',content)
        self.assertIn('action = waf-unified[source=attack]',content)
        self.assertIn('action = waf-unified[source=rate]',content)
        self.assertIn('[waf-api-invalid]\naction = waf-unified[source=api]',content)

    def test_108_legacy_jail_and_disabled_nginx_jails_migrate_without_losing_policy(self):
        previous='''# Managed shared WAF; only trusted defence events, isolated by canonical site and client.
[waf-attack]
enabled = true
findtime = 120
maxretry = 20
bantime = 600
logpath = /home/web/log/nginx/waf-audit.json
action = waf-local[reason=attack]
[waf-rate]
enabled = true
findtime = 120
maxretry = 120
bantime = 600
logpath = /home/web/log/nginx/waf-rate.log
action = waf-local[reason=rate]
[fail2ban-nginx-cc]
enabled = false
[nginx-418]
enabled = false
[nginx-bad-request]
enabled = false
[nginx-badbots]
enabled = false
[nginx-botsearch]
enabled = false
[nginx-deny]
enabled = false
[nginx-http-auth]
enabled = false
[nginx-unauthorized]
enabled = false
[php-url-fopen]
enabled = false
'''
        content=ban.managed_jail_content(previous,None)
        self.assertEqual(ban.managed_jail_marker(content),'current')
        self.assertIn('maxretry = 20',content)
        self.assertIn('maxretry = 120',content)
        self.assertIn('logpath = /home/web/log/nginx/waf-audit.json',content)
        self.assertIn('logpath = /home/web/log/nginx/waf-rate.log',content)
        self.assertIn('action = waf-unified[source=attack]',content)
        self.assertIn('action = waf-unified[source=rate]',content)
        self.assertIn('[nginx-418]\nenabled = false',content)
        self.assertIn('[php-url-fopen]\nenabled = false',content)

    def test_unmarked_legacy_jail_migrates_only_when_actions_and_logs_match(self):
        previous='''\ufeff# Operator note
[waf-attack]
enabled = true
findtime = 120
maxretry = 20
bantime = 600
logpath = /home/web/log/nginx/waf-audit.json tail
action = waf-local[reason=attack]
[waf-rate]
enabled = true
findtime = 120
maxretry = 120
bantime = 600
logpath = /home/web/log/nginx/waf-rate.log
action = waf-local[reason=rate]
'''
        content=ban.managed_jail_content(previous,None)
        self.assertEqual(ban.managed_jail_marker(content),'current')
        self.assertIn('# Operator note\n',content)
        self.assertIn('logpath = /home/web/log/nginx/waf-audit.json tail',content)
        self.assertIn('action = waf-unified[source=attack]',content)
        self.assertIn('action = waf-unified[source=rate]',content)

        jail_dir=self.f2b/'jail.d';action_dir=self.f2b/'action.d'
        jail_dir.mkdir(parents=True);action_dir.mkdir(parents=True)
        previous_at_root=previous.replace('/home/web/log/nginx/',str(self.root).replace('\\','/')+'/log/nginx/')
        (jail_dir/'zz-waf-managed.local').write_text(previous_at_root,encoding='utf-8')
        (action_dir/'waf-local.conf').write_text('''[Definition]
actionban = <python> <runtime> --root <root> ban --key "<ip>" --ttl <bantime> --reason <reason>
actionunban = <python> <runtime> --root <root> unban --key "<ip>" --reason <reason>
[Init]
python = /usr/bin/python3
runtime = /home/web/conf.d/waf/wafctl.py
root = /home/web
reason = attack
''',encoding='utf-8')
        with (patch.object(ban,'LEGACY_CF_ACTION',self.f2b/'action.d/cloudflare-docker.conf'),
              patch.object(ban,'LEGACY_RECONCILER',self.root/'missing.service')):
            plan=ban.migration_plan(self.root)
        self.assertTrue(plan['requiresMigration'])
        self.assertEqual(plan['managedJail'],previous_at_root)

    def test_unmarked_legacy_jail_with_custom_action_or_log_is_not_claimed(self):
        previous='''[waf-attack]
enabled = true
findtime = 120
maxretry = 20
bantime = 600
logpath = /home/web/log/nginx/waf-audit.json
action = custom-ban
[waf-rate]
enabled = true
findtime = 120
maxretry = 120
bantime = 600
logpath = /home/web/log/nginx/waf-rate.log
action = waf-local[reason=rate]
'''
        with self.assertRaisesRegex(ValueError,'requires explicit migration'):
            ban.validate_managed_jail(previous,allow_unmarked_legacy=True)
        changed=previous.replace('action = custom-ban','action = waf-local[reason=attack]').replace('waf-audit.json','custom.log')
        with self.assertRaisesRegex(ValueError,'requires explicit migration'):
            ban.validate_managed_jail(changed,allow_unmarked_legacy=True)
        custom_filter=previous.replace('[waf-attack]','[waf-attack]\nfilter = custom-nginx-filter')
        self.assertFalse(ban.is_unmarked_legacy_managed_jail(custom_filter))

    def test_unmarked_legacy_jails_accept_reason_aliases_and_known_rotated_logs(self):
        previous='''# Operator note
[waf-attack]
enabled = true
findtime = 120
maxretry = 20
bantime = 600
logpath = /home/web/log/nginx/waf-audit*.json /home/web/log/nginx/waf-audit-2026-10-29.json tail
action = waf-local [ reason = waf-attack ]
[waf-rate]
enabled = true
findtime = 120
maxretry = 120
bantime = 600
logpath = /home/web/log/nginx/waf-rate.log.* /home/web/log/nginx/waf-rate-2026-10-29.log
action = waf-local[reason = waf-rate]
'''
        self.assertTrue(ban.is_unmarked_legacy_managed_jail(previous))
        migrated=ban.managed_jail_content(previous,None)
        self.assertIn('action = waf-unified[source=attack]',migrated)
        self.assertIn('action = waf-unified[source=rate]',migrated)
        self.assertIn('waf-audit*.json /home/web/log/nginx/waf-audit-2026-10-29.json tail',migrated)

    def test_unmarked_legacy_error_log_and_default_inheritance_migrate(self):
        previous='''# Operator note
[DEFAULT]
action = waf-local[reason=attack]
logpath = /home/web/log/nginx/error.log /home/web/log/nginx/error.log.1.gz tail
[waf-attack]
enabled = true
findtime = 120
maxretry = 20
bantime = 600
[waf-rate]
enabled = true
findtime = 120
maxretry = 120
bantime = 600
logpath = /home/web/log/nginx/waf-rate.log
action = waf-local[reason=rate]
'''
        self.assertTrue(ban.is_unmarked_legacy_managed_jail(previous))
        migrated=ban.managed_jail_content(previous,None)
        parsed=ban.parse_jail(migrated)
        self.assertEqual(parsed.get('waf-attack','action'),'waf-unified[source=attack]')
        self.assertEqual(parsed.get('waf-rate','action'),'waf-unified[source=rate]')
        self.assertEqual(parsed.get('waf-attack','logpath'),
                         '/home/web/log/nginx/waf-audit.json /home/web/log/nginx/waf-audit.json.1.gz tail')
        # Keep shared defaults unchanged for any non-WAF jails in this file.
        self.assertIn('action = waf-local[reason=attack]\n',migrated)
        self.assertIn('logpath = /home/web/log/nginx/error.log /home/web/log/nginx/error.log.1.gz tail\n',migrated)
        self.assertFalse(ban.is_unmarked_legacy_managed_jail(
            previous.replace('/home/web/log/nginx/error.log','/home/web/log/nginx/custom.log')))

    def test_partial_legacy_waf_jail_with_case_variants_is_completed_from_install_defaults(self):
        previous='''[DEFAULT]
action = waf-local[reason=attack]
logpath = /home/web/log/nginx/error.log
maxretry = 24
findtime = 240
bantime = 720
[WAF-ATTACK]
enabled = true
'''
        defaults=ban.MARKER+'''[waf-attack]
enabled = true
findtime = 300
maxretry = 20
bantime = 600
logpath = /home/web/log/nginx/waf-audit.json
action = waf-unified[source=attack]
[waf-rate]
enabled = true
findtime = 300
maxretry = 120
bantime = 600
logpath = /home/web/log/nginx/waf-rate.log
action = waf-unified[source=rate]
'''
        self.assertTrue(ban.is_unmarked_legacy_managed_jail(previous))
        migrated=ban.managed_jail_content(previous,None,defaults=defaults)
        parsed=ban.parse_jail(migrated)
        self.assertEqual(parsed.get('waf-attack','action'),'waf-unified[source=attack]')
        self.assertEqual(parsed.get('waf-attack','logpath'),'/home/web/log/nginx/waf-audit.json')
        self.assertEqual(parsed.getint('waf-attack','maxretry'),24)
        self.assertEqual(parsed.get('waf-rate','action'),'waf-unified[source=rate]')
        self.assertEqual(parsed.get('waf-rate','logpath'),'/home/web/log/nginx/waf-rate.log')
        self.assertIn('[waf-attack]\n',migrated)
        self.assertNotIn('[WAF-ATTACK]',migrated)
        self.assertIn('action = waf-local[reason=attack]\n',migrated)

    def test_partial_rate_only_legacy_jail_is_recognized_but_custom_log_is_not(self):
        previous='''[WAF-RATE]
enabled = true
findtime = 120
maxretry = 120
bantime = 600
logpath = /home/web/log/nginx/waf-rate.log tail
action = waf-local [ reason = waf-rate ]
'''
        defaults=ban.MARKER+'''[waf-attack]
enabled = true
findtime = 300
maxretry = 20
bantime = 600
logpath = /home/web/log/nginx/waf-audit.json
action = waf-unified[source=attack]
[waf-rate]
enabled = true
findtime = 300
maxretry = 120
bantime = 600
logpath = /home/web/log/nginx/waf-rate.log
action = waf-unified[source=rate]
'''
        self.assertTrue(ban.is_unmarked_legacy_managed_jail(previous))
        migrated=ban.managed_jail_content(previous,None,defaults=defaults)
        parsed=ban.parse_jail(migrated)
        self.assertEqual(parsed.get('waf-rate','action'),'waf-unified[source=rate]')
        self.assertEqual(parsed.get('waf-attack','action'),'waf-unified[source=attack]')
        self.assertFalse(ban.is_unmarked_legacy_managed_jail(
            previous.replace('/home/web/log/nginx/waf-rate.log','/home/web/log/nginx/site.log')))
        with self.assertRaisesRegex(ValueError,'incomplete'):
            ban.validate_managed_jail(ban.MARKER+previous.replace('[WAF-RATE]','[waf-rate]'))

    def test_current_header_with_legacy_action_is_detected_and_migrated(self):
        previous=ban.MARKER+'''[waf-attack]
enabled = true
findtime = 120
maxretry = 20
bantime = 600
logpath = /home/web/log/nginx/waf-audit.json
action = waf-local[reason=attack]
[waf-rate]
enabled = true
findtime = 120
maxretry = 120
bantime = 600
logpath = /home/web/log/nginx/waf-rate.log
action = waf-local[reason=rate]
'''
        jail_dir=self.f2b/'jail.d';action_dir=self.f2b/'action.d'
        jail_dir.mkdir(parents=True);action_dir.mkdir(parents=True)
        (jail_dir/'zz-waf-managed.local').write_text(previous,encoding='utf-8')
        (action_dir/'waf-local.conf').write_text('''[Definition]
actionban = <python> <runtime> --root <root> ban --key "<ip>" --ttl <bantime> --reason <reason>
actionunban = <python> <runtime> --root <root> unban --key "<ip>" --reason <reason>
[Init]
python = /usr/bin/python3
runtime = /home/web/conf.d/waf/wafctl.py
root = /home/web
reason = attack
''',encoding='utf-8')
        with (patch.object(ban,'LEGACY_CF_ACTION',action_dir/'cloudflare-docker.conf'),
              patch.object(ban,'LEGACY_RECONCILER',self.root/'missing.service'),
              patch.object(ban,'legacy_state',return_value=None)):
            plan=ban.migration_plan(self.root)
        self.assertTrue(plan['requiresMigration'])
        migrated=ban.managed_jail_content(previous,None)
        self.assertEqual(ban.managed_jail_marker(migrated),'current')
        self.assertIn('action = waf-unified[source=attack]',migrated)
        self.assertIn('action = waf-unified[source=rate]',migrated)

    def test_legacy_marker_survives_bom_comments_whitespace_and_crlf(self):
        previous='\ufeff# Operator note\r\n\r\n  '+ban.LEGACY_MARKER.rstrip('\n')+'  \r\n'
        previous+='[waf-attack]\r\nenabled = true\r\nmaxretry = 20\r\nfindtime = 120\r\nbantime = 600\r\naction = waf-local[reason=attack]\r\n'
        previous+='[waf-rate]\r\nenabled = true\r\nmaxretry = 120\r\nfindtime = 120\r\nbantime = 600\r\naction = waf-local[reason=rate]\r\n'
        self.assertEqual(ban.managed_jail_marker(previous),'legacy')
        content=ban.managed_jail_content(previous,None)
        self.assertEqual(ban.managed_jail_marker(content),'current')
        self.assertIn('# Operator note\r\n',content)
        self.assertIn('action = waf-unified[source=attack]\r\n',content)
        self.assertIn('action = waf-unified[source=rate]\r\n',content)

    def test_historical_shared_waf_header_variants_accept_only_known_legacy_actions(self):
        headers=(
            '# Managed shared WAF; existing integration\n',
            '# Managed shared WAF. Includes only generated, validated data.\n',
            '# Managed shared WAF; an older product-owned revision\n',
            '# Managed shared WAF: older compatible release\n',
            '# Managed shared WAF - translated release\n',
            '# Managed Shared WAF\n',
        )
        for header in headers:
            with self.subTest(header=header):
                previous=header+'[waf-attack]\nenabled = true\nfindtime = 120\nmaxretry = 20\nbantime = 600\naction = waf-local[reason=attack]\n'
                previous+='[waf-rate]\nenabled = true\nfindtime = 120\nmaxretry = 120\nbantime = 600\naction = waf-local[reason=rate]\n'
                self.assertEqual(ban.managed_jail_marker(previous),'legacy')
                migrated=ban.managed_jail_content(previous,None)
                self.assertIn('action = waf-unified[source=attack]',migrated)
                self.assertIn('action = waf-unified[source=rate]',migrated)

    def test_historical_shared_waf_header_does_not_authorize_custom_actions(self):
        for header in ('# Managed shared WAF; an older product-owned revision\n',
                       '# Managed shared WAF: historical header\n',
                       '# Managed shared WAF - translated header\n',
                       '# Managed Shared WAF\n'):
            with self.subTest(header=header):
                previous=header
                previous+='[waf-attack]\nenabled = true\nfindtime = 120\nmaxretry = 20\nbantime = 600\naction = custom-ban\n'
                previous+='[waf-rate]\nenabled = true\nfindtime = 120\nmaxretry = 120\nbantime = 600\naction = custom-ban\n'
                with self.assertRaisesRegex(ValueError,'Custom ban action requires explicit migration'):
                    ban.validate_managed_jail(previous)

    def test_legacy_api_jail_embedded_in_managed_file_migrates_known_action(self):
        jail_dir=self.f2b/'jail.d';action_dir=self.f2b/'action.d'
        jail_dir.mkdir(parents=True);action_dir.mkdir(parents=True)
        previous=ban.LEGACY_MARKER+'''[waf-attack]
enabled = true
maxretry = 20
findtime = 120
bantime = 600
logpath = /home/web/log/nginx/waf-audit.json
action = waf-local[reason=attack]
[waf-rate]
enabled = true
maxretry = 120
findtime = 120
bantime = 600
logpath = /home/web/log/nginx/waf-rate.log
action = waf-local[reason=rate]
[waf-api-invalid]
enabled = true
filter = waf-api-invalid
logpath = /home/web/log/nginx/waf-protocol.log
maxretry = 120
findtime = 120
bantime = 600
action = waf-local[reason=api]
'''
        managed_path=jail_dir/'zz-waf-managed.local'
        managed_path.write_text(previous)
        action='''[Definition]
actionban = <python> <runtime> --root <root> ban --key "<ip>" --ttl <bantime> --reason <reason>
actionunban = <python> <runtime> --root <root> unban --key "<ip>" --reason <reason>
[Init]
python = /usr/bin/python3
runtime = /home/web/conf.d/waf/wafctl.py
root = /home/web
reason = attack
'''
        (action_dir/'waf-local.conf').write_text(action)
        api=ban.api_jail()
        self.assertTrue(api['managed'])
        self.assertTrue(api['enabled'])
        self.assertEqual(api['action'],'waf-local[reason=api]')
        content=ban.managed_jail_content(previous,api)
        self.assertIn('action = waf-unified[source=attack]',content)
        self.assertIn('action = waf-unified[source=rate]',content)
        self.assertIn('action = waf-unified[source=api]',content)
        self.assertIn('logpath = /home/web/log/nginx/waf-protocol.log',content)

    def test_unmarked_custom_jail_still_requires_explicit_migration(self):
        previous='[waf-attack]\nenabled = true\naction = custom-ban\n[waf-rate]\nenabled = true\naction = custom-ban\n'
        with self.assertRaisesRegex(ValueError,'requires explicit migration'):
            ban.validate_managed_jail(previous)

    def test_api_jail_action_migrates_only_known_wafctl_action(self):
        jail_dir=self.f2b/'jail.d';action_dir=self.f2b/'action.d'
        jail_dir.mkdir(parents=True);action_dir.mkdir(parents=True)
        (jail_dir/'zz-waf-api-invalid.local').write_text('[WAF-API-INVALID]\nenabled = true\nfilter = waf-api-invalid\nlogpath = /home/web/log/nginx/waf-protocol.log tail\nmaxretry = 120\nfindtime = 120\nbantime = 600\naction = waf-api-invalid\n')
        action='[Definition]\nactionstart =\nactionstop =\nactioncheck =\nactionban = <python> <runtime> --root <root> ban --key "<ip>" --ttl <bantime> --reason api\nactionunban = <python> <runtime> --root <root> unban --key "<ip>" --reason api\n[Init]\npython = /usr/bin/python3\nruntime = /home/web/conf.d/waf/wafctl.py\nroot = /home/web\nreason = api\n'
        (action_dir/'waf-api-invalid.conf').write_text(action)
        result=ban.api_jail()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['action'],'waf-api-invalid')
        self.assertIn('action = waf-unified[source=api]',ban.managed_jail_content('',result))

    def test_api_jail_unknown_action_is_not_overwritten(self):
        jail_dir=self.f2b/'jail.d';jail_dir.mkdir(parents=True)
        (jail_dir/'custom.local').write_text('[waf-api-invalid]\nenabled = true\nfilter = waf-api-invalid\nlogpath = /home/web/log/nginx/waf-protocol.log\naction = custom-ban\n')
        with self.assertRaisesRegex(ValueError,'Custom API jail action'):
            ban.api_jail()

    def test_disabled_managed_jail_is_not_an_api_configuration(self):
        jail_dir=self.f2b/'jail.d'; jail_dir.mkdir(parents=True)
        (jail_dir/'zz-waf-managed.local').write_text(ban.DISABLED)
        self.assertIsNone(ban.api_jail())

    def test_scoped_legacy_api_action_preserves_site(self):
        jail_dir=self.f2b/'jail.d'; action_dir=self.f2b/'action.d'
        jail_dir.mkdir(parents=True); action_dir.mkdir(parents=True)
        (jail_dir/'zz-waf-api-invalid.local').write_text('[waf-api-invalid]\nenabled = true\nfilter = waf-api-invalid\nlogpath = /home/web/log/nginx/waf-protocol.log tail\nmaxretry = 120\nfindtime = 120\nbantime = 600\naction = waf-api-invalid\n')
        action='[Definition]\nactionstart =\nactionstop =\nactioncheck =\nactionban = /usr/bin/python3 /home/web/conf.d/waf/wafctl.py --root /home/web ban --key "one.example.com|<ip>" --ttl <bantime> --reason rate\nactionunban =\n'
        (action_dir/'waf-api-invalid.conf').write_text(action)
        api=ban.api_jail()
        self.assertEqual(api['site'],'one.example.com')
        self.assertIn('action = waf-unified-api[site=one.example.com]',ban.managed_jail_content('',api))
        (jail_dir/'zz-waf-managed.local').write_text(ban.MARKER+'[waf-api-invalid]\naction = waf-unified-api[site=one.example.com]\n')
        self.assertEqual(ban.api_jail()['site'],'one.example.com')
        (jail_dir/'zz-waf-managed.local').write_text(ban.MARKER+'[waf-api-invalid]\naction = waf-unified-api[site=two.example.com]\n')
        with self.assertRaisesRegex(ValueError,'API site scope changed'):
            ban.api_jail()
        (jail_dir/'zz-waf-managed.local').unlink()
        (action_dir/'waf-api-invalid.conf').write_text(action.replace('one.example.com|<ip>', 'one.example.com|<ip>"; touch /tmp/evil; echo "'))
        with self.assertRaisesRegex(ValueError,'Unknown legacy WAF action'):
            ban.api_jail()

    def test_scoped_api_ticket_snapshot_preserves_site(self):
        with patch.object(ban,'state',return_value={'generation':2}), \
             patch.object(ban,'configured_sources',return_value=['api']), \
             patch.object(ban,'read',return_value={'apiSite':'one.example.com'}), \
             patch.object(ban,'query_tickets',return_value={'8.8.8.8'}):
            self.assertEqual(ban.ticket_snapshot(self.root)['sources']['api'],{'one.example.com|8.8.8.8'})
        with patch.object(ban,'state',return_value={'generation':2}), \
             patch.object(ban,'configured_sources',return_value=['api']), \
             patch.object(ban,'read',return_value={}), \
             patch.object(ban,'query_tickets',return_value={'8.8.8.8'}):
            self.assertIsNone(ban.ticket_snapshot(self.root))

    def test_direct_legacy_wafctl_action_without_init_is_recognized(self):
        directory=self.f2b/'action.d';directory.mkdir(parents=True)
        path=directory/'waf-api-invalid.conf'
        path.write_text('[Definition]\nactionban = /usr/bin/python3 /home/web/conf.d/waf/wafctl.py --root /home/web ban --key <ip> --ttl <bantime> --reason api\nactionunban = /usr/bin/python3 /home/web/conf.d/waf/wafctl.py --root /home/web unban --key <ip> --reason api\n')
        ban.validate_legacy_wafctl_action('waf-api-invalid')

    def test_known_legacy_reconciler_unit_is_recognized(self):
        unit=self.root/'kejilion-waf.service'
        unit.write_text('''[Unit]
Description=Shared site-scoped WAF ban reconciler
After=docker.service
Requires=docker.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/web/conf.d/waf/wafctl.py --root /home/web watch
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=/home/web/config/waf /home/web/conf.d/waf
[Install]
WantedBy=multi-user.target
''')
        unit.chmod(0o600)
        patch.object(ban,'LEGACY_RECONCILER',unit).start()
        active=type('Result',(),{'returncode':0,'stdout':'active'})()
        enabled=type('Result',(),{'returncode':0,'stdout':'enabled'})()
        fragment=type('Result',(),{'returncode':0,'stdout':str(unit)})()
        dropins=type('Result',(),{'returncode':0,'stdout':''})()
        with patch('subprocess.run',side_effect=[active,enabled,fragment,dropins]) as run:
            self.assertEqual(ban.legacy_reconciler_state(),{'recognized':True,'enabled':True,'active':True})
        self.assertEqual(run.call_count,4)

    def test_custom_legacy_reconciler_unit_is_not_stopped(self):
        unit=self.root/'kejilion-waf.service'
        unit.write_text('''[Unit]
Description=Shared site-scoped WAF ban reconciler
[Service]
ExecStart=/usr/bin/python3 /home/web/conf.d/waf/wafctl.py --root /home/web watch
ExecStartPre=/bin/touch /tmp/custom
Restart=on-failure
''')
        unit.chmod(0o600)
        patch.object(ban,'LEGACY_RECONCILER',unit).start()
        with patch('subprocess.run') as run, self.assertRaisesRegex(ValueError,'Unknown legacy WAF reconciler'):
            ban.legacy_reconciler_state()
        run.assert_not_called()

    def test_api_tickets_use_existing_api_jail_name(self):
        result=type('Result',(),{'returncode':0,'stdout':'one.example.com|8.8.8.8'})()
        with patch('subprocess.run',return_value=result) as run:
            self.assertEqual(ban.query_tickets('api'),{'one.example.com|8.8.8.8'})
        self.assertEqual(run.call_args.args[0],['fail2ban-client','get','waf-api-invalid','banip'])

    def test_api_source_is_accepted_by_runtime_action_cli(self):
        started=time.time()
        args=['ban.py','--root',str(self.root),'ban','--identity','one.example.com|8.8.8.8',
              '--source','api','--seconds','600','--started',str(started)]
        with patch.object(sys,'argv',args),patch('os.geteuid',return_value=0),patch.object(ban,'change') as change:
            ban.main()
        self.assertEqual(change.call_args.args[:5],
                         (self.root,'ban','one.example.com|8.8.8.8','api',600))

    def test_legacy_record_survives_ticket_snapshot_until_clear(self):
        expiry=int(time.time())+600
        value={'owner':OWNER,'records':{'one.example.com|8.8.8.8':{'legacy':expiry}}}
        before=copy.deepcopy(value)
        ban.reconcile_tickets(value,{'generation':0,'sources':{'attack':set(),'rate':set()}})
        self.assertEqual(value,before)


if __name__=='__main__':unittest.main()
