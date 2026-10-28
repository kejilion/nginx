import contextlib
import copy
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
        for seconds in [0,59,3601]:
            with self.assertRaises(ValueError):self.event(seconds=seconds)
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
        self.assertEqual(edge.sets[ZONE]['rules'][0]['expression'],'false')

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
        self.assertEqual(edge.sets[ZONE]['rules'][0]['expression'],'false')

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
        with patch.object(ban,'Cloudflare',return_value=edge):
            ban.configure_cf(self.root,{'email':'','key':'x'*40})
            self.event()
            self.assertEqual(edge.sets[ZONE]['rules'][0]['expression'],'false')
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


if __name__=='__main__':unittest.main()
