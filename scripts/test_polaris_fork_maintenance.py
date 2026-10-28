import copy
import json
from pathlib import Path
import unittest
import polaris_fork_maintenance as maintenance

REPO=Path(__file__).resolve().parents[1]
class MaintenanceTests(unittest.TestCase):
    def setUp(self):self.catalog=json.loads((REPO/maintenance.CATALOG).read_bytes())
    def test_original14_plus_dns_have_complete_unique_source_inventory(self):
        result=maintenance.validate_catalog(self.catalog)
        self.assertEqual(len(result['features']),15)
        self.assertEqual(len(result['runtimeFiles']),64)
        self.assertTrue(any(r['role']=='mobile-and-shared-daemon' for r in result['features']))
    def test_missing_duplicate_or_traversal_inventory_is_rejected(self):
        for kind in ['missing','duplicate','traversal']:
            value=copy.deepcopy(self.catalog)
            if kind=='missing':value['runtimeFiles'].pop(next(iter(value['runtimeFiles'])))
            elif kind=='duplicate':value['features'][0]['id']=value['features'][1]['id']
            else:value['features'][0]['paths'][0]='../outside'
            with self.subTest(kind=kind),self.assertRaises(ValueError):maintenance.validate_catalog(value)
    def observation(self):
        return {'atUTC':'2026-10-12T13:00:00Z','forkRepository':{'full_name':'polaris-arch/polaris-box','id':1407705262},
            'forkMain':{'object':{'sha':'a'*40}},'forkTesting':{'object':{'sha':'b'*40}},
            'upstreamTesting':{'object':{'sha':'c'*40}},'upstreamAlpha12':{'object':{'type':'commit','sha':self.catalog['baselineCommit']}},
            'upstreamReleases':[{'tag_name':tag,'draft':False,'published_at':'2026-10-12T00:00:00Z'} for tag in ['v1.14.3','v1.15.0-alpha.12','v1.15.0-alpha.13']]}
    def test_diverged_testing_is_not_called_synced_or_promoted_to_baseline(self):
        result=maintenance.upstream_observation(self.observation(),self.catalog)
        self.assertTrue(result['testingMirror'].startswith('not aligned'))
        self.assertEqual(result['latestObservedRelease'],'v1.15.0-alpha.13')
        self.assertEqual(result['newerObservedReleaseCount'],1);self.assertFalse(result['refWritesPerformed'])
        self.assertEqual(self.catalog['baselineTag'],'v1.15.0-alpha.12')
    def test_foreign_repository_or_wrong_baseline_cannot_supply_observations(self):
        for kind in ['repository','baseline']:
            value=self.observation()
            if kind=='repository':value['forkRepository']['id']=1
            else:value['upstreamAlpha12']['object']['sha']='d'*40
            with self.subTest(kind=kind),self.assertRaises(ValueError):maintenance.upstream_observation(value,self.catalog)
    def test_prerelease_order_does_not_confuse_alpha10_with_alpha9(self):
        self.assertGreater(maintenance.parse_version('v1.15.0-alpha.10'),maintenance.parse_version('v1.15.0-alpha.9'))
        self.assertGreater(maintenance.parse_version('v1.15.0-beta.1'),maintenance.parse_version('v1.15.0-alpha.12'))
        self.assertGreater(maintenance.parse_version('v1.15.0'),maintenance.parse_version('v1.15.0-rc.1'))
    def test_selfcheck_keeps_upstream_baseline_out_of_product_tag_namespace(self):
        text=(REPO/'.github/workflows/polaris-selfcheck.yml').read_text()
        self.assertIn('refs/tags/$BASE_REF:refs/polaris/upstream-baseline',text)
        self.assertNotIn('refs/tags/$BASE_REF:refs/tags/$BASE_REF',text)
        self.assertIn('test "$actual_baseline" = "$BASE_COMMIT"',text)
        self.assertIn("default: v1.15.0-alpha.12",text)
if __name__=='__main__':unittest.main()
