import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import polaris_runner_resources as resources


class RunnerResourceTests(unittest.TestCase):
    def observation(self, **changes):
        value = {'platform': 'Linux', 'effectiveCPUs': 8, 'busyCPUObservation': 0.25,
                 'memoryTotalBytes': 16 * resources.GIB,
                 'memoryAvailableBytes': 12 * resources.GIB,
                 'diskTotalBytes': 64 * resources.GIB, 'diskFreeBytes': 24 * resources.GIB}
        value.update(changes)
        return value

    def test_cpu_memory_and_system_reserves_bound_worker_budget(self):
        value = resources.budget(self.observation(), 'selfcheck')
        self.assertEqual(value['goPackageJobs'], 4)  # Memory, not eight CPUs, is limiting.
        self.assertEqual(value['compileGOMAXPROCS'], 1)  # Applies to explicit compile commands only.
        self.assertNotIn('GOMAXPROCS', value)
        self.assertFalse(value['resourceReservationsHeld'])
        value = resources.budget(self.observation(effectiveCPUs=4, busyCPUObservation=0), 'desktop')
        self.assertEqual((value['compileGOMAXPROCS'], value['goPackageJobs']), (3, 1))
        value = resources.budget(self.observation(effectiveCPUs=4, busyCPUObservation=2.1), 'desktop')
        self.assertEqual(value['compileGOMAXPROCS'], 1)

    def test_busy_or_single_cpu_stays_bounded_without_zero_workers(self):
        for cpus, busy in [(1, 0), (2, 10)]:
            value = resources.budget(self.observation(effectiveCPUs=cpus, busyCPUObservation=busy), 'selfcheck')
            self.assertEqual((value['compileGOMAXPROCS'], value['goPackageJobs']), (1, 1))

    def test_estimated_pressure_reduces_concurrency_without_a_new_capacity_gate(self):
        for changes, field in [({'memoryAvailableBytes': 2 * resources.GIB}, 'memoryEstimatePressure'),
                               ({'diskFreeBytes': 9 * resources.GIB}, 'diskEstimatePressure')]:
            with self.subTest(changes=changes):
                value = resources.budget(self.observation(**changes), 'openwrt')
                self.assertTrue(value[field])
                self.assertTrue(value['singlePackageFallback'])
                self.assertEqual((value['compileGOMAXPROCS'], value['goPackageJobs']), (1, 1))
                self.assertEqual(value['memoryPerPackageBytes'], 2 * resources.GIB)

    def test_original_seven_gib_apple_failures_select_existing_serial_lane(self):
        for available in [3199664128, 3187687424, 3180789760, 3253420032]:
            value = resources.budget(self.observation(effectiveCPUs=3, memoryTotalBytes=7 * resources.GIB,
                                                     memoryAvailableBytes=available), 'selfcheck')
            self.assertTrue(value['memoryEstimatePressure'])
            self.assertEqual(value['estimatedMemorySlots'], 0)
            self.assertEqual((value['compileGOMAXPROCS'], value['goPackageJobs']), (1, 1))
            self.assertEqual(value['memoryPerPackageBytes'], 2 * resources.GIB)

    def test_invalid_observations_cannot_create_unbounded_worker_count(self):
        for name, value in [('effectiveCPUs', True), ('effectiveCPUs', 0),
                            ('busyCPUObservation', float('nan')),
                            ('busyCPUObservation', float('inf')),
                            ('busyCPUObservation', -1), ('busyCPUObservation', '1'),
                            ('memoryAvailableBytes', 32 * resources.GIB),
                            ('diskFreeBytes', 65 * resources.GIB)]:
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                resources.budget(self.observation(**{name: value}), 'desktop')
        with self.assertRaises(ValueError):
            resources.budget(self.observation(), 'arbitrary-runner')

    def test_linux_cgroup_memory_is_not_confused_with_host_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'proc').mkdir()
            (root / 'proc/meminfo').write_text('MemTotal: 16777216 kB\nMemAvailable: 12582912 kB\n')
            group = root / 'sys/fs/cgroup'
            group.mkdir(parents=True)
            (group / 'memory.max').write_text(str(6 * resources.GIB))
            (group / 'memory.current').write_text(str(4 * resources.GIB))
            self.assertEqual(resources.linux_memory(root), (6 * resources.GIB, 2 * resources.GIB))
            (group / 'memory.max').write_text('max')
            self.assertEqual(resources.linux_memory(root), (16 * resources.GIB, 12 * resources.GIB))

    def test_mac_memory_uses_actual_page_size_without_double_counting(self):
        for page in [4096, 16384]:
            stat = (f'Mach Virtual Memory Statistics: (page size of {page} bytes)\n'
                    'Pages free: 100.\nPages inactive: 200.\nPages speculative: 50.\nPages purgeable: 80.\n')
            with patch.object(resources.subprocess, 'check_output', side_effect=[str(16 * resources.GIB), stat]):
                self.assertEqual(resources.darwin_memory(), (16 * resources.GIB, 350 * page))

    def test_speculative_pages_cross_real_admission_threshold_without_purgeable(self):
        total = 8 * resources.GIB
        threshold = max(resources.GIB, total // 5) + resources.MEMORY_PER_PACKAGE
        for page in [4096, 16384]:
            below_pages = (threshold - 1) // page
            stat = (f'Mach Virtual Memory Statistics: (page size of {page} bytes)\n'
                    f'Pages free: {below_pages // 2}.\n'
                    f'Pages inactive: {below_pages - below_pages // 2}.\n'
                    'Pages speculative: 1.\nPages purgeable: 1000000.\n')
            with patch.object(resources.subprocess, 'check_output', side_effect=[str(total), stat]):
                measured_total, available = resources.darwin_memory()
            observation = self.observation(memoryTotalBytes=measured_total, memoryAvailableBytes=available)
            self.assertGreaterEqual(available, threshold)
            self.assertEqual(resources.budget(observation, 'desktop')['goPackageJobs'], 1)
            below = resources.budget({**observation, 'memoryAvailableBytes': available - page}, 'desktop')
            self.assertTrue(below['memoryEstimatePressure'])
            self.assertTrue(below['singlePackageFallback'])
            self.assertEqual(below['goPackageJobs'], 1)
            self.assertFalse(resources.budget(observation, 'desktop')['memoryEstimatePressure'])

    def test_rejected_observation_survives_unwritable_scratch_without_logging_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = ['resources', '--kind', 'selfcheck', '--scratch', directory,
                         '--output', str(root / 'report.json')]
            observed = self.observation(diskFreeBytes=0)
            with patch('sys.argv', arguments), patch.object(resources, 'observe', return_value=observed), \
                 patch.object(Path, 'write_text', side_effect=OSError('scratch unavailable')), \
                 patch.dict(resources.os.environ, {'GITHUB_TOKEN': 'secret-test-marker'}), \
                 patch('builtins.print') as printed:
                with self.assertRaisesRegex(OSError, 'scratch unavailable'): resources.main()
            value = json.loads(printed.call_args.args[0])
            self.assertEqual(value['status'], 'rejected')
            self.assertEqual(value['observation'], observed)
            self.assertIn('invalid resource measurement: diskFreeBytes', value['error'])
            self.assertTrue(printed.call_args.kwargs['flush'])
            self.assertNotIn('secret-test-marker', printed.call_args.args[0])

    def test_measurement_subprocess_failure_is_logged_before_reraise(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = ['resources', '--kind', 'selfcheck', '--scratch', directory,
                         '--output', str(root / 'report.json')]
            error = resources.subprocess.CalledProcessError(1, ['vm_stat'])
            with patch('sys.argv', arguments), patch.object(resources, 'observe', side_effect=error), \
                 patch('builtins.print') as printed:
                with self.assertRaises(resources.subprocess.CalledProcessError): resources.main()
            self.assertEqual(json.loads(printed.call_args.args[0])['status'], 'rejected')
            self.assertEqual(printed.call_args.args[0], (root / 'report.json').read_text())

    def test_windows_cpu_sample_excludes_idle_kernel_time(self):
        class Call:
            def __init__(self): self.samples = iter([(100, 200, 100), (160, 280, 140)])
            def __call__(self, *pointers):
                for pointer, value in zip(pointers, next(self.samples)): pointer._obj.value = value
                return 1
        kernel = type('Kernel', (), {'GetSystemTimes': Call()})()
        with patch.object(resources.ctypes, 'WinDLL', return_value=kernel, create=True), \
             patch.object(resources.time, 'sleep'):
            self.assertEqual(resources.windows_busy_cpus(4), 2)

    def test_success_and_failure_preserve_observations_and_do_not_write_global_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); report = root / 'report.json'; env = root / 'github-env'
            arguments = ['resources', '--kind', 'selfcheck', '--scratch', directory,
                         '--output', str(report), '--github-env', str(env)]
            with patch('sys.argv', arguments), patch.object(resources, 'observe', return_value=self.observation()), \
                 patch.dict(resources.os.environ, {'GOFLAGS': '', 'GITHUB_SHA': 'a' * 40, 'SOURCE_COMMIT': 'b' * 40}), \
                 patch('builtins.print'):
                resources.main()
            data = json.loads(report.read_text())
            self.assertEqual((data['workflowCommit'], data['sourceCommit']), ('a' * 40, 'b' * 40))
            self.assertIn('POLARIS_COMPILE_GOMAXPROCS=1\nPOLARIS_GO_JOBS=4\nGOFLAGS=-p=4\n', env.read_text())
            self.assertNotIn('\nGOMAXPROCS=', '\n' + env.read_text())
            before = env.read_bytes()
            with patch('sys.argv', arguments), patch.object(resources, 'observe', return_value=self.observation(diskFreeBytes=0)), \
                 patch('builtins.print') as printed:
                with self.assertRaisesRegex(ValueError, 'diskFreeBytes'): resources.main()
            self.assertEqual(printed.call_args.args[0], report.read_text())
            self.assertTrue(printed.call_args.kwargs['flush'])
            self.assertEqual(env.read_bytes(), before)
            self.assertEqual(json.loads(report.read_text())['status'], 'rejected')

    def test_workflow_keeps_full_assembly_barrier_but_guests_have_no_desktop_dependency(self):
        repo = Path(__file__).resolve().parents[1]
        workflow = (repo / '.github/workflows/polaris-production-release.yml').read_text()
        self.assertIn('needs: [plan, native-openwrt]', workflow)
        self.assertIn('needs: [plan, native, native-openwrt, openwrt-guests]', workflow)
        self.assertNotIn('max-parallel:', workflow)
        self.assertIn('cancel-in-progress: false', workflow)
        native = (repo / '.github/workflows/polaris-production-native.yml').read_text()
        self.assertIn("if: github.repository == 'polaris-arch/polaris-box'", native)
        self.assertIn('--kind \"$RESOURCE_KIND\" --scratch', native)
        self.assertNotIn("--kind '${{ inputs.kind }}'", native)
        self.assertIn("inputs.attest && github.ref == 'refs/heads/polaris-main'", workflow)
        selfcheck = (repo / '.github/workflows/polaris-selfcheck.yml').read_text()
        self.assertIn("format('audit-{0}', github.run_id)", selfcheck)
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'push' && github.ref_type == 'branch' }}", selfcheck)
        self.assertEqual(selfcheck.count('Bound runner work using the fixed workflow-owned resource tool'), 7)
        self.assertIn('git show "$GITHUB_SHA:scripts/polaris_runner_resources.py"', selfcheck)
        self.assertIn('if: ${{ inputs.run_instance_tests }}', selfcheck)
        self.assertIn('patch_only:', selfcheck)
        self.assertIn('/usr/bin/time -l go build', selfcheck)
        self.assertIn('/usr/bin/time -l go test', selfcheck)
        self.assertIn('/usr/bin/time -l \"$@\"', native)
        self.assertIn('go test -p \"$POLARIS_GO_JOBS\" -parallel 2 -race', selfcheck)
        for line in selfcheck.splitlines():
            if ' go test ' in line or line.lstrip().startswith('go test '):
                self.assertNotIn('POLARIS_COMPILE_GOMAXPROCS', line)
        self.assertEqual(selfcheck.count('GOMAXPROCS=\"$POLARIS_COMPILE_GOMAXPROCS\"'), 7)


if __name__ == '__main__':
    unittest.main()
