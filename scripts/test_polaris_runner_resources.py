import copy
import json
from pathlib import Path
import re
import shlex
import tempfile
import unittest
from unittest.mock import patch

import polaris_runner_resources as resources
import yaml


def shell_commands(source):
    """Tokenize literal selfcheck commands, without expanding or executing shell input."""
    command = []
    quote = None
    word_start = True
    offset = 0
    while offset < len(source):
        character = source[offset]
        if character == '\\' and quote != "'" and offset + 1 < len(source):
            following = source[offset + 1]
            if following != '\n':
                command.extend((character, following))
                word_start = False
            offset += 2
            continue
        if quote is None and character == '#' and word_start:
            newline = source.find('\n', offset)
            offset = len(source) if newline < 0 else newline
            continue
        if character in "\"'" and (quote is None or quote == character):
            quote = character if quote is None else None
            word_start = False
        elif quote is None and character in '\n;&|()':
            if command:
                yield shlex.split(''.join(command))
                command = []
            word_start = True
            offset += 1
            continue
        elif quote is None:
            word_start = character.isspace()
        command.append(character)
        offset += 1
    if command:
        yield shlex.split(''.join(command))


def prefixed_shell_commands(source):
    for command in shell_commands(source):
        index = 0
        while index < len(command):
            token = command[index]
            if '=' in token and token.split('=', 1)[0].isidentifier():
                index += 1
            elif token in ('env', 'time', '/usr/bin/time', '-l', '-p', '--',
                           'if', 'elif', 'then', 'else', 'while', 'until', 'do', '!'):
                index += 1
            else:
                break
        yield command[:index], command[index:]


def go_test_commands(source):
    for prefix, command in prefixed_shell_commands(source):
        if command[:2] == ['go', 'test']:
            yield prefix, command[2:]


def compile_only_go_test(arguments):
    # Value flags consume their next argv even when it is literally '-c'. Unknown
    # value flags fail conservatively rather than granting a compile exemption.
    boolean_flags = {'-race', '-msan', '-asan', '-cover', '-v', '-x', '-n', '-work',
                     '-failfast', '-short', '-fullpath', '-json', '-a', '-i', '-linkshared', '-trimpath'}
    compile_only = False
    arguments = iter(arguments)
    for argument in arguments:
        if argument in ('-args', '--'):
            break
        flag, equal, value = argument.partition('=')
        if flag in ('-c', '--c'):
            compile_only = not equal or value in ('1', 't', 'T', 'TRUE', 'true', 'True')
        elif flag.startswith('-') and not equal and flag not in boolean_flags:
            next(arguments, None)
    return compile_only


class RunnerResourceTests(unittest.TestCase):
    def assert_go_test_resource_profiles(self, source):
        commands = list(go_test_commands(source))
        self.assertTrue(commands, 'no literal go test command found')
        for prefix, arguments in commands:
            assignments = [token for token in prefix if token.startswith('GOMAXPROCS=')]
            expected = ['GOMAXPROCS=$POLARIS_COMPILE_GOMAXPROCS'] if compile_only_go_test(arguments) else []
            self.assertEqual(assignments, expected, (prefix, arguments))

    def test_compile_only_go_test_uses_compile_budget_across_shell_lines(self):
        for command in [
            ('GOMAXPROCS="$POLARIS_COMPILE_GOMAXPROCS" go test -p "$POLARIS_GO_JOBS" '
             '\\\n' '  -c -o /dev/null -tags "$off_tags" "$package"'),
            "env GOMAXPROCS=$POLARIS_COMPILE_GOMAXPROCS go test '-c' -o /dev/null .",
            'GOMAXPROCS=$POLARIS_COMPILE_GOMAXPROCS /usr/bin/time -l go test -c=true .',
            'GOMAXPROCS=$POLARIS_COMPILE_GOMAXPROCS go test -run ";" -c ./...',
        ]:
            with self.subTest(command=command):
                self.assertEqual(len(list(go_test_commands(command))), 1)
                self.assert_go_test_resource_profiles(command)
        with self.assertRaises(AssertionError):
            self.assert_go_test_resource_profiles('go test -c -o /dev/null ./...')

    def test_running_go_test_cannot_borrow_compile_budget_from_arguments_or_quotes(self):
        for arguments in ['-count=1 .', "-run '-c' .", "-tags '-c' .", "-args '-c'",
                          '-c=false .', '-c -c=false .', "-ldflags '-c' ."]:
            with self.subTest(arguments=arguments):
                self.assertFalse(compile_only_go_test(shlex.split(arguments)))
                self.assert_go_test_resource_profiles('go test ' + arguments)
                with self.assertRaises(AssertionError):
                    self.assert_go_test_resource_profiles(
                        'GOMAXPROCS=$POLARIS_COMPILE_GOMAXPROCS go test ' + arguments)

    def test_shell_command_boundaries_do_not_transfer_compile_only_exemption(self):
        source = ('echo "go test -c"; # go test -c ' '\\\n'
                  'GOMAXPROCS=$POLARIS_COMPILE_GOMAXPROCS go test -c . && '
                  'GOMAXPROCS=$POLARIS_COMPILE_GOMAXPROCS go test -run "-c" .')
        commands = list(go_test_commands(source))
        self.assertEqual(len(commands), 2)
        self.assertEqual([compile_only_go_test(args) for _, args in commands], [True, False])
        with self.assertRaises(AssertionError):
            self.assert_go_test_resource_profiles(source)
        compile_step = 'GOMAXPROCS=$POLARIS_COMPILE_GOMAXPROCS go test -c .'
        runtime = 'GOMAXPROCS=$POLARIS_COMPILE_GOMAXPROCS go test -run "^TestRun$" .'
        for compound in [f'if {runtime}; then :; fi',
                         f'if true; then {runtime}; fi',
                         f'for package in .; do {runtime}; done',
                         f'! {runtime}']:
            with self.subTest(compound=compound):
                self.assertEqual(len(list(go_test_commands(compound))), 1)
                self.assert_go_test_resource_profiles(
                    compound.replace('GOMAXPROCS=$POLARIS_COMPILE_GOMAXPROCS ', ''))
                # A successful compile-only check in another step or the same
                # step cannot exempt this actual running test command.
                self.assert_go_test_resource_profiles(compile_step)
                with self.assertRaises(AssertionError):
                    self.assert_go_test_resource_profiles(compound)
                with self.assertRaises(AssertionError):
                    self.assert_go_test_resource_profiles(compile_step + '; ' + compound)

    def assert_selfcheck_command_closure(self, workflow, makefile, libbox):
        # Named command contracts: comments or unrelated steps cannot replace
        # a missing command cap. Matrix expressions represent single values.
        expected = {
            'linux': ['go build'], 'windows_build': ['go build'], 'macos': ['go build'],
            'android': ['make lib_install', 'go run android'],
            'ios': ['make lib_install', 'go run apple'],
            # Original feature-off compile precedes the selected netns compile.
            'patch_tests': ['go test -c', 'go test -c'],
        }
        resource_jobs = set(expected) | {'windows_test'}
        metadata_queries = {
            ('go', 'list', '-tags', '$tags', '${packages[@]}', '>', '$selection_dir/resolved-root-packages.txt'): 'packages',
            ('go', 'list', '-mod=readonly', '-m', '-json', 'github.com/sagernet/tailscale', '>', '$selection_dir/tailscale-module.json'): 'module',
        }
        actual, metadata, initialized = {}, {}, set()
        for name, job in workflow['jobs'].items():
            self.assertNotIn('GOMAXPROCS', job.get('env', {}))
            setup = None
            for index, step in enumerate(job.get('steps', [])):
                self.assertNotIn('GOMAXPROCS', step.get('env', {}))
                self.assertNotIn('GOFLAGS', step.get('env', {}))
                if step.get('name', '').startswith('Bound runner work'):
                    self.assertIsNone(setup, name)
                    setup = index
                    initialized.add(name)
                    self.assertIn('git show "$GITHUB_SHA:scripts/polaris_runner_resources.py"', step['run'])
                    self.assertIn('--github-env "$GITHUB_ENV"', step['run'])
                source = re.sub(r'\$\{\{[^}\n]+\}\}', 'WORKFLOW_VALUE', step.get('run', ''))
                for prefix, command in prefixed_shell_commands(source):
                    if not command or command[0] == 'export':
                        self.assertFalse(any(token.startswith(('GOMAXPROCS=', 'GOFLAGS=')) for token in prefix + command))
                    if not command or command[0] not in ('go', 'make'):
                        continue
                    if command in (['go', 'env', 'GOPATH'], ['go', 'version']):
                        continue
                    self.assertIsNotNone(setup, (name, command))
                    self.assertLess(setup, index, (name, command))
                    if command[:2] == ['go', 'list']:
                        # These exact queries select packages/module metadata;
                        # neither requests compiled/export data. Other list
                        # modes need their own reviewed resource contract.
                        self.assertIn(tuple(command), metadata_queries)
                        metadata.setdefault(name, []).append(metadata_queries[tuple(command)])
                        compile_only, signature = False, None
                    elif command[:2] == ['go', 'test']:
                        compile_only = compile_only_go_test(command[2:])
                        signature = 'go test -c' if compile_only else None
                    elif command[:2] == ['go', 'build']:
                        compile_only, signature = True, 'go build'
                    elif command[:2] == ['go', 'run']:
                        self.assertEqual(command[2], './cmd/internal/build_libbox')
                        self.assertIn('-target', command)
                        compile_only, signature = True, 'go run ' + command[command.index('-target') + 1]
                    elif command[0] == 'make':
                        self.assertEqual(command, ['make', 'lib_install'])
                        compile_only, signature = True, 'make lib_install'
                    else:
                        self.fail(f'unclassified work command: {name}: {command}')
                    assignments = [token for token in prefix if token.startswith('GOMAXPROCS=')]
                    self.assertFalse(any(token.startswith('GOFLAGS=') for token in prefix), (name, command))
                    self.assertEqual(assignments, ['GOMAXPROCS=$POLARIS_COMPILE_GOMAXPROCS'] if compile_only else [], (name, command))
                    if compile_only:
                        actual.setdefault(name, []).append(signature)
                    if command[-1] == 'github.com/sagernet/sing-box/common/netns':
                        self.assertEqual(name, 'patch_tests')
                        self.assertTrue(compile_only)
                        self.assertEqual(command[:4], ['go', 'test', '-p', '$POLARIS_GO_JOBS'])
                        self.assertIn('-race', command)
                        self.assertNotIn('-exec', command)
            if name in resource_jobs:
                self.assertIsNotNone(setup, name)
        self.assertEqual(initialized, resource_jobs)
        self.assertEqual(actual, expected)
        self.assertEqual(metadata, {'patch_tests': ['packages', 'module']})
        recipe = re.search(r'(?m)^lib_install:\n((?:\t[^\n]*\n|\n)+)', makefile)
        self.assertIsNotNone(recipe)
        self.assertEqual(list(shell_commands(recipe.group(1))), [
            ['go', 'install', '-v', 'github.com/sagernet/gomobile/cmd/gomobile@v0.1.13'],
            ['go', 'install', '-v', 'github.com/sagernet/gomobile/cmd/gobind@v0.1.13'],
        ])
        # The resource producer's existing environment-output test covers the
        # GOFLAGS package cap. Env=nil preserves it and command GOMAXPROCS
        # through time/make/go run into both gomobile bind launches.
        launches = re.findall(r'command := exec.Command\(build_shared.GoBinPath\+"/gomobile", args\.\.\.\)(.*?)\n}', libbox, re.S)
        self.assertEqual(len(launches), 2)
        for launch in launches:
            self.assertIn('command.Run()', launch)
            self.assertNotRegex(launch, r'command\.Env\s*=')
        self.assertNotRegex(libbox, r'os\.(?:Setenv|Unsetenv|Clearenv)\s*\(')

    def test_selfcheck_command_closure_rejects_missing_budget_and_uncovered_builds(self):
        repo = Path(__file__).resolve().parents[1]
        workflow = yaml.safe_load((repo / '.github/workflows/polaris-selfcheck.yml').read_text())
        makefile = (repo / 'Makefile').read_text()
        libbox = (repo / 'cmd/internal/build_libbox/main.go').read_text()
        self.assert_selfcheck_command_closure(workflow, makefile, libbox)
        for change in ['missing cap', 'wrong cap', 'uncovered build', 'ordinary test cap', 'late setup', 'job cap', 'step flags', 'command flags', 'export cap', 'unknown command', 'compiled list', 'metadata cap', 'missing metadata',
                       'netns missing cap', 'netns wrong cap', 'netns missing jobs', 'netns wrong jobs', 'netns missing compile']:
            with self.subTest(change=change):
                broken = copy.deepcopy(workflow)
                steps = broken['jobs']['linux']['steps']
                build = next(s for s in steps if s.get('name') == 'Build')
                if change.startswith('netns '):
                    queue = next(s for s in broken['jobs']['patch_tests']['steps']
                                 if s.get('name') == 'Test packages changed by the queue')
                    before, after = {
                        'netns missing cap': ('GOMAXPROCS="$POLARIS_COMPILE_GOMAXPROCS" ', ''),
                        'netns wrong cap': ('GOMAXPROCS="$POLARIS_COMPILE_GOMAXPROCS"', 'GOMAXPROCS=99'),
                        'netns missing jobs': ('-p "$POLARIS_GO_JOBS" ', ''),
                        'netns wrong jobs': ('-p "$POLARIS_GO_JOBS"', '-p 99'),
                        'netns missing compile': ('-v -c -skip', '-v -skip'),
                    }[change]
                    self.assertEqual(queue['run'].count(before), 1)
                    queue['run'] = queue['run'].replace(before, after)
                elif change == 'missing cap':
                    build['run'] = build['run'].replace('GOMAXPROCS="$POLARIS_COMPILE_GOMAXPROCS" ', '')
                elif change == 'wrong cap':
                    build['run'] = build['run'].replace('GOMAXPROCS="$POLARIS_COMPILE_GOMAXPROCS"', 'GOMAXPROCS=99')
                elif change == 'uncovered build':
                    steps.append({'run': 'go build ./uncovered'})
                elif change == 'ordinary test cap':
                    steps.append({'run': 'GOMAXPROCS=$POLARIS_COMPILE_GOMAXPROCS go test .'})
                elif change == 'late setup':
                    setup = next(s for s in steps if s.get('name', '').startswith('Bound runner work'))
                    steps.remove(setup)
                    steps.append(setup)
                elif change == 'job cap':
                    broken['jobs']['windows_test']['env'] = {'GOMAXPROCS': '1'}
                elif change == 'step flags':
                    build['env'] = {'GOFLAGS': ''}
                elif change == 'command flags':
                    build['run'] = build['run'].replace('GOMAXPROCS=', 'GOFLAGS= GOMAXPROCS=', 1)
                elif change == 'export cap':
                    build['run'] = 'export GOMAXPROCS=1\n' + build['run']
                elif change == 'unknown command':
                    steps.append({'run': 'go generate ./unreviewed'})
                elif change == 'compiled list':
                    steps.append({'run': 'go list -export ./...'})
                else:
                    query = 'go list -tags "$tags" "${packages[@]}" > "$selection_dir/resolved-root-packages.txt"'
                    query_step = next(s for s in broken['jobs']['patch_tests']['steps'] if query in s.get('run', ''))
                    self.assertEqual(query_step['run'].count(query), 1)
                    replacement = 'GOMAXPROCS=$POLARIS_COMPILE_GOMAXPROCS ' + query if change == 'metadata cap' else ':'
                    query_step['run'] = query_step['run'].replace(query, replacement, 1)
                self.assertNotEqual(broken, workflow, f'negative mutation missed its target: {change}')
                with self.assertRaises(AssertionError):
                    self.assert_selfcheck_command_closure(broken, makefile, libbox)
        recipe = re.search(r'(?m)^lib_install:\n((?:\t[^\n]*\n|\n)+)', makefile)
        self.assertIsNotNone(recipe)
        install = '\tgo install -v github.com/sagernet/gomobile/cmd/gomobile@v0.1.13\n'
        self.assertEqual(recipe.group(1).count(install), 1)
        bad_recipe = recipe.group(1).replace(install, install.replace('go install', 'GOMAXPROCS=99 go install', 1), 1)
        self.assertNotEqual(bad_recipe, recipe.group(1))
        bad_makefile = makefile[:recipe.start(1)] + bad_recipe + makefile[recipe.end(1):]
        self.assertEqual(re.search(r'(?m)^lib_install:\n((?:\t[^\n]*\n|\n)+)', bad_makefile).group(1), bad_recipe)
        self.assertEqual(libbox.count('command.Stdout = os.Stdout'), 2)
        for bad_make, bad_libbox in [
            (bad_makefile, libbox),
            (makefile, libbox.replace('command.Stdout = os.Stdout', 'command.Env = []string{"GOFLAGS="}\n\tcommand.Stdout = os.Stdout', 1)),
        ]:
            self.assertNotEqual((bad_make, bad_libbox), (makefile, libbox))
            with self.assertRaises(AssertionError):
                self.assert_selfcheck_command_closure(workflow, bad_make, bad_libbox)

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

    def test_historical_assembly_barrier_and_active_selfcheck_resources(self):
        repo = Path(__file__).resolve().parents[1]
        workflow = (repo / 'scripts/testdata/historical-workflows/polaris-production-release.yml').read_text()
        self.assertIn('needs: [plan, native-openwrt]', workflow)
        self.assertIn('needs: [plan, native, native-openwrt, openwrt-guests]', workflow)
        self.assertNotIn('max-parallel:', workflow)
        self.assertIn('cancel-in-progress: false', workflow)
        native = (repo / 'scripts/testdata/historical-workflows/polaris-production-native.yml').read_text()
        self.assertIn("if: github.repository == 'polaris-arch/polaris-box'", native)
        self.assertIn('--kind \"$RESOURCE_KIND\" --scratch', native)
        self.assertNotIn("--kind '${{ inputs.kind }}'", native)
        self.assertIn("inputs.attest && github.ref == 'refs/heads/polaris-main'", workflow)
        selfcheck = (repo / '.github/workflows/polaris-selfcheck.yml').read_text()
        self.assertIn("format('audit-{0}', github.run_id)", selfcheck)
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' || (github.event_name == 'push' && github.ref_type == 'branch') }}", selfcheck)
        self.assertEqual(selfcheck.count('Bound runner work using the fixed workflow-owned resource tool'), 7)
        self.assertIn('git show "$GITHUB_SHA:scripts/polaris_runner_resources.py"', selfcheck)
        self.assertIn('if: ${{ inputs.run_instance_tests }}', selfcheck)
        self.assertIn('patch_only:', selfcheck)
        self.assertIn('/usr/bin/time -l go build', selfcheck)
        self.assertIn('/usr/bin/time -l go test', selfcheck)
        self.assertIn('/usr/bin/time -l \"$@\"', native)
        self.assertIn('go test -p \"$POLARIS_GO_JOBS\" -parallel 2 -race', selfcheck)
        for job in yaml.safe_load(selfcheck)['jobs'].values():
            for step in job.get('steps', []):
                if 'go test ' in step.get('run', ''):
                    self.assert_go_test_resource_profiles(step['run'])
        self.assert_selfcheck_command_closure(yaml.safe_load(selfcheck),
                                             (repo / 'Makefile').read_text(),
                                             (repo / 'cmd/internal/build_libbox/main.go').read_text())
        ordinary = yaml.safe_load((repo / '.github/workflows/test.yml').read_text())
        compile_step = next(s for s in ordinary['jobs']['test']['steps']
                            if s.get('name', '').startswith('Compile Linux netns tests'))
        self.assertEqual(compile_step['env'], {'GOMAXPROCS': '2'})
        commands = list(go_test_commands(compile_step['run']))
        self.assertEqual(len(commands), 1)
        prefix, arguments = commands[0]
        self.assertEqual(prefix, [])
        self.assertEqual(arguments[:4], ['-p', '2', '-c', '-tags'])
        self.assertEqual(arguments[-1], 'github.com/sagernet/sing-box/common/netns')


if __name__ == '__main__':
    unittest.main()
