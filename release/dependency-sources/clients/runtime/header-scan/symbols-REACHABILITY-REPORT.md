# CodeEditSymbols: fixed-source import and target reachability

## Result

CodeEditSymbols is a declared production library dependency of CodeEditSourceEditor, and the fixed SourceEditor library source contains an actual, unconditional `import CodeEditSymbols` in `FindPanelView.swift:10`. That view is constructed on the client’s `MacLibrary/CodeEditTextView` → `TextViewController.loadView()` → find-panel path. This confirms source import and library-target reachability; it is stronger than a lockfile-only candidate.

The same fixed source does **not** establish an invocation of a CodeEditSymbols image API or use of its asset catalog. A lexical scan of all 159 SourceEditor library-target Swift files and all 312 retained Apple-client Swift files found no Symbols initializer, named-image method, or static-property call. The sole SourceEditor module-name hit is the import. The three loose `.github` property-pattern hits are a comment URL or string URLs/media type, not image API calls. Treat the import as an apparently unused import for API-use purposes, not proof that Symbols assets execute, ship, or are stripped.

No build, final Mach-O, link map, resource-copy output, or packaged application was inspected. Final binary/resource inclusion remains unproven. This report does not determine notice sufficiency or change any frozen delivery file.

## Fixed revisions

- Apple client: `SagerNet/sing-box-for-apple@e232aaf22d6d68773196ffc8e6e79684a6be717c`.
- Source editor: `nekohasekai/CodeEditSourceEditor@0478fd4b8d45f191b6c400d2c7bf6cc648485593`.
- Symbols: `CodeEditApp/CodeEditSymbols@ae69712b08571c4469c2ed5cd38ad9f19439793e`, version `0.2.3`.
- The client’s [Package.resolved, lines 22–39](https://github.com/SagerNet/sing-box-for-apple/blob/e232aaf22d6d68773196ffc8e6e79684a6be717c/sing-box.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved#L22-L39) pins both dependency revisions. The Xcode project specifies SourceEditor’s main branch, but this inquiry uses the recorded fixed resolution, not the moving branch tip.

## Exact source and target chain

1. **Symbols is a library product, not only a test dependency.** [Symbols Package.swift:10–14 and 23–33](https://github.com/CodeEditApp/CodeEditSymbols/blob/ae69712b08571c4469c2ed5cd38ad9f19439793e/Package.swift#L10-L33) exposes the `CodeEditSymbols` library target. The target has no dependencies; SnapshotTesting is used by the separate test target.
2. **SourceEditor’s production target depends on it.** [SourceEditor Package.swift:8–14, 27–31 and 44–57](https://github.com/nekohasekai/CodeEditSourceEditor/blob/0478fd4b8d45f191b6c400d2c7bf6cc648485593/Package.swift#L8-L57) declares a macOS 13 library and includes `CodeEditSymbols` in its ordinary target dependencies. The target has no custom path, source list, or exclusions, so `Sources/CodeEditSourceEditor` is its default source tree; the importing file is in that tree, outside Tests and Example.
3. **The production source actually imports Symbols.** [FindPanelView.swift:8–11 and 24–85](https://github.com/nekohasekai/CodeEditSourceEditor/blob/0478fd4b8d45f191b6c400d2c7bf6cc648485593/Sources/CodeEditSourceEditor/Find/PanelView/FindPanelView.swift#L8-L85) has the unconditional import on line 10 and defines the actual find-panel view. The import is not within a Preview block or a conditional compilation branch.
4. **The imported view is constructed by the editor’s normal source path.** [TextViewController+Lifecycle.swift:29–59](https://github.com/nekohasekai/CodeEditSourceEditor/blob/0478fd4b8d45f191b6c400d2c7bf6cc648485593/Sources/CodeEditSourceEditor/Controller/TextViewController%2BLifecycle.swift#L29-L59) constructs and adds `FindViewController`. [FindViewController.swift:35–43](https://github.com/nekohasekai/CodeEditSourceEditor/blob/0478fd4b8d45f191b6c400d2c7bf6cc648485593/Sources/CodeEditSourceEditor/Find/FindViewController.swift#L35-L43) constructs `FindPanelHostingView`. [FindPanelHostingView.swift:24–38](https://github.com/nekohasekai/CodeEditSourceEditor/blob/0478fd4b8d45f191b6c400d2c7bf6cc648485593/Sources/CodeEditSourceEditor/Find/PanelView/FindPanelHostingView.swift#L24-L38) initializes its root `FindPanelView` at line 31.
5. **The Apple client imports and constructs that editor.** [MacLibrary/CodeEditTextView.swift:1–9 and 127–142](https://github.com/SagerNet/sing-box-for-apple/blob/e232aaf22d6d68773196ffc8e6e79684a6be717c/MacLibrary/CodeEditTextView.swift#L1-L142) imports `CodeEditSourceEditor` at line 3, creates its `TextViewController` at lines 132–137, and calls `loadView()` at line 138. [ProfileEditorWrapperView.swift:13–15](https://github.com/SagerNet/sing-box-for-apple/blob/e232aaf22d6d68773196ffc8e6e79684a6be717c/MacLibrary/ProfileEditorWrapperView.swift#L13-L15) uses the wrapper; [GhosttyConfigEditorWrapperView.swift:7–12](https://github.com/SagerNet/sing-box-for-apple/blob/e232aaf22d6d68773196ffc8e6e79684a6be717c/MacLibrary/GhosttyConfigEditorWrapperView.swift#L7-L12) is a second use.
6. **The Xcode framework target includes this source group and package product.** In the fixed [project.pbxproj](https://github.com/SagerNet/sing-box-for-apple/blob/e232aaf22d6d68773196ffc8e6e79684a6be717c/sing-box.xcodeproj/project.pbxproj), line 757 maps the synchronized group to `MacLibrary`; lines 662–669 exclude only `AppIcon.icon` and `Assets.xcassets` for MacLibrary, not the Swift files. [Lines 1486–1509](https://github.com/SagerNet/sing-box-for-apple/blob/e232aaf22d6d68773196ffc8e6e79684a6be717c/sing-box.xcodeproj/project.pbxproj#L1486-L1509) attach that group and the SourceEditor package product to the MacLibrary framework target. Lines 928–935 place SourceEditor in its framework build phase. Lines 4105–4112 identify the package repository; lines 4164–4168 identify the product.

## API-use check

[CodeEditSymbols.swift:9–70](https://github.com/CodeEditApp/CodeEditSymbols/blob/ae69712b08571c4469c2ed5cd38ad9f19439793e/Sources/CodeEditSymbols/CodeEditSymbols.swift#L9-L70) provides `Image.init(symbol:)`, `NSImage.symbol(named:)`, and 16 static properties on each image type: branch, breakpoint, breakpointFill, checkout, chevronUpChevronDown, commit, docJava, docJavascript, docJson, docPython, docRuby, github, squareSplitHorizontalPlus, squareSplitVerticalPlus, vault, and vaultFill. All use the Symbols module’s asset bundle.

`API-USAGE-SCAN.json` retains the scan patterns and every match, including the three false positives. The negative result is a bounded lexical-source finding, not compiler or runtime proof. No new components were acquired for this check.

## Retained evidence and integrity

- `sourceeditor/SOURCE-MANIFEST.json`: all 159 fixed target Swift files, 525,319 total bytes, per-file raw fixed-revision URL, Git blob SHA-1, and SHA-256. Every byte count and Git blob matches the pre-existing fixed SourceEditor TREE.json.
- `sourceeditor/Sources/CodeEditSourceEditor/`: exact decoded UTF-8 source bytes; eight source-bundle JSON records preserve the fetched text used to materialize them.
- `EVIDENCE-MANIFEST.json`: fixed client and package source copies with raw/source URLs, SHA-256, and verified Git blob identities. Every retained client/package copy matches the prior acquisition/tree provenance.
- `codeeditsymbols/Sources/CodeEditSymbols/CodeEditSymbols.swift`: 2,987 bytes; Git blob `c8f6548914181d8a8b59bf6f77de79a0e3a07454`; SHA-256 `c485c03203d96aa4ac75576202f1a676ec911d90b21531f9689f536e48947d4e`.
- `API-USAGE-SCAN.json`: exact module/API patterns and scan results.
- Network retrieval was limited to fixed raw source GETs through the GitHub connector. All outputs from this inquiry are under `research/three-notice-header-closure/symbols-reachability`.
