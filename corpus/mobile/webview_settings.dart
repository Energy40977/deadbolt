// The WebView case is Dart rather than Kotlin on purpose. CodeQL's default setup
// detects languages per run, and a single `.kt` file adds a java-kotlin job that
// cannot extract Kotlin without a build — there is no Gradle project here, so that
// job fails and takes main red. Dart is not a CodeQL language, and DB-MOB-003 is
// language-agnostic, so the rule stays covered. Do not convert this back to Kotlin
// without adding a build for it.
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

final statementViewSettings = InAppWebViewSettings(
  // deadbolt-expect DB-MOB-003:high
  allowFileAccessFromFileURLs: true,
);
