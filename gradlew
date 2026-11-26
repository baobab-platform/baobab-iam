#!/usr/bin/env bash
# The repository's Gradle project is the Android N06 qualification utility.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
project="$repo/tools/n06-android-probe"
wrapper="$repo/gradle/wrapper/gradle-wrapper.jar"
wrapper_sha=498495120a03b9a6ab5d155f5de3c8f0d986a449153702fb80fc80e134484f17
printf '%s  %s\n' "$wrapper_sha" "$wrapper" | sha256sum -c -

export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-"$project/.android-sdk"}}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
if [[ ! -f "$ANDROID_HOME/platforms/android-35/android.jar" ||
      ! -x "$ANDROID_HOME/build-tools/35.0.0/apksigner" ]]; then
    if [[ "$(uname -s)-$(uname -m)" != Linux-x86_64 ]]; then
        echo "Install API 35 and Build Tools 35.0.0 in ANDROID_HOME before running the wrapper." >&2
        exit 1
    fi
    tools_build=15859902
    tools_sha=4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583
    command_tools="$ANDROID_HOME/cmdline-tools/$tools_build"
    if [[ ! -x "$command_tools/bin/sdkmanager" ]]; then
        temp=$(mktemp -d)
        trap 'rm -rf -- "$temp"' EXIT
        curl --fail --silent --show-error --location --retry 3 \
            "https://dl.google.com/android/repository/commandlinetools-linux-${tools_build}_latest.zip" \
            -o "$temp/android-tools.zip"
        printf '%s  %s\n' "$tools_sha" "$temp/android-tools.zip" | sha256sum -c -
        unzip -q "$temp/android-tools.zip" -d "$temp"
        mkdir -p "$ANDROID_HOME/cmdline-tools"
        mv "$temp/cmdline-tools" "$command_tools"
        rm -rf -- "$temp"
        trap - EXIT
    fi
    sdkmanager="$command_tools/bin/sdkmanager"
    if [[ "${CI:-}" == true ]]; then
        (set +o pipefail; yes | "$sdkmanager" --licenses >/dev/null)
    fi
    "$sdkmanager" 'platforms;android-35' 'build-tools;35.0.0'
fi

java=java
if [[ -n "${JAVA_HOME:-}" ]]; then
    java="$JAVA_HOME/bin/java"
fi
exec "$java" -classpath "$wrapper" org.gradle.wrapper.GradleWrapperMain --project-dir "$project" "$@"
