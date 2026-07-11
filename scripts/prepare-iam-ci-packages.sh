#!/usr/bin/env bash
set -euo pipefail

readonly messaging_source="${1:-.ci-sources/Maliev.MessagingContracts}"
readonly aspire_source="${2:-.ci-sources/Maliev.Aspire}"
readonly output_path="${3:-.ci-packages}"
readonly messaging_commit="0bcd4c704d842211c5ff9bd6b9c4b3aacfcbd8e7"
readonly aspire_commit="7121d57705fc1eff6c7ebb6a69e33e9c26ebfccc"
readonly messaging_version="1.0.91-alpha"
readonly service_defaults_version="1.0.81-alpha"
readonly ci_nuget_config="$(pwd)/NuGet.PRValidation.Config"

assert_checkout() {
  local repository_path="$1"
  local expected_commit="$2"
  local actual_commit

  actual_commit="$(git -C "$repository_path" rev-parse HEAD)"
  if [[ "$actual_commit" != "$expected_commit" ]]; then
    printf 'Expected %s at %s, found %s\n' "$repository_path" "$expected_commit" "$actual_commit" >&2
    exit 1
  fi
}

assert_checkout "$messaging_source" "$messaging_commit"
assert_checkout "$aspire_source" "$aspire_commit"

# Source checkouts live beneath IAMService in CI. Prevent IAMService analyzer settings from
# changing immutable dependency builds merely because they are nested beneath this repository.
if [[ ! -f "$messaging_source/.editorconfig" ]]; then
  printf 'root = true\n' > "$messaging_source/.editorconfig"
fi
if [[ ! -f "$aspire_source/.editorconfig" ]]; then
  printf 'root = true\n' > "$aspire_source/.editorconfig"
fi

mkdir -p -- "$output_path"
find "$output_path" -maxdepth 1 -type f \( -name '*.nupkg' -o -name '*.snupkg' -o -name 'SHA256SUMS.txt' \) -delete
readonly output_dir="$(cd "$output_path" && pwd)"

readonly generator_project="$messaging_source/tools/Generator/Generator.csproj"
readonly messaging_project="$messaging_source/generated/csharp/Maliev.MessagingContracts.csproj"
readonly service_defaults_project="$aspire_source/Maliev.Aspire.ServiceDefaults/Maliev.Aspire.ServiceDefaults.csproj"

dotnet restore "$generator_project" --configfile "$ci_nuget_config"
(cd "$messaging_source" && dotnet run --project tools/Generator/Generator.csproj --configuration Release --no-restore)
dotnet restore "$messaging_project" --configfile "$ci_nuget_config"
dotnet pack "$messaging_project" \
  --configuration Release \
  --no-restore \
  -p:NoWarn=CS1570 \
  -p:PackageVersion="$messaging_version" \
  --output "$output_dir"

dotnet restore "$service_defaults_project" \
  --configfile "$ci_nuget_config" \
  -p:GITHUB_ACTIONS=true \
  -p:SharedLibraryVersion="$messaging_version"
dotnet pack "$service_defaults_project" \
  --configuration Release \
  --no-restore \
  -p:GITHUB_ACTIONS=true \
  -p:SharedLibraryVersion="$messaging_version" \
  -p:PackageVersion="$service_defaults_version" \
  --output "$output_dir"

test -s "$output_dir/Maliev.MessagingContracts.$messaging_version.nupkg"
test -s "$output_dir/Maliev.Aspire.ServiceDefaults.$service_defaults_version.nupkg"

(
  cd "$output_dir"
  sha256sum \
    "Maliev.MessagingContracts.$messaging_version.nupkg" \
    "Maliev.Aspire.ServiceDefaults.$service_defaults_version.nupkg" \
    > SHA256SUMS.txt
  sha256sum --check SHA256SUMS.txt
)
