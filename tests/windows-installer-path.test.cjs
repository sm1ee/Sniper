// Source contract checks only. Native Inno compilation and a disposable Windows
// account are still required to exercise the installer and registry APIs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../packaging/windows/sniper.iss'), 'utf8');

function routine(name) {
  const start = source.search(new RegExp(`^(?:function|procedure) ${name}\\b`, 'm'));
  assert.notEqual(start, -1, `missing Pascal routine ${name}`);
  const rest = source.slice(start);
  const end = rest.slice(1).search(/^(?:function|procedure) \w+/m);
  return end < 0 ? rest : rest.slice(0, end + 1);
}

function before(body, first, second) {
  const a = body.indexOf(first);
  const b = body.indexOf(second);
  assert.ok(a >= 0 && b > a, `${first} must precede ${second}`);
}

test('CLI PATH remains an explicit user-only opt-in, including upgrades', () => {
  assert.match(source, /^PrivilegesRequired=lowest$/m);
  assert.doesNotMatch(source, /^PrivilegesRequiredOverridesAllowed=/m);
  assert.match(source, /^Name: "clipath";.*user PATH.*Flags: unchecked checkedonce$/m);
  assert.match(source, /^ChangesEnvironment=yes$/m);
  assert.doesNotMatch(source, /\[Registry\][\s\S]*ValueName:\s*"Path"/i);
});

test('Setup tracks its completed initial choice without adding a marker to portable ZIPs', () => {
  assert.match(source, /^Source: "installed-by-setup\.txt"; DestDir: "\{app\}"; DestName: "\.sniper-installed"; Flags: ignoreversion$/m);
  assert.doesNotMatch(source, /^Source: "installed-by-setup\.txt";.*(?:Tasks:|uninsneveruninstall|deleteafterinstall)/m);
  const marker = fs.readFileSync(path.join(__dirname, '../packaging/windows/installed-by-setup.txt'), 'utf8');
  assert.match(marker, /Settings/);
  const zip = fs.readFileSync(path.join(__dirname, '../packaging/windows/make-zip.ps1'), 'utf8');
  assert.doesNotMatch(zip, /installed-by-setup|\.sniper-installed/);
  assert.match(zip, /foreach \(\$binary in @\('sniper-desktop\.exe', 'sniper\.exe', 'sniper-cli\.exe'\)\)/);
  assert.match(zip, /foreach \(\$license in @\('LICENSE', 'LICENSE\.md', 'COPYING'\)\)/);
  assert.match(zip, /Copy-Item -LiteralPath \(Join-Path \$PSScriptRoot 'README\.md'\) -Destination \$stage/);
  assert.equal((zip.match(/Copy-Item /g) || []).length, 3);
});

test('PATH installation starts only after completed installation and selected task', () => {
  const body = routine('CurStepChanged');
  assert.match(body, /if \(CurStep = ssPostInstall\) and WizardIsTaskSelected\('clipath'\) then\s+AddBundledCliToPath;/);
  assert.equal((source.match(/\bAddBundledCliToPath;/g) || []).length, 2);
  assert.doesNotMatch(source, /procedure (?:InitializeWizard|DeinitializeSetup|CancelButtonClick)/);
  assert.match(routine('CurUninstallStepChanged'), /if CurUninstallStep = usUninstall then\s+RemoveOwnedCliPath;/);
});

test('PATH reads preserve raw UTF-16 and refuse malformed or unsupported values', () => {
  const body = routine('ReadRawPath');
  assert.match(source, /external 'RegQueryValueExW@advapi32\.dll stdcall'/);
  assert.doesNotMatch(source, /external 'RegGetValueW@/);
  assert.match(body, /Size mod 2 <> 0/);
  assert.match(body, /Size > Capacity/);
  assert.match(body, /\(ValueType <> RegSz\) and \(ValueType <> RegExpandSz\)/);
  assert.match(body, /Buffer\[Size div 2\] <> #0/);
  assert.match(body, /Pos\(#0, Value\) <> 0/);
  assert.match(body, /Status = ErrorFileNotFound/);
  assert.match(body, /ValueType := RegExpandSz/);
  assert.match(body, /finally\s+ClosePathRegistryKey\(Handle\)/);
});

test('writing preserves the existing registry kind and never writes machine PATH', () => {
  const body = routine('WriteRawUserPath');
  assert.match(body, /if ValueType = RegSz then\s+Result := RegWriteStringValue\(HKCU, EnvironmentKey, 'Path', Value\)/);
  assert.match(body, /else if ValueType = RegExpandSz then\s+Result := RegWriteExpandStringValue\(HKCU, EnvironmentKey, 'Path', Value\)/);
  assert.match(body, /else\s+Result := False/);
  assert.doesNotMatch(source, /Reg(?:Write\w+|Delete\w+)\(HKLM/);
  assert.doesNotMatch(source, /\bsetx\b/i);
});

test('duplicate comparison is case-insensitive and tolerates quotes and separators', () => {
  const body = routine('NormalizePathDirectory');
  assert.match(body, /Trim\(Value\)/);
  assert.match(body, /Result\[1\] = '"'/);
  assert.match(body, /Result\[Length\(Result\)\] = '"'/);
  assert.match(body, /StringChangeEx\(Result, '\/', '\\', True\)/);
  assert.match(body, /while \(Length\(Result\) > 3\) and \(Result\[Length\(Result\)\] = '\\'\)/);
  assert.match(body, /Lowercase\(Result\)/);
  assert.doesNotMatch(routine('PathHasDirectory'), /ExpandPathForComparison/);
});

test('environment expansion failures abort before checking or writing PATH', () => {
  const expand = routine('TryExpandPathForComparison');
  assert.match(expand, /Result := False;/);
  assert.match(expand, /if not ExpandVariables then begin\s+ExpandedValue := Value;\s+Result := True;\s+Exit;/);
  assert.match(expand, /if \(Required = 0\) or \(Required > 32767\) then\s+Exit;/);
  assert.match(expand, /if \(Written = 0\) or \(Written > Required\) then\s+Exit;/);
  assert.match(expand, /if Buffer\[Written\] <> #0 then\s+Exit;/);
  before(expand, 'if (Written = 0)', 'ExpandedValue := Copy');
  const body = routine('AddBundledCliToPath');
  assert.match(body, /if not TryExpandPathForComparison\(BeforePath, ValueType = RegExpandSz, UserSearchPath\) or\s+not TryExpandPathForComparison\(MachinePath, MachineType = RegExpandSz, MachineSearchPath\) then begin[\s\S]*?Exit;\s+end;/);
  before(body, 'if not TryExpandPathForComparison', 'if not PathHasSupportedQuoting');
  before(body, 'if not TryExpandPathForComparison', 'if not SaveCliPathOwnership');
  const uninstall = routine('RemoveOwnedCliPath');
  assert.match(uninstall, /if not TryExpandPathForComparison\(BeforePath, ValueType = RegExpandSz, BeforeSearchPath\) then\s+Exit;/);
  before(uninstall, 'if not TryExpandPathForComparison', 'Removed := WriteRawUserPath');
});

test('quoted semicolons stay in a single PATH entry and unsupported quoting blocks writes', () => {
  const separator = routine('NextPathSeparator');
  assert.match(separator, /if Path\[Index\] = '"' then\s+Quoted := not Quoted/);
  assert.match(separator, /else if \(Path\[Index\] = ';'\) and not Quoted then/);
  for (const name of ['PathHasDirectory', 'PathHasOtherCli', 'PathHasSupportedQuoting']) {
    assert.match(routine(name), /Separator := NextPathSeparator\(Path\)/);
    assert.doesNotMatch(routine(name), /Separator := Pos\(';', Path\)/);
  }
  const validation = routine('PathHasSupportedQuoting');
  assert.match(validation, /\(Entry\[1\] <> '"'\) or \(Entry\[Length\(Entry\)\] <> '"'\)/);
  assert.match(validation, /Pos\('"', Copy\(Entry, 2, Length\(Entry\) - 2\)\) <> 0/);
  const body = routine('AddBundledCliToPath');
  assert.match(body, /not PathHasSupportedQuoting\(UserSearchPath\)/);
  assert.match(body, /not PathHasSupportedQuoting\(MachineSearchPath\)/);
  assert.match(body, /not PathHasSupportedQuoting\(GetEnv\('PATH'\)\)/);
  before(body, 'if not PathHasSupportedQuoting', 'if not SaveCliPathOwnership');
});

test('equivalent pre-existing PATH entries are returned without claiming ownership', () => {
  const body = routine('AddBundledCliToPath');
  assert.match(body, /if PathHasDirectory\(UserSearchPath, Directory\) or\s+PathHasDirectory\(MachineSearchPath, Directory\) then begin[\s\S]*?Exit;\s+end;/);
  before(body, 'if PathHasDirectory', 'if RegKeyExists');
  before(body, 'if RegKeyExists', 'if not SaveCliPathOwnership');
  assert.match(body, /if RegKeyExists\(HKCU64, CliPathKey\) then begin[\s\S]*?Exit;\s+end;/);
});

test('an unrelated same-name command prevents registration without replacing files', () => {
  const body = routine('PathHasOtherCli');
  assert.match(body, /\(Entry <> ''\) and \(Entry <> Directory\)/);
  assert.match(body, /DirectoryHasOtherCli\(Entry, False\)/);
  const directory = routine('DirectoryHasOtherCli');
  assert.match(directory, /Extensions := '\.exe;\.com;\.bat;\.cmd;' \+ GetEnv\('PATHEXT'\)/);
  assert.match(directory, /FileExists\(AddBackslash\(Directory\) \+ 'sniper-cli' \+ Extension\)/);
  const install = routine('AddBundledCliToPath');
  assert.ok(install.includes('PathHasOtherCli(MachineSearchPath, Directory)'));
  assert.ok(install.includes('PathHasOtherCli(UserSearchPath, Directory)'));
  assert.ok(install.includes("PathHasOtherCli(GetEnv('PATH'), Directory)"));
  before(install, 'if DirectoryHasOtherCli', 'if not SaveCliPathOwnership');
  assert.doesNotMatch(install, /\b(?:FileCopy|DeleteFile|RenameFile|Exec|ShellExec)\(/);
});

test('target-folder same-name siblings and custom PATHEXT commands are checked safely', () => {
  const install = routine('AddBundledCliToPath');
  assert.match(install, /if DirectoryHasOtherCli\(Directory, True\) or/);
  assert.match(routine('DirectoryHasOtherCli'), /not \(AllowBundledExe and \(Extension = '\.exe'\)\)/);
  assert.match(install, /if not CliExtensionsAreSafe\(GetEnv\('PATHEXT'\)\) then begin[\s\S]*?Exit;\s+end;/);
  before(install, 'if not CliExtensionsAreSafe', 'if DirectoryHasOtherCli');
  const safe = routine('CliExtensionsAreSafe');
  assert.match(safe, /\(Length\(Extension\) < 2\) or \(Extension\[1\] <> '\.'\)/);
  assert.match(safe, /Extension\[Index\] in \['a'\.\.'z', 'A'\.\.'Z', '0'\.\.'9'\]/);
});

test('append keeps the original raw text intact, including trailing empty entries', () => {
  assert.match(routine('AppendCliDirectory'), /if BeforePath = '' then\s+Result := Directory\s+else\s+Result := BeforePath \+ ';' \+ Directory/);
  const body = routine('AddBundledCliToPath');
  assert.match(body, /Pos\(';', Directory\) <> 0/);
  assert.match(body, /Pos\(#13, Directory\) <> 0/);
  assert.match(body, /Pos\(#10, Directory\) <> 0/);
  assert.match(body, /\(ValueType = RegExpandSz\) and \(Pos\('%', Directory\) <> 0\)/);
  assert.match(body, /Length\(AfterPath\) > 32766/);
});

test('installer and runtime share a bounded named mutex for all ownership mutations', () => {
  assert.ok(source.includes("CliPathMutexName = 'Local\\SniperCliPathRegistration'"));
  assert.match(routine('LockCliPath'), /WaitForCliPathMutex\(Handle, 5000\)/);
  assert.match(routine('LockCliPath'), /\(Status = WaitObject0\) or \(Status = WaitAbandoned\)/);
  for (const name of ['AddBundledCliToPath', 'RemoveOwnedCliPath']) {
    const body = routine(name);
    assert.match(body, /if not LockCliPath\(Handle\) then begin[\s\S]*?Exit;/);
    assert.match(body, /finally\s+UnlockCliPath\(Handle\)/);
  }
});

test('complete ownership is persisted before PATH, with schema published last', () => {
  assert.ok(source.includes("CliPathKey = 'Software\\Sniper\\CliPath'"));
  const marker = routine('SaveCliPathOwnership');
  for (const key of ['Directory', 'OwnerExecutable', 'BeforePath', 'AfterPath', 'PathType', 'BeforePresent']) {
    before(marker, `'${key}'`, "'SchemaVersion'");
  }
  assert.match(marker, /RegWriteDWordValue\(HKCU64, CliPathKey, 'SchemaVersion', 1\)/);
  assert.match(marker, /if not Result then\s+RegDeleteKeyIncludingSubkeys\(HKCU64, CliPathKey\)/);
  const body = routine('AddBundledCliToPath');
  before(body, 'if not SaveCliPathOwnership', 'if not WriteRawUserPath');
  assert.match(body, /if not SaveCliPathOwnership[\s\S]*?then begin[\s\S]*?Exit;\s+end;/);
});

test('a concurrent PATH change or failed PATH write removes only new ownership', () => {
  const body = routine('AddBundledCliToPath');
  assert.match(body, /\(CheckPresent <> Present\) or \(CheckPath <> BeforePath\) or \(CheckType <> ValueType\) then begin\s+RegDeleteKeyIncludingSubkeys[\s\S]*?Exit;/);
  assert.match(body, /if not WriteRawUserPath\(AfterPath, ValueType\) then begin\s+RegDeleteKeyIncludingSubkeys[\s\S]*?Exit;/);
  assert.equal((body.match(/WriteRawUserPath\(/g) || []).length, 1);
});

test('uninstall restores only a validated record owned by this installation', () => {
  const body = routine('RemoveOwnedCliPath');
  assert.match(body, /\(Schema <> 1\) or \(BeforePresent > 1\)/);
  assert.match(body, /NormalizePathDirectory\(Directory\) <> NormalizePathDirectory\(ThisDirectory\)/);
  assert.match(body, /CompareText\(Owner, AddBackslash\(ThisDirectory\) \+ 'sniper-desktop\.exe'\) <> 0/);
  assert.match(body, /\(BeforePresent = 0\) and \(BeforePath <> ''\)/);
  assert.match(body, /AfterPath <> AppendCliDirectory\(BeforePath, Directory\)/);
  assert.match(body, /PathHasDirectory\(BeforeSearchPath, Directory\)/);
  before(body, 'AfterPath <> AppendCliDirectory', 'Removed := WriteRawUserPath');
});

test('post-install PATH edits or type changes make uninstall leave PATH untouched', () => {
  const body = routine('RemoveOwnedCliPath');
  assert.match(body, /if not CurrentPresent or \(CurrentPath <> AfterPath\) or \(CurrentType <> ValueType\) then begin[\s\S]*?Exit;\s+end;/);
  before(body, 'CurrentPath <> AfterPath', 'Removed := WriteRawUserPath');
  assert.match(body, /if BeforePresent = 1 then\s+Removed := WriteRawUserPath\(BeforePath, ValueType\)\s+else\s+Removed := RegDeleteValue\(HKCU, EnvironmentKey, 'Path'\)/);
  assert.match(body, /if Removed then\s+RegDeleteKeyIncludingSubkeys\(HKCU64, CliPathKey\)/);
});

test('successful changes broadcast only after releasing the PATH mutex', () => {
  assert.match(routine('NotifyPathChange'), /BroadcastPathChange\(\$FFFF, \$001A, 0, 'Environment', \$0002, 1000, Ignored\)/);
  assert.match(routine('AddBundledCliToPath'), /finally\s+UnlockCliPath\(Handle\);\s+if Changed then\s+NotifyPathChange/);
  assert.match(routine('RemoveOwnedCliPath'), /finally\s+UnlockCliPath\(Handle\);\s+if Removed then\s+NotifyPathChange/);
});
