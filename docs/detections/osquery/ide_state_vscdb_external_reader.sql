-- Detect non-IDE processes holding open file handles to VS Code / Cursor / Windsurf state.vscdb
-- Useful for identifying external credential/session/secret readers targeting IDE SQLite state.
SELECT
  p.pid,
  p.name AS process_name,
  p.path AS process_path,
  p.cmdline,
  pof.path AS opened_file
FROM process_open_files AS pof
JOIN processes AS p ON pof.pid = p.pid
WHERE pof.path LIKE '%state.vscdb%'
  AND LOWER(p.name) NOT IN (
    'code',
    'code.exe',
    'code - insiders',
    'code-insiders.exe',
    'cursor',
    'cursor.exe',
    'windsurf',
    'windsurf.exe',
    'codium',
    'codium.exe'
  );
