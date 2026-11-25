-- Open-Shepherd for Neovim (>= 0.9)
-- Zero-dependency security event monitor writing to ~/.open-shepherd/events.jsonl

local M = {}

local default_log_path = vim.env.OPEN_SHEPHERD_LOG or vim.fn.expand("~/.open-shepherd/events.jsonl")

local function emit(event_type, severity, details)
  local log_path = M.config.log_path or default_log_path
  local ok = pcall(vim.fn.mkdir, vim.fn.fnamemodify(log_path, ":h"), "p")
  if not ok then
    return
  end

  local ok_json, payload = pcall(vim.json.encode, {
    timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    source = "neovim",
    event_type = event_type,
    severity = severity,
    details = details or {},
  })
  if not ok_json then
    return
  end

  local f = io.open(log_path, "a")
  if f then
    f:write(payload .. "\n")
    f:close()
  end
end

M.config = {
  log_path = default_log_path,
}

function M.setup(opts)
  M.config = vim.tbl_deep_extend("force", M.config, opts or {})

  local group = vim.api.nvim_create_augroup("OpenShepherd", { clear = true })

  vim.api.nvim_create_autocmd("TermOpen", {
    group = group,
    callback = function(args)
      emit("terminal_open", "info", {
        bufname = vim.api.nvim_buf_get_name(args.buf),
        cwd = vim.fn.getcwd(),
      })
    end,
  })

  vim.api.nvim_create_autocmd("BufWritePost", {
    group = group,
    callback = function(args)
      local name = vim.api.nvim_buf_get_name(args.buf)
      if name:match("%.env") or name:match("%.ssh") or name:match("id_rsa") then
        emit("sensitive_file_write", "high", { file = name })
      end
    end,
  })

  local function check_exrc_and_local_rc()
    if vim.o.exrc then
      emit("unsafe_option", "high", { option = "exrc" })
    end

    local cwd = vim.fn.getcwd()
    for _, rc in ipairs({ ".exrc", ".nvim.lua", ".nvimrc" }) do
      local candidate = cwd .. "/" .. rc
      if vim.fn.filereadable(candidate) == 1 then
        emit("local_rc_detected", "high", { file = candidate })
      end
    end
  end

  vim.api.nvim_create_autocmd({ "VimEnter", "DirChanged" }, {
    group = group,
    callback = check_exrc_and_local_rc,
  })
  check_exrc_and_local_rc()
end

return M
