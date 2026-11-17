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

  local payload = vim.json.encode({
    timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    source = "neovim",
    event_type = event_type,
    severity = severity,
    details = details or {},
  })

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
end

return M
