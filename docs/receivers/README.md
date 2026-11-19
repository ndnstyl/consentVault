# Receiver templates: notes for whoever switches one live

- **Before switching the n8n template live, deal with pushes created before the channel fields were added.** Those pushes carry no
  `channel_state` or `channel_version`, and the template refuses them (HTTP 422, shown as Undelivered in the portal). A redrive re-sends a
  stored push with its old body, so it does not add the fields; a new change for that person does. Switch the template only when the
  system has no pending or retrying pushes from before the change, or keep the older receiver until they are delivered.
- Set the crypto setting for code steps on a self-hosted n8n (`NODE_FUNCTION_ALLOW_BUILTIN=crypto`).
- The templates are not tested by ConsentVault against your CRM. Run the check at the end of the help article first.
