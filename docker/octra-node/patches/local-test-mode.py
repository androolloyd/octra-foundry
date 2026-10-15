"""Startup-only opt-in for isolated native tests; no consensus/profile edits."""
from pathlib import Path

def replace(path, old, new):
    p = Path(path)
    text = p.read_text()
    if text.count(old) != 1:
        raise SystemExit(f"pinned upstream patch drift: {path}")
    p.write_text(text.replace(old, new))

replace('bin/octra_node.ml',
    '    if not (Rule_graph.live_chain ~chain_id:startup_network.chain_id) then begin',
    '''    let local_test_mode = env_opt "OCTRA_LOCAL_TEST_MODE" = Some "1" in
    if local_test_mode then begin
      let private_chain =
        String.starts_with ~prefix:"octra-local-" startup_network.chain_id in
      let single_mode = match env_opt "OCTRA_CONSENSUS_MODE" with
        | None -> true
        | Some value -> String.equal (String.lowercase_ascii (String.trim value)) "single" in
      let no_peers = startup_network.consensus_peers = [] &&
        (try Yojson.Basic.from_file "nodes.config" = `List [] with _ -> false) in
      if not (private_chain && single_mode && no_peers &&
              startup_network.consensus_port = 0 &&
              not (cli_has_flag "--observer") && not (cli_has_flag "--publisher") &&
              not (cli_has_flag "--state-sync-publisher")) then begin
        Log.fatal "init" "event = local_test_mode status = rejected reason = isolated_single_required";
        exit_error ()
      end;
      Log.warn "init" "event = local_test_mode private_single_chain = true profile = prior p2p = disabled"
    end;
    if not local_test_mode && not (Rule_graph.live_chain ~chain_id:startup_network.chain_id) then begin''')
replace('bin/octra_node.ml',
    '    let consensus_mode = role.consensus_enabled in',
    '''    let consensus_mode = role.consensus_enabled in
    if local_test_mode && consensus_mode then begin
      Log.fatal "init" "event = local_test_mode status = rejected reason = consensus_enabled";
      exit_error ()
    end;''')
replace('node_runtime/startup_node_launch_shell.ml',
    '        p2p = p2p deps.p2p_port;',
    '''        p2p = (if Sys.getenv_opt "OCTRA_LOCAL_TEST_MODE" = Some "1"
               then (fun () -> fst (Lwt.wait ())) else p2p deps.p2p_port);''')
