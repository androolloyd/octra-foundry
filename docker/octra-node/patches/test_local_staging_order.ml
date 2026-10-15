module Source = Octra_node_runtime.Consensus_epoch_apply_source
module Tx = Octra_core.Transaction
module Graph = Octra_core.Rule_graph

let expect label value = if not value then failwith label
let tx from nonce = Tx.{ from; to_ = "octRecipient"; amount = Z.one;
  nonce; ou = Z.one; timestamp = 1.; signature = ""; public_key = None;
  message = None; op_type = Standard; encrypted_data = None }

let () =
  let a = tx "octA" 1 and z = tx "octZ" 1 in
  let inputs = [z; a] in
  let rules = Graph.create ~chain_id:"octra-local-regression"
    ~root_at:(fun _ -> Graph.Missing) in
  let deps = Source.{ rules;
    check_override_receipts = (fun ~epoch_id:_ ~receipts:_ _ -> Ok ());
    find_finalized = (fun _ -> None); cached_bundle = (fun _ -> None);
    receipt_root_matches = (fun _ _ -> false);
    header_has_empty_bundle = (fun _ -> false); staging_txs = (fun () -> inputs) } in
  let request = Source.{ epoch_id = 1; override_ordered_txs = None;
    override_receipts_json = None; consensus_mode = false } in
  expect "single staging must be canonical"
    (match Source.choose deps request with
     | Ok selected -> selected.txs = Tx.consensus_order inputs
     | Error _ -> false);
  expect "override ordering validation must remain strict"
    (Result.is_error (Source.choose deps {request with override_ordered_txs = Some inputs}));
  expect "consensus source must still require a finalized header"
    (Result.is_error (Source.choose deps {request with consensus_mode = true}));
  expect "duplicate staging hashes must still be refused"
    (Result.is_error (Source.choose {deps with staging_txs = (fun () -> [a; a])} request));
  print_endline "native staging-order regression PASS"
