-module(secp256k1).

-export([secp256k1_ecdsa_sign/4,
         secp256k1_ecdsa_verify/3,
         secp256k1_ec_pubkey_create/2,
         secp256k1_ec_privkey_tweak_add/2,
         secp256k1_ec_pubkey_tweak_add/2,
         secp256k1_ec_pubkey_decompress/1,
         secp256k1_ec_seckey_verify/1,
         secp256k1_ec_pubkey_verify/1]).


-on_load(init/0).

-define(nif_stub, nif_stub_error(?LINE)).
nif_stub_error(Line) ->
    erlang:nif_error({nif_not_loaded,module,?MODULE,line,Line}).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

init() ->
    PrivDir = case code:priv_dir(?MODULE) of
                  {error, bad_name} ->
                      EbinDir = filename:dirname(code:which(?MODULE)),
                      AppPath = filename:dirname(EbinDir),
                      filename:join(AppPath, "priv");
                  Path ->
                      Path
              end,
    erlang:load_nif(filename:join(PrivDir, "secp256k1_drv"), 0).

secp256k1_ecdsa_sign(_Msg32, _SecKey, _Nonce, _NonceData) ->
    ?nif_stub.

secp256k1_ecdsa_verify(_Msg32, _Sig, _Pubkey) ->
    ?nif_stub.

secp256k1_ec_pubkey_create(_SecKey, _Compressed) ->
    ?nif_stub.

secp256k1_ec_privkey_tweak_add(_PrivKey, _Add) ->
    ?nif_stub.

secp256k1_ec_pubkey_tweak_add(_PubKey, _Add) ->
    ?nif_stub.

secp256k1_ec_pubkey_decompress(_PubKey) ->
    ?nif_stub.

secp256k1_ec_seckey_verify(_SecKey) ->
    ?nif_stub.

secp256k1_ec_pubkey_verify(_PubKey) ->
    ?nif_stub.

%% ===================================================================
%% EUnit tests
%% ===================================================================
-ifdef(TEST).

sign_test() ->
  SecKey = <<128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128>>,
  Msg32 = crypto:hash(sha256, <<"Hello">>),
  << _/binary >> = Sig = secp256k1_ecdsa_sign(Msg32, SecKey, default, <<>>),
  ?assertEqual(correct, secp256k1_ecdsa_verify(Msg32, Sig, secp256k1_ec_pubkey_create(SecKey, false))).

tweak_test() ->
  SecKey = <<128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128>>,
  Add = <<1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1>>,
  Expected = <<129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129>>,
  ?assertEqual(Expected, secp256k1_ec_privkey_tweak_add(SecKey, Add)).

verify_test() ->
  SecKey = <<128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128>>,

  PubKey = secp256k1_ec_pubkey_create(SecKey, false),
  ?assertEqual(true, secp256k1_ec_seckey_verify(SecKey)),
  ?assertEqual(true, secp256k1_ec_pubkey_verify(PubKey)).

decompress_test() ->
  SecKey = <<128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128>>,

  PubKey = secp256k1_ec_pubkey_create(SecKey, false),
  PubKeyComp = secp256k1_ec_pubkey_create(SecKey, true),

  ?assertEqual(PubKey, secp256k1_ec_pubkey_decompress(PubKeyComp)).
 
-endif.
