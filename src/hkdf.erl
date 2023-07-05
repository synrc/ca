-module(hkdf).

-export([derive_secrets/2, derive_secrets/3, derive_secrets/4, derive_secrets/5,
	 extract/2, extract/3, expand/3, expand/4, max_length/1]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-type hash_algorithm() :: md5 | sha | sha224 | sha256 | sha384 | sha512.
-type salt() :: iodata().
-type info() :: iodata().
-type prk() :: binary().
-type ikm() :: iodata().
-type okm() :: binary().

-spec derive_secrets(IKM, L) -> OKM when
      IKM :: ikm(), 
      L :: pos_integer(), 
      OKM :: okm().
%% @doc Generate a HKDF key derivation of a supplied key IKM with a
%% desired output length L in bytes, using the sha256 hmac function as
%% a default.
derive_secrets(IKM, L) ->
    derive_secrets(sha256, IKM, <<>>, <<>>, L).

-spec derive_secrets(Hash_algorithm, IKM, L) -> OKM when
      Hash_algorithm :: hash_algorithm(), 
      IKM :: ikm(), 
      L :: pos_integer(),
      OKM :: okm().
%% @doc Generate a HKDF key derivation of a supplied key IKM with a
%% desired output length L in bytes, using Hash_algorithm.
derive_secrets(Hash_algorithm, IKM, L) when is_integer(L) ->
    derive_secrets(Hash_algorithm, IKM, <<>>, <<>>, L).

-spec derive_secrets(Hash_algorithm, IKM, Info, L) -> OKM when
      Hash_algorithm :: hash_algorithm(), 
      IKM :: ikm(), 
      Info :: info(), 
      L :: pos_integer(),
      OKM :: okm().
derive_secrets(Hash_algorithm, IKM, Info, L) ->
    derive_secrets(Hash_algorithm, IKM, Info, <<>>, L).

-spec derive_secrets(Hash_algorithm, IKM, Info, Salt, L) -> OKM when
      Hash_algorithm :: hash_algorithm(), 
      IKM :: ikm(), 
      Info :: info(), 
      Salt :: salt(),
      L :: pos_integer(),
      OKM :: okm().
%% @doc Generate a HKDF key derivation of a supplied key IKM and salt with a
%% desired output length L in bytes, using Hash_algorithm.
derive_secrets(Hash_algorithm, IKM, Info, Salt, L) ->
    PRK = extract(Hash_algorithm, Salt, IKM),
    expand(Hash_algorithm, PRK, Info, L).

-spec extract(Hash_algorithm, IKM) -> PRK when
      Hash_algorithm :: hash_algorithm(),
      IKM :: ikm(),
      PRK :: prk(). 
%% @doc extract/2 takes the input keying material IKM and "extracts" from it
%% a fixed-length pseudo random key PRK.
extract(Hash_algorithm, IKM) ->
    extract(Hash_algorithm, <<>>, IKM).

-spec extract(Hash_algorithm, Salt, IKM) -> PRK when
      Hash_algorithm :: hash_algorithm(),
      Salt :: salt(),
      IKM :: ikm(),
      PRK :: prk(). 
%% @doc extract/3 takes the input keying material IKM plus a salt and "extracts" from it
%% a fixed-length pseudo random key PRK.
extract(Hash_algorithm, <<>>, IKM) -> 
    hmac(Hash_algorithm, <<0:(hash_length(Hash_algorithm))>>, IKM);
extract(Hash_algorithm, Salt, IKM) -> 
    hmac(Hash_algorithm, Salt, IKM).

-spec expand(Hash_algorithm, PRK, L) -> OKM when
      Hash_algorithm :: hash_algorithm(), 
      PRK :: prk(), 
      L :: pos_integer(), 
      OKM :: okm().
% @doc expand/3 "expands" the key PRK from the extract stage into L additional pseudorandom keys.
expand(Hash_algorithm, PRK, L) ->
    expand(Hash_algorithm, PRK, <<>>, L).

-spec expand(Hash_algorithm, PRK, Info, L) -> OKM when
      Hash_algorithm :: hash_algorithm(), 
      PRK :: prk(), 
      Info :: info(), 
      L :: pos_integer(),
      OKM :: okm().
expand(Hash_algorithm, PRK, "", L) ->
    expand(Hash_algorithm, PRK, <<>>, L);
expand(Hash_algorithm, PRK, Info, L) when is_integer(L) ->
    case {L, max_length(Hash_algorithm)} of
	{L, _Max_L} when L =< 0 ->
	    {error, derived_length_leq_zero};
	{L, Max_L} when L =< Max_L ->
	    OKM = expand_(Hash_algorithm, 
			  PRK, Info, 
			  1, % Iteration, start with first
			  calc_iters(L, Hash_algorithm), % Number of iterations to go
			  <<>>, <<>>), % T[0] and Acc
	    <<OKM:L/binary>>; % first L octets of T
	_  ->
	    {error, max_derived_length_exceeded}
    end.

expand_(_Hash_algorithm, _PRK, _Info, I, N, _Prev, Acc) 
  when I > N ->
    Acc;
expand_(Hash_algorithm, PRK, Info, I, N, Prev, Acc) ->
    Ti = hmac(Hash_algorithm, PRK, <<Prev/binary, Info/binary, I:8>>),
    expand_(Hash_algorithm, PRK, Info, I + 1, N, Ti, <<Acc/binary, Ti/binary>>).

-spec max_length(hash_algorithm()) -> pos_integer().
%% length of output keying material in octets should be <= 255 *
%% HashLen (See page 3)
max_length(Hash_algorithm) ->
    (hash_length(Hash_algorithm) bsr 3) * 255.

%% This is the N = ceil(L/HashLen) calculation
calc_iters(L, Hash_algorithm) ->
    Hl = hash_length(Hash_algorithm) bsr 3,
    N = L div Hl,
    case (L rem Hl) of
	0 ->
	    N;
	_ ->
	    N + 1
    end.

hash_length(md5) -> 128;
hash_length(sha) -> 128;
hash_length(sha224) -> 224;
hash_length(sha256) -> 256;
hash_length(sha384) -> 384;
hash_length(sha512) -> 512.

hmac(Hash_algorithm, Salt, IKM) ->
    crypto:mac(hmac, Hash_algorithm, Salt, IKM).

-ifdef(TEST).

%% Test data from https://datatracker.ietf.org/doc/html/rfc5869#appendix-A

case_1_test() ->
    Hash = sha256,
    IKM = binary:decode_hex(<<"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b">>),
    Salt = binary:decode_hex(<<"000102030405060708090a0b0c">>),
    Info = binary:decode_hex(<<"f0f1f2f3f4f5f6f7f8f9">>),
    L = 42,
    PRK = binary:decode_hex(<<"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5">>),
    OKM = binary:decode_hex(<<"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865">>),
    ?assert(PRK =:= extract(Hash, Salt, IKM) andalso
	    OKM =:= expand(Hash, PRK, Info, L) andalso
	    OKM =:= derive_secrets(Hash, IKM, Info, Salt, L)).

case_2_test() ->
    Hash = sha256,
    IKM = binary:decode_hex(<<"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f">>),
    Salt = binary:decode_hex(<<"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf">>),
    Info = binary:decode_hex(<<"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff">>),
    L = 82,
    PRK = binary:decode_hex(<<"06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244">>),
    OKM = binary:decode_hex(<<"b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87">>),
    ?assert(PRK =:= extract(Hash, Salt, IKM) andalso
	    OKM =:= expand(Hash, PRK, Info, L) andalso
	    OKM =:= derive_secrets(Hash, IKM, Info, Salt, L)).

case_3_test() ->
    Hash = sha256,
    IKM = binary:decode_hex(<<"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b">>),
    Salt = "",
    Info = "",
    L = 42,
    PRK = binary:decode_hex(<<"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04">>),
    OKM = binary:decode_hex(<<"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8">>),
    ?assert(PRK =:= extract(Hash, Salt, IKM) andalso
	    OKM =:= expand(Hash, PRK, Info, L) andalso
	    OKM =:= derive_secrets(Hash, IKM, Info, Salt, L)).

case_4_test() ->
    Hash = sha,
    IKM = binary:decode_hex(<<"0b0b0b0b0b0b0b0b0b0b0b">>),
    Salt = binary:decode_hex(<<"000102030405060708090a0b0c">>),
    Info = binary:decode_hex(<<"f0f1f2f3f4f5f6f7f8f9">>),
    L = 42,
    PRK = binary:decode_hex(<<"9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243">>),
    OKM = binary:decode_hex(<<"085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896">>),
    ?assert(PRK =:= extract(Hash, Salt, IKM) andalso
	    OKM =:= expand(Hash, PRK, Info, L) andalso
	    OKM =:= derive_secrets(Hash, IKM, Info, Salt, L)).

case_5_test() ->
    Hash = sha,
    IKM = binary:decode_hex(<<"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f">>),
    Salt = binary:decode_hex(<<"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf">>),
    Info = binary:decode_hex(<<"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff">>),
    L = 82,
    PRK = binary:decode_hex(<<"8adae09a2a307059478d309b26c4115a224cfaf6">>),
    OKM = binary:decode_hex(<<"0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4">>),
    ?assert(PRK =:= extract(Hash, Salt, IKM) andalso
	    OKM =:= expand(Hash, PRK, Info, L) andalso
	    OKM =:= derive_secrets(Hash, IKM, Info, Salt, L)).

case_6_test() ->
    Hash = sha,
    IKM = binary:decode_hex(<<"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b">>),
    Salt = "",
    Info = "",
    L = 42,
    PRK = binary:decode_hex(<<"da8c8a73c7fa77288ec6f5e7c297786aa0d32d01">>),
    OKM = binary:decode_hex(<<"0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918">>),
    ?assert(PRK =:= extract(Hash, Salt, IKM) andalso
	    OKM =:= expand(Hash, PRK, Info, L) andalso
	    OKM =:= derive_secrets(Hash, IKM, L)).
    
case_7_test() ->
    Hash = sha,
    IKM = binary:decode_hex(<<"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c">>),
    Info = "",
    L = 42,
    PRK = binary:decode_hex(<<"2adccada18779e7c2077ad2eb19d3f3e731385dd">>),
    OKM = binary:decode_hex(<<"2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48">>),
    ?assert(PRK =:= extract(Hash, IKM) andalso
	    OKM =:= expand(Hash, PRK, Info, L) andalso
	    OKM =:= derive_secrets(Hash, IKM, L)).


-endif.
