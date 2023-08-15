-module(aes_kw).
-export([wrap/2]).
-export([wrap/3]).
-export([unwrap/2]).
-export([unwrap/3]).
-export([test/0]).

-define(MSB64,      1/unsigned-big-integer-unit:64).
-define(DEFAULT_IV, << 16#A6A6A6A6A6A6A6A6:?MSB64 >>).

wrap(PlainText, KEK) -> wrap(PlainText, KEK, ?DEFAULT_IV).
wrap(PlainText, KEK, IV)
        when (byte_size(PlainText) rem 8) =:= 0
        andalso (bit_size(KEK) =:= 128
            orelse bit_size(KEK) =:= 192
            orelse bit_size(KEK) =:= 256) ->
    Buffer = << IV/binary, PlainText/binary >>,
    BlockCount = (byte_size(Buffer) div 8) - 1,
    do_wrap(Buffer, 0, BlockCount, KEK).

unwrap(CipherText, KEK) -> unwrap(CipherText, KEK, ?DEFAULT_IV).
unwrap(CipherText, KEK, IV)
        when (byte_size(CipherText) rem 8) =:= 0
        andalso (bit_size(KEK) =:= 128
            orelse bit_size(KEK) =:= 192
            orelse bit_size(KEK) =:= 256) ->
    BlockCount = (byte_size(CipherText) div 8) - 1,
    IVSize = byte_size(IV),
    case do_unwrap(CipherText, 5, BlockCount, KEK) of
        << IV:IVSize/binary, PlainText/binary >> ->
            PlainText;
        _ ->
            erlang:error({badarg, [CipherText, KEK, IV]})
    end.

do_wrap(Buffer, 6, _BlockCount, _KEK) -> Buffer;
do_wrap(Buffer, J, BlockCount, KEK) -> do_wrap(do_wrap(Buffer, J, 1, BlockCount, KEK), J + 1, BlockCount, KEK).

codec(128) -> aes_128_ecb;
codec(192) -> aes_192_ecb;
codec(256) -> aes_256_ecb.

do_wrap(Buffer, _J, I, BlockCount, _KEK) when I > BlockCount -> Buffer;
do_wrap(<< A0:8/binary, Rest/binary >>, J, I, BlockCount, KEK) ->
    HeadSize = (I - 1) * 8,
    << Head:HeadSize/binary, B0:8/binary, Tail/binary >> = Rest,
    Round = (BlockCount * J) + I,
    Data = << A0/binary, B0/binary >>,
    << A1:?MSB64, B1/binary >> = crypto:crypto_one_time(codec(bit_size(KEK)), KEK, ?DEFAULT_IV, Data, [{encrypt,true}]),
    A2 = A1 bxor Round,
    do_wrap(<< A2:?MSB64, Head/binary, B1/binary, Tail/binary >>, J, I + 1, BlockCount, KEK).

do_unwrap(Buffer, J, _BlockCount, _KEK) when J < 0 -> Buffer;
do_unwrap(Buffer, J, BlockCount, KEK) -> do_unwrap(do_unwrap(Buffer, J, BlockCount, BlockCount, KEK), J - 1, BlockCount, KEK).

do_unwrap(Buffer, _J, I, _BlockCount, _KEK) when I < 1 -> Buffer;
do_unwrap(<< A0:?MSB64, Rest/binary >>, J, I, BlockCount, KEK) ->
    HeadSize = (I - 1) * 8,
    << Head:HeadSize/binary, B0:8/binary, Tail/binary >> = Rest,
    Round = (BlockCount * J) + I,
    A1 = A0 bxor Round,
    Data = << A1:?MSB64, B0/binary >>,
    << A2:8/binary, B1/binary >> = crypto:crypto_one_time(codec(bit_size(KEK)), KEK, ?DEFAULT_IV, Data, [{encrypt,false}]),
    do_unwrap(<< A2/binary, Head/binary, B1/binary, Tail/binary >>, J, I - 1, BlockCount, KEK).

test() ->
    KEK = << 16#000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F:1/unsigned-big-integer-unit:256 >>,
    KeyData = << 16#00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F:1/unsigned-big-integer-unit:256 >>,
    CipherText = << 16#28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21:2/unsigned-big-integer-unit:160 >>,
    CipherText = wrap(KeyData, KEK),
    KeyData = unwrap(CipherText, KEK),
    true.
