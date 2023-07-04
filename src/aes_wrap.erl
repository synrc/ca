-module(aes_wrap).
-export([wrap/2, unwrap/2]).

wrap(Key, PlainText)
  when bit_size(PlainText) >= 256,
       bit_size(PlainText) rem 64 == 0 ->
    Checksum = <<16#A6A6A6A6A6A6A6A6:64>>,
    Blocks = split(PlainText),
    wrap(Key, Checksum, 1, 0, Blocks, []).

wrap(_Key, Checksum, I, 5, Blocks, Acc) when I > length(Blocks) -> <<Checksum/binary, (iolist_to_binary(lists:reverse(Acc)))/binary>>;
wrap(Key, Checksum, I, J, Blocks, Acc) when I > length(Blocks) -> wrap(Key, Checksum, 1, J + 1, lists:reverse(Acc), []);
wrap(Key, Checksum, I, J, Blocks, Acc) ->
    NthBlock = lists:nth(I, Blocks),
    <<MSB:64, LSB:64>> = crypto:crypto_one_time(aes_128_ecb,
        Key, <<>>, <<Checksum/binary, NthBlock/binary>>, [{encrypt,true}]),
    wrap(Key, crypto:exor(<<MSB:64>>, <<((length(Blocks) * J) + I):64>>),
         I + 1, J, Blocks, [<<LSB:64>> | Acc]).


unwrap(Key, CipherText)
  when bit_size(CipherText) >= 192,
       bit_size(CipherText) rem 64 == 0 ->
    [Checksum | Blocks] = split(CipherText),
    unwrap(Key, Checksum, length(Blocks), 5, Blocks, []).

unwrap(_Key, Checksum, 0, 0, Blocks, Acc) ->
    case Checksum of
        <<16#A6A6A6A6A6A6A6A6:64>> ->
            iolist_to_binary(Acc);
        _ ->
            throw({invalid_checksum, Checksum, Blocks, Acc})
    end;

unwrap(Key, Checksum, 0, J, Blocks, Acc) -> unwrap(Key, Checksum, length(Blocks), J - 1, Acc, []);
unwrap(Key, Checksum, I, J, Blocks, Acc) ->
    NthBlock = lists:nth(I, Blocks),
    Xor = crypto:exor(Checksum, <<((length(Blocks) * J) + I):64>>),
    <<MSB:64, LSB:64>> = crypto:crypto_one_time(aes_128_ecb,
        Key, <<>>, <<Xor/binary, NthBlock/binary>>, [{encrypt,false}]),
    unwrap(Key, <<MSB:64>>, I - 1, J, Blocks, [<<LSB:64>> | Acc]).

split(Bin) when bit_size(Bin) rem 64 == 0 -> split(Bin, []).
split(<<>>, Acc) -> lists:reverse(Acc);
split(<<H:64, T/binary>>, Acc) -> split(T, [<<H:64>> | Acc]).
