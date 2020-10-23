-module(oid).
-export([decode/1]).

match_tags({T, V}, [T]) -> V;
match_tags({T, V}, [T | Tt]) -> match_tags(V, Tt);
match_tags([{T, V}], [T | Tt]) -> match_tags(V, Tt);
match_tags([{T, _V} | _] = Vlist, [T]) -> Vlist;
match_tags(Tlv, []) -> Tlv;
match_tags({Tag, _V} = Tlv, [T | _Tt]) -> {error, {asn1, {wrong_tag, {{expected, T}, {got, Tag, Tlv}}}}}.

dec_subidentifiers(<<>>, _Av, Al) -> lists:reverse(Al);
dec_subidentifiers(<<1:1,H:7,T/binary>>, Av, Al) -> dec_subidentifiers(T, Av bsl 7 + H, Al);
dec_subidentifiers(<<H,T/binary>>, Av, Al) -> dec_subidentifiers(T, 0, [Av bsl 7 + H | Al]).

decode(Tlv) ->
    Val = match_tags(Tlv, []),
    [AddedObjVal | ObjVals] = dec_subidentifiers(Val, 0, []),
    {Val1, Val2} =
        if
            AddedObjVal < 40 ->
                {0, AddedObjVal};
            AddedObjVal < 80 ->
                {1, AddedObjVal - 40};
            true ->
                {2, AddedObjVal - 80}
        end,
    list_to_tuple([Val1, Val2 | ObjVals]).
