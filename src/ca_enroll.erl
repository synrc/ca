-module(ca_enroll).
-include_lib("public_key/include/public_key.hrl").
-compile(export_all).
-export([init/2,create/2]).

reply(X,Y,Z,R) -> cowboy_req:reply(X,Y,Z,R).
bind(X,Y) -> cowboy_req:binding(X,Y).

create(Crypto,Type) ->
    Pass = application:get_env(ca,passin,"pass:0"),
    Policy = case Type of "server" -> "server_cert"; "client" -> "usr_cert" end,
    Args = "openssl ca -config cert/"++Crypto++"/synrc.cnf -extensions "++Policy++" -days 365"
          " -in cert/"++Crypto++"/"++Type++".csr -out cert/"++Crypto++"/"++Type++".pem -passin "
          ++ Pass ++ " -cert cert/"++Crypto++"/caroot.pem -keyfile cert/"++Crypto++"/caroot.key",
    Port = erlang:open_port({spawn_executable, os:find_executable("sh")},
        [stream, in, out, eof, use_stdio, stderr_to_stdout, binary, exit_status,
            {args, ["-c",Args]}, {cd, element(2,file:get_cwd())}, {env, []}]),
    X = sh(Port, fun({_, Chunk}, Acc) -> [Chunk|Acc] end, []),
    X.

sh(Port, Fun, Acc) ->
    receive
        {Port, {exit_status, Status}} -> {done, Status, iolist_to_binary(lists:reverse(Acc))};
        {Port, {data, {eol, Line}}} -> sh(Port, Fun, Fun({eol, Line}, Acc));
        {Port, {data, {noeol, Line}}} -> sh(Port, Fun, Fun({noeol, Line}, Acc));
        {Port, {data, Data}} ->
           case {binary:match(Data,  <<"Sign the certificate? [y/n]:">>) =/= nomatch,
                 binary:match(Data,  <<"requests certified, commit?">>)  =/= nomatch} of
                {true,_}   -> Port ! {self(),{command,<<"y\n">>}};
                {_,true}   -> Port ! {self(),{command,<<"y\n">>}};
                {_,_}      -> skip
           end,
           sh(Port, Fun, Fun({data,Data}, Acc))
    end.


init(Req0, Opts) ->
    Method = cowboy_req:method(Req0),
    HasBody = cowboy_req:has_body(Req0),
    Req = maybe_echo(Method, HasBody, Req0),
    {ok, Req, Opts}.

maybe_echo(<<"POST">>, true,  R) -> enroll(bind('crypto',R),bind('nsCertType',R),R);
maybe_echo(<<"POST">>, false, R) -> reply(400, #{}, <<"Missing body.">>, R);
maybe_echo(_, _, R)              -> reply(405, #{}, <<"Unknown.">>, R).

enroll(Crypto,Type,Req0)
    when (Crypto == <<"rsa">> orelse Crypto == <<"ecc">>) andalso
         (Type == <<"client">> orelse Type == <<"server">>) ->
    C = binary_to_list(Crypto),
    T = binary_to_list(Type),
    {ok, CSR, Req} = cowboy_req:read_body(Req0),
    file:write_file("cert/"++C++"/"++T++".csr",CSR),
    create(C,T),
    {ok,Cert} = file:read_file("cert/"++C++"/"++T++".pem"),
    Entries = public_key:pem_decode(Cert),
    {value, CertEntry} = lists:keysearch('Certificate', 1, Entries),
    {_, DerCert, _} = CertEntry,
    Decoded = public_key:pkix_decode_cert(DerCert, otp),
    PKInfo = Decoded#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subjectPublicKeyInfo,
    io:format("Log [~s,~s] ~p~n",[C,T,PKInfo]),
    echo(Cert, Req);
enroll(_,_,R) -> echo(<<>>,R).

echo(<<>>, Req) -> reply(400,#{},<<"Enrolment Error">>,Req);
echo(Echo, Req) -> reply(200,#{<<"content-type">> => <<"text/plain;charset=utf-8">>},Echo,Req).

