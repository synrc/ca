-module(ca_enroll).
-compile(export_all).
-export([init/2,create/0]).

create() ->
    Args = "openssl ca -config cert/rsa/synrc.cnf -extensions usr_cert -days 365"
          " -in cert/rsa/client.csr -out cert/rsa/client.pem"
          " -cert cert/rsa/caroot.pem -keyfile cert/rsa/caroot.key",

    Port = erlang:open_port({spawn_executable, os:find_executable("sh")},
        [stream, in, out, eof, use_stdio, stderr_to_stdout, binary, exit_status,
            {args, ["-c",Args]}, {cd, element(2,file:get_cwd())}, {env, []}]),

    sh(Port, fun({_, Chunk}, Acc) -> [Chunk|Acc] end, []).

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

maybe_echo(<<"POST">>, true, Req0) ->
    {ok, CSR, Req} = cowboy_req:read_body(Req0),
    file:write_file("cert/rsa/client.csr",CSR),
    create(),
    {ok,Cert} = file:read_file("cert/rsa/client.pem"),
    echo(Cert, Req);

maybe_echo(<<"POST">>, false, Req) -> cowboy_req:reply(400, #{}, <<"Missing body.">>, Req);
maybe_echo(_, _, Req)              -> cowboy_req:reply(405, Req).

echo(<<>>, Req) ->
    cowboy_req:reply(400, #{}, <<"Enrolment Error">>, Req);
echo(Echo, Req) ->
    cowboy_req:reply(200, #{<<"content-type">> => <<"text/plain; charset=utf-8">>}, Echo, Req).
