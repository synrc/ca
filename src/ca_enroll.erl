-module(ca_enroll).
-include_lib("public_key/include/public_key.hrl").
-compile(export_all).
-export([init/2,create/2]).

run(X)          -> sh:sh(sh:run(X)).
reply(X,Y,Z,R)  -> cowboy_req:reply(X,Y,Z,R).
bind(X,Y)       -> cowboy_req:binding(X,Y).
template()      -> {ok,Bin} = file:read_file("priv/cnf/synrc.cnf"), Bin.
replace(S,A,B)  -> re:replace(S,A,B,[global,{return,list}]).
echo(<<>>, Req) -> reply(400,#{},<<"General Enrolment Error">>,Req);
echo(Echo, Req) -> reply(200,#{<<"content-type">> => <<"text/plain;charset=utf-8">>},Echo,Req).

boot(Crypto) ->
   Temp    = template(),
   Tem2    = replace(Temp,"PATH", mad_utils:cwd()),
   Bin     = iolist_to_binary(replace(Tem2,"CRYPTO",Crypto)),
   Gen     = lists:concat(["cert/",Crypto,"/synrc.cnf"]),
   Index   = lists:concat(["cert/",Crypto,"/index.txt"]),
   CRL     = lists:concat(["cert/",Crypto,"/crlnumber"]),
   Serial  = lists:concat(["cert/",Crypto,"/serial"]),
   Counter = <<"1000">>,
   case file:read_file_info("cert/"++Crypto++"/synrc.cnf") of
         {error,_} ->
             filelib:ensure_dir(Gen),
             lists:map(fun({A,B}) -> file:write_file(A,B) end,
                [{Index,<<>>},{CRL,Counter},{Serial,Counter},{Gen,Bin}]),
             ca(Crypto);
         {ok,_} -> skip end,
   {ok,man}.

ca("rsa") ->
    {done,0,_} = run("openssl genrsa -out cert/rsa/caroot.key 2048"),
    {done,0,_} = run("openssl req -new -x509 -days 3650 -config cert/rsa/synrc.cnf"
                         " -key cert/rsa/caroot.key -out cert/rsa/caroot.pem"
                         " -subj \"/C=UA/ST=Kyiv/O=SYNRC/CN=CA\"");

ca("ecc") ->
    Pass = application:get_env(ca,passin,"pass:0"),
    {done,0,Bin} = run("openssl ecparam -genkey -name secp384r1"),
    file:write_file("cert/ecc/ca.key",Bin),
    {done,0,_} = run("openssl ec -aes256 -in cert/ecc/ca.key -out cert/ecc/caroot.key -passout " ++ Pass),
    {done,0,_} = run("openssl req -config cert/ecc/synrc.cnf -days 3650 -new -x509"
        " -key cert/ecc/caroot.key -out cert/ecc/caroot.pem -passin " ++ Pass ++
        " -subj \"/C=UA/ST=Kyiv/O=SYNRC/CN=CA\"").

create(Crypto,Type) ->
    Pass = application:get_env(ca,passin,"pass:0"),
    Policy = case Type of "server" -> "server_cert"; "client" -> "usr_cert" end,
    {done,0,_} = run("openssl ca -config cert/"++Crypto++"/synrc.cnf -extensions "++Policy++" -days 365"
        " -in cert/"++Crypto++"/"++Type++".csr -out cert/"++Crypto++"/"++Type++".pem -passin "
     ++ Pass ++ " -cert cert/"++Crypto++"/caroot.pem -keyfile cert/"++Crypto++"/caroot.key").

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
    io:format("ENROLL REQUEST [~s,~s] ~p~n",[C,T,PKInfo]),
    echo(Cert, Req);

enroll(_,_,R) ->
    echo(<<>>,R).
