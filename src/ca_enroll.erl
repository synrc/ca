-module(ca_enroll).
-copyright('Namdak Tonpa').
-include_lib("public_key/include/public_key.hrl").
-export([init/2, boot/0, boot/1, cwd/0, ca/1, enroll/3, service/3, maybe_service/3, echo/2]).

init(Req,Opts) ->
    Method  = cowboy_req:method(Req),
    HasBody = cowboy_req:has_body(Req),
    Request = maybe_service(Method, HasBody, Req),
    {ok, Request, Opts}.

boot() ->
  [ ca_enroll:boot(Crypto) || Crypto <- [ "rsa", "ecc" ] ],
  cowboy_router:compile([{'_', [
      {"/up/:crypto", ca_up, []},
      {"/enroll/:crypto/:nsCertType", ca_enroll, []}
  ]}]).

cwd() -> {ok, Cwd} = file:get_cwd(), Cwd.
cat(X)          -> lists:concat(X).
run(X)          -> sh:sh(sh:run(X)).
reply(X,Y,Z,R)  -> cowboy_req:reply(X,Y,Z,R).
bind(X,Y)       -> binary_to_list(cowboy_req:binding(X,Y)).
cnf()           -> {ok,Bin} = file:read_file(code:priv_dir(ca) ++ "/cnf/synrc.cnf"), Bin.
replace(S,A,B)  -> re:replace(S,A,B,[global,{return,binary}]).
echo(<<>>, Req) -> reply(400,#{},<<"General Enrolment Error">>,Req);
echo(Echo, Req) -> reply(200,#{<<"content-type">> => <<"text/plain;charset=utf-8">>},Echo,Req).
root(Crypto)    -> {lists:concat(["cert/",Crypto,"/"]),"synrc.cnf"}.

boot(Crypto) ->
   {Dir,CNF} = root(Crypto),
   case file:read_file_info(Dir++CNF) of
        {error,_} -> do_boot(Crypto);
        {ok,_} -> skip end, {ok,Crypto}.

do_boot(Crypto) ->
   {Num,Bin} = {<<"1000">>,replace(replace(cnf(),"PATH",cwd()),"CRYPTO",Crypto)},
   {Dir,CNF} = root(Crypto), filelib:ensure_dir(Dir),
   Files     = [{"index.txt",<<>>},{"crlnumber",Num},{"serial",Num},{CNF,Bin}],
   lists:map(fun({A,B}) -> file:write_file(Dir++A,B) end, Files), ca(Crypto).

ca("rsa") ->
    {done,0,_} = run("openssl genrsa -out openssl/rsa/caroot.key 2048"),
    {done,0,_} = run("openssl req -new -x509 -days 3650 -config openssl/rsa/synrc.cnf"
       " -key openssl/rsa/caroot.key -out cert/rsa/caroot.pem"
       " -subj \"/C=UA/ST=Kyiv/O=SYNRC/CN=CA\"");

ca("ecc") ->
    Pass = application:get_env(ca,passin,"pass:0"),
    {done,0,_} = run("openssl ecparam -genkey -name secp384r1 -out openssl/ecc/ca.key"),
    {done,0,_} = run("openssl ec -aes256 -in openssl/ecc/ca.key -out openssl/ecc/caroot.key -passout " ++ Pass),
    {done,0,_} = run("openssl req -config openssl/ecc/synrc.cnf -days 3650 -new -x509"
        " -key openssl/ecc/caroot.key -out openssl/ecc/caroot.pem -passin " ++ Pass ++
        " -subj \"/C=UA/ST=Kyiv/O=SYNRC/CN=CA\"").

enroll(CSR,Crypto,Type) ->
    file:write_file(cat(["openssl/",Crypto,"/",Type,".csr"]),CSR),
    Pass = application:get_env(ca,passin,"pass:0"),
    Policy = case Type of "server" -> "server_cert"; "client" -> "usr_cert"; _ -> Type end,
    {done,0,_} = run("openssl ca -config openssl/"++Crypto++"/synrc.cnf -extensions "++Policy++" -days 365"
        " -in cert/"++Crypto++"/"++Type++".csr -out openssl/"++Crypto++"/"++Type++".pem -passin "
     ++ Pass ++ " -cert openssl/"++Crypto++"/caroot.pem -keyfile cert/"++Crypto++"/caroot.key"),
    file:read_file(cat(["openssl/",Crypto,"/",Type,".pem"])).

maybe_service(<<"POST">>, true,  R) -> service(bind('crypto',R),bind('nsCertType',R),R);
maybe_service(<<"POST">>, false, R) -> reply(400, #{}, <<"Missing body.">>, R);
maybe_service(_, _, R)              -> reply(405, #{}, <<"Unknown.">>, R).

service(Crypto,Type,Req) when (Crypto == "rsa" orelse Crypto == "ecc")
                      andalso (Type == "client" orelse Type == "server" orelse Type == "ocsp") ->
    {ok,CSR, _} = cowboy_req:read_body(Req),
    {ok,PEM}    = enroll(CSR,Crypto,Type),
    {_,{_,D,_}} = lists:keysearch('Certificate',1,public_key:pem_decode(PEM)),
    OTPCert = public_key:pkix_decode_cert(D,otp),
    PKIInfo = OTPCert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subjectPublicKeyInfo,
    io:format("ENROLL PUBLIC KEY [~s,~s] ~p~n",[Crypto,Type,PKIInfo]),
    echo(PEM,Req);

service(_,_,R) ->
    echo(<<>>,R).
