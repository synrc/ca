// MIT License

open System
open System.IO
open System.Text
open UA.Cryptography
open FSharp.Data

let split (ss:#seq<obj>) (s:string) =
    s.Split(ss |> Seq.map string |> Seq.toArray, StringSplitOptions.None)

let eval args =
    match split [|"-vars"; "-in"; "-out"|] (args |> String.concat " ") with
    | _ -> ()

let ret (_:unit) = 0

[<EntryPoint>]
let main args = args |> eval |> ret
