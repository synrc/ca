defmodule CA.Profile.Data do
  @moduledoc "Central registry for all Security Controls and their ODPs"

  def controls do
    [
      CA.SPE.oid(:"id-spe-ac"),
      CA.SPE.oid(:"id-spe-at"),
      CA.SPE.oid(:"id-spe-au"),
      CA.SPE.oid(:"id-spe-ca"),
      CA.SPE.oid(:"id-spe-cm"),
      CA.SPE.oid(:"id-spe-cp"),
      CA.SPE.oid(:"id-spe-ia"),
      CA.SPE.oid(:"id-spe-ir"),
      CA.SPE.oid(:"id-spe-ma"),
      CA.SPE.oid(:"id-spe-mp"),
      CA.SPE.oid(:"id-spe-pe"),
      CA.SPE.oid(:"id-spe-pl"),
      CA.SPE.oid(:"id-spe-ps"),
      CA.SPE.oid(:"id-spe-ra"),
      CA.SPE.oid(:"id-spe-sa"),
      CA.SPE.oid(:"id-spe-sc"),
      CA.SPE.oid(:"id-spe-si"),
      CA.SPE.oid(:"id-spe-sr"),
      CA.SPE.oid(:"id-spe-pm"),
      CA.SPE.oid(:"id-spe-pt"),
      CA.SPE.oid(:"id-spe-ac-1"),
      CA.SPE.oid(:"id-spe-ac-2"),
      CA.SPE.oid(:"id-spe-ac-2-1"),
      CA.SPE.oid(:"id-spe-ac-2-3"),
      CA.SPE.oid(:"id-spe-ac-2-4"),
      CA.SPE.oid(:"id-spe-ac-2-5"),
      CA.SPE.oid(:"id-spe-ac-2-6"),
      CA.SPE.oid(:"id-spe-ac-2-7"),
      CA.SPE.oid(:"id-spe-ac-2-8"),
      CA.SPE.oid(:"id-spe-ac-2-9"),
      CA.SPE.oid(:"id-spe-ac-2-10"),
      CA.SPE.oid(:"id-spe-ac-2-11"),
      CA.SPE.oid(:"id-spe-ac-2-12"),
      CA.SPE.oid(:"id-spe-ac-2-13"),
      CA.SPE.oid(:"id-spe-ac-3"),
      CA.SPE.oid(:"id-spe-ac-3-1"),
      CA.SPE.oid(:"id-spe-ac-3-2"),
      CA.SPE.oid(:"id-spe-ac-3-3"),
      CA.SPE.oid(:"id-spe-ac-3-4"),
      CA.SPE.oid(:"id-spe-ac-3-5"),
      CA.SPE.oid(:"id-spe-ac-3-6"),
      CA.SPE.oid(:"id-spe-ac-3-7"),
      CA.SPE.oid(:"id-spe-ac-3-8"),
      CA.SPE.oid(:"id-spe-ac-3-9"),
      CA.SPE.oid(:"id-spe-ac-3-10"),
      CA.SPE.oid(:"id-spe-ac-3-11"),
      CA.SPE.oid(:"id-spe-ac-3-12"),
      CA.SPE.oid(:"id-spe-ac-3-13"),
      CA.SPE.oid(:"id-spe-ac-3-14"),
      CA.SPE.oid(:"id-spe-ac-3-15"),
      CA.SPE.oid(:"id-spe-ac-4"),
      CA.SPE.oid(:"id-spe-ac-4-1"),
      CA.SPE.oid(:"id-spe-ac-4-2"),
      CA.SPE.oid(:"id-spe-ac-4-3"),
      CA.SPE.oid(:"id-spe-ac-4-4"),
      CA.SPE.oid(:"id-spe-ac-4-5"),
      CA.SPE.oid(:"id-spe-ac-4-6"),
      CA.SPE.oid(:"id-spe-ac-4-7"),
      CA.SPE.oid(:"id-spe-ac-4-8"),
      CA.SPE.oid(:"id-spe-ac-4-9"),
      CA.SPE.oid(:"id-spe-ac-4-10"),
      CA.SPE.oid(:"id-spe-ac-4-11"),
      CA.SPE.oid(:"id-spe-ac-4-12"),
      CA.SPE.oid(:"id-spe-ac-4-13"),
      CA.SPE.oid(:"id-spe-ac-4-14"),
      CA.SPE.oid(:"id-spe-ac-4-15"),
      CA.SPE.oid(:"id-spe-ac-4-16"),
      CA.SPE.oid(:"id-spe-ac-4-18"),
      CA.SPE.oid(:"id-spe-ac-4-19"),
      CA.SPE.oid(:"id-spe-ac-4-20"),
      CA.SPE.oid(:"id-spe-ac-4-21"),
      CA.SPE.oid(:"id-spe-ac-4-22"),
      CA.SPE.oid(:"id-spe-ac-4-23"),
      CA.SPE.oid(:"id-spe-ac-4-24"),
      CA.SPE.oid(:"id-spe-ac-4-25"),
      CA.SPE.oid(:"id-spe-ac-4-26"),
      CA.SPE.oid(:"id-spe-ac-4-27"),
      CA.SPE.oid(:"id-spe-ac-4-28"),
      CA.SPE.oid(:"id-spe-ac-4-29"),
      CA.SPE.oid(:"id-spe-ac-4-30"),
      CA.SPE.oid(:"id-spe-ac-4-31"),
      CA.SPE.oid(:"id-spe-ac-4-32"),
      CA.SPE.oid(:"id-spe-ac-5"),
      CA.SPE.oid(:"id-spe-ac-6"),
      CA.SPE.oid(:"id-spe-ac-6-1"),
      CA.SPE.oid(:"id-spe-ac-6-2"),
      CA.SPE.oid(:"id-spe-ac-6-4"),
      CA.SPE.oid(:"id-spe-ac-6-5"),
      CA.SPE.oid(:"id-spe-ac-6-6"),
      CA.SPE.oid(:"id-spe-ac-6-7"),
      CA.SPE.oid(:"id-spe-ac-6-8"),
      CA.SPE.oid(:"id-spe-ac-6-9"),
      CA.SPE.oid(:"id-spe-ac-6-10"),
      CA.SPE.oid(:"id-spe-ac-7"),
      CA.SPE.oid(:"id-spe-ac-7-1"),
      CA.SPE.oid(:"id-spe-ac-7-2"),
      CA.SPE.oid(:"id-spe-ac-7-3"),
      CA.SPE.oid(:"id-spe-ac-7-4"),
      CA.SPE.oid(:"id-spe-ac-8"),
      CA.SPE.oid(:"id-spe-ac-9"),
      CA.SPE.oid(:"id-spe-ac-9-1"),
      CA.SPE.oid(:"id-spe-ac-9-2"),
      CA.SPE.oid(:"id-spe-ac-9-3"),
      CA.SPE.oid(:"id-spe-ac-9-4"),
      CA.SPE.oid(:"id-spe-ac-10"),
      CA.SPE.oid(:"id-spe-ac-11"),
      CA.SPE.oid(:"id-spe-ac-11-1"),
      CA.SPE.oid(:"id-spe-ac-12"),
      CA.SPE.oid(:"id-spe-ac-12-1"),
      CA.SPE.oid(:"id-spe-ac-12-2"),
      CA.SPE.oid(:"id-spe-ac-12-3"),
      CA.SPE.oid(:"id-spe-ac-13"),
      CA.SPE.oid(:"id-spe-ac-14"),
      CA.SPE.oid(:"id-spe-ac-14-1"),
      CA.SPE.oid(:"id-spe-ac-15"),
      CA.SPE.oid(:"id-spe-ac-16"),
      CA.SPE.oid(:"id-spe-ac-16-1"),
      CA.SPE.oid(:"id-spe-ac-16-2"),
      CA.SPE.oid(:"id-spe-ac-16-3"),
      CA.SPE.oid(:"id-spe-ac-16-4"),
      CA.SPE.oid(:"id-spe-ac-16-5"),
      CA.SPE.oid(:"id-spe-ac-16-6"),
      CA.SPE.oid(:"id-spe-ac-16-7"),
      CA.SPE.oid(:"id-spe-ac-16-8"),
      CA.SPE.oid(:"id-spe-ac-16-9"),
      CA.SPE.oid(:"id-spe-ac-16-10"),
      CA.SPE.oid(:"id-spe-ac-17"),
      CA.SPE.oid(:"id-spe-ac-17-1"),
      CA.SPE.oid(:"id-spe-ac-17-2"),
      CA.SPE.oid(:"id-spe-ac-17-3"),
      CA.SPE.oid(:"id-spe-ac-17-4"),
      CA.SPE.oid(:"id-spe-ac-17-5"),
      CA.SPE.oid(:"id-spe-ac-17-6"),
      CA.SPE.oid(:"id-spe-ac-17-7"),
      CA.SPE.oid(:"id-spe-ac-17-8"),
      CA.SPE.oid(:"id-spe-ac-17-9"),
      CA.SPE.oid(:"id-spe-ac-17-10"),
      CA.SPE.oid(:"id-spe-ac-18"),
      CA.SPE.oid(:"id-spe-ac-18-1"),
      CA.SPE.oid(:"id-spe-ac-18-2"),
      CA.SPE.oid(:"id-spe-ac-18-3"),
      CA.SPE.oid(:"id-spe-ac-18-4"),
      CA.SPE.oid(:"id-spe-ac-18-5"),
      CA.SPE.oid(:"id-spe-ac-19"),
      CA.SPE.oid(:"id-spe-ac-19-1"),
      CA.SPE.oid(:"id-spe-ac-19-2"),
      CA.SPE.oid(:"id-spe-ac-19-3"),
      CA.SPE.oid(:"id-spe-ac-19-4"),
      CA.SPE.oid(:"id-spe-ac-19-5"),
      CA.SPE.oid(:"id-spe-ac-20"),
      CA.SPE.oid(:"id-spe-ac-20-1"),
      CA.SPE.oid(:"id-spe-ac-20-2"),
      CA.SPE.oid(:"id-spe-ac-20-3"),
      CA.SPE.oid(:"id-spe-ac-20-4"),
      CA.SPE.oid(:"id-spe-ac-20-5"),
      CA.SPE.oid(:"id-spe-ac-21"),
      CA.SPE.oid(:"id-spe-ac-21-1"),
      CA.SPE.oid(:"id-spe-ac-21-2"),
      CA.SPE.oid(:"id-spe-ac-22"),
      CA.SPE.oid(:"id-spe-ac-23"),
      CA.SPE.oid(:"id-spe-ac-24"),
      CA.SPE.oid(:"id-spe-ac-24-1"),
      CA.SPE.oid(:"id-spe-ac-24-2"),
      CA.SPE.oid(:"id-spe-ac-25"),
      CA.SPE.oid(:"id-spe-at-1"),
      CA.SPE.oid(:"id-spe-at-2"),
      CA.SPE.oid(:"id-spe-at-3"),
      CA.SPE.oid(:"id-spe-at-3-1"),
      CA.SPE.oid(:"id-spe-at-3-2"),
      CA.SPE.oid(:"id-spe-at-4"),
      CA.SPE.oid(:"id-spe-at-5"),
      CA.SPE.oid(:"id-spe-at-6"),
      CA.SPE.oid(:"id-spe-au-1"),
      CA.SPE.oid(:"id-spe-au-2"),
      CA.SPE.oid(:"id-spe-au-2-1"),
      CA.SPE.oid(:"id-spe-au-2-2"),
      CA.SPE.oid(:"id-spe-au-2-3"),
      CA.SPE.oid(:"id-spe-au-2-4"),
      CA.SPE.oid(:"id-spe-au-3"),
      CA.SPE.oid(:"id-spe-au-3-1"),
      CA.SPE.oid(:"id-spe-au-3-2"),
      CA.SPE.oid(:"id-spe-au-3-3"),
      CA.SPE.oid(:"id-spe-au-4"),
      CA.SPE.oid(:"id-spe-au-4-1"),
      CA.SPE.oid(:"id-spe-au-5"),
      CA.SPE.oid(:"id-spe-au-5-1"),
      CA.SPE.oid(:"id-spe-au-5-2"),
      CA.SPE.oid(:"id-spe-au-5-3"),
      CA.SPE.oid(:"id-spe-au-5-4"),
      CA.SPE.oid(:"id-spe-au-5-5"),
      CA.SPE.oid(:"id-spe-au-6"),
      CA.SPE.oid(:"id-spe-au-6-1"),
      CA.SPE.oid(:"id-spe-au-6-2"),
      CA.SPE.oid(:"id-spe-au-6-3"),
      CA.SPE.oid(:"id-spe-au-6-4"),
      CA.SPE.oid(:"id-spe-au-6-5"),
      CA.SPE.oid(:"id-spe-au-6-6"),
      CA.SPE.oid(:"id-spe-au-6-7"),
      CA.SPE.oid(:"id-spe-au-6-8"),
      CA.SPE.oid(:"id-spe-au-6-10"),
      CA.SPE.oid(:"id-spe-au-7"),
      CA.SPE.oid(:"id-spe-au-7-1"),
      CA.SPE.oid(:"id-spe-au-7-2"),
      CA.SPE.oid(:"id-spe-au-8"),
      CA.SPE.oid(:"id-spe-au-8-1"),
      CA.SPE.oid(:"id-spe-au-8-2"),
      CA.SPE.oid(:"id-spe-au-9"),
      CA.SPE.oid(:"id-spe-au-9-1"),
      CA.SPE.oid(:"id-spe-au-9-2"),
      CA.SPE.oid(:"id-spe-au-9-3"),
      CA.SPE.oid(:"id-spe-au-9-4"),
      CA.SPE.oid(:"id-spe-au-9-5"),
      CA.SPE.oid(:"id-spe-au-9-6"),
      CA.SPE.oid(:"id-spe-au-9-7"),
      CA.SPE.oid(:"id-spe-au-10"),
      CA.SPE.oid(:"id-spe-au-10-1"),
      CA.SPE.oid(:"id-spe-au-10-2"),
      CA.SPE.oid(:"id-spe-au-10-3"),
      CA.SPE.oid(:"id-spe-au-10-4"),
      CA.SPE.oid(:"id-spe-au-10-5"),
      CA.SPE.oid(:"id-spe-au-11"),
      CA.SPE.oid(:"id-spe-au-11-1"),
      CA.SPE.oid(:"id-spe-au-12"),
      CA.SPE.oid(:"id-spe-au-12-1"),
      CA.SPE.oid(:"id-spe-au-12-2"),
      CA.SPE.oid(:"id-spe-au-12-3"),
      CA.SPE.oid(:"id-spe-au-12-4"),
      CA.SPE.oid(:"id-spe-au-13"),
      CA.SPE.oid(:"id-spe-au-13-1"),
      CA.SPE.oid(:"id-spe-au-13-2"),
      CA.SPE.oid(:"id-spe-au-13-3"),
      CA.SPE.oid(:"id-spe-au-14"),
      CA.SPE.oid(:"id-spe-au-14-1"),
      CA.SPE.oid(:"id-spe-au-14-2"),
      CA.SPE.oid(:"id-spe-au-14-3"),
      CA.SPE.oid(:"id-spe-au-15"),
      CA.SPE.oid(:"id-spe-au-16"),
      CA.SPE.oid(:"id-spe-au-16-1"),
      CA.SPE.oid(:"id-spe-au-16-2"),
      CA.SPE.oid(:"id-spe-au-16-3"),
      CA.SPE.oid(:"id-spe-ca-1"),
      CA.SPE.oid(:"id-spe-ca-2"),
      CA.SPE.oid(:"id-spe-ca-2-1"),
      CA.SPE.oid(:"id-spe-ca-2-2"),
      CA.SPE.oid(:"id-spe-ca-2-3"),
      CA.SPE.oid(:"id-spe-ca-3"),
      CA.SPE.oid(:"id-spe-ca-3-1"),
      CA.SPE.oid(:"id-spe-ca-3-2"),
      CA.SPE.oid(:"id-spe-ca-3-3"),
      CA.SPE.oid(:"id-spe-ca-3-4"),
      CA.SPE.oid(:"id-spe-ca-3-5"),
      CA.SPE.oid(:"id-spe-ca-3-6"),
      CA.SPE.oid(:"id-spe-ca-3-7"),
      CA.SPE.oid(:"id-spe-ca-4"),
      CA.SPE.oid(:"id-spe-ca-5"),
      CA.SPE.oid(:"id-spe-ca-5-1"),
      CA.SPE.oid(:"id-spe-ca-6"),
      CA.SPE.oid(:"id-spe-ca-6-1"),
      CA.SPE.oid(:"id-spe-ca-6-2"),
      CA.SPE.oid(:"id-spe-ca-7"),
      CA.SPE.oid(:"id-spe-ca-7-1"),
      CA.SPE.oid(:"id-spe-ca-7-2"),
      CA.SPE.oid(:"id-spe-ca-7-3"),
      CA.SPE.oid(:"id-spe-ca-7-4"),
      CA.SPE.oid(:"id-spe-ca-7-5"),
      CA.SPE.oid(:"id-spe-ca-7-6"),
      CA.SPE.oid(:"id-spe-ca-8"),
      CA.SPE.oid(:"id-spe-ca-8-1"),
      CA.SPE.oid(:"id-spe-ca-8-2"),
      CA.SPE.oid(:"id-spe-ca-8-3"),
      CA.SPE.oid(:"id-spe-ca-9"),
      CA.SPE.oid(:"id-spe-cm-1"),
      CA.SPE.oid(:"id-spe-cm-2"),
      CA.SPE.oid(:"id-spe-cm-2-1"),
      CA.SPE.oid(:"id-spe-cm-2-2"),
      CA.SPE.oid(:"id-spe-cm-2-3"),
      CA.SPE.oid(:"id-spe-cm-2-4"),
      CA.SPE.oid(:"id-spe-cm-2-5"),
      CA.SPE.oid(:"id-spe-cm-2-6"),
      CA.SPE.oid(:"id-spe-cm-2-7"),
      CA.SPE.oid(:"id-spe-cm-3"),
      CA.SPE.oid(:"id-spe-cm-3-1"),
      CA.SPE.oid(:"id-spe-cm-3-2"),
      CA.SPE.oid(:"id-spe-cm-3-3"),
      CA.SPE.oid(:"id-spe-cm-3-4"),
      CA.SPE.oid(:"id-spe-cm-3-5"),
      CA.SPE.oid(:"id-spe-cm-3-6"),
      CA.SPE.oid(:"id-spe-cm-3-7"),
      CA.SPE.oid(:"id-spe-cm-3-8"),
      CA.SPE.oid(:"id-spe-cm-4"),
      CA.SPE.oid(:"id-spe-cm-4-1"),
      CA.SPE.oid(:"id-spe-cm-4-2"),
      CA.SPE.oid(:"id-spe-cm-5"),
      CA.SPE.oid(:"id-spe-cm-5-1"),
      CA.SPE.oid(:"id-spe-cm-5-2"),
      CA.SPE.oid(:"id-spe-cm-5-3"),
      CA.SPE.oid(:"id-spe-cm-5-4"),
      CA.SPE.oid(:"id-spe-cm-5-5"),
      CA.SPE.oid(:"id-spe-cm-5-6"),
      CA.SPE.oid(:"id-spe-cm-5-7"),
      CA.SPE.oid(:"id-spe-cm-6"),
      CA.SPE.oid(:"id-spe-cm-6-1"),
      CA.SPE.oid(:"id-spe-cm-6-2"),
      CA.SPE.oid(:"id-spe-cm-6-4"),
      CA.SPE.oid(:"id-spe-cm-7"),
      CA.SPE.oid(:"id-spe-cm-7-1"),
      CA.SPE.oid(:"id-spe-cm-7-2"),
      CA.SPE.oid(:"id-spe-cm-7-3"),
      CA.SPE.oid(:"id-spe-cm-7-4"),
      CA.SPE.oid(:"id-spe-cm-7-5"),
      CA.SPE.oid(:"id-spe-cm-7-6"),
      CA.SPE.oid(:"id-spe-cm-7-7"),
      CA.SPE.oid(:"id-spe-cm-7-8"),
      CA.SPE.oid(:"id-spe-cm-7-9"),
      CA.SPE.oid(:"id-spe-cm-8"),
      CA.SPE.oid(:"id-spe-cm-8-1"),
      CA.SPE.oid(:"id-spe-cm-8-2"),
      CA.SPE.oid(:"id-spe-cm-8-3"),
      CA.SPE.oid(:"id-spe-cm-8-4"),
      CA.SPE.oid(:"id-spe-cm-8-5"),
      CA.SPE.oid(:"id-spe-cm-8-6"),
      CA.SPE.oid(:"id-spe-cm-8-7"),
      CA.SPE.oid(:"id-spe-cm-8-8"),
      CA.SPE.oid(:"id-spe-cm-8-9"),
      CA.SPE.oid(:"id-spe-cm-9"),
      CA.SPE.oid(:"id-spe-cm-9-1"),
      CA.SPE.oid(:"id-spe-cm-10"),
      CA.SPE.oid(:"id-spe-cm-10-1"),
      CA.SPE.oid(:"id-spe-cm-11"),
      CA.SPE.oid(:"id-spe-cm-11-1"),
      CA.SPE.oid(:"id-spe-cm-11-2"),
      CA.SPE.oid(:"id-spe-cm-11-3"),
      CA.SPE.oid(:"id-spe-cm-12"),
      CA.SPE.oid(:"id-spe-cm-12-1"),
      CA.SPE.oid(:"id-spe-cm-13"),
      CA.SPE.oid(:"id-spe-cm-14"),
      CA.SPE.oid(:"id-spe-cp-1"),
      CA.SPE.oid(:"id-spe-cp-2"),
      CA.SPE.oid(:"id-spe-cp-2-1"),
      CA.SPE.oid(:"id-spe-cp-3"),
      CA.SPE.oid(:"id-spe-cp-4"),
      CA.SPE.oid(:"id-spe-cp-4-2"),
      CA.SPE.oid(:"id-spe-cp-4-3"),
      CA.SPE.oid(:"id-spe-cp-4-4"),
      CA.SPE.oid(:"id-spe-cp-4-5"),
      CA.SPE.oid(:"id-spe-cp-5"),
      CA.SPE.oid(:"id-spe-cp-6"),
      CA.SPE.oid(:"id-spe-cp-6-1"),
      CA.SPE.oid(:"id-spe-cp-6-2"),
      CA.SPE.oid(:"id-spe-cp-6-3"),
      CA.SPE.oid(:"id-spe-cp-7"),
      CA.SPE.oid(:"id-spe-cp-7-1"),
      CA.SPE.oid(:"id-spe-cp-7-2"),
      CA.SPE.oid(:"id-spe-cp-7-3"),
      CA.SPE.oid(:"id-spe-cp-7-4"),
      CA.SPE.oid(:"id-spe-cp-7-6"),
      CA.SPE.oid(:"id-spe-cp-8"),
      CA.SPE.oid(:"id-spe-cp-8-1"),
      CA.SPE.oid(:"id-spe-cp-8-2"),
      CA.SPE.oid(:"id-spe-cp-8-3"),
      CA.SPE.oid(:"id-spe-cp-8-4"),
      CA.SPE.oid(:"id-spe-cp-8-5"),
      CA.SPE.oid(:"id-spe-cp-9"),
      CA.SPE.oid(:"id-spe-cp-9-1"),
      CA.SPE.oid(:"id-spe-cp-9-2"),
      CA.SPE.oid(:"id-spe-cp-9-3"),
      CA.SPE.oid(:"id-spe-cp-9-5"),
      CA.SPE.oid(:"id-spe-cp-9-6"),
      CA.SPE.oid(:"id-spe-cp-9-7"),
      CA.SPE.oid(:"id-spe-cp-9-8"),
      CA.SPE.oid(:"id-spe-cp-10"),
      CA.SPE.oid(:"id-spe-cp-10-2"),
      CA.SPE.oid(:"id-spe-cp-10-4"),
      CA.SPE.oid(:"id-spe-cp-10-5"),
      CA.SPE.oid(:"id-spe-cp-11"),
      CA.SPE.oid(:"id-spe-cp-12"),
      CA.SPE.oid(:"id-spe-cp-13"),
      CA.SPE.oid(:"id-spe-ia-1"),
      CA.SPE.oid(:"id-spe-ia-2"),
      CA.SPE.oid(:"id-spe-ia-2-1"),
      CA.SPE.oid(:"id-spe-ia-2-2"),
      CA.SPE.oid(:"id-spe-ia-2-3"),
      CA.SPE.oid(:"id-spe-ia-2-4"),
      CA.SPE.oid(:"id-spe-ia-2-5"),
      CA.SPE.oid(:"id-spe-ia-2-7"),
      CA.SPE.oid(:"id-spe-ia-2-8"),
      CA.SPE.oid(:"id-spe-ia-2-9"),
      CA.SPE.oid(:"id-spe-ia-2-10"),
      CA.SPE.oid(:"id-spe-ia-2-11"),
      CA.SPE.oid(:"id-spe-ia-2-12"),
      CA.SPE.oid(:"id-spe-ia-2-13"),
      CA.SPE.oid(:"id-spe-ia-3"),
      CA.SPE.oid(:"id-spe-ia-3-1"),
      CA.SPE.oid(:"id-spe-ia-3-2"),
      CA.SPE.oid(:"id-spe-ia-3-3"),
      CA.SPE.oid(:"id-spe-ia-3-4"),
      CA.SPE.oid(:"id-spe-ia-4"),
      CA.SPE.oid(:"id-spe-ia-4-1"),
      CA.SPE.oid(:"id-spe-ia-4-2"),
      CA.SPE.oid(:"id-spe-ia-4-3"),
      CA.SPE.oid(:"id-spe-ia-4-4"),
      CA.SPE.oid(:"id-spe-ia-4-5"),
      CA.SPE.oid(:"id-spe-ia-4-6"),
      CA.SPE.oid(:"id-spe-ia-4-7"),
      CA.SPE.oid(:"id-spe-ia-4-8"),
      CA.SPE.oid(:"id-spe-ia-4-9"),
      CA.SPE.oid(:"id-spe-ia-5-1"),
      CA.SPE.oid(:"id-spe-ia-5-2"),
      CA.SPE.oid(:"id-spe-ia-5-3"),
      CA.SPE.oid(:"id-spe-ia-5-4"),
      CA.SPE.oid(:"id-spe-ia-5-5"),
      CA.SPE.oid(:"id-spe-ia-5-6"),
      CA.SPE.oid(:"id-spe-ia-5-7"),
      CA.SPE.oid(:"id-spe-ia-5-8"),
      CA.SPE.oid(:"id-spe-ia-5-9"),
      CA.SPE.oid(:"id-spe-ia-5-10"),
      CA.SPE.oid(:"id-spe-ia-5-11"),
      CA.SPE.oid(:"id-spe-ia-5-12"),
      CA.SPE.oid(:"id-spe-ia-5-13"),
      CA.SPE.oid(:"id-spe-ia-5-14"),
      CA.SPE.oid(:"id-spe-ia-5-15"),
      CA.SPE.oid(:"id-spe-ia-5-16"),
      CA.SPE.oid(:"id-spe-ia-5-17"),
      CA.SPE.oid(:"id-spe-ia-5-18"),
      CA.SPE.oid(:"id-spe-ia-7"),
      CA.SPE.oid(:"id-spe-ia-8"),
      CA.SPE.oid(:"id-spe-ia-8-3"),
      CA.SPE.oid(:"id-spe-ia-8-5"),
      CA.SPE.oid(:"id-spe-ia-8-6"),
      CA.SPE.oid(:"id-spe-ia-9"),
      CA.SPE.oid(:"id-spe-ia-9-1"),
      CA.SPE.oid(:"id-spe-ia-9-2"),
      CA.SPE.oid(:"id-spe-ia-10"),
      CA.SPE.oid(:"id-spe-ia-11"),
      CA.SPE.oid(:"id-spe-ia-12"),
      CA.SPE.oid(:"id-spe-ia-12-1"),
      CA.SPE.oid(:"id-spe-ia-12-2"),
      CA.SPE.oid(:"id-spe-ia-12-4"),
      CA.SPE.oid(:"id-spe-ia-12-5"),
      CA.SPE.oid(:"id-spe-ia-12-6"),
      CA.SPE.oid(:"id-spe-ir-1"),
      CA.SPE.oid(:"id-spe-ir-2"),
      CA.SPE.oid(:"id-spe-ir-2-1"),
      CA.SPE.oid(:"id-spe-ir-2-3"),
      CA.SPE.oid(:"id-spe-ir-3"),
      CA.SPE.oid(:"id-spe-ir-3-2"),
      CA.SPE.oid(:"id-spe-ir-3-3"),
      CA.SPE.oid(:"id-spe-ir-4"),
      CA.SPE.oid(:"id-spe-ir-4-2"),
      CA.SPE.oid(:"id-spe-ir-4-3"),
      CA.SPE.oid(:"id-spe-ir-4-4"),
      CA.SPE.oid(:"id-spe-ir-4-6"),
      CA.SPE.oid(:"id-spe-ir-4-8"),
      CA.SPE.oid(:"id-spe-ir-4-9"),
      CA.SPE.oid(:"id-spe-ir-4-10"),
      CA.SPE.oid(:"id-spe-ir-4-11"),
      CA.SPE.oid(:"id-spe-ir-4-12"),
      CA.SPE.oid(:"id-spe-ir-4-13"),
      CA.SPE.oid(:"id-spe-ir-4-14"),
      CA.SPE.oid(:"id-spe-ir-4-15"),
      CA.SPE.oid(:"id-spe-ir-5"),
      CA.SPE.oid(:"id-spe-ir-5-1"),
      CA.SPE.oid(:"id-spe-ir-6"),
      CA.SPE.oid(:"id-spe-ir-6-1"),
      CA.SPE.oid(:"id-spe-ir-6-3"),
      CA.SPE.oid(:"id-spe-ir-7"),
      CA.SPE.oid(:"id-spe-ir-7-1"),
      CA.SPE.oid(:"id-spe-ir-7-2"),
      CA.SPE.oid(:"id-spe-ir-8"),
      CA.SPE.oid(:"id-spe-ir-8-1"),
      CA.SPE.oid(:"id-spe-ir-9"),
      CA.SPE.oid(:"id-spe-ir-9-1"),
      CA.SPE.oid(:"id-spe-ir-9-2"),
      CA.SPE.oid(:"id-spe-ir-9-3"),
      CA.SPE.oid(:"id-spe-ir-9-4"),
      CA.SPE.oid(:"id-spe-ir-10"),
      CA.SPE.oid(:"id-spe-ma-1"),
      CA.SPE.oid(:"id-spe-ma-2-1"),
      CA.SPE.oid(:"id-spe-ma-2-2"),
      CA.SPE.oid(:"id-spe-ma-3"),
      CA.SPE.oid(:"id-spe-ma-3-1"),
      CA.SPE.oid(:"id-spe-ma-3-2"),
      CA.SPE.oid(:"id-spe-ma-3-3"),
      CA.SPE.oid(:"id-spe-ma-3-4"),
      CA.SPE.oid(:"id-spe-ma-3-5"),
      CA.SPE.oid(:"id-spe-ma-3-6"),
      CA.SPE.oid(:"id-spe-ma-4"),
      CA.SPE.oid(:"id-spe-ma-4-1"),
      CA.SPE.oid(:"id-spe-ma-4-2"),
      CA.SPE.oid(:"id-spe-ma-4-3"),
      CA.SPE.oid(:"id-spe-ma-4-5"),
      CA.SPE.oid(:"id-spe-ma-4-7"),
      CA.SPE.oid(:"id-spe-ma-5"),
      CA.SPE.oid(:"id-spe-ma-5-1"),
      CA.SPE.oid(:"id-spe-ma-5-2"),
      CA.SPE.oid(:"id-spe-ma-5-3"),
      CA.SPE.oid(:"id-spe-ma-5-4"),
      CA.SPE.oid(:"id-spe-ma-5-5"),
      CA.SPE.oid(:"id-spe-ma-6"),
      CA.SPE.oid(:"id-spe-ma-6-1"),
      CA.SPE.oid(:"id-spe-ma-6-2"),
      CA.SPE.oid(:"id-spe-ma-6-3"),
      CA.SPE.oid(:"id-spe-ma-7"),
      CA.SPE.oid(:"id-spe-mp-1"),
      CA.SPE.oid(:"id-spe-mp-2"),
      CA.SPE.oid(:"id-spe-mp-2-1"),
      CA.SPE.oid(:"id-spe-mp-2-2"),
      CA.SPE.oid(:"id-spe-mp-3"),
      CA.SPE.oid(:"id-spe-mp-4"),
      CA.SPE.oid(:"id-spe-mp-4-1"),
      CA.SPE.oid(:"id-spe-mp-4-2"),
      CA.SPE.oid(:"id-spe-mp-5"),
      CA.SPE.oid(:"id-spe-mp-5-1"),
      CA.SPE.oid(:"id-spe-mp-5-2"),
      CA.SPE.oid(:"id-spe-mp-5-3"),
      CA.SPE.oid(:"id-spe-mp-5-4"),
      CA.SPE.oid(:"id-spe-mp-6"),
      CA.SPE.oid(:"id-spe-mp-6-1"),
      CA.SPE.oid(:"id-spe-mp-6-2"),
      CA.SPE.oid(:"id-spe-mp-6-3"),
      CA.SPE.oid(:"id-spe-mp-6-4"),
      CA.SPE.oid(:"id-spe-mp-6-5"),
      CA.SPE.oid(:"id-spe-mp-6-6"),
      CA.SPE.oid(:"id-spe-mp-6-7"),
      CA.SPE.oid(:"id-spe-mp-6-8"),
      CA.SPE.oid(:"id-spe-mp-7"),
      CA.SPE.oid(:"id-spe-mp-7-1"),
      CA.SPE.oid(:"id-spe-mp-7-2"),
      CA.SPE.oid(:"id-spe-mp-8"),
      CA.SPE.oid(:"id-spe-mp-8-1"),
      CA.SPE.oid(:"id-spe-mp-8-2"),
      CA.SPE.oid(:"id-spe-mp-8-3"),
      CA.SPE.oid(:"id-spe-mp-8-4"),
      CA.SPE.oid(:"id-spe-pe-1"),
      CA.SPE.oid(:"id-spe-pe-2"),
      CA.SPE.oid(:"id-spe-pe-3-5"),
      CA.SPE.oid(:"id-spe-pe-4"),
      CA.SPE.oid(:"id-spe-pe-6-2"),
      CA.SPE.oid(:"id-spe-pe-8-3"),
      CA.SPE.oid(:"id-spe-pe-12"),
      CA.SPE.oid(:"id-spe-pe-17"),
      CA.SPE.oid(:"id-spe-pe-18"),
      CA.SPE.oid(:"id-spe-pe-20"),
      CA.SPE.oid(:"id-spe-pe-21"),
      CA.SPE.oid(:"id-spe-pe-22"),
      CA.SPE.oid(:"id-spe-pl-1"),
      CA.SPE.oid(:"id-spe-pl-2"),
      CA.SPE.oid(:"id-spe-pl-2-1"),
      CA.SPE.oid(:"id-spe-pl-2-2"),
      CA.SPE.oid(:"id-spe-pl-3"),
      CA.SPE.oid(:"id-spe-pl-4"),
      CA.SPE.oid(:"id-spe-pl-4-1"),
      CA.SPE.oid(:"id-spe-pl-5"),
      CA.SPE.oid(:"id-spe-pl-6"),
      CA.SPE.oid(:"id-spe-pl-7"),
      CA.SPE.oid(:"id-spe-pl-8"),
      CA.SPE.oid(:"id-spe-pl-8-1"),
      CA.SPE.oid(:"id-spe-pl-8-2"),
      CA.SPE.oid(:"id-spe-pl-9"),
      CA.SPE.oid(:"id-spe-pl-10"),
      CA.SPE.oid(:"id-spe-pl-11"),
      CA.SPE.oid(:"id-spe-pm-2"),
      CA.SPE.oid(:"id-spe-pm-3"),
      CA.SPE.oid(:"id-spe-pm-5"),
      CA.SPE.oid(:"id-spe-pm-7"),
      CA.SPE.oid(:"id-spe-pm-7-1"),
      CA.SPE.oid(:"id-spe-pm-8"),
      CA.SPE.oid(:"id-spe-pm-9"),
      CA.SPE.oid(:"id-spe-pm-10"),
      CA.SPE.oid(:"id-spe-pm-11"),
      CA.SPE.oid(:"id-spe-pm-12"),
      CA.SPE.oid(:"id-spe-pm-13"),
      CA.SPE.oid(:"id-spe-pm-14"),
      CA.SPE.oid(:"id-spe-pm-15"),
      CA.SPE.oid(:"id-spe-pm-16"),
      CA.SPE.oid(:"id-spe-pm-16-1"),
      CA.SPE.oid(:"id-spe-pm-17"),
      CA.SPE.oid(:"id-spe-pm-18"),
      CA.SPE.oid(:"id-spe-pm-19"),
      CA.SPE.oid(:"id-spe-pm-20"),
      CA.SPE.oid(:"id-spe-pm-21"),
      CA.SPE.oid(:"id-spe-pm-22"),
      CA.SPE.oid(:"id-spe-pm-23"),
      CA.SPE.oid(:"id-spe-pm-24"),
      CA.SPE.oid(:"id-spe-pm-25"),
      CA.SPE.oid(:"id-spe-pm-26"),
      CA.SPE.oid(:"id-spe-pm-27"),
      CA.SPE.oid(:"id-spe-pm-28"),
      CA.SPE.oid(:"id-spe-pm-29"),
      CA.SPE.oid(:"id-spe-pm-30"),
      CA.SPE.oid(:"id-spe-pm-31"),
      CA.SPE.oid(:"id-spe-pm-32"),
      CA.SPE.oid(:"id-spe-ps-1"),
      CA.SPE.oid(:"id-spe-ps-2"),
      CA.SPE.oid(:"id-spe-ps-3"),
      CA.SPE.oid(:"id-spe-ps-4"),
      CA.SPE.oid(:"id-spe-ps-5"),
      CA.SPE.oid(:"id-spe-ps-6"),
      CA.SPE.oid(:"id-spe-ps-6-1"),
      CA.SPE.oid(:"id-spe-ps-7"),
      CA.SPE.oid(:"id-spe-ps-8"),
      CA.SPE.oid(:"id-spe-ps-9"),
      CA.SPE.oid(:"id-spe-pt-1"),
      CA.SPE.oid(:"id-spe-pt-2"),
      CA.SPE.oid(:"id-spe-pt-2-1"),
      CA.SPE.oid(:"id-spe-pt-2-2"),
      CA.SPE.oid(:"id-spe-pt-3"),
      CA.SPE.oid(:"id-spe-pt-3-1"),
      CA.SPE.oid(:"id-spe-pt-3-2"),
      CA.SPE.oid(:"id-spe-pt-4"),
      CA.SPE.oid(:"id-spe-pt-4-1"),
      CA.SPE.oid(:"id-spe-pt-4-2"),
      CA.SPE.oid(:"id-spe-pt-4-3"),
      CA.SPE.oid(:"id-spe-pt-5"),
      CA.SPE.oid(:"id-spe-pt-5-1"),
      CA.SPE.oid(:"id-spe-pt-5-2"),
      CA.SPE.oid(:"id-spe-pt-6"),
      CA.SPE.oid(:"id-spe-pt-6-1"),
      CA.SPE.oid(:"id-spe-pt-6-2"),
      CA.SPE.oid(:"id-spe-pt-7"),
      CA.SPE.oid(:"id-spe-pt-7-1"),
      CA.SPE.oid(:"id-spe-pt-7-2"),
      CA.SPE.oid(:"id-spe-pt-8"),
      CA.SPE.oid(:"id-spe-ra-1"),
      CA.SPE.oid(:"id-spe-ra-2"),
      CA.SPE.oid(:"id-spe-ra-2-1"),
      CA.SPE.oid(:"id-spe-ra-3"),
      CA.SPE.oid(:"id-spe-ra-3-1"),
      CA.SPE.oid(:"id-spe-ra-3-2"),
      CA.SPE.oid(:"id-spe-ra-3-3"),
      CA.SPE.oid(:"id-spe-ra-3-4"),
      CA.SPE.oid(:"id-spe-ra-4"),
      CA.SPE.oid(:"id-spe-ra-5"),
      CA.SPE.oid(:"id-spe-ra-5-1"),
      CA.SPE.oid(:"id-spe-ra-5-2"),
      CA.SPE.oid(:"id-spe-ra-5-3"),
      CA.SPE.oid(:"id-spe-ra-5-4"),
      CA.SPE.oid(:"id-spe-ra-5-5"),
      CA.SPE.oid(:"id-spe-ra-5-6"),
      CA.SPE.oid(:"id-spe-ra-5-7"),
      CA.SPE.oid(:"id-spe-ra-5-8"),
      CA.SPE.oid(:"id-spe-ra-5-9"),
      CA.SPE.oid(:"id-spe-ra-6"),
      CA.SPE.oid(:"id-spe-ra-7"),
      CA.SPE.oid(:"id-spe-ra-8"),
      CA.SPE.oid(:"id-spe-ra-9"),
      CA.SPE.oid(:"id-spe-ra-10"),
      CA.SPE.oid(:"id-spe-sa-1"),
      CA.SPE.oid(:"id-spe-sa-2"),
      CA.SPE.oid(:"id-spe-sa-3"),
      CA.SPE.oid(:"id-spe-sa-3-1"),
      CA.SPE.oid(:"id-spe-sa-3-2"),
      CA.SPE.oid(:"id-spe-sa-3-3"),
      CA.SPE.oid(:"id-spe-sa-4"),
      CA.SPE.oid(:"id-spe-sa-4-1"),
      CA.SPE.oid(:"id-spe-sa-4-2"),
      CA.SPE.oid(:"id-spe-sa-4-3"),
      CA.SPE.oid(:"id-spe-sa-4-4"),
      CA.SPE.oid(:"id-spe-sa-4-5"),
      CA.SPE.oid(:"id-spe-sa-4-6"),
      CA.SPE.oid(:"id-spe-sa-4-7"),
      CA.SPE.oid(:"id-spe-sa-4-8"),
      CA.SPE.oid(:"id-spe-sa-4-9"),
      CA.SPE.oid(:"id-spe-sa-5"),
      CA.SPE.oid(:"id-spe-sa-5-1"),
      CA.SPE.oid(:"id-spe-sa-5-2"),
      CA.SPE.oid(:"id-spe-sa-5-3"),
      CA.SPE.oid(:"id-spe-sa-5-4"),
      CA.SPE.oid(:"id-spe-sa-5-5"),
      CA.SPE.oid(:"id-spe-sa-6"),
      CA.SPE.oid(:"id-spe-sa-7"),
      CA.SPE.oid(:"id-spe-sa-8"),
      CA.SPE.oid(:"id-spe-sa-8-1"),
      CA.SPE.oid(:"id-spe-sa-8-2"),
      CA.SPE.oid(:"id-spe-sa-8-3"),
      CA.SPE.oid(:"id-spe-sa-8-4"),
      CA.SPE.oid(:"id-spe-sa-8-5"),
      CA.SPE.oid(:"id-spe-sa-8-6"),
      CA.SPE.oid(:"id-spe-sa-8-7"),
      CA.SPE.oid(:"id-spe-sa-8-8"),
      CA.SPE.oid(:"id-spe-sa-8-9"),
      CA.SPE.oid(:"id-spe-sa-8-10"),
      CA.SPE.oid(:"id-spe-sa-8-11"),
      CA.SPE.oid(:"id-spe-sa-8-12"),
      CA.SPE.oid(:"id-spe-sa-8-13"),
      CA.SPE.oid(:"id-spe-sa-8-14"),
      CA.SPE.oid(:"id-spe-sa-8-15"),
      CA.SPE.oid(:"id-spe-sa-8-16"),
      CA.SPE.oid(:"id-spe-sa-8-17"),
      CA.SPE.oid(:"id-spe-sa-8-18"),
      CA.SPE.oid(:"id-spe-sa-8-19"),
      CA.SPE.oid(:"id-spe-sa-8-20"),
      CA.SPE.oid(:"id-spe-sa-8-21"),
      CA.SPE.oid(:"id-spe-sa-8-23"),
      CA.SPE.oid(:"id-spe-sa-8-25"),
      CA.SPE.oid(:"id-spe-sa-8-26"),
      CA.SPE.oid(:"id-spe-sa-8-27"),
      CA.SPE.oid(:"id-spe-sa-8-28"),
      CA.SPE.oid(:"id-spe-sa-8-31"),
      CA.SPE.oid(:"id-spe-sa-8-32"),
      CA.SPE.oid(:"id-spe-sa-8-33"),
      CA.SPE.oid(:"id-spe-sa-9"),
      CA.SPE.oid(:"id-spe-sa-9-1"),
      CA.SPE.oid(:"id-spe-sa-9-2"),
      CA.SPE.oid(:"id-spe-sa-9-3"),
      CA.SPE.oid(:"id-spe-sa-9-4"),
      CA.SPE.oid(:"id-spe-sa-9-5"),
      CA.SPE.oid(:"id-spe-sa-9-6"),
      CA.SPE.oid(:"id-spe-sa-9-7"),
      CA.SPE.oid(:"id-spe-sa-9-8"),
      CA.SPE.oid(:"id-spe-sa-10"),
      CA.SPE.oid(:"id-spe-sa-10-1"),
      CA.SPE.oid(:"id-spe-sa-10-6"),
      CA.SPE.oid(:"id-spe-sa-11"),
      CA.SPE.oid(:"id-spe-sa-11-2"),
      CA.SPE.oid(:"id-spe-sa-11-3"),
      CA.SPE.oid(:"id-spe-sa-11-5"),
      CA.SPE.oid(:"id-spe-sa-11-7"),
      CA.SPE.oid(:"id-spe-sa-11-8"),
      CA.SPE.oid(:"id-spe-sa-12"),
      CA.SPE.oid(:"id-spe-sa-13"),
      CA.SPE.oid(:"id-spe-sa-14"),
      CA.SPE.oid(:"id-spe-sa-15"),
      CA.SPE.oid(:"id-spe-sa-15-5"),
      CA.SPE.oid(:"id-spe-sa-15-6"),
      CA.SPE.oid(:"id-spe-sa-15-7"),
      CA.SPE.oid(:"id-spe-sa-15-8"),
      CA.SPE.oid(:"id-spe-sa-15-9"),
      CA.SPE.oid(:"id-spe-sa-16"),
      CA.SPE.oid(:"id-spe-sa-17"),
      CA.SPE.oid(:"id-spe-sa-17-1"),
      CA.SPE.oid(:"id-spe-sa-17-2"),
      CA.SPE.oid(:"id-spe-sa-17-3"),
      CA.SPE.oid(:"id-spe-sa-17-4"),
      CA.SPE.oid(:"id-spe-sa-18"),
      CA.SPE.oid(:"id-spe-sa-19"),
      CA.SPE.oid(:"id-spe-sa-20"),
      CA.SPE.oid(:"id-spe-sa-21"),
      CA.SPE.oid(:"id-spe-sa-22"),
      CA.SPE.oid(:"id-spe-sa-23"),
      CA.SPE.oid(:"id-spe-sc-1"),
      CA.SPE.oid(:"id-spe-sc-2"),
      CA.SPE.oid(:"id-spe-sc-2-1"),
      CA.SPE.oid(:"id-spe-sc-2-2"),
      CA.SPE.oid(:"id-spe-sc-3"),
      CA.SPE.oid(:"id-spe-sc-3-1"),
      CA.SPE.oid(:"id-spe-sc-3-2"),
      CA.SPE.oid(:"id-spe-sc-3-3"),
      CA.SPE.oid(:"id-spe-sc-3-4"),
      CA.SPE.oid(:"id-spe-sc-3-5"),
      CA.SPE.oid(:"id-spe-sc-4"),
      CA.SPE.oid(:"id-spe-sc-4-1"),
      CA.SPE.oid(:"id-spe-sc-4-2"),
      CA.SPE.oid(:"id-spe-sc-5"),
      CA.SPE.oid(:"id-spe-sc-5-1"),
      CA.SPE.oid(:"id-spe-sc-5-2"),
      CA.SPE.oid(:"id-spe-sc-5-3"),
      CA.SPE.oid(:"id-spe-sc-6"),
      CA.SPE.oid(:"id-spe-sc-7"),
      CA.SPE.oid(:"id-spe-sc-7-1"),
      CA.SPE.oid(:"id-spe-sc-7-2"),
      CA.SPE.oid(:"id-spe-sc-7-3"),
      CA.SPE.oid(:"id-spe-sc-7-4"),
      CA.SPE.oid(:"id-spe-sc-7-5"),
      CA.SPE.oid(:"id-spe-sc-7-6"),
      CA.SPE.oid(:"id-spe-sc-7-7"),
      CA.SPE.oid(:"id-spe-sc-7-8"),
      CA.SPE.oid(:"id-spe-sc-7-9"),
      CA.SPE.oid(:"id-spe-sc-7-13"),
      CA.SPE.oid(:"id-spe-sc-8"),
      CA.SPE.oid(:"id-spe-sc-8-1"),
      CA.SPE.oid(:"id-spe-sc-8-2"),
      CA.SPE.oid(:"id-spe-sc-8-3"),
      CA.SPE.oid(:"id-spe-sc-8-4"),
      CA.SPE.oid(:"id-spe-sc-8-5"),
      CA.SPE.oid(:"id-spe-sc-9"),
      CA.SPE.oid(:"id-spe-sc-10"),
      CA.SPE.oid(:"id-spe-sc-11"),
      CA.SPE.oid(:"id-spe-sc-12"),
      CA.SPE.oid(:"id-spe-sc-13"),
      CA.SPE.oid(:"id-spe-sc-14"),
      CA.SPE.oid(:"id-spe-sc-15"),
      CA.SPE.oid(:"id-spe-sc-16"),
      CA.SPE.oid(:"id-spe-sc-17"),
      CA.SPE.oid(:"id-spe-sc-18"),
      CA.SPE.oid(:"id-spe-sc-19"),
      CA.SPE.oid(:"id-spe-sc-20"),
      CA.SPE.oid(:"id-spe-sc-21"),
      CA.SPE.oid(:"id-spe-sc-22"),
      CA.SPE.oid(:"id-spe-sc-23"),
      CA.SPE.oid(:"id-spe-sc-24"),
      CA.SPE.oid(:"id-spe-sc-25"),
      CA.SPE.oid(:"id-spe-sc-26"),
      CA.SPE.oid(:"id-spe-sc-27"),
      CA.SPE.oid(:"id-spe-sc-28"),
      CA.SPE.oid(:"id-spe-sc-29"),
      CA.SPE.oid(:"id-spe-sc-30"),
      CA.SPE.oid(:"id-spe-sc-31"),
      CA.SPE.oid(:"id-spe-sc-32"),
      CA.SPE.oid(:"id-spe-sc-33"),
      CA.SPE.oid(:"id-spe-sc-34"),
      CA.SPE.oid(:"id-spe-sc-35"),
      CA.SPE.oid(:"id-spe-sc-36"),
      CA.SPE.oid(:"id-spe-sc-37"),
      CA.SPE.oid(:"id-spe-sc-38"),
      CA.SPE.oid(:"id-spe-sc-39"),
      CA.SPE.oid(:"id-spe-sc-40"),
      CA.SPE.oid(:"id-spe-sc-41"),
      CA.SPE.oid(:"id-spe-sc-42"),
      CA.SPE.oid(:"id-spe-sc-43"),
      CA.SPE.oid(:"id-spe-sc-44"),
      CA.SPE.oid(:"id-spe-sc-45"),
      CA.SPE.oid(:"id-spe-sc-46"),
      CA.SPE.oid(:"id-spe-sc-47"),
      CA.SPE.oid(:"id-spe-sc-48"),
      CA.SPE.oid(:"id-spe-sc-48-1"),
      CA.SPE.oid(:"id-spe-sc-49"),
      CA.SPE.oid(:"id-spe-sc-50"),
      CA.SPE.oid(:"id-spe-sc-51"),
      CA.SPE.oid(:"id-spe-si-1"),
      CA.SPE.oid(:"id-spe-si-2"),
      CA.SPE.oid(:"id-spe-si-2-1"),
      CA.SPE.oid(:"id-spe-si-2-2"),
      CA.SPE.oid(:"id-spe-si-2-3"),
      CA.SPE.oid(:"id-spe-si-2-4"),
      CA.SPE.oid(:"id-spe-si-2-5"),
      CA.SPE.oid(:"id-spe-si-2-6"),
      CA.SPE.oid(:"id-spe-si-3"),
      CA.SPE.oid(:"id-spe-si-3-1"),
      CA.SPE.oid(:"id-spe-si-3-2"),
      CA.SPE.oid(:"id-spe-si-3-3"),
      CA.SPE.oid(:"id-spe-si-3-4"),
      CA.SPE.oid(:"id-spe-si-3-5"),
      CA.SPE.oid(:"id-spe-si-3-6"),
      CA.SPE.oid(:"id-spe-si-3-7"),
      CA.SPE.oid(:"id-spe-si-3-8"),
      CA.SPE.oid(:"id-spe-si-3-9"),
      CA.SPE.oid(:"id-spe-si-3-10"),
      CA.SPE.oid(:"id-spe-si-4"),
      CA.SPE.oid(:"id-spe-si-4-1"),
      CA.SPE.oid(:"id-spe-si-4-2"),
      CA.SPE.oid(:"id-spe-si-4-3"),
      CA.SPE.oid(:"id-spe-si-4-4"),
      CA.SPE.oid(:"id-spe-si-4-5"),
      CA.SPE.oid(:"id-spe-si-4-6"),
      CA.SPE.oid(:"id-spe-si-4-7"),
      CA.SPE.oid(:"id-spe-si-4-8"),
      CA.SPE.oid(:"id-spe-si-4-9"),
      CA.SPE.oid(:"id-spe-si-4-10"),
      CA.SPE.oid(:"id-spe-si-4-11"),
      CA.SPE.oid(:"id-spe-si-4-12"),
      CA.SPE.oid(:"id-spe-si-4-13"),
      CA.SPE.oid(:"id-spe-si-4-14"),
      CA.SPE.oid(:"id-spe-si-4-15"),
      CA.SPE.oid(:"id-spe-si-4-16"),
      CA.SPE.oid(:"id-spe-si-4-17"),
      CA.SPE.oid(:"id-spe-si-4-18"),
      CA.SPE.oid(:"id-spe-si-4-19"),
      CA.SPE.oid(:"id-spe-si-4-20"),
      CA.SPE.oid(:"id-spe-si-4-21"),
      CA.SPE.oid(:"id-spe-si-4-22"),
      CA.SPE.oid(:"id-spe-si-4-23"),
      CA.SPE.oid(:"id-spe-si-4-24"),
      CA.SPE.oid(:"id-spe-si-4-25"),
      CA.SPE.oid(:"id-spe-si-5"),
      CA.SPE.oid(:"id-spe-si-5-1"),
      CA.SPE.oid(:"id-spe-si-6"),
      CA.SPE.oid(:"id-spe-si-6-1"),
      CA.SPE.oid(:"id-spe-si-6-2"),
      CA.SPE.oid(:"id-spe-si-6-3"),
      CA.SPE.oid(:"id-spe-si-7"),
      CA.SPE.oid(:"id-spe-si-7-1"),
      CA.SPE.oid(:"id-spe-si-7-2"),
      CA.SPE.oid(:"id-spe-si-7-3"),
      CA.SPE.oid(:"id-spe-si-7-4"),
      CA.SPE.oid(:"id-spe-si-7-5"),
      CA.SPE.oid(:"id-spe-si-7-6"),
      CA.SPE.oid(:"id-spe-si-7-7"),
      CA.SPE.oid(:"id-spe-si-7-8"),
      CA.SPE.oid(:"id-spe-si-7-9"),
      CA.SPE.oid(:"id-spe-si-7-10"),
      CA.SPE.oid(:"id-spe-si-7-11"),
      CA.SPE.oid(:"id-spe-si-7-12"),
      CA.SPE.oid(:"id-spe-si-7-13"),
      CA.SPE.oid(:"id-spe-si-7-14"),
      CA.SPE.oid(:"id-spe-si-7-15"),
      CA.SPE.oid(:"id-spe-si-7-16"),
      CA.SPE.oid(:"id-spe-si-7-17"),
      CA.SPE.oid(:"id-spe-si-8"),
      CA.SPE.oid(:"id-spe-si-8-1"),
      CA.SPE.oid(:"id-spe-si-8-2"),
      CA.SPE.oid(:"id-spe-si-8-3"),
      CA.SPE.oid(:"id-spe-si-9"),
      CA.SPE.oid(:"id-spe-si-10"),
      CA.SPE.oid(:"id-spe-si-10-1"),
      CA.SPE.oid(:"id-spe-si-10-2"),
      CA.SPE.oid(:"id-spe-si-10-3"),
      CA.SPE.oid(:"id-spe-si-10-4"),
      CA.SPE.oid(:"id-spe-si-10-5"),
      CA.SPE.oid(:"id-spe-si-10-6"),
      CA.SPE.oid(:"id-spe-si-11"),
      CA.SPE.oid(:"id-spe-si-12"),
      CA.SPE.oid(:"id-spe-si-12-1"),
      CA.SPE.oid(:"id-spe-si-12-2"),
      CA.SPE.oid(:"id-spe-si-12-3"),
      CA.SPE.oid(:"id-spe-si-13"),
      CA.SPE.oid(:"id-spe-si-13-1"),
      CA.SPE.oid(:"id-spe-si-13-2"),
      CA.SPE.oid(:"id-spe-si-13-3"),
      CA.SPE.oid(:"id-spe-si-13-4"),
      CA.SPE.oid(:"id-spe-si-13-5"),
      CA.SPE.oid(:"id-spe-si-14"),
      CA.SPE.oid(:"id-spe-si-14-1"),
      CA.SPE.oid(:"id-spe-si-14-2"),
      CA.SPE.oid(:"id-spe-si-14-3"),
      CA.SPE.oid(:"id-spe-si-15"),
      CA.SPE.oid(:"id-spe-si-16"),
      CA.SPE.oid(:"id-spe-si-17"),
      CA.SPE.oid(:"id-spe-si-18"),
      CA.SPE.oid(:"id-spe-si-18-1"),
      CA.SPE.oid(:"id-spe-si-18-2"),
      CA.SPE.oid(:"id-spe-si-18-3"),
      CA.SPE.oid(:"id-spe-si-18-4"),
      CA.SPE.oid(:"id-spe-si-18-5"),
      CA.SPE.oid(:"id-spe-si-19"),
      CA.SPE.oid(:"id-spe-si-19-1"),
      CA.SPE.oid(:"id-spe-si-19-2"),
      CA.SPE.oid(:"id-spe-si-19-3"),
      CA.SPE.oid(:"id-spe-si-19-4"),
      CA.SPE.oid(:"id-spe-si-19-5"),
      CA.SPE.oid(:"id-spe-si-19-6"),
      CA.SPE.oid(:"id-spe-si-19-7"),
      CA.SPE.oid(:"id-spe-si-19-8"),
      CA.SPE.oid(:"id-spe-si-20"),
      CA.SPE.oid(:"id-spe-si-21"),
      CA.SPE.oid(:"id-spe-si-22"),
      CA.SPE.oid(:"id-spe-si-23"),
      CA.SPE.oid(:"id-spe-sr-1"),
      CA.SPE.oid(:"id-spe-sr-2"),
      CA.SPE.oid(:"id-spe-sr-2-1"),
      CA.SPE.oid(:"id-spe-sr-3"),
      CA.SPE.oid(:"id-spe-sr-3-1"),
      CA.SPE.oid(:"id-spe-sr-3-2"),
      CA.SPE.oid(:"id-spe-sr-3-3"),
      CA.SPE.oid(:"id-spe-sr-4"),
      CA.SPE.oid(:"id-spe-sr-4-1"),
      CA.SPE.oid(:"id-spe-sr-4-2"),
      CA.SPE.oid(:"id-spe-sr-4-3"),
      CA.SPE.oid(:"id-spe-sr-4-4"),
      CA.SPE.oid(:"id-spe-sr-5"),
      CA.SPE.oid(:"id-spe-sr-5-1"),
      CA.SPE.oid(:"id-spe-sr-5-2"),
      CA.SPE.oid(:"id-spe-sr-6"),
      CA.SPE.oid(:"id-spe-sr-6-1"),
      CA.SPE.oid(:"id-spe-sr-7"),
      CA.SPE.oid(:"id-spe-sr-8"),
      CA.SPE.oid(:"id-spe-sr-9"),
      CA.SPE.oid(:"id-spe-sr-9-1"),
      CA.SPE.oid(:"id-spe-sr-10"),
      CA.SPE.oid(:"id-spe-sr-11"),
      CA.SPE.oid(:"id-spe-sr-11-1"),
      CA.SPE.oid(:"id-spe-sr-12"),
      CA.SPE.oid(:"id-spe-at-2-2"),
      CA.SPE.oid(:"id-spe-at-2-3"),
      CA.SPE.oid(:"id-spe-ia-5"),
      CA.SPE.oid(:"id-spe-ia-6"),
      CA.SPE.oid(:"id-spe-pe-3"),
      CA.SPE.oid(:"id-spe-pe-5"),
      CA.SPE.oid(:"id-spe-pe-6"),
      CA.SPE.oid(:"id-spe-sc-28-1")
    ]
  end

  def specs do
    [
      spec(:"id-spe-ac"),
      spec(:"id-spe-at"),
      spec(:"id-spe-au"),
      spec(:"id-spe-ca"),
      spec(:"id-spe-cm"),
      spec(:"id-spe-cp"),
      spec(:"id-spe-ia"),
      spec(:"id-spe-ir"),
      spec(:"id-spe-ma"),
      spec(:"id-spe-mp"),
      spec(:"id-spe-pe"),
      spec(:"id-spe-pl"),
      spec(:"id-spe-ps"),
      spec(:"id-spe-ra"),
      spec(:"id-spe-sa"),
      spec(:"id-spe-sc"),
      spec(:"id-spe-si"),
      spec(:"id-spe-sr"),
      spec(:"id-spe-pm"),
      spec(:"id-spe-pt"),
      spec(:"id-spe-ac-1"),
      spec(:"id-spe-ac-2"),
      spec(:"id-spe-ac-2-1"),
      spec(:"id-spe-ac-2-3"),
      spec(:"id-spe-ac-2-4"),
      spec(:"id-spe-ac-2-5"),
      spec(:"id-spe-ac-2-6"),
      spec(:"id-spe-ac-2-7"),
      spec(:"id-spe-ac-2-8"),
      spec(:"id-spe-ac-2-9"),
      spec(:"id-spe-ac-2-10"),
      spec(:"id-spe-ac-2-11"),
      spec(:"id-spe-ac-2-12"),
      spec(:"id-spe-ac-2-13"),
      spec(:"id-spe-ac-3"),
      spec(:"id-spe-ac-3-1"),
      spec(:"id-spe-ac-3-2"),
      spec(:"id-spe-ac-3-3"),
      spec(:"id-spe-ac-3-4"),
      spec(:"id-spe-ac-3-5"),
      spec(:"id-spe-ac-3-6"),
      spec(:"id-spe-ac-3-7"),
      spec(:"id-spe-ac-3-8"),
      spec(:"id-spe-ac-3-9"),
      spec(:"id-spe-ac-3-10"),
      spec(:"id-spe-ac-3-11"),
      spec(:"id-spe-ac-3-12"),
      spec(:"id-spe-ac-3-13"),
      spec(:"id-spe-ac-3-14"),
      spec(:"id-spe-ac-3-15"),
      spec(:"id-spe-ac-4"),
      spec(:"id-spe-ac-4-1"),
      spec(:"id-spe-ac-4-2"),
      spec(:"id-spe-ac-4-3"),
      spec(:"id-spe-ac-4-4"),
      spec(:"id-spe-ac-4-5"),
      spec(:"id-spe-ac-4-6"),
      spec(:"id-spe-ac-4-7"),
      spec(:"id-spe-ac-4-8"),
      spec(:"id-spe-ac-4-9"),
      spec(:"id-spe-ac-4-10"),
      spec(:"id-spe-ac-4-11"),
      spec(:"id-spe-ac-4-12"),
      spec(:"id-spe-ac-4-13"),
      spec(:"id-spe-ac-4-14"),
      spec(:"id-spe-ac-4-15"),
      spec(:"id-spe-ac-4-16"),
      spec(:"id-spe-ac-4-18"),
      spec(:"id-spe-ac-4-19"),
      spec(:"id-spe-ac-4-20"),
      spec(:"id-spe-ac-4-21"),
      spec(:"id-spe-ac-4-22"),
      spec(:"id-spe-ac-4-23"),
      spec(:"id-spe-ac-4-24"),
      spec(:"id-spe-ac-4-25"),
      spec(:"id-spe-ac-4-26"),
      spec(:"id-spe-ac-4-27"),
      spec(:"id-spe-ac-4-28"),
      spec(:"id-spe-ac-4-29"),
      spec(:"id-spe-ac-4-30"),
      spec(:"id-spe-ac-4-31"),
      spec(:"id-spe-ac-4-32"),
      spec(:"id-spe-ac-5"),
      spec(:"id-spe-ac-6"),
      spec(:"id-spe-ac-6-1"),
      spec(:"id-spe-ac-6-2"),
      spec(:"id-spe-ac-6-4"),
      spec(:"id-spe-ac-6-5"),
      spec(:"id-spe-ac-6-6"),
      spec(:"id-spe-ac-6-7"),
      spec(:"id-spe-ac-6-8"),
      spec(:"id-spe-ac-6-9"),
      spec(:"id-spe-ac-6-10"),
      spec(:"id-spe-ac-7"),
      spec(:"id-spe-ac-7-1"),
      spec(:"id-spe-ac-7-2"),
      spec(:"id-spe-ac-7-3"),
      spec(:"id-spe-ac-7-4"),
      spec(:"id-spe-ac-8"),
      spec(:"id-spe-ac-9"),
      spec(:"id-spe-ac-9-1"),
      spec(:"id-spe-ac-9-2"),
      spec(:"id-spe-ac-9-3"),
      spec(:"id-spe-ac-9-4"),
      spec(:"id-spe-ac-10"),
      spec(:"id-spe-ac-11"),
      spec(:"id-spe-ac-11-1"),
      spec(:"id-spe-ac-12"),
      spec(:"id-spe-ac-12-1"),
      spec(:"id-spe-ac-12-2"),
      spec(:"id-spe-ac-12-3"),
      spec(:"id-spe-ac-13"),
      spec(:"id-spe-ac-14"),
      spec(:"id-spe-ac-14-1"),
      spec(:"id-spe-ac-15"),
      spec(:"id-spe-ac-16"),
      spec(:"id-spe-ac-16-1"),
      spec(:"id-spe-ac-16-2"),
      spec(:"id-spe-ac-16-3"),
      spec(:"id-spe-ac-16-4"),
      spec(:"id-spe-ac-16-5"),
      spec(:"id-spe-ac-16-6"),
      spec(:"id-spe-ac-16-7"),
      spec(:"id-spe-ac-16-8"),
      spec(:"id-spe-ac-16-9"),
      spec(:"id-spe-ac-16-10"),
      spec(:"id-spe-ac-17"),
      spec(:"id-spe-ac-17-1"),
      spec(:"id-spe-ac-17-2"),
      spec(:"id-spe-ac-17-3"),
      spec(:"id-spe-ac-17-4"),
      spec(:"id-spe-ac-17-5"),
      spec(:"id-spe-ac-17-6"),
      spec(:"id-spe-ac-17-7"),
      spec(:"id-spe-ac-17-8"),
      spec(:"id-spe-ac-17-9"),
      spec(:"id-spe-ac-17-10"),
      spec(:"id-spe-ac-18"),
      spec(:"id-spe-ac-18-1"),
      spec(:"id-spe-ac-18-2"),
      spec(:"id-spe-ac-18-3"),
      spec(:"id-spe-ac-18-4"),
      spec(:"id-spe-ac-18-5"),
      spec(:"id-spe-ac-19"),
      spec(:"id-spe-ac-19-1"),
      spec(:"id-spe-ac-19-2"),
      spec(:"id-spe-ac-19-3"),
      spec(:"id-spe-ac-19-4"),
      spec(:"id-spe-ac-19-5"),
      spec(:"id-spe-ac-20"),
      spec(:"id-spe-ac-20-1"),
      spec(:"id-spe-ac-20-2"),
      spec(:"id-spe-ac-20-3"),
      spec(:"id-spe-ac-20-4"),
      spec(:"id-spe-ac-20-5"),
      spec(:"id-spe-ac-21"),
      spec(:"id-spe-ac-21-1"),
      spec(:"id-spe-ac-21-2"),
      spec(:"id-spe-ac-22"),
      spec(:"id-spe-ac-23"),
      spec(:"id-spe-ac-24"),
      spec(:"id-spe-ac-24-1"),
      spec(:"id-spe-ac-24-2"),
      spec(:"id-spe-ac-25"),
      spec(:"id-spe-at-1"),
      spec(:"id-spe-at-2"),
      spec(:"id-spe-at-3"),
      spec(:"id-spe-at-3-1"),
      spec(:"id-spe-at-3-2"),
      spec(:"id-spe-at-4"),
      spec(:"id-spe-at-5"),
      spec(:"id-spe-at-6"),
      spec(:"id-spe-au-1"),
      spec(:"id-spe-au-2"),
      spec(:"id-spe-au-2-1"),
      spec(:"id-spe-au-2-2"),
      spec(:"id-spe-au-2-3"),
      spec(:"id-spe-au-2-4"),
      spec(:"id-spe-au-3"),
      spec(:"id-spe-au-3-1"),
      spec(:"id-spe-au-3-2"),
      spec(:"id-spe-au-3-3"),
      spec(:"id-spe-au-4"),
      spec(:"id-spe-au-4-1"),
      spec(:"id-spe-au-5"),
      spec(:"id-spe-au-5-1"),
      spec(:"id-spe-au-5-2"),
      spec(:"id-spe-au-5-3"),
      spec(:"id-spe-au-5-4"),
      spec(:"id-spe-au-5-5"),
      spec(:"id-spe-au-6"),
      spec(:"id-spe-au-6-1"),
      spec(:"id-spe-au-6-2"),
      spec(:"id-spe-au-6-3"),
      spec(:"id-spe-au-6-4"),
      spec(:"id-spe-au-6-5"),
      spec(:"id-spe-au-6-6"),
      spec(:"id-spe-au-6-7"),
      spec(:"id-spe-au-6-8"),
      spec(:"id-spe-au-6-10"),
      spec(:"id-spe-au-7"),
      spec(:"id-spe-au-7-1"),
      spec(:"id-spe-au-7-2"),
      spec(:"id-spe-au-8"),
      spec(:"id-spe-au-8-1"),
      spec(:"id-spe-au-8-2"),
      spec(:"id-spe-au-9"),
      spec(:"id-spe-au-9-1"),
      spec(:"id-spe-au-9-2"),
      spec(:"id-spe-au-9-3"),
      spec(:"id-spe-au-9-4"),
      spec(:"id-spe-au-9-5"),
      spec(:"id-spe-au-9-6"),
      spec(:"id-spe-au-9-7"),
      spec(:"id-spe-au-10"),
      spec(:"id-spe-au-10-1"),
      spec(:"id-spe-au-10-2"),
      spec(:"id-spe-au-10-3"),
      spec(:"id-spe-au-10-4"),
      spec(:"id-spe-au-10-5"),
      spec(:"id-spe-au-11"),
      spec(:"id-spe-au-11-1"),
      spec(:"id-spe-au-12"),
      spec(:"id-spe-au-12-1"),
      spec(:"id-spe-au-12-2"),
      spec(:"id-spe-au-12-3"),
      spec(:"id-spe-au-12-4"),
      spec(:"id-spe-au-13"),
      spec(:"id-spe-au-13-1"),
      spec(:"id-spe-au-13-2"),
      spec(:"id-spe-au-13-3"),
      spec(:"id-spe-au-14"),
      spec(:"id-spe-au-14-1"),
      spec(:"id-spe-au-14-2"),
      spec(:"id-spe-au-14-3"),
      spec(:"id-spe-au-15"),
      spec(:"id-spe-au-16"),
      spec(:"id-spe-au-16-1"),
      spec(:"id-spe-au-16-2"),
      spec(:"id-spe-au-16-3"),
      spec(:"id-spe-ca-1"),
      spec(:"id-spe-ca-2"),
      spec(:"id-spe-ca-2-1"),
      spec(:"id-spe-ca-2-2"),
      spec(:"id-spe-ca-2-3"),
      spec(:"id-spe-ca-3"),
      spec(:"id-spe-ca-3-1"),
      spec(:"id-spe-ca-3-2"),
      spec(:"id-spe-ca-3-3"),
      spec(:"id-spe-ca-3-4"),
      spec(:"id-spe-ca-3-5"),
      spec(:"id-spe-ca-3-6"),
      spec(:"id-spe-ca-3-7"),
      spec(:"id-spe-ca-4"),
      spec(:"id-spe-ca-5"),
      spec(:"id-spe-ca-5-1"),
      spec(:"id-spe-ca-6"),
      spec(:"id-spe-ca-6-1"),
      spec(:"id-spe-ca-6-2"),
      spec(:"id-spe-ca-7"),
      spec(:"id-spe-ca-7-1"),
      spec(:"id-spe-ca-7-2"),
      spec(:"id-spe-ca-7-3"),
      spec(:"id-spe-ca-7-4"),
      spec(:"id-spe-ca-7-5"),
      spec(:"id-spe-ca-7-6"),
      spec(:"id-spe-ca-8"),
      spec(:"id-spe-ca-8-1"),
      spec(:"id-spe-ca-8-2"),
      spec(:"id-spe-ca-8-3"),
      spec(:"id-spe-ca-9"),
      spec(:"id-spe-cm-1"),
      spec(:"id-spe-cm-2"),
      spec(:"id-spe-cm-2-1"),
      spec(:"id-spe-cm-2-2"),
      spec(:"id-spe-cm-2-3"),
      spec(:"id-spe-cm-2-4"),
      spec(:"id-spe-cm-2-5"),
      spec(:"id-spe-cm-2-6"),
      spec(:"id-spe-cm-2-7"),
      spec(:"id-spe-cm-3"),
      spec(:"id-spe-cm-3-1"),
      spec(:"id-spe-cm-3-2"),
      spec(:"id-spe-cm-3-3"),
      spec(:"id-spe-cm-3-4"),
      spec(:"id-spe-cm-3-5"),
      spec(:"id-spe-cm-3-6"),
      spec(:"id-spe-cm-3-7"),
      spec(:"id-spe-cm-3-8"),
      spec(:"id-spe-cm-4"),
      spec(:"id-spe-cm-4-1"),
      spec(:"id-spe-cm-4-2"),
      spec(:"id-spe-cm-5"),
      spec(:"id-spe-cm-5-1"),
      spec(:"id-spe-cm-5-2"),
      spec(:"id-spe-cm-5-3"),
      spec(:"id-spe-cm-5-4"),
      spec(:"id-spe-cm-5-5"),
      spec(:"id-spe-cm-5-6"),
      spec(:"id-spe-cm-5-7"),
      spec(:"id-spe-cm-6"),
      spec(:"id-spe-cm-6-1"),
      spec(:"id-spe-cm-6-2"),
      spec(:"id-spe-cm-6-4"),
      spec(:"id-spe-cm-7"),
      spec(:"id-spe-cm-7-1"),
      spec(:"id-spe-cm-7-2"),
      spec(:"id-spe-cm-7-3"),
      spec(:"id-spe-cm-7-4"),
      spec(:"id-spe-cm-7-5"),
      spec(:"id-spe-cm-7-6"),
      spec(:"id-spe-cm-7-7"),
      spec(:"id-spe-cm-7-8"),
      spec(:"id-spe-cm-7-9"),
      spec(:"id-spe-cm-8"),
      spec(:"id-spe-cm-8-1"),
      spec(:"id-spe-cm-8-2"),
      spec(:"id-spe-cm-8-3"),
      spec(:"id-spe-cm-8-4"),
      spec(:"id-spe-cm-8-5"),
      spec(:"id-spe-cm-8-6"),
      spec(:"id-spe-cm-8-7"),
      spec(:"id-spe-cm-8-8"),
      spec(:"id-spe-cm-8-9"),
      spec(:"id-spe-cm-9"),
      spec(:"id-spe-cm-9-1"),
      spec(:"id-spe-cm-10"),
      spec(:"id-spe-cm-10-1"),
      spec(:"id-spe-cm-11"),
      spec(:"id-spe-cm-11-1"),
      spec(:"id-spe-cm-11-2"),
      spec(:"id-spe-cm-11-3"),
      spec(:"id-spe-cm-12"),
      spec(:"id-spe-cm-12-1"),
      spec(:"id-spe-cm-13"),
      spec(:"id-spe-cm-14"),
      spec(:"id-spe-cp-1"),
      spec(:"id-spe-cp-2"),
      spec(:"id-spe-cp-2-1"),
      spec(:"id-spe-cp-3"),
      spec(:"id-spe-cp-4"),
      spec(:"id-spe-cp-4-2"),
      spec(:"id-spe-cp-4-3"),
      spec(:"id-spe-cp-4-4"),
      spec(:"id-spe-cp-4-5"),
      spec(:"id-spe-cp-5"),
      spec(:"id-spe-cp-6"),
      spec(:"id-spe-cp-6-1"),
      spec(:"id-spe-cp-6-2"),
      spec(:"id-spe-cp-6-3"),
      spec(:"id-spe-cp-7"),
      spec(:"id-spe-cp-7-1"),
      spec(:"id-spe-cp-7-2"),
      spec(:"id-spe-cp-7-3"),
      spec(:"id-spe-cp-7-4"),
      spec(:"id-spe-cp-7-6"),
      spec(:"id-spe-cp-8"),
      spec(:"id-spe-cp-8-1"),
      spec(:"id-spe-cp-8-2"),
      spec(:"id-spe-cp-8-3"),
      spec(:"id-spe-cp-8-4"),
      spec(:"id-spe-cp-8-5"),
      spec(:"id-spe-cp-9"),
      spec(:"id-spe-cp-9-1"),
      spec(:"id-spe-cp-9-2"),
      spec(:"id-spe-cp-9-3"),
      spec(:"id-spe-cp-9-5"),
      spec(:"id-spe-cp-9-6"),
      spec(:"id-spe-cp-9-7"),
      spec(:"id-spe-cp-9-8"),
      spec(:"id-spe-cp-10"),
      spec(:"id-spe-cp-10-2"),
      spec(:"id-spe-cp-10-4"),
      spec(:"id-spe-cp-10-5"),
      spec(:"id-spe-cp-11"),
      spec(:"id-spe-cp-12"),
      spec(:"id-spe-cp-13"),
      spec(:"id-spe-ia-1"),
      spec(:"id-spe-ia-2"),
      spec(:"id-spe-ia-2-1"),
      spec(:"id-spe-ia-2-2"),
      spec(:"id-spe-ia-2-3"),
      spec(:"id-spe-ia-2-4"),
      spec(:"id-spe-ia-2-5"),
      spec(:"id-spe-ia-2-7"),
      spec(:"id-spe-ia-2-8"),
      spec(:"id-spe-ia-2-9"),
      spec(:"id-spe-ia-2-10"),
      spec(:"id-spe-ia-2-11"),
      spec(:"id-spe-ia-2-12"),
      spec(:"id-spe-ia-2-13"),
      spec(:"id-spe-ia-3"),
      spec(:"id-spe-ia-3-1"),
      spec(:"id-spe-ia-3-2"),
      spec(:"id-spe-ia-3-3"),
      spec(:"id-spe-ia-3-4"),
      spec(:"id-spe-ia-4"),
      spec(:"id-spe-ia-4-1"),
      spec(:"id-spe-ia-4-2"),
      spec(:"id-spe-ia-4-3"),
      spec(:"id-spe-ia-4-4"),
      spec(:"id-spe-ia-4-5"),
      spec(:"id-spe-ia-4-6"),
      spec(:"id-spe-ia-4-7"),
      spec(:"id-spe-ia-4-8"),
      spec(:"id-spe-ia-4-9"),
      spec(:"id-spe-ia-5-1"),
      spec(:"id-spe-ia-5-2"),
      spec(:"id-spe-ia-5-3"),
      spec(:"id-spe-ia-5-4"),
      spec(:"id-spe-ia-5-5"),
      spec(:"id-spe-ia-5-6"),
      spec(:"id-spe-ia-5-7"),
      spec(:"id-spe-ia-5-8"),
      spec(:"id-spe-ia-5-9"),
      spec(:"id-spe-ia-5-10"),
      spec(:"id-spe-ia-5-11"),
      spec(:"id-spe-ia-5-12"),
      spec(:"id-spe-ia-5-13"),
      spec(:"id-spe-ia-5-14"),
      spec(:"id-spe-ia-5-15"),
      spec(:"id-spe-ia-5-16"),
      spec(:"id-spe-ia-5-17"),
      spec(:"id-spe-ia-5-18"),
      spec(:"id-spe-ia-7"),
      spec(:"id-spe-ia-8"),
      spec(:"id-spe-ia-8-3"),
      spec(:"id-spe-ia-8-5"),
      spec(:"id-spe-ia-8-6"),
      spec(:"id-spe-ia-9"),
      spec(:"id-spe-ia-9-1"),
      spec(:"id-spe-ia-9-2"),
      spec(:"id-spe-ia-10"),
      spec(:"id-spe-ia-11"),
      spec(:"id-spe-ia-12"),
      spec(:"id-spe-ia-12-1"),
      spec(:"id-spe-ia-12-2"),
      spec(:"id-spe-ia-12-4"),
      spec(:"id-spe-ia-12-5"),
      spec(:"id-spe-ia-12-6"),
      spec(:"id-spe-ir-1"),
      spec(:"id-spe-ir-2"),
      spec(:"id-spe-ir-2-1"),
      spec(:"id-spe-ir-2-3"),
      spec(:"id-spe-ir-3"),
      spec(:"id-spe-ir-3-2"),
      spec(:"id-spe-ir-3-3"),
      spec(:"id-spe-ir-4"),
      spec(:"id-spe-ir-4-2"),
      spec(:"id-spe-ir-4-3"),
      spec(:"id-spe-ir-4-4"),
      spec(:"id-spe-ir-4-6"),
      spec(:"id-spe-ir-4-8"),
      spec(:"id-spe-ir-4-9"),
      spec(:"id-spe-ir-4-10"),
      spec(:"id-spe-ir-4-11"),
      spec(:"id-spe-ir-4-12"),
      spec(:"id-spe-ir-4-13"),
      spec(:"id-spe-ir-4-14"),
      spec(:"id-spe-ir-4-15"),
      spec(:"id-spe-ir-5"),
      spec(:"id-spe-ir-5-1"),
      spec(:"id-spe-ir-6"),
      spec(:"id-spe-ir-6-1"),
      spec(:"id-spe-ir-6-3"),
      spec(:"id-spe-ir-7"),
      spec(:"id-spe-ir-7-1"),
      spec(:"id-spe-ir-7-2"),
      spec(:"id-spe-ir-8"),
      spec(:"id-spe-ir-8-1"),
      spec(:"id-spe-ir-9"),
      spec(:"id-spe-ir-9-1"),
      spec(:"id-spe-ir-9-2"),
      spec(:"id-spe-ir-9-3"),
      spec(:"id-spe-ir-9-4"),
      spec(:"id-spe-ir-10"),
      spec(:"id-spe-ma-1"),
      spec(:"id-spe-ma-2-1"),
      spec(:"id-spe-ma-2-2"),
      spec(:"id-spe-ma-3"),
      spec(:"id-spe-ma-3-1"),
      spec(:"id-spe-ma-3-2"),
      spec(:"id-spe-ma-3-3"),
      spec(:"id-spe-ma-3-4"),
      spec(:"id-spe-ma-3-5"),
      spec(:"id-spe-ma-3-6"),
      spec(:"id-spe-ma-4"),
      spec(:"id-spe-ma-4-1"),
      spec(:"id-spe-ma-4-2"),
      spec(:"id-spe-ma-4-3"),
      spec(:"id-spe-ma-4-5"),
      spec(:"id-spe-ma-4-7"),
      spec(:"id-spe-ma-5"),
      spec(:"id-spe-ma-5-1"),
      spec(:"id-spe-ma-5-2"),
      spec(:"id-spe-ma-5-3"),
      spec(:"id-spe-ma-5-4"),
      spec(:"id-spe-ma-5-5"),
      spec(:"id-spe-ma-6"),
      spec(:"id-spe-ma-6-1"),
      spec(:"id-spe-ma-6-2"),
      spec(:"id-spe-ma-6-3"),
      spec(:"id-spe-ma-7"),
      spec(:"id-spe-mp-1"),
      spec(:"id-spe-mp-2"),
      spec(:"id-spe-mp-2-1"),
      spec(:"id-spe-mp-2-2"),
      spec(:"id-spe-mp-3"),
      spec(:"id-spe-mp-4"),
      spec(:"id-spe-mp-4-1"),
      spec(:"id-spe-mp-4-2"),
      spec(:"id-spe-mp-5"),
      spec(:"id-spe-mp-5-1"),
      spec(:"id-spe-mp-5-2"),
      spec(:"id-spe-mp-5-3"),
      spec(:"id-spe-mp-5-4"),
      spec(:"id-spe-mp-6"),
      spec(:"id-spe-mp-6-1"),
      spec(:"id-spe-mp-6-2"),
      spec(:"id-spe-mp-6-3"),
      spec(:"id-spe-mp-6-4"),
      spec(:"id-spe-mp-6-5"),
      spec(:"id-spe-mp-6-6"),
      spec(:"id-spe-mp-6-7"),
      spec(:"id-spe-mp-6-8"),
      spec(:"id-spe-mp-7"),
      spec(:"id-spe-mp-7-1"),
      spec(:"id-spe-mp-7-2"),
      spec(:"id-spe-mp-8"),
      spec(:"id-spe-mp-8-1"),
      spec(:"id-spe-mp-8-2"),
      spec(:"id-spe-mp-8-3"),
      spec(:"id-spe-mp-8-4"),
      spec(:"id-spe-pe-1"),
      spec(:"id-spe-pe-2"),
      spec(:"id-spe-pe-3-5"),
      spec(:"id-spe-pe-4"),
      spec(:"id-spe-pe-6-2"),
      spec(:"id-spe-pe-8-3"),
      spec(:"id-spe-pe-12"),
      spec(:"id-spe-pe-17"),
      spec(:"id-spe-pe-18"),
      spec(:"id-spe-pe-20"),
      spec(:"id-spe-pe-21"),
      spec(:"id-spe-pe-22"),
      spec(:"id-spe-pl-1"),
      spec(:"id-spe-pl-2"),
      spec(:"id-spe-pl-2-1"),
      spec(:"id-spe-pl-2-2"),
      spec(:"id-spe-pl-3"),
      spec(:"id-spe-pl-4"),
      spec(:"id-spe-pl-4-1"),
      spec(:"id-spe-pl-5"),
      spec(:"id-spe-pl-6"),
      spec(:"id-spe-pl-7"),
      spec(:"id-spe-pl-8"),
      spec(:"id-spe-pl-8-1"),
      spec(:"id-spe-pl-8-2"),
      spec(:"id-spe-pl-9"),
      spec(:"id-spe-pl-10"),
      spec(:"id-spe-pl-11"),
      spec(:"id-spe-pm-2"),
      spec(:"id-spe-pm-3"),
      spec(:"id-spe-pm-5"),
      spec(:"id-spe-pm-7"),
      spec(:"id-spe-pm-7-1"),
      spec(:"id-spe-pm-8"),
      spec(:"id-spe-pm-9"),
      spec(:"id-spe-pm-10"),
      spec(:"id-spe-pm-11"),
      spec(:"id-spe-pm-12"),
      spec(:"id-spe-pm-13"),
      spec(:"id-spe-pm-14"),
      spec(:"id-spe-pm-15"),
      spec(:"id-spe-pm-16"),
      spec(:"id-spe-pm-16-1"),
      spec(:"id-spe-pm-17"),
      spec(:"id-spe-pm-18"),
      spec(:"id-spe-pm-19"),
      spec(:"id-spe-pm-20"),
      spec(:"id-spe-pm-21"),
      spec(:"id-spe-pm-22"),
      spec(:"id-spe-pm-23"),
      spec(:"id-spe-pm-24"),
      spec(:"id-spe-pm-25"),
      spec(:"id-spe-pm-26"),
      spec(:"id-spe-pm-27"),
      spec(:"id-spe-pm-28"),
      spec(:"id-spe-pm-29"),
      spec(:"id-spe-pm-30"),
      spec(:"id-spe-pm-31"),
      spec(:"id-spe-pm-32"),
      spec(:"id-spe-ps-1"),
      spec(:"id-spe-ps-2"),
      spec(:"id-spe-ps-3"),
      spec(:"id-spe-ps-4"),
      spec(:"id-spe-ps-5"),
      spec(:"id-spe-ps-6"),
      spec(:"id-spe-ps-6-1"),
      spec(:"id-spe-ps-7"),
      spec(:"id-spe-ps-8"),
      spec(:"id-spe-ps-9"),
      spec(:"id-spe-pt-1"),
      spec(:"id-spe-pt-2"),
      spec(:"id-spe-pt-2-1"),
      spec(:"id-spe-pt-2-2"),
      spec(:"id-spe-pt-3"),
      spec(:"id-spe-pt-3-1"),
      spec(:"id-spe-pt-3-2"),
      spec(:"id-spe-pt-4"),
      spec(:"id-spe-pt-4-1"),
      spec(:"id-spe-pt-4-2"),
      spec(:"id-spe-pt-4-3"),
      spec(:"id-spe-pt-5"),
      spec(:"id-spe-pt-5-1"),
      spec(:"id-spe-pt-5-2"),
      spec(:"id-spe-pt-6"),
      spec(:"id-spe-pt-6-1"),
      spec(:"id-spe-pt-6-2"),
      spec(:"id-spe-pt-7"),
      spec(:"id-spe-pt-7-1"),
      spec(:"id-spe-pt-7-2"),
      spec(:"id-spe-pt-8"),
      spec(:"id-spe-ra-1"),
      spec(:"id-spe-ra-2"),
      spec(:"id-spe-ra-2-1"),
      spec(:"id-spe-ra-3"),
      spec(:"id-spe-ra-3-1"),
      spec(:"id-spe-ra-3-2"),
      spec(:"id-spe-ra-3-3"),
      spec(:"id-spe-ra-3-4"),
      spec(:"id-spe-ra-4"),
      spec(:"id-spe-ra-5"),
      spec(:"id-spe-ra-5-1"),
      spec(:"id-spe-ra-5-2"),
      spec(:"id-spe-ra-5-3"),
      spec(:"id-spe-ra-5-4"),
      spec(:"id-spe-ra-5-5"),
      spec(:"id-spe-ra-5-6"),
      spec(:"id-spe-ra-5-7"),
      spec(:"id-spe-ra-5-8"),
      spec(:"id-spe-ra-5-9"),
      spec(:"id-spe-ra-6"),
      spec(:"id-spe-ra-7"),
      spec(:"id-spe-ra-8"),
      spec(:"id-spe-ra-9"),
      spec(:"id-spe-ra-10"),
      spec(:"id-spe-sa-1"),
      spec(:"id-spe-sa-2"),
      spec(:"id-spe-sa-3"),
      spec(:"id-spe-sa-3-1"),
      spec(:"id-spe-sa-3-2"),
      spec(:"id-spe-sa-3-3"),
      spec(:"id-spe-sa-4"),
      spec(:"id-spe-sa-4-1"),
      spec(:"id-spe-sa-4-2"),
      spec(:"id-spe-sa-4-3"),
      spec(:"id-spe-sa-4-4"),
      spec(:"id-spe-sa-4-5"),
      spec(:"id-spe-sa-4-6"),
      spec(:"id-spe-sa-4-7"),
      spec(:"id-spe-sa-4-8"),
      spec(:"id-spe-sa-4-9"),
      spec(:"id-spe-sa-5"),
      spec(:"id-spe-sa-5-1"),
      spec(:"id-spe-sa-5-2"),
      spec(:"id-spe-sa-5-3"),
      spec(:"id-spe-sa-5-4"),
      spec(:"id-spe-sa-5-5"),
      spec(:"id-spe-sa-6"),
      spec(:"id-spe-sa-7"),
      spec(:"id-spe-sa-8"),
      spec(:"id-spe-sa-8-1"),
      spec(:"id-spe-sa-8-2"),
      spec(:"id-spe-sa-8-3"),
      spec(:"id-spe-sa-8-4"),
      spec(:"id-spe-sa-8-5"),
      spec(:"id-spe-sa-8-6"),
      spec(:"id-spe-sa-8-7"),
      spec(:"id-spe-sa-8-8"),
      spec(:"id-spe-sa-8-9"),
      spec(:"id-spe-sa-8-10"),
      spec(:"id-spe-sa-8-11"),
      spec(:"id-spe-sa-8-12"),
      spec(:"id-spe-sa-8-13"),
      spec(:"id-spe-sa-8-14"),
      spec(:"id-spe-sa-8-15"),
      spec(:"id-spe-sa-8-16"),
      spec(:"id-spe-sa-8-17"),
      spec(:"id-spe-sa-8-18"),
      spec(:"id-spe-sa-8-19"),
      spec(:"id-spe-sa-8-20"),
      spec(:"id-spe-sa-8-21"),
      spec(:"id-spe-sa-8-23"),
      spec(:"id-spe-sa-8-25"),
      spec(:"id-spe-sa-8-26"),
      spec(:"id-spe-sa-8-27"),
      spec(:"id-spe-sa-8-28"),
      spec(:"id-spe-sa-8-31"),
      spec(:"id-spe-sa-8-32"),
      spec(:"id-spe-sa-8-33"),
      spec(:"id-spe-sa-9"),
      spec(:"id-spe-sa-9-1"),
      spec(:"id-spe-sa-9-2"),
      spec(:"id-spe-sa-9-3"),
      spec(:"id-spe-sa-9-4"),
      spec(:"id-spe-sa-9-5"),
      spec(:"id-spe-sa-9-6"),
      spec(:"id-spe-sa-9-7"),
      spec(:"id-spe-sa-9-8"),
      spec(:"id-spe-sa-10"),
      spec(:"id-spe-sa-10-1"),
      spec(:"id-spe-sa-10-6"),
      spec(:"id-spe-sa-11"),
      spec(:"id-spe-sa-11-2"),
      spec(:"id-spe-sa-11-3"),
      spec(:"id-spe-sa-11-5"),
      spec(:"id-spe-sa-11-7"),
      spec(:"id-spe-sa-11-8"),
      spec(:"id-spe-sa-12"),
      spec(:"id-spe-sa-13"),
      spec(:"id-spe-sa-14"),
      spec(:"id-spe-sa-15"),
      spec(:"id-spe-sa-15-5"),
      spec(:"id-spe-sa-15-6"),
      spec(:"id-spe-sa-15-7"),
      spec(:"id-spe-sa-15-8"),
      spec(:"id-spe-sa-15-9"),
      spec(:"id-spe-sa-16"),
      spec(:"id-spe-sa-17"),
      spec(:"id-spe-sa-17-1"),
      spec(:"id-spe-sa-17-2"),
      spec(:"id-spe-sa-17-3"),
      spec(:"id-spe-sa-17-4"),
      spec(:"id-spe-sa-18"),
      spec(:"id-spe-sa-19"),
      spec(:"id-spe-sa-20"),
      spec(:"id-spe-sa-21"),
      spec(:"id-spe-sa-22"),
      spec(:"id-spe-sa-23"),
      spec(:"id-spe-sc-1"),
      spec(:"id-spe-sc-2"),
      spec(:"id-spe-sc-2-1"),
      spec(:"id-spe-sc-2-2"),
      spec(:"id-spe-sc-3"),
      spec(:"id-spe-sc-3-1"),
      spec(:"id-spe-sc-3-2"),
      spec(:"id-spe-sc-3-3"),
      spec(:"id-spe-sc-3-4"),
      spec(:"id-spe-sc-3-5"),
      spec(:"id-spe-sc-4"),
      spec(:"id-spe-sc-4-1"),
      spec(:"id-spe-sc-4-2"),
      spec(:"id-spe-sc-5"),
      spec(:"id-spe-sc-5-1"),
      spec(:"id-spe-sc-5-2"),
      spec(:"id-spe-sc-5-3"),
      spec(:"id-spe-sc-6"),
      spec(:"id-spe-sc-7"),
      spec(:"id-spe-sc-7-1"),
      spec(:"id-spe-sc-7-2"),
      spec(:"id-spe-sc-7-3"),
      spec(:"id-spe-sc-7-4"),
      spec(:"id-spe-sc-7-5"),
      spec(:"id-spe-sc-7-6"),
      spec(:"id-spe-sc-7-7"),
      spec(:"id-spe-sc-7-8"),
      spec(:"id-spe-sc-7-9"),
      spec(:"id-spe-sc-7-13"),
      spec(:"id-spe-sc-8"),
      spec(:"id-spe-sc-8-1"),
      spec(:"id-spe-sc-8-2"),
      spec(:"id-spe-sc-8-3"),
      spec(:"id-spe-sc-8-4"),
      spec(:"id-spe-sc-8-5"),
      spec(:"id-spe-sc-9"),
      spec(:"id-spe-sc-10"),
      spec(:"id-spe-sc-11"),
      spec(:"id-spe-sc-12"),
      spec(:"id-spe-sc-13"),
      spec(:"id-spe-sc-14"),
      spec(:"id-spe-sc-15"),
      spec(:"id-spe-sc-16"),
      spec(:"id-spe-sc-17"),
      spec(:"id-spe-sc-18"),
      spec(:"id-spe-sc-19"),
      spec(:"id-spe-sc-20"),
      spec(:"id-spe-sc-21"),
      spec(:"id-spe-sc-22"),
      spec(:"id-spe-sc-23"),
      spec(:"id-spe-sc-24"),
      spec(:"id-spe-sc-25"),
      spec(:"id-spe-sc-26"),
      spec(:"id-spe-sc-27"),
      spec(:"id-spe-sc-28"),
      spec(:"id-spe-sc-29"),
      spec(:"id-spe-sc-30"),
      spec(:"id-spe-sc-31"),
      spec(:"id-spe-sc-32"),
      spec(:"id-spe-sc-33"),
      spec(:"id-spe-sc-34"),
      spec(:"id-spe-sc-35"),
      spec(:"id-spe-sc-36"),
      spec(:"id-spe-sc-37"),
      spec(:"id-spe-sc-38"),
      spec(:"id-spe-sc-39"),
      spec(:"id-spe-sc-40"),
      spec(:"id-spe-sc-41"),
      spec(:"id-spe-sc-42"),
      spec(:"id-spe-sc-43"),
      spec(:"id-spe-sc-44"),
      spec(:"id-spe-sc-45"),
      spec(:"id-spe-sc-46"),
      spec(:"id-spe-sc-47"),
      spec(:"id-spe-sc-48"),
      spec(:"id-spe-sc-48-1"),
      spec(:"id-spe-sc-49"),
      spec(:"id-spe-sc-50"),
      spec(:"id-spe-sc-51"),
      spec(:"id-spe-si-1"),
      spec(:"id-spe-si-2"),
      spec(:"id-spe-si-2-1"),
      spec(:"id-spe-si-2-2"),
      spec(:"id-spe-si-2-3"),
      spec(:"id-spe-si-2-4"),
      spec(:"id-spe-si-2-5"),
      spec(:"id-spe-si-2-6"),
      spec(:"id-spe-si-3"),
      spec(:"id-spe-si-3-1"),
      spec(:"id-spe-si-3-2"),
      spec(:"id-spe-si-3-3"),
      spec(:"id-spe-si-3-4"),
      spec(:"id-spe-si-3-5"),
      spec(:"id-spe-si-3-6"),
      spec(:"id-spe-si-3-7"),
      spec(:"id-spe-si-3-8"),
      spec(:"id-spe-si-3-9"),
      spec(:"id-spe-si-3-10"),
      spec(:"id-spe-si-4"),
      spec(:"id-spe-si-4-1"),
      spec(:"id-spe-si-4-2"),
      spec(:"id-spe-si-4-3"),
      spec(:"id-spe-si-4-4"),
      spec(:"id-spe-si-4-5"),
      spec(:"id-spe-si-4-6"),
      spec(:"id-spe-si-4-7"),
      spec(:"id-spe-si-4-8"),
      spec(:"id-spe-si-4-9"),
      spec(:"id-spe-si-4-10"),
      spec(:"id-spe-si-4-11"),
      spec(:"id-spe-si-4-12"),
      spec(:"id-spe-si-4-13"),
      spec(:"id-spe-si-4-14"),
      spec(:"id-spe-si-4-15"),
      spec(:"id-spe-si-4-16"),
      spec(:"id-spe-si-4-17"),
      spec(:"id-spe-si-4-18"),
      spec(:"id-spe-si-4-19"),
      spec(:"id-spe-si-4-20"),
      spec(:"id-spe-si-4-21"),
      spec(:"id-spe-si-4-22"),
      spec(:"id-spe-si-4-23"),
      spec(:"id-spe-si-4-24"),
      spec(:"id-spe-si-4-25"),
      spec(:"id-spe-si-5"),
      spec(:"id-spe-si-5-1"),
      spec(:"id-spe-si-6"),
      spec(:"id-spe-si-6-1"),
      spec(:"id-spe-si-6-2"),
      spec(:"id-spe-si-6-3"),
      spec(:"id-spe-si-7"),
      spec(:"id-spe-si-7-1"),
      spec(:"id-spe-si-7-2"),
      spec(:"id-spe-si-7-3"),
      spec(:"id-spe-si-7-4"),
      spec(:"id-spe-si-7-5"),
      spec(:"id-spe-si-7-6"),
      spec(:"id-spe-si-7-7"),
      spec(:"id-spe-si-7-8"),
      spec(:"id-spe-si-7-9"),
      spec(:"id-spe-si-7-10"),
      spec(:"id-spe-si-7-11"),
      spec(:"id-spe-si-7-12"),
      spec(:"id-spe-si-7-13"),
      spec(:"id-spe-si-7-14"),
      spec(:"id-spe-si-7-15"),
      spec(:"id-spe-si-7-16"),
      spec(:"id-spe-si-7-17"),
      spec(:"id-spe-si-8"),
      spec(:"id-spe-si-8-1"),
      spec(:"id-spe-si-8-2"),
      spec(:"id-spe-si-8-3"),
      spec(:"id-spe-si-9"),
      spec(:"id-spe-si-10"),
      spec(:"id-spe-si-10-1"),
      spec(:"id-spe-si-10-2"),
      spec(:"id-spe-si-10-3"),
      spec(:"id-spe-si-10-4"),
      spec(:"id-spe-si-10-5"),
      spec(:"id-spe-si-10-6"),
      spec(:"id-spe-si-11"),
      spec(:"id-spe-si-12"),
      spec(:"id-spe-si-12-1"),
      spec(:"id-spe-si-12-2"),
      spec(:"id-spe-si-12-3"),
      spec(:"id-spe-si-13"),
      spec(:"id-spe-si-13-1"),
      spec(:"id-spe-si-13-2"),
      spec(:"id-spe-si-13-3"),
      spec(:"id-spe-si-13-4"),
      spec(:"id-spe-si-13-5"),
      spec(:"id-spe-si-14"),
      spec(:"id-spe-si-14-1"),
      spec(:"id-spe-si-14-2"),
      spec(:"id-spe-si-14-3"),
      spec(:"id-spe-si-15"),
      spec(:"id-spe-si-16"),
      spec(:"id-spe-si-17"),
      spec(:"id-spe-si-18"),
      spec(:"id-spe-si-18-1"),
      spec(:"id-spe-si-18-2"),
      spec(:"id-spe-si-18-3"),
      spec(:"id-spe-si-18-4"),
      spec(:"id-spe-si-18-5"),
      spec(:"id-spe-si-19"),
      spec(:"id-spe-si-19-1"),
      spec(:"id-spe-si-19-2"),
      spec(:"id-spe-si-19-3"),
      spec(:"id-spe-si-19-4"),
      spec(:"id-spe-si-19-5"),
      spec(:"id-spe-si-19-6"),
      spec(:"id-spe-si-19-7"),
      spec(:"id-spe-si-19-8"),
      spec(:"id-spe-si-20"),
      spec(:"id-spe-si-21"),
      spec(:"id-spe-si-22"),
      spec(:"id-spe-si-23"),
      spec(:"id-spe-sr-1"),
      spec(:"id-spe-sr-2"),
      spec(:"id-spe-sr-2-1"),
      spec(:"id-spe-sr-3"),
      spec(:"id-spe-sr-3-1"),
      spec(:"id-spe-sr-3-2"),
      spec(:"id-spe-sr-3-3"),
      spec(:"id-spe-sr-4"),
      spec(:"id-spe-sr-4-1"),
      spec(:"id-spe-sr-4-2"),
      spec(:"id-spe-sr-4-3"),
      spec(:"id-spe-sr-4-4"),
      spec(:"id-spe-sr-5"),
      spec(:"id-spe-sr-5-1"),
      spec(:"id-spe-sr-5-2"),
      spec(:"id-spe-sr-6"),
      spec(:"id-spe-sr-6-1"),
      spec(:"id-spe-sr-7"),
      spec(:"id-spe-sr-8"),
      spec(:"id-spe-sr-9"),
      spec(:"id-spe-sr-9-1"),
      spec(:"id-spe-sr-10"),
      spec(:"id-spe-sr-11"),
      spec(:"id-spe-sr-11-1"),
      spec(:"id-spe-sr-12"),
      spec(:"id-spe-at-2-2"),
      spec(:"id-spe-at-2-3"),
      spec(:"id-spe-ia-5"),
      spec(:"id-spe-ia-6"),
      spec(:"id-spe-pe-3"),
      spec(:"id-spe-pe-5"),
      spec(:"id-spe-pe-6"),
      spec(:"id-spe-sc-28-1")
    ]
  end

  def spec(:"id-spe-ac") do
    %{
      id: :"id-spe-ac",
      description: "Клас заходів захисту AC — УПРАВЛІННЯ ДОСТУПОМ",
      title: "УПРАВЛІННЯ ДОСТУПОМ (AC)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-at") do
    %{
      id: :"id-spe-at",
      description: "Клас заходів захисту AT — ОБІЗНАНІСТЬ ТА НАВЧАННЯ",
      title: "ОБІЗНАНІСТЬ ТА НАВЧАННЯ (AT)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-au") do
    %{
      id: :"id-spe-au",
      description: "Клас заходів захисту AU — АУДИТ ТА ПІДЗВІТНІСТЬ",
      title: "АУДИТ ТА ПІДЗВІТНІСТЬ (AU)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ca") do
    %{
      id: :"id-spe-ca",
      description: "Клас заходів захисту CA — ОЦІНЮВАННЯ,",
      title: "ОЦІНЮВАННЯ, АВТОРИЗАЦІЯ ТА МОНІТОРИНГ (CA)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-cm") do
    %{
      id: :"id-spe-cm",
      description: "Клас заходів захисту CM — УПРАВЛІННЯ КОНФІГУРАЦІЄЮ",
      title: "УПРАВЛІННЯ КОНФІГУРАЦІЄЮ (CM)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-cp") do
    %{
      id: :"id-spe-cp",
      description: "Клас заходів захисту CP — ПЛАНУВАННЯ БЕЗПЕРЕРВНОЇ РОБОТИ",
      title: "ПЛАНУВАННЯ БЕЗПЕРЕРВНОЇ РОБОТИ (CP)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ia") do
    %{
      id: :"id-spe-ia",
      description: "Клас заходів захисту IA — ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (IA)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ir") do
    %{
      id: :"id-spe-ir",
      description: "Клас заходів захисту IR — РЕАГУВАННЯ НА ІНЦИДЕНТИ",
      title: "РЕАГУВАННЯ НА ІНЦИДЕНТИ (IR)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ma") do
    %{
      id: :"id-spe-ma",
      description: "Клас заходів захисту MA — ТЕХНІЧНЕ ОБСЛУГОВУВАННЯ",
      title: "ТЕХНІЧНЕ ОБСЛУГОВУВАННЯ (MA)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-mp") do
    %{
      id: :"id-spe-mp",
      description: "Клас заходів захисту MP — ЗАХИСТ НОСІЇВ ІНФОРМАЦІЇ",
      title: "ЗАХИСТ НОСІЇВ ІНФОРМАЦІЇ (MP)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-pe") do
    %{
      id: :"id-spe-pe",
      description: "Клас заходів захисту PE — ФІЗИЧНИЙ ЗАХИСТ І ЗАХИСТ РОБОЧОГО",
      title: "ФІЗИЧНИЙ ЗАХИСТ ТА ЗАХИСТ НАВКОЛИШНЬОГО СЕРЕДОВИЩА (PE)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-pl") do
    %{
      id: :"id-spe-pl",
      description: "Клас заходів захисту PL — ПЛАНУВАННЯ БЕЗПЕКИ",
      title: "ПЛАНУВАННЯ (PL)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ps") do
    %{
      id: :"id-spe-ps",
      description: "Клас заходів захисту PS — КАДРОВА БЕЗПЕКА",
      title: "БЕЗПЕКА ПЕРСОНАЛУ (PS)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ra") do
    %{
      id: :"id-spe-ra",
      description: "Клас заходів захисту RA — ОЦІНЮВАННЯ РИЗИКУ",
      title: "ОЦІНКА РИЗИКІВ (RA)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sa") do
    %{
      id: :"id-spe-sa",
      description: "Клас заходів захисту SA — ПРИДБАННЯ СИСТЕМИ ТА ПОСЛУГ",
      title: "ПРИДБАННЯ СИСТЕМ ТА ПОСЛУГ (SA)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sc") do
    %{
      id: :"id-spe-sc",
      description: "Клас заходів захисту SC — ЗАХИСТ ІНФОРМАЦІЙНОЇ СИСТЕМИ ТА",
      title: "ЗАХИСТ СИСТЕМ ТА КОМУНІКАЦІЙ (SC)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-si") do
    %{
      id: :"id-spe-si",
      description: "Клас заходів захисту SI — ЦІЛІСНІСТЬ СИСТЕМИ ТА ІНФОРМАЦІЇ",
      title: "ЦІЛІСНІСТЬ СИСТЕМИ ТА ІНФОРМАЦІЇ (SI)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sr") do
    %{
      id: :"id-spe-sr",
      description: "Клас заходів захисту SR — УПРАВЛІННЯ РИЗИКАМИ ЛАНЦЮГА",
      title: "УПРАВЛІННЯ РИЗИКАМИ В ЛАНЦЮГУ ПОСТАЧАННЯ (SR)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-pm") do
    %{
      id: :"id-spe-pm",
      description: "Клас заходів захисту PM — МЕНЕДЖМЕНТ ІНФОРМАЦІЙНОЇ БЕЗПЕКИ",
      title: "УПРАВЛІННЯ ПРОГРАМАМИ (PM)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-pt") do
    %{
      id: :"id-spe-pt",
      description: "Клас заходів захисту PT — ПОВНОВАЖЕННЯ",
      title: "ОБРОБКА ПЕРСОНАЛЬНИХ ДАНИХ ТА ПРОЗОРІСТЬ (PT)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ac-1") do
    %{
      id: :"id-spe-ac-1",
      description: "a. Розробити, задокументувати та поширити [Призначення: серед визначеного організацією персоналу або ролей]: 1. 2. [Вибір (один або декілька): Рівень організації; Рівень місії/бізнес-процесу; рівень системи] політики контролю доступу, яка: (a) містить мету, сферу застосування, ролі, відповідальність, зобов’язання керівництва, координацію між організаційними підрозділами та систему контролю відповідності (compliances); (b) відповідає чинному законодавству, нормативним документам, директивам, нормам, політикам, стандартам і керівним документам. Процедури, що сприяють реалізації політики управління доступом і відповідних заходів управління доступом. b. Призначити на посаду [Призначення: визначену організацією посадову особу] для управління, документування і розповсюдження політики та процедур контролю доступом. c. Переглянути та оновити: 1. поточну політику управління доступом [Призначення: з визначеною організацією частотою] та [Призначення: події, визначені організацією]; 2. поточні процедури управління доступом [Призначення: з визначеною організацією частотою] та [Завдання: події, визначені організацією].",
      title: "ПОЛІТИКА ТА ПРОЦЕДУРИ УПРАВЛІННЯ ДОСТУПОМ (AC-1)",
      parameters: [
        {:ac_1_odp_01,
         "Визначено персонал або ролі, на які поширюється політика контролю доступу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_1_odp_02,
         "Визначено персонал або ролі, на які поширюються процедури контролю доступу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнес-процесу; рівень системи}",
         [type: :string, default: nil]},
        {:ac_1_odp_04,
         "Визначено посадову особу, яка керуватиме політикою та процедурами контролю доступу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_1_odp_05,
         "Визначено частоту, з якою переглядається та оновлюється поточна політика контролю доступу",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_1_odp_06,
         "Визначено події, які вимагають перегляду та оновлення поточної політики контролю доступу",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_1_odp_07,
         "Визначено частоту, з якою переглядаються та оновлюються поточні процедури контролю доступу",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ac-2") do
    %{
      id: :"id-spe-ac-2",
      description: "a. Визначити та задокументувати типи облікових записів системи, дозволених для використання в ІС для підтримки цілей, завдань, функцій і процесів організації. b. Призначити менеджерів облікових записів для управління системними обліковими записами. c. Створити умови для групового та рольового членства. d. Визначити авторизованих користувачів інформаційної системи, членство в групі та ролі, а також дозволи доступу (наприклад, привілеї) та інші атрибути (за потреби) для кожного облікового запису. e. Вимагати схвалення [Призначення: визначеною організацією відповідальною особою або роллю] запитів на створення облікових записів системи. f. Створювати, активувати, змінювати, деактивувати та видаляти системні облікові записи відповідно до [Призначення: визначених організацією політики, процедур та умов]. g. Впровадити моніторинг використання облікових записів системи. h. Повідомляти адміністраторів облікових записів у межах [Призначення: визначеного організацією часового періоду для кожної ситуації]: 1. коли облікові записи більше не потрібні; 2. коли користувачі звільнені чи переведені; 3. коли використовуються індивідуальні системи або наявні зміни, які потребують нових знань. i. Авторизувати доступ до системи на основі: 1. Дійсної авторизації доступу. 2. Передбачуваного використання системи. 3. Інших атрибутів, що вимагаються організацією. j. Проводити перегляд облікових записів на відповідність вимогам управління обліковими записами з [Призначення: визначеною організацією частотою]. k. Впровадити процес повторного випуску облікових даних спільного/групового облікового запису (якщо він буде розгорнутий), коли особи виходять з групи. l. Узгодити процеси управління обліковими записами з процесами звільнення та переводу (передачі повноважень) персоналу.",
      title: "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ (AC-2)",
      parameters: [
        {:ac_2_odp_09,
         "Визначено передумови та критерії членства в групах і ролях; визначено атрибути (за необхідності) для кожного облікового запису; визначено персонал або ролі, необхідні для затвердження запитів на створення облікових записів; визначено політику, процедури, передумови та критерії створення, активації, зміни, деактивації та видалення облікових записів; визначено персонал або ролі, які мають бути повідомлені; визначено період часу, протягом якого адміністратори облікових записів повинні бути повідомлені про те, що облікові записи більше не потрібні; визначено термін, протягом якого необхідно повідомляти адміністраторів облікових записів про звільнення або переведення користувачів; визначено період часу, протягом якого необхідно повідомляти адміністраторів облікових записів про зміни у використанні системи або необхідність знати про зміни для окремої особи; визначено атрибути, необхідні для авторизації доступу до системи (за потреби); AC-02_ODP[10] AC-02a.[01] AC-02a.[02] AC-02b AC-02с AC-02d.01 AC-02d.02 AC-02d.03[01] AC-02d.03[02] AC-02e AC-02f.[01] AC-02f.[02] AC-02f.[03] AC-02f.[04] AC-02f.[05] AC-02g AC-02h.01 AC-02h.02 AC-02h.03 AC-02i.01 AC-02i.02 AC-02i.03 визначено періодичність перегляду облікових записів; визначено та задокументовано типи облікових записів, дозволених для використання в системі; визначено та задокументовано типи облікових записів, які заборонено використовувати в системі; призначені менеджери облікових записів; необхідні умови та критерії для членства в групах та ролях; визначено авторизованих користувачів системи; вказано приналежність до групи або ролі; для кожного облікового запису вказуються повноваження доступу (тобто привілеї); атрибути (за необхідності) вказуються для кожного облікового запису; для запитів на створення облікових записів потрібні схвалення від персоналу або ролей; облікові записи створюються відповідно до політики, процедур, передумов та критеріїв; облікові записи активуються відповідно до політики, процедур, передумов та критеріїв; облікові записи змінюються відповідно до політики, процедур, передумов та критеріїв; облікові записи деактивуються відповідно до політики, процедур, передумов та критеріїв; облікові записи видаляються відповідно до політики, процедур, передумов та критеріїв; контролюється використання облікових записів; адміністратори облікових записів та персонал або ролі отримують повідомлення протягом періоду часу, коли облікові записи більше не потрібні; адміністратори облікових записів та персонал або ролі отримують повідомлення протягом періоду часу, коли користувачі звільнені чи переведені; адміністратори облікових записів та персонал або ролі отримують повідомлення протягом періоду часу, коли використовуються індивідуальні системи або наявні зміни, які потребують нових знань. доступ до системи здійснюється на підставі дійсної авторизації доступу; доступ до системи авторизується на основі передбачуваного використання системи; доступ до системи авторизовано на основі атрибутів (за необхідності); AC-02j AC-02k.[01] AC-02k.[02] AC-02l.[01] AC-02l.[02] облікові записи переглядаються на відповідність вимогам управління обліковими записами частота; створено процес повторного випуску облікових даних спільного доступу або групових облікових записів (якщо вони розгорнуті), коли користувачів вилучено з групи; впроваджено процес повторного випуску облікових даних спільного доступу або групових облікових записів (якщо вони розгорнуті), коли користувачів вилучено з групи; процеси управління обліковими записами узгоджуються з процесами звільнення персоналу; процеси управління обліковими записами узгоджуються з процесами переводу персоналу",
         [type: :integer, default: 24]}
      ]
    }
  end

  def spec(:"id-spe-ac-2-1") do
    %{
      id: :"id-spe-ac-2-1",
      description: "Використовувати автоматизовані системними обліковими записами. механізми для підтримки управління",
      title: "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - АВТОМАТИЗОВАНЕ УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ СИСТЕМИ (AC-2(1))",
      parameters: [
        {:ac_2_1_01,
         "Управління обліковими записами системи підтримується за допомогою автоматизовані механізми",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ac_2_1_odp,
         "Визначено автоматизовані механізми, що використовуються для підтримки управління обліковими записами системи",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ac-2-3") do
    %{
      id: :"id-spe-ac-2-3",
      description: "Автоматично деактивувати облікові записи коли: a) їх строк дії минув; b) вони більше не пов’язані з користувачем; c) вони порушують організаційну політику; d) вони були неактивними впродовж [Призначення: визначеного організацією періоду часу].",
      title: "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - ДЕАКТИВАЦІЯ ОБЛІКОВИХ ЗАПИСІВ (AC-2(3))",
      parameters: [
        {:ac_2_3_b,
         "Облікові записи деактивуються протягом часового періоду, коли облікові записи більше не пов'язані з користувачем або фізичною особою",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_2_3_d,
         "Облікові записи відключено протягом часового періоду, коли облікові записи порушують політику організації; облікові записи деактивуються протягом , якщо вони були неактивними протягом ",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_2_3_odp_01,
         "Визначено період часу, протягом якого необхідно деактивувати облікові записи",
         [type: :integer, default: 30]},
        {:ac_2_3_odp_02,
         "Визначено період часу неактивності, після закінчення якого облікові записи будуть деактивовані; AC-02(03)(a) облікові записи деактивуються протягом часового періоду, коли термін дії облікових записів минув",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-2-4") do
    %{
      id: :"id-spe-ac-2-4",
      description: "Проводити автоматизований аудит створення, модифікації, деактивації та видалення облікових записів і сповіщення про дії. ПРИ активації,",
      title: "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - ДІЇ ПРИ АВТОМАТИЗОВАНОМУ АУДИТІ (AC-2(4))",
      parameters: [
        {:ac_2_4_01,
         "Створення облікового запису автоматично аудитується",
         [type: :string, default: nil]},
        {:ac_2_4_02,
         "Модифікація облікового запису автоматично аудитується",
         [type: :string, default: nil]},
        {:ac_2_4_03,
         "Активація облікового запису автоматично аудитується",
         [type: :string, default: nil]},
        {:ac_2_4_04,
         "Деактивація облікового запису автоматично аудитується",
         [type: :string, default: nil]},
        {:ac_2_4_05,
         "Видалення облікового запису автоматично аудитується",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-2-5") do
    %{
      id: :"id-spe-ac-2-5",
      description: "Вимагати від користувачів виходити із системи, коли [Призначення: вичерпано визначений організацією періоду часу очікування або опис того, коли необхідно вийти із системи].",
      title: "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - ВИХІД ІЗ СИСТЕМИ ЗА ВІДСУТНОСТІ АКТИВНОСТІ (AC-2(5))",
      parameters: [
        {:ac_2_5_01,
         "Користувачі повинні виходити з системи, коли період очікуваної бездіяльності або опис часу, коли потрібно вийти з системи",
         [type: :integer, default: 30]},
        {:ac_2_5_odp,
         "Визначено часовий період очікуваної бездіяльності або опис, коли потрібно вийти з системи",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ac-2-6") do
    %{
      id: :"id-spe-ac-2-6",
      description: "Реалізувати такі можливості динамічного управління привілеями: [Призначення: визначений організацією перелік можливостей динамічного управління привілеями].",
      title: "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - ДИНАМІЧНЕ УПРАВЛІННЯ ПРИВІЛЕЯМИ (AC-2(6))",
      parameters: [
        {:ac_2_6_01,
         "Реалізовано можливості динамічного управління привілеями",
         [type: :string, default: nil]},
        {:ac_2_6_odp,
         "Визначено можливості динамічного управління привілеями",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-2-7") do
    %{
      id: :"id-spe-ac-2-7",
      description: "a) Створювати й адмініструвати привілейовані облікові записи користувачів відповідно до схеми доступу на основі ролей (role-based), яка реалізує дозволений доступ до системи та призначення привілеїв для ролей. b) Проводити моніторинг призначення привілейованих ролей. c) Відстежувати зміни ролей або атрибутів. d) Скасовувати доступ, коли призначені привілейовані ролі більше не потрібні.",
      title: "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - СХЕМИ, ЗАСНОВАНІ НА РОЛЯХ (AC-2(7))",
      parameters: [
        {:ac_2_7_b,
         "Проводиться моніторинг призначення привілейованих ролей або атрибутів",
         [type: :string, default: nil]},
        {:ac_2_7_c,
         "Відстежуються зміни ролей або атрибутів",
         [type: :string, default: nil]},
        {:ac_2_7_d,
         "Доступ скасовується, коли призначені привілейовані ролі більше не потрібні.0",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_2_7_odp,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {схема доступу на основі ролей; схема доступу на основі атрибутів}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-2-8") do
    %{
      id: :"id-spe-ac-2-8",
      description: "Створювати, активувати, управляти та деактивувати [Призначення: системні облікові записи, визначені організацією] динамічно.",
      title: "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - ДИНАМІЧНЕ УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ (AC-2(8))",
      parameters: [
        {:ac_2_8_01,
         "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - ДИНАМІЧНЕ УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:ac_2_8_02,
         "Облікові записи системи активуються динамічно",
         [type: :string, default: nil]},
        {:ac_2_8_03,
         "Облікові записи системи активуються динамічно",
         [type: :string, default: nil]},
        {:ac_2_8_04,
         "Облікові записи системи деактивуються динамічно",
         [type: :string, default: nil]},
        {:ac_2_8_odp,
         "Визначено облікові записи системи, які динамічно створюються, активуються, управляються та деактивуються",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-2-9") do
    %{
      id: :"id-spe-ac-2-9",
      description: "Використовувати лише ті спільні та групові облікові записи, які відповідають [Призначення: визначеним організацією умовам для створення спільних та групових облікових записів].",
      title: "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - ОБМЕЖЕННЯ НА ВИКОРИСТАННЯ СПІЛЬНИХ ТА ГРУПОВИХ ОБЛІКОВИХ ЗАПИСІВ (AC-2(9))",
      parameters: [
        {:ac_2_9_01,
         "Використання спільних та групових облікових записів дозволено лише за умови дотримання умов",
         [type: :list, default: []]},
        {:ac_2_9_odp,
         "Визначено умови створення спільних та групових облікових записів",
         [type: :list, default: []]}
      ]
    }
  end

  def spec(:"id-spe-ac-2-10") do
    %{
      id: :"id-spe-ac-2-10",
      description: "",
      title: "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - ЗМІНА ДАНИХ СПІЛЬНИХ І ГРУПОВИХ ОБЛІКОВИХ ЗАПИСІВ (AC-2(10))",
      parameters: [
        {:ac_2_10_01,
         "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - ЗМІНА ДАНИХ СПІЛЬНИХ І ГРУПОВИХ ОБЛІКОВИХ ЗАПИСІВ [Вилучено: включено до AC-02(k)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-2-11") do
    %{
      id: :"id-spe-ac-2-11",
      description: "Забезпечити дотримання [Призначення: обставин та/або умов використання, визначених організацією] для [Призначення: визначених організацією облікових записів системи].",
      title: "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - УМОВИ ВИКОРИСТАННЯ (AC-2(11))",
      parameters: [
        {:ac_2_11_01,
         "Обставини та/або умови використання для облікових записів системи застосовуються",
         [type: :list, default: []]},
        {:ac_2_11_odp_01,
         "Визначено обставини та/або умови використання визначених облікових записів системи",
         [type: :list, default: []]},
        {:ac_2_11_odp_02,
         "Визначені облікові записи системи, що підлягають виконанню обставин та/або умов використання",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-2-12") do
    %{
      id: :"id-spe-ac-2-12",
      description: "a) Проводити моніторинг облікових записів системи на [Призначення: визначене організацією нетипове використання]. b) Повідомляти про нетипове використання облікових записів системи [Призначення: визначеного організацією персоналу або ролей].",
      title: "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - МОНІТОРИНГ НЕТИПОВОГО ВИКОРИСТАННЯ ОБЛІКОВИХ ЗАПИСІВ (AC-2(12))",
      parameters: [
        {:ac_2_12_a,
         "Облікові записи системи відстежуються на предмет обставини та/або умови використання",
         [type: :list, default: []]},
        {:ac_2_12_b,
         "Про визначені обставини та/або умови використання системних облікових записів повідомляється персонал або ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_2_12_odp_01,
         "Визначено обставини та/або умови використання, для яких необхідно здійснювати моніторинг обліко- вих записів системи",
         [type: :list, default: []]},
        {:ac_2_12_odp_02,
         "Визначено персонал або ролі, яким належить повідомляти про визначені обставини та/або умови використання",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-2-13") do
    %{
      id: :"id-spe-ac-2-13",
      description: "Деактивувати облікові записи користувачів, які становлять значний ризик, у межах [Призначення: визначеного організацією періоду часу] після виявлення ризику.",
      title: "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ - ДЕАКТИВАЦІЯ ОБЛІКОВИХ ЗАПИСІВ ОСІБ З ВИСОКИМ РІВНЕМ РИЗИКУ (AC-2(13))",
      parameters: [
        {:ac_2_13_01,
         "Облікові записи користувачів деактивуються протягом періоду часу з моменту виявлення значних ризиків",
         [type: :integer, default: 30]},
        {:ac_2_13_odp_01,
         "Визначено період часу, протягом якого необхідно деактивувати облікові записи фізичних осіб, які становлять значний ризик",
         [type: :integer, default: 30]},
        {:ac_2_13_odp_02,
         "Визначено значні ризики, що призводять до деактивації облікових записів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-3") do
    %{
      id: :"id-spe-ac-3",
      description: "Застосовувати затверджені повноваження для логічного доступу до інформації та ресурсів системи відповідно до чинної політики (правил) управління доступом.",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ (AC-3)",
      parameters: [
        {:ac_3_01,
         "Затверджені повноваження на логічний доступ до інформації та ресурсів системи виконуються відповідно до чинних політик(правил) управління доступом",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-1") do
    %{
      id: :"id-spe-ac-3-1",
      description: "",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - ОБМЕЖЕНИЙ ДОСТУП ДО ПРИВІЛЕЙОВАНИХ ФУНКЦІЙ (AC-3(1))",
      parameters: [
        {:ac_3_1_01,
         "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - ОБМЕЖЕНИЙ ДОСТУП ДО ПРИВІЛЕЙОВАНИХ ФУНКЦІЙ [Вилучено: включено до складу AC-06]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-2") do
    %{
      id: :"id-spe-ac-3-2",
      description: "Забезпечити подвійну авторизацію для [Призначення: визначених організацією привілейованих команд та/або інших дій, визначених організацією].",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - ПОДВІЙНА АВТОРИЗАЦІЯ (AC-3(2))",
      parameters: [
        {:ac_3_2_01,
         "Подвійна авторизація застосовується для привілейованих команд та/або інших дій",
         [type: :string, default: nil]},
        {:ac_3_2_odp,
         "Визначено привілейовані команди та/або інші дії, що потребують подвійної авторизації",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-3") do
    %{
      id: :"id-spe-ac-3-3",
      description: "Застосовувати [Призначення: визначену організацією мандатну (mandatory) політику управління доступом] щодо всіх суб’єктів і об’єктів доступу, у яких політика: (a) одноманітно застосовується для всіх суб’єктів і об’єктів у межах системи; (b) вказує, що суб’єкт, якому було надано доступ до інформації, обмежений у виконанні будь-якої з таких дій: (c) (1) передача інформації неавторизованим суб’єктам або об’єктам; (2) надання іншим суб’єктам привілеїв; (3) зміна одного чи декількох атрибутів безпеки суб’єкта, об’єкта, системи або компонентів системи; (4) вибір атрибутів безпеки та значень атрибутів, які повинні бути пов’язані з новоствореними або зміненими об’єктами; (5) зміна правил, що регулюють управління доступом; має бути вказано, що [Призначення: визначеним організацією суб’єктам] можуть бути явно надані [Призначення: визначені організацією привілеї], так що вони не обмежуються будь-яким з перелічених вище обмежень.",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - МАНДАТНЕ УПРАВЛІННЯ ДОСТУПОМ (AC-3(3))",
      parameters: [
        {:ac_3_3_01,
         "Мандатна політика контролю доступу застосовується до набору охоплених суб'єктів, зазначених у політиці",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_3_02,
         "Мандатна політика контролю доступу застосовується до набору охоплених об'єктів, зазначених у політиці",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_3_a_01,
         "Мандатна політика контролю доступу застосовується одноманітно до всіх суб'єктів системи",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_3_a_02,
         "Мандатна політика контролю доступу застосовується одноманітно до всіх об'єктів системи; AC-03(03)(b)(01) мандатна політика контролю доступу та мандатна політика контролю доступу, які визначають, що суб'єкт, якому надано доступ до інформації, зобов'язаний не передавати інформацію неавторизованим суб'єктам або об'єктам; AC-03(03)(b)(02) мандатна політика контролю доступу та мандатна політика контролю доступу, які визначають, що суб'єкт, якому надано доступ до інформації, обмежений у наданні своїх привілеїв іншим суб'єктам; AC-03(03)(b)(03) мандатна політика контролю доступу та мандатна політика контролю доступу, які визначають, що суб'єкт, якому надано доступ до інформації, не може змінювати один або декілька атрибутів безпеки (визначених політикою) суб'єктів, об'єктів, системи або компонентів системи; AC-03(03)(b)(04) мандатна політика контролю доступу та мандатна політика контролю доступу, які визначають, що суб'єкт, якому надано доступ до інформації, обмежений у виборі атрибутів безпеки та значень атрибутів (визначених політикою), що повинні бути пов'язані з новостворюваними або зміненими об'єктами; AC-03(03)(b)(05) мандатна політика контролю доступу та мандатна політика контролю доступу, які визначають, що суб'єкт, якому надано доступ до інформації, не має права змінювати правила, що регулюють управління доступом",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_3_c,
         "Мандатна політика контролю доступу та мандатна політика контролю доступу, які визначають, що суб'єктам можуть бути явно надані привілеї таким чином, щоб вони не були обмежені будь-якою визначеною підмножиною (або всіма) з наведених вище обмежень",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_3_odp_01,
         "Визначено мандатну політику контролю доступу, що застосовується до набору охоплених суб'єктів",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_3_odp_02,
         "Визначено мандатну політику контролю доступу, що застосовується до набору охоплених об'єктів",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_3_odp_03,
         "Визначені суб'єкти, яким явно надаються привілеї",
         [type: :string, default: nil]},
        {:ac_3_3_odp_04,
         "Визначено привілеї, які мають бути прямо надані суб'єктам",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-4") do
    %{
      id: :"id-spe-ac-3-4",
      description: "Застосовувати [Призначення: визначену організацією дискреційну політику управління доступом] щодо визначених суб’єктів і об’єктів доступу, для яких політика визначає, що суб’єкт, якому було надано доступ до інформації, може виконати одну чи більше з таких дій: (a) передача інформацію будь-яким іншим суб’єктам чи об’єктам; (b) призначення своїх привілей іншим суб’єктам; (c) зміна атрибутів безпеки суб’єктів, об’єктів, систем або компонентів системи; (d) вибір атрибутів безпеки, які будуть пов’язані з новоствореними або переглянутими об’єктами; (e) зміна правил, що регулюють управління доступом.",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - ДИСКРЕЦІЙНЕ УПРАВЛІННЯ ДОСТУПОМ (AC-3(4))",
      parameters: [
        {:ac_3_4_01,
         "Дискреційна політика управління доступом застосовується до набору охоплених суб'єктів, зазначених у політиці",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_4_02,
         "Дискреційна політика управління доступом застосовується до набору охоплених об'єктів, зазначених у політиці",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_4_a,
         "Дискреційна політика управління доступом та дискреційна політика управління доступом застосовуються, коли політика визначає, що суб'єкт, якому надано доступ до інформації, може передавати інформацію будь-яким іншим суб'єктам або об'єктам",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_4_b,
         "Дискреційна політика управління доступом та дискреційна політика управління доступом застосовуються, коли політика визначає, що суб'єкт, якому надано доступ до інформації, може надавати свої привілеї іншим суб'єктам",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_4_c,
         "Дискреційна політика управління доступом та дискреційна політика управління доступом застосовуються, коли політика визначає, що суб'єкт, якому надано доступ до інформації, може змінювати атрибути безпеки суб'єктів, об'єктів, системи або компонентів системи",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_4_d,
         "Дискреційна політика управління доступом та дискреційна політика управління доступом застосовуються там, де політика визначає, що суб'єкт, якому надано доступ до інформації, може вибирати атрибути безпеки, які будуть пов'язані з новоствореними або переглянутими об'єктами",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_4_e,
         "Дискреційна політика управління доступом та дискреційна політика управління доступом застосовуються, коли політика визначає, що суб'єкт, якому надано доступ до інформації, може змінювати правила управління доступом",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_4_odp_01,
         "Визначено дискреційну політику управління доступом, яка застосовується до набору охоплених суб'єктів",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_4_odp_02,
         "Визначено дискреційну політику управління доступом, яка застосовується до набору охоплених об'єктів",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-5") do
    %{
      id: :"id-spe-ac-3-5",
      description: "Запобігати доступу до [Призначення: інформації щодо безпеки, яка визначена організацією], за винятком випадків, коли наявні безпечні неробочі стани системи.",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - ІНФОРМАЦІЯ ЩОДО БЕЗПЕКИ (AC-3(5))",
      parameters: [
        {:ac_3_5_01,
         "Доступ до інформація щодо безпеки заборонено, за винятком випадків, коли наявні безпечні неробочі стани системи",
         [type: :string, default: nil]},
        {:ac_3_5_odp,
         "Визначено інформацію щодо безпеки, доступ до якої заборонено, за винятком випадків, коли наявні безпечні неробочі стани системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-6") do
    %{
      id: :"id-spe-ac-3-6",
      description: "",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - ЗАХИСТ ІНФОРМАЦІЇ КОРИСТУВАЧА ТА СИСТЕМИ (AC-3(6))",
      parameters: [
        {:ac_3_6_01,
         "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - ЗАХИСТ ІНФОРМАЦІЇ КОРИСТУВАЧА ТА СИСТЕМИ [Вилучено: Включено в MP-04 та SC-28]. AC-03(07) ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - УПРАВЛІННЯ ДОСТУПОМ НА ОСНОВІ РОЛЕЙ",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-7") do
    %{
      id: :"id-spe-ac-3-7",
      description: "Застосовувати політику управління доступом на основі ролей щодо визначених суб’єктів і об’єктів та управління доступом на основі [Призначення: визначених організацією ролей та користувачів, уповноважених приймати такі ролі].",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - УПРАВЛІННЯ ДОСТУПОМ НА ОСНОВІ РОЛЕЙ (AC-3(7))",
      parameters: [
        {:ac_3_7_01,
         "Політика управління доступом на основі ролей застосовується до визначених суб'єктів",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_7_02,
         "Політика управління доступом на основі ролей застосовується до визначених об'єктів",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_7_03,
         "Доступ контролюється на основі ролей та користувачів, яким дозволено приймати такі ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_3_7_odp_01,
         "Визначено ролі, на яких базується управління доступом",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_3_7_odp_02,
         "Визначено користувачів, уповноважених на прийняття ролей (визначених у AC-03(07)_ODP[01])",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-8") do
    %{
      id: :"id-spe-ac-3-8",
      description: "Здійснювати анулювання прав доступу в результаті змін атрибутів безпеки суб’єктів і об’єктів на основі [Призначення: визначених організацією правил, що регулюють терміни скасування прав доступу].",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - АНУЛЮВАННЯ ПРАВ ДОСТУПУ (AC-3(8))",
      parameters: [
        {:ac_3_8_01,
         "Здійснюється анулювання прав доступу в результаті зміни атрибутів безпеки суб'єктів на основі правил",
         [type: :string, default: nil]},
        {:ac_3_8_02,
         "Здійснюється анулювання прав доступу в результаті зміни атрибутів безпеки об'єктів на основі пра- вил",
         [type: :string, default: nil]},
        {:ac_3_8_odp,
         "Визначено правила, що регулюють терміни скасування дозволів на доступ",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-9") do
    %{
      id: :"id-spe-ac-3-9",
      description: "Передавати (публікувати) інформацію за межами встановленої межі системи можливо, якщо: a) Приймальна [Призначення: визначена організацією система або компонент системи] забезпечує [Призначення: визначені організацією заходи безпеки]; b) [Призначення: визначені організацією заходи безпеки] використовуються для підтвердження відповідності інформації, призначеної для керованих передач (публікації).",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - КЕРОВАНА ПЕРЕДАЧА (ПУБЛІКАЦІЯ) ІНФОРМАЦІЇ (AC-3(9))",
      parameters: [
        {:ac_3_9_a,
         "Інформація випускається за межі системи, тільки якщо отримуюча система або компонент системи забезпечує заходи захисту",
         [type: :string, default: nil]},
        {:ac_3_9_b,
         "Інформація публікується за межами системи, тільки якщо заходи захисту використовуються для перевірки відповідності інформації, призначеної для публікації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-10") do
    %{
      id: :"id-spe-ac-3-10",
      description: "Застосувати перегляд аудитом механізмів автоматизованого управління доступу при [Призначення: визначених організацією умовах] [Призначення: визначеними організацією ролями].",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - ПЕРЕГЛЯД АУДИТОМ МЕХАНІЗМІВ КОНТРОЛЮ ДОСТУПУ (AC-3(10))",
      parameters: [
        {:ac_3_10_01,
         "За умов застосовується перегляд аудитом механізмів автоматизованого контролю доступу за допомогою ролей",
         [type: :string, default: nil]},
        {:ac_3_10_odp_01,
         "Визначено умови, за яких можна застосовувати перегляд аудитом механізмів автоматизованого управління доступом",
         [type: :list, default: []]},
        {:ac_3_10_odp_02,
         "Визначено ролі, яким дозволено використовувати перегляд аутом механізмів автоматизованого управління доступом",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-11") do
    %{
      id: :"id-spe-ac-3-11",
      description: "Обмежити прямий доступ до сховищ даних, що містять [Призначення: визначені організацією типи інформації].",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - ОБМЕЖЕННЯ ДОСТУПУ ДО СПЕЦІАЛЬНОЇ ІНФОРМАЦІЇ (AC-3(11))",
      parameters: [
        {:ac_3_11_01,
         "Обмежено доступ до сховищ даних, що містять типи інформації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-12") do
    %{
      id: :"id-spe-ac-3-12",
      description: "a) Вимагати від застосунків встановити в процесі інсталяції доступ до таких застосунків системи і функцій: [Призначення: визначених організацією програм та функції системи]; b) Впровадити механізм примусового застосування, щоб запобігти доступу, відмінному від заявленого. c) Схвалити зміни доступу після початкового встановлення застосунків.",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - ВСТАНОВЛЕННЯ ТА ЗАБЕЗПЕЧЕННЯ ДОСТУПУ ДО ЗАСТОСУНКІВ (AC-3(12))",
      parameters: [
        {:ac_3_12_a,
         "У процесі інсталяції програми повинні встановити доступ до таких системних застосунків і функцій системи: програм та функції системи",
         [type: :string, default: nil]},
        {:ac_3_12_b,
         "Передбачено механізм примусового застосування запобігання несанкціонованому доступу",
         [type: :string, default: nil]},
        {:ac_3_12_c,
         "Зміни доступу після первинної інсталяції програми схвалено",
         [type: :string, default: nil]},
        {:ac_3_12_odp,
         "Визначено програми та функції системи, яким необхідно встановити права доступу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-13") do
    %{
      id: :"id-spe-ac-3-13",
      description: "Здійснювати політику управління доступу на основі атрибутів (atribute-based) для визначених суб’єктів і об’єктів доступу й управляти доступом на основі [Призначення: визначених організацією атрибутів для ухвалення рішень про доступ].",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - УПРАВЛІННЯ ДОСТУПОМ НА ОСНОВІ АТРИБУТІВ (AC-3(13))",
      parameters: [
        {:ac_3_13_1,
         "Політика управління доступом на здійснюється до визначених суб'єктів; основі атрибутів AC-03(13)[2] політика управління доступом на здійснюється до визначених об'єктів; основі атрибутів",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_13_3,
         "Доступ контролюється на основі атрибутів",
         [type: :string, default: nil]},
        {:ac_3_13_odp,
         "Визначено атрибути для визначення прав доступу",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-14") do
    %{
      id: :"id-spe-ac-3-14",
      description: "Надайте [Призначення: механізми, визначені організацією], щоб дозволити особам мати доступ до певних елементів їх особистої інформації: [Призначення: елементи, визначені організацією]",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - ІНДИВІДУАЛЬНИЙ ДОСТУП (AC-3(14))",
      parameters: [
        {:ac_3_14_01,
         "Механізми надаються для того, щоб дозволити особам мати доступ до елементів їхньої персональної інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_3_14_odp_01,
         "Визначено механізми, що дозволяють фізичним особам мати доступ до елементів їхньої персональної інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_3_14_odp_02,
         "Визначено елементи інформації, що ідентифікує особу, до якої мають доступ фізичні особи",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-3-15") do
    %{
      id: :"id-spe-ac-3-15",
      description: "(a) Застосовувати [Призначення: визначену організацією політику обов’язкового контролю доступу] до набору охоплених суб’єктів і об’єктів, указаних у політиці; (b) Застосування [Призначення: визначена організацією дискреційна політика контролю доступу] до набору охоплених суб’єктів і об’єктів, указаних у політиці.",
      title: "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ - ДИСКРЕЦІЙНИЙ ТА ОБОВʼЯЗКОВИЙ ДОСТУП (AC-3(15))",
      parameters: [
        {:ac_3_15_a_01,
         "Політика обов'язкового контролю доступу застосовується до набору охоплених суб'єктів, зазначених у політиці",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_15_a_02,
         "Політика обов'язкового контролю доступу застосовується до набору охоплених об'єктів, зазначених у політиці",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_15_b_01,
         "Дискреційна політика контролю доступу застосовується до набору суб'єктів, зазначених у політиці",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_15_b_02,
         "Дискреційна політика контролю доступу застосовується до набору об'єктів, зазначених у політиці",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_15_odp_01,
         "Визначено обов'язкову політику контролю доступу, яка застосовується до набору суб'єктів, зазначених у політиці",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_15_odp_02,
         "Визначено обов'язкову політику контролю доступу, яка застосовується до набору об'єктів, зазначених у політиці",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_15_odp_03,
         "Визначено дискреційну політику контролю доступу, яка застосовується до набору суб'єктів, зазначених у політиці",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_3_15_odp_04,
         "Визначено дискреційну політику контролю доступу, яка застосовується до набору об'єктів, зазначених у політиці",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4") do
    %{
      id: :"id-spe-ac-4",
      description: "Застосувати затверджені повноваження для управління потоком інформації всередині системи та між пов’язаними системами на основі [Призначення: визначеними організацією політиками управління інформаційним потоком].",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ (AC-4)",
      parameters: [
        {:ac_4_01,
         "Затверджені повноваження застосовуються для контролю потоку інформації всередині системи та між підключеними системами на основі політики управління інформаційними потоками",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_odp,
         "Визначено політики управління інформаційними потоками всередині системи та між підключеними системами",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-1") do
    %{
      id: :"id-spe-ac-4-1",
      description: "Використовувати [Призначення: визначені організацією атрибути безпеки], пов’язані з [Призначення: визначеними організацією інформацією, джерелами та об’єктами призначення], щоб запровадити [Призначення: визначену організацією політику управління потоками інформації] як основу для ухвалення рішень щодо управління потоками.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - АТРИБУТИ БЕЗПЕКИ ОБ'ЄКТУ (AC-4(1))",
      parameters: [
        {:ac_4_1_01,
         "Атрибути безпеки, пов'язані з об'єктами інформації, джерела об'єктів та об'єктами призначення, використовуються для забезпечення виконання політик управління інформаційними потоками як основи для прийняття рішень щодо управління потоками",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_1_02,
         "Атрибути конфіденційності, пов'язані з об'єктами інформації, джерела об'єктів та об'єктами призначення, використовуються для забезпечення виконання політик управління інформаційними потоками як основи для прийняття рішень щодо управління потоками",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_1_odp_01,
         "Визначено атрибути безпеки, які будуть пов'язані з інформацією, джерелом та об'єктами призначення",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_1_odp_02,
         "Визначено атрибути конфіденційності, які будуть пов'язані з інформацією, джерелом та об'єктами призначення",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_1_odp_03,
         "Визначено об'єкти інформації, які будуть пов'язані з атрибутами безпеки",
         [type: :string, default: nil]},
        {:ac_4_1_odp_04,
         "Визначено об'єкти інформації, які будуть пов'язані з атрибутами конфіденційності",
         [type: :string, default: nil]},
        {:ac_4_1_odp_05,
         "Визначено джерела об'єктів, які будуть пов'язані з атрибутами безпеки",
         [type: :string, default: nil]},
        {:ac_4_1_odp_06,
         "Визначено джерела об'єктів, які будуть пов'язані з атрибутами конфіденційності",
         [type: :string, default: nil]},
        {:ac_4_1_odp_07,
         "Визначено об'єкти призначення, які будуть пов'язані з атрибутами безпеки",
         [type: :string, default: nil]},
        {:ac_4_1_odp_08,
         "Визначено об'єкти призначення, які будуть пов'язані з атрибутами конфіденційності",
         [type: :string, default: nil]},
        {:ac_4_1_odp_09,
         "Визначено політику управління інформаційними потоками як основу для ухвалення рішень щодо управління потоками",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-2") do
    %{
      id: :"id-spe-ac-4-2",
      description: "Використовувати захищені домени обробки даних для забезпечення [Призначення: визначеної організацією політики управління потоками інформації] як основу для ухвалення рішень щодо управління потоками.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ДОМЕНИ ОБРОБ- (AC-4(2))",
      parameters: [
        {:ac_4_2_01,
         "Захищені домени обробки використовуються для забезпечення дотримання політики управління інформаційними потоками як основи для ухвалення рішень щодо управління потоками",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_2_odp,
         "Визначено політики управління інформаційними потоками, які будуть застосовуватися з використанням захищених доменів обробки",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-3") do
    %{
      id: :"id-spe-ac-4-3",
      description: "Здійснювати динамічне управління потоком інформації на основі [Призначення: визначених організацією політик (правил)].",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ УПРАВЛІННЯ ІНФОРМАЦІЙНИМ ПОТОКОМ (AC-4(3))",
      parameters: [
        {:ac_4_3_01,
         "Здійснюється динамічне управління потоком інформації на основі політики управління інформаційними потоками",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_3_odp,
         "Визначені політики контролю інформаційних потоків, які необхідно впроваджувати",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-4") do
    %{
      id: :"id-spe-ac-4-4",
      description: "Запобігати обходу [Призначення: механізмів управління потоками, визначених організацією] зашифрованої інформації шляхом [Вибір (один або декілька): дешифрування інформації; блокування потоку зашифрованої інформації; завершення сеансів зв’язку, що намагаються передавати зашифровану інформацію; [Призначення: визначеними організацією процедурою або методом]].",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - УПРАВЛІННЯ ПОТОКОМ ЗАШИФРОВАНОЇ ІНФОРМАЦІЇ (AC-4(4))",
      parameters: [
        {:ac_4_4_odp_01,
         "Визначено механізми контролю інформаційних потоків, які унеможливлюють обхід зашифрованої інформації",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ac_4_4_odp_02,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {дешифрування інформації; блокування потоку зашифрованої інформації; завершення сеансів зв'язку що намагаються передавати зашифровану інформацію; визначена організацією процедура або метод}",
         [type: :string, default: "AES-256-GCM"]},
        {:ac_4_4_odp_03,
         "Визначено організацією процедуру або метод, що використовується для запобігання обходу зашифрованої інформації через механізми контролю інформаційних потоків (якщо вибрано)",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-5") do
    %{
      id: :"id-spe-ac-4-5",
      description: "Впровадити [Призначення: визначені організацією обмеження] для вбудовування типів даних в інші типи даних.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ВБУДОВУВАННЯ ТИПІВ ДАНИХ (AC-4(5))",
      parameters: [
        {:ac_4_5_odp,
         "Визначеного обмеження, які слід застосовувати щодо вбудовування типів даних в інші типи даних; обмеження накладаються на вбудовування типів даних у інші типи даних",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-6") do
    %{
      id: :"id-spe-ac-4-6",
      description: "Здійснювати управління інформаційним потоком на основі [Призначення: визначених організацією метаданих].",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - МЕТАДАНІ (AC-4(6))",
      parameters: [
        {:ac_4_6_01,
         "Інформаційна система здійснює управління інформаційним потоком на основі метадані",
         [type: :string, default: nil]},
        {:ac_4_6_odp,
         "Визначено метадані, які слід використовувати як засіб управління інформаційним потоком",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-7") do
    %{
      id: :"id-spe-ac-4-7",
      description: "Впровадити [Призначення: визначені організацією односторонні інформаційні потоки] за допомогою апаратних механізмів.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - МЕХАНІЗМИ ОДНОСТОРОННЬОГО ПОТОКУ (AC-4(7))",
      parameters: [
        {:ac_4_7_01,
         "Односторонні інформаційні потоки забезпечуються за допомогою апаратних механізмів управління потоками. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-8") do
    %{
      id: :"id-spe-ac-4-8",
      description: "a) Забезпечити контроль над потоком інформації, використовуючи [Призначення: визначені організацією фільтри безпеки або політики конфіденційності] як основу для рішень щодо керування потоком для [Призначення: визначені організацією потоки інформації]; b) [Вибір (один або кілька): Блокування; Зміна; Карантин] даних після помилки обробки фільтра відповідно до [Призначення: політика безпеки або конфіденційності, визначена організацією].",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОЛІТИКИ БЕЗПЕКИ (AC-4(8))",
      parameters: [
        {:ac_4_8_01,
         "ODP[02] визначено фільтри політики конфіденційності, які будуть використовуватися як основа для забезпечення керування інформаційними потоками",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_8_a_01,
         "Управління інформаційними потоками здійснюється за допомогою <AC-04(08) _ODP[01] фільтр політики безпеки> як основи для прийняття рішень щодо управління потоками для <AC-04(08) _ODP[03] інформаційних потоків>; AC-04(08)(a)[01] контроль інформаційних потоків здійснюється за допомогою <AC-04(08) _ODP[02] фільтр політики конфіденційності> як основи для прийняття рішень щодо контролю потоків для <AC-04(08) _ODP[04] інформаційних потоків>",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-9") do
    %{
      id: :"id-spe-ac-4-9",
      description: "Примусово використовувати перевірку персоналом [Призначення: потоки інформації, визначені організацією] за таких умов: [Призначення: умови, визначені організацією].",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ПЕРЕВІРКИ, ЩО ПРОВОДИТЬ ПЕРСОНАЛ (AC-4(9))",
      parameters: [
        {:ac_4_9_01,
         "Перевірка персоналом використовуються для інформаційних потоків за умов",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_4_9_odp_01,
         "Визначено інформаційні потоки, які потребують використання перевірку персоналом",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_4_9_odp_02,
         "Визначено умови, за яких використання перевірки персоналом на інформаційні потоки має бути обов'язковим",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-10") do
    %{
      id: :"id-spe-ac-4-10",
      description: "Впровадити можливість для привілейованих адміністраторів активувати та деактивувати [Призначення: фільтри політики безпеки, що визначаються організацією] за таких умов: [Призначення: визначені організацією умови].",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - АКТИВАЦІЯ ТА ДЕАКТИВАЦІЯ ФІЛЬТРІВ ПОЛІТИКИ БЕЗПЕКИ (AC-4(10))",
      parameters: [
        {:ac_4_10_01,
         "Привілейованим адміністраторам надано можливість активувати та деактивувати <AC-04(10) _ODP[01] фільтри безпеки> за <AC-04(10) _ODP[03] умов>",
         [type: :string, default: nil]},
        {:ac_4_10_02,
         "Привілейованим адміністраторам надано можливість активувати та деактивувати <AC-04(10) _ODP[02] фільтри конфіденційності> за <AC-04(10) _ODP[04] умов>",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-11") do
    %{
      id: :"id-spe-ac-4-11",
      description: "Впровадити можливість для привілейованих адміністраторів налаштувати [Призначення: визначені організацією фільтри політики безпеки] для підтримки різних політик безпеки.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - КОНФІГУРАЦІЯ ФІЛЬТРІВ ПОЛІТИКИ БЕЗПЕКИ (AC-4(11))",
      parameters: [
        {:ac_4_11_01,
         "Привілейованим адміністраторам надано можливість налаштовувати фільтри політики безпеки для підтримки різних політик безпеки або конфіденційності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_11_02,
         "Привілейованим адміністраторам надано можливість налаштовувати фільтри політики конфіденційності для підтримки різних політик безпеки або конфіденційності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_11_odp_01,
         "Визначено фільтри політики безпеки, які привілейовані адміністратори можуть налаштовувати для підтримки різних політик безпеки та конфіденційності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_11_odp_02,
         "Визначено фільтри політики конфіденційності, які привілейовані адміністратори можуть налаштовувати для підтримки різних політик безпеки та конфіденційності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-12") do
    %{
      id: :"id-spe-ac-4-12",
      description: "При передачі інформації між різними захищеними доменами використовувати [Призначення: визначені організацією ідентифікатори типів даних] для перевірки даних, необхідних для ухвалення рішень щодо інформаційного потоку.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ІДЕНТИФІКАТОРИ ТИПУ ДАНИХ (AC-4(12))",
      parameters: [
        {:ac_4_12_odp,
         "Визначено ідентифікатори типів даних, які будуть використовуватися для перевірки даних, необхідних для ухвалення рішень щодо інформаційних потоків; AC-04(12) при передачі інформації між різними доменами безпеки, ідентифікатори типів даних використовуються для перевірки даних, необхідних для ухвалення рішень щодо інформаційних потоків",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-13") do
    %{
      id: :"id-spe-ac-4-13",
      description: "При передачі інформації між різними захищеними доменами здійснювати декомпозицію інформації на [Призначення: визначені організацією субкомпоненти, що відповідають політиці] для представлення в механізмах реалізації політики.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ДЕКОМПОЗИЦІЯ НА ВІДПОВІДНІ ПОЛІТИЦІ СУБКОМПОНЕНТИ (AC-4(13))",
      parameters: [
        {:ac_4_13_01,
         "При передачі інформації між різними доменами безпеки інформація розкладається на субкомпоненти політики для подання механізмам забезпечення дотримання політики",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_13_odp,
         "Визначено субкомпоненти політики, на які слід розкласти інформацію для подання до механізмів реалізації політики",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-14") do
    %{
      id: :"id-spe-ac-4-14",
      description: "При передачі інформації між різними захищеними доменами реалізувати [Призначення: визначені організацією фільтри політики безпеки], що вимагають повного переліку форматів, які обмежують структуру та зміст даних.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ОБМЕЖЕННЯ ФІЛЬТРА ПОЛІТИКИ БЕЗПЕКИ (AC-4(14))",
      parameters: [
        {:ac_4_14_01,
         "При передачі інформації між різними захищеними доменами, реалізовані фільтри політики безпеки вимагають повністю перелічених форматів, які обмежують структуру та вміст даних",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_14_02,
         "При передачі інформації між різними захищеними доменами, реалізовані фільтри політики конфіденційності вимагають повністю перелічених форматів, які обмежують структуру та вміст даних",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_14_odp_02,
         "Визначено фільтри політики конфіденційності, які вимагають повного переліку форматів, що обмежують структуру та зміст даних",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-15") do
    %{
      id: :"id-spe-ac-4-15",
      description: "При передачі інформації між різними захищеними доменами перевіряти інформацію на наявність [Призначення: визначеної організацією несанкціонованої інформації] та забороняти передачу такої інформації відповідно до [Призначення: визначеної організацією політики безпеки].",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ВИЯВЛЕННЯ НЕСАНКЦІОНОВАНОЇ ІНФОРМАЦІЇ (AC-4(15))",
      parameters: [
        {:ac_4_15_01,
         "При передачі інформації між різними доменами безпеки інформація перевіряється на наявність <AC- 04(15)_ODP[01] несанкціонованої інформації>",
         [type: :string, default: nil]},
        {:ac_4_15_02,
         "При передачі інформації між різними доменами безпеки забороняється передача несанкціонованої інформації відповідно до політики безпеки",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_15_03,
         "При передачі інформації між різними доменами безпеки забороняється передача несанкціонованої інформації відповідно до політики конфіденційності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_15_odp_01,
         "Визначено несанкціоновану інформацію, яку потрібно виявляти",
         [type: :string, default: nil]},
        {:ac_4_15_odp_02,
         "Визначено політику безпеки, яка вимагає заборонити передачу несанкціонованої інформації між різними доменами безпеки (якщо вибрано)",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_15_odp_03,
         "Визначено політику конфіденційності, яка вимагає заборонити передачу визначеної організацією несанкціонованої інформації між різними доменами безпеки (якщо вибрано)",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-16") do
    %{
      id: :"id-spe-ac-4-16",
      description: "",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ПЕРЕДАЧА ІНФОРМАЦІЇ ПРО ВЗАЄМОПОВ’ЯЗАНІ СИСТЕМИ (AC-4(16))",
      parameters: [
        {:ac_4_16_01,
         "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ПЕРЕДАЧА ІНФОРМАЦІЇ ПРО ВЗАЄМОПОВ’ЯЗАНІ СИСТЕМИ [Вилучено: Включено в АС-04]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-18") do
    %{
      id: :"id-spe-ac-4-18",
      description: "",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ПРИВ’ЯЗКА АТРИБУТУ БЕЗПЕКИ (AC-4(18))",
      parameters: [
        {:ac_4_18_01,
         "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ПРИВ’ЯЗКА АТРИБУТУ БЕЗПЕКИ [Вилучено: Включено в АС-16]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-19") do
    %{
      id: :"id-spe-ac-4-19",
      description: "Під час передачі інформації між різними захищеними доменами застосовувати до метаданих ту ж політику безпеки фільтрації, що й для корисних даних.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ПЕРЕВІРКА МЕТАДАНИХ (AC-4(19))",
      parameters: [
        {:ac_4_19_01,
         "При передачі інформації між різними доменами безпеки, фільтри політики безпеки реалізовано на метаданих",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_19_02,
         "При передачі інформації між різними доменами безпеки, фільтри політики конфіденційності реалізовано на метаданих",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_19_odp_01,
         "Визначено фільтри політики безпеки, які буде застосовано до метаданих (якщо вибрано)",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_4_19_odp_02,
         "Визначено фільтри політики конфіденційності, які буде застосовано до метаданих (якщо вибрано)",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-20") do
    %{
      id: :"id-spe-ac-4-20",
      description: "Впровадити [Призначення: визначені організацією рішення про схвалені конфігурації] для керування потоком [Призначення: інформації, визначеної організацією] через захищені домени.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ЗАТВЕРДЖЕНІ РІШЕННЯ (AC-4(20))",
      parameters: [
        {:ac_4_20_01,
         "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ЗАТВЕРДЖЕНІ РІШЕННЯ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:ac_4_20_odp_01,
         "Визначені рішення про схвалені конфігурації для керування потоками інформації через захищені домени",
         [type: :string, default: nil]},
        {:ac_4_20_odp_02,
         "Визначено інформацію, якою потрібно керувати, коли вона проходить через захищені домени",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-21") do
    %{
      id: :"id-spe-ac-4-21",
      description: "Відокремлювати потоки інформації логічно або фізично, використовуючи [Призначення: визначені організацією механізми та/або методи] для досягнення [Призначення: визначеного організацією необхідного поділу за типами інформації].",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ФІЗИЧНЕ ТА ЛОГІЧНЕ ВІДДІЛЕННЯ ІНФОРМАЦІЙНИХ ПОТОКІВ (AC-4(21))",
      parameters: [
        {:ac_4_21_02,
         "Інформаційні потоки логічно розділені за допомогою механізмів та/або методів для виконання необхідних розділень; інформаційні потоки фізично розділені за допомогою механізмів та/або методів для виконання розділень>; <AC-04(21)_ODP[03] необхідних",
         [type: :string, default: nil]},
        {:ac_4_21_odp_01,
         "Визначено механізми та/або методи, що використовуються для логічного розділення інформаційних потоків (якщо вибрано)",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ac_4_21_odp_02,
         "Визначено механізми та/або методи, що використовуються для фізичного розділення інформаційних потоків (якщо вибрано)",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ac_4_21_odp_03,
         "Визначено необхідні поділи за типами інформації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-22") do
    %{
      id: :"id-spe-ac-4-22",
      description: "Забезпечити доступ з одного пристрою до обчислювальних платформ, застосунків або даних, що розташовуються в декількох різних захищених доменах, одночасно запобігаючи передачі будь-якого потоку інформації між різними захищеними доменами.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ЄДИНИЙ ДОСТУП (AC-4(22))",
      parameters: [
        {:ac_4_22_01,
         "Доступ забезпечується з одного пристрою до обчислювальних платформ, застосунків або даних, що розташовуються в декількох різних захищених доменах, одночасно запобігаючи передачі інформації між різними захищеними доменами",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-23") do
    %{
      id: :"id-spe-ac-4-23",
      description: "Під час передачі інформації між різними доменами безпеки змінюйте інформацію, яка не підлягає оприлюдненню, реалізувавши [Призначення: визначена організацією дія модифікації]",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - МОДИФІКОВАНА ІНФОРМАЦІЯ, ЯКА НЕ ПІДЛЯГАЄ ОПРИЛЮДНЕННЮ (AC-4(23))",
      parameters: [
        {:ac_4_23_odp,
         "Визначено дію модифікації, що застосовується до інформації, яка не підлягає оприлюдненню; AC-04(23) при передачі інформації між доменами безпеки інформація, що не підлягає оприлюдненню, модифікується шляхом реалізації дія модифікації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-24") do
    %{
      id: :"id-spe-ac-4-24",
      description: "Під час передачі інформації між різними доменами безпеки аналізуйте вхідні дані у внутрішньому нормалізованому форматі та повторно генеруйте дані, щоб вони відповідали призначеній специфікації.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ НОРМАЛІЗОВАНИЙ ФОРМАТ (AC-4(24))",
      parameters: [
        {:ac_4_24_1,
         "При передачі інформації між різними доменами безпеки вхідні дані розбираються у внутрішній, нормалізований формат",
         [type: :string, default: nil]},
        {:ac_4_24_2,
         "При передачі інформації між різними доменами безпеки дані регенеруються, щоб відповідати їхній специфікації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-25") do
    %{
      id: :"id-spe-ac-4-25",
      description: "Під час передачі інформації між різними доменами безпеки очищуйте дані, щоб мінімізувати [Вибір (один або кілька): доставка зловмисного вмісту, керування та керування зловмисним кодом, доповнення зловмисного коду та стеганографічно закодовані дані; витік конфіденційної інформації] відповідно до [Призначення: політика, визначена організацією]].",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ОЧИЩЕННЯ ДАНИХ (AC-4(25))",
      parameters: [
        {:ac_4_25_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {доставка шкідливого коду, керування та контроль шкідливого коду, доповнення шкідливого коду та даних, закодованих стеганографією; витік конфіденційної інформації}",
         [type: :string, default: nil]},
        {:ac_4_25_odp_02,
         "Визначено політику очищення даних",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-26") do
    %{
      id: :"id-spe-ac-4-26",
      description: "Під час передачі інформації між різними доменами безпеки записуйте та перевіряйте дії фільтрації вмісту та результати для інформації, що фільтрується.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ДІЇ З ФІЛЬТРАЦІЇ АУДИТУ (AC-4(26))",
      parameters: [
        {:ac_4_26_01,
         "При передачі інформації між різними доменами безпеки дії з фільтрації вмісту фіксуються і перевіряються",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ac_4_26_02,
         "При передачі інформації між різними доменами безпеки, результати для інформації, що фільтрується, записуються і перевіряються",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-27") do
    %{
      id: :"id-spe-ac-4-27",
      description: "НАДЛИШКОВІ/НЕЗАЛЕЖНІ ФІЛЬТРУЮЧІ МЕХАНІЗМИ - Під час передачі інформації між різними доменами безпеки впроваджуйте рішення фільтрації вмісту, які забезпечують надлишкові та незалежні механізми фільтрації для кожного типу даних.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ КОВІ/НЕЗАЛЕЖНІ ФІЛЬТРУЮЧІ МЕХАНІЗМИ (AC-4(27))",
      parameters: [
        {:ac_4_27_01,
         "Під час передачі інформації між системами безпеки впроваджені рішення для фільтрації контенту забезпечують надлишкові та незалежні механізми фільтрації для кожного типу даних",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-28") do
    %{
      id: :"id-spe-ac-4-28",
      description: "Під час передачі інформації між різними доменами безпеки запровадьте конвеєр лінійного фільтрування вмісту, який забезпечується дискреційним і обов’язковим контролем доступу.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ЛІНІЙНІ ФІЛЬТРУВАЛЬНІ КАНАЛИ (AC-4(28))",
      parameters: [
        {:ac_4_28_01,
         "При передачі інформації між доменами безпеки реалізовано лінійний конвеєр фільтрації контенту, який забезпечується дискретними та обов'язковими засобами контролю доступу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-29") do
    %{
      id: :"id-spe-ac-4-29",
      description: "Під час передачі інформації між різними доменами безпеки використовуйте механізми оркестровки фільтрів вмісту, щоб забезпечити: a. Механізми фільтрації вмісту успішно завершують виконання без помилок; b. Дії фільтрації вмісту виконуються в правильному порядку та відповідають [Призначення: політика, визначена організацією]",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ХАНІЗМІВ ОРКЕСТРОВКИ (AC-4(29))",
      parameters: [
        {:ac_4_29_a,
         "При передачі інформації між доменами безпеки використовуються механізми оркестрування фільтрації контенту, які гарантують, що механізми фільтрації контенту успішно завершать виконання без помилок",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ac_4_29_b_01,
         "При передачі інформації між доменами безпеки використовуються механізми оркестрування фільтрації контенту, які гарантують, що дії з фільтрації контенту відбуваються в правильному порядку",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ac_4_29_b_02,
         "При передачі інформації між доменами безпеки використовуються механізми оркестрування фільтрації контенту, які гарантують, що дії з фільтрації контенту відповідають політиці. ",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ac_4_29_odp,
         "Визначено політику щодо дій з фільтрації контенту",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-30") do
    %{
      id: :"id-spe-ac-4-30",
      description: "Під час передачі інформації між різними доменами безпеки реалізуйте механізми фільтрації вмісту за допомогою кількох процесів.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - МЕХАНІЗМИ ФІЛЬТРАЦІЇ З ВИКОРИСТАННЯМ КІЛЬКОХ ПРОЦЕСІВ (AC-4(30))",
      parameters: [
        {:ac_4_30_01,
         "При передачі інформації між доменами безпеки реалізовані механізми контент-фільтрації з використанням декількох процесів. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-31") do
    %{
      id: :"id-spe-ac-4-31",
      description: "Під час передачі інформації між різними доменами безпеки запобігайте передачі вмісту, який не пройшов перевірку фільтрації до домену-одержувача.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ЗАПОБІГАННЯ СПРОБАМ ПЕРЕДАЧІ ВМІСТУ, ЯКИЙ НЕ ПРОЙШОВ ПЕРЕВІРКУ ФІЛЬТРАЦІЇ (AC-4(31))",
      parameters: [
        {:ac_4_31_01,
         "При передачі інформації між різними доменами безпеки запобігається передача вмісту який не пройшов фільрацію",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-4-32") do
    %{
      id: :"id-spe-ac-4-32",
      description: "Під час передачі інформації між різними доменами безпеки, процес, який передає інформацію між конвеєрами фільтрації: a. не фільтрує вміст повідомлення; b. перевіряє метадані фільтрації; c. забезпечує успішне завершення фільтрації вмісту, пов’язаного з метаданими фільтрації; і d. передає вміст до цільового фільтруючого конвеєра.",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ - ВИМОГИ ДО ПРОЦЕСУ ПЕРЕДАЧІ ІНФОРМАЦІЇ (AC-4(32))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ac-5") do
    %{
      id: :"id-spe-ac-5",
      description: "a. Розмежувати і документувати [Призначення: визначені організацією обов’язки окремих осіб]. b. Установити правила авторизації доступу для підтримки розмежування обов’язків.",
      title: "РОЗМЕЖУВАННЯ ОБОВ'ЯЗКІВ (AC-5)",
      parameters: [
        {:ac_5_odp,
         "Визначено обов'язки осіб, які потребують розмежування; AC-05[a] обов'язки осіб визначені та задокументовані; AC-05[b] визначено права авторизації доступу до системи для підтримки розмежування обов'язків",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-6") do
    %{
      id: :"id-spe-ac-6",
      description: "Впровадити принцип мінімізації повноважень, який дозволяє користувачам (або процесам, що діють від імені користувачів) здійснювати лише такі авторизовані звернення, які необхідні для виконання визначених завдань відповідно до цілей (призначення, місії) організації та функцій.",
      title: "МІНІМІЗАЦІЯ ПОВНОВАЖЕНЬ (AC-6)",
      parameters: [
        {:ac_6_01,
         "Застосовується принцип мінімалізації повноважень, який дозволяє користувачам (або процесам, що діють від імені користувачів) здійснювати лише такі авторизовані звернення, які необхідні для виконання поставлених завдань організації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-6-1") do
    %{
      id: :"id-spe-ac-6-1",
      description: "",
      title: "МІНІМІЗАЦІЯ ПОВНОВАЖЕНЬ - АВТОРИЗОВАНИЙ ДОСТУП ДО ФУНКЦІЙ БЕЗПЕКИ (AC-6(1))",
      parameters: [
        {:ac_6_1_a_01,
         "Авторизовано доступ для осіб та ролей до функцій безпеки (розгорнуті на апаратному забезпеченні)",
         [type: :string, default: nil]},
        {:ac_6_1_a_02,
         "Авторизовано доступ для осіб та ролей до функцій безпеки (роз- горнуті на програмному забезпеченні)",
         [type: :string, default: nil]},
        {:ac_6_1_a_03,
         "Авторизовано доступ для осіб та ролей до функцій безпеки (розгорнуті на мікропрограмному забезпеченні)",
         [type: :string, default: nil]},
        {:ac_6_1_b,
         "Авторизовано доступ для осіб та ролей до інформації",
         [type: :string, default: nil]},
        {:ac_6_1_odp_01,
         "Визначені особи або ролі з авторизованим доступом до функцій безпеки та інформації, що має відношення до безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_6_1_odp_02,
         "Визначені функції безпеки (розгорнуті в апаратному забезпеченні) для авторизованого доступу",
         [type: :string, default: nil]},
        {:ac_6_1_odp_03,
         "Визначені функції безпеки (розгорнуті в програмному забезпеченні) для авторизованого доступу",
         [type: :string, default: nil]},
        {:ac_6_1_odp_04,
         "Визначені функції безпеки (розгорнуті в мікропрограмному забезпеченні) для авторизованого доступу",
         [type: :string, default: nil]},
        {:ac_6_1_odp_05,
         "Визначено інформацію, важливу для забезпечення безпеки, для авторизованого доступу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-6-2") do
    %{
      id: :"id-spe-ac-6-2",
      description: "Вимагати від користувачів облікових записів системи або ролей, які мають доступ до [Призначення: визначених організацією функцій безпеки або інформації, що стосується безпеки], використовувати непривілейовані облікові записи чи ролі під час доступу до незахищених функцій.",
      title: "МІНІМІЗАЦІЯ ПОВНОВАЖЕНЬ - НЕПРИВІЛЕЙОВАНИЙ ДОСТУП ДО НЕЗАХИЩЕНИХ ФУНКЦІЙ (AC-6(2))",
      parameters: [
        {:ac_6_2_01,
         "Користувачі облікових записів (або ролей) системи з доступом до функцій безпеки або інформації, що стосується безпеки, повинні використовувати непривілейовані облікові записи або ролі під час доступу до незахищених функцій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_6_2_odp,
         "Визначені функції безпеки або інформація, що стосується безпеки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-6-4") do
    %{
      id: :"id-spe-ac-6-4",
      description: "Надати окремі домени обробки даних для забезпечення більш точного розподілу повноважень користувача.",
      title: "МІНІМІЗАЦІЯ ПОВНОВАЖЕНЬ - РОЗДІЛЬНІ ДОМЕНИ ОБРОБКИ (AC-6(4))",
      parameters: [
        {:ac_6_4_01,
         "Надаються окремі домени обробки для більш тонкого розподілу повноважень користувачів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-6-5") do
    %{
      id: :"id-spe-ac-6-5",
      description: "Обмежити привілейовані облікові записи в системі згідно з [Призначення: визначеним організацією персоналом або ролями].",
      title: "МІНІМІЗАЦІЯ ПОВНОВАЖЕНЬ - ПРИВІЛЕЙОВАНІ ОБЛІКОВІ ЗАПИСИ (AC-6(5))",
      parameters: [
        {:ac_6_5_01,
         "Привілейовані облікові записи в системі обмежено персонал або ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_6_5_odp,
         "Визначено персонал або ролі, яким мають бути обмежені привілейовані облікові записи в системі",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-6-6") do
    %{
      id: :"id-spe-ac-6-6",
      description: "Заборонити привілейований доступ до системи користувачам, які не належать до організації.",
      title: "МІНІМІЗАЦІЯ ПОВНОВАЖЕНЬ - ПРИВІЛЕЙОВАНИЙ ДОСТУП КОРИСТУВАЧАМИ, ЩО НЕ НАЛЕЖАТЬ ДО ОРГАНІЗАЦІЇ (AC-6(6))",
      parameters: [
        {:ac_6_6_01,
         "Привілейований доступ до системи для користувачів, які не є членами організації, заборонено",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-6-7") do
    %{
      id: :"id-spe-ac-6-7",
      description: "a) Переглядати [Призначення: з визначеною організацією частотою] повноваження призначених для [Призначення: визначених організацією посад або класів користувачів] для перевірки необхідності таких повноважень; b) За необхідності перепризначити або зняти повноваження, правильного відображення цілей (місії) організації та потреб організації. для",
      title: "МІНІМІЗАЦІЯ ПОВНОВАЖЕНЬ - ПЕРЕГЛЯД ПОВНОВАЖЕНЬ КОРИСТУВАЧА (AC-6(7))",
      parameters: [
        {:ac_6_7_a,
         "Повноваження, призначені ролям і класам, переглядаються з частотою для перевірки необхідності таких повноважень",
         [type: :integer, default: 30]},
        {:ac_6_7_b,
         "Привілеї перепризначаються або знімаються, якщо це необхідно, для правильного відображення місії організації та потреб",
         [type: :string, default: nil]},
        {:ac_6_7_odp_01,
         "Визначено частоту перегляду повноважень, призначених ролям або класам користувачів",
         [type: :integer, default: 30]},
        {:ac_6_7_odp_02,
         "Визначено ролі або класи користувачів, яким призначено повноваження ",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-6-8") do
    %{
      id: :"id-spe-ac-6-8",
      description: "Запобігати виконанню програмного забезпечення на рівні привілеїв вищому, ніж доступний користувачеві, який використовує програмне забезпечення [Призначення: визначене організацією програмне забезпечення].",
      title: "МІНІМІЗАЦІЯ ПОВНОВАЖЕНЬ - РІВНІ ПРИВІЛЕЇВ ДЛЯ ВИКОНАННЯ КОДУ (AC-6(8))",
      parameters: [
        {:ac_6_8_01,
         "Програмне забезпечення заборонено виконувати з вищими рівнями привілеїв, ніж у користувачів, які виконують це програмне забезпечення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-6-9") do
    %{
      id: :"id-spe-ac-6-9",
      description: "Реєструвати виконання привілейованих функцій.",
      title: "МІНІМІЗАЦІЯ ПОВНОВАЖЕНЬ - АУДИТ ВИКОРИСТАННЯ ПРИВІЛЕЙОВАНИХ ФУНКЦІЙ (AC-6(9))",
      parameters: [
        {:ac_6_9_01,
         "Проводиться аудит виконання привілейованих функцій",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-6-10") do
    %{
      id: :"id-spe-ac-6-10",
      description: "Вжити заходи для запобігання можливості виконувати привілейовані функції непривілейованими користувачами.",
      title: "МІНІМІЗАЦІЯ ПОВНОВАЖЕНЬ - ЗАБОРОНА НЕПРИВІЛЕЙОВАНИМ КОРИСТУВАЧАМ ВИКОНУВАТИ ПРИВІЛЕЙОВАНІ ФУНКЦІЇ (AC-6(10))",
      parameters: [
        {:ac_6_10_01,
         "МІНІМІЗАЦІЯ ПОВНОВАЖЕНЬ - ЗАБОРОНА НЕПРИВІЛЕЙОВАНИМ КОРИСТУВАЧАМ ВИКОНУВАТИ ПРИВІЛЕЙОВАНІ ФУНКЦІЇ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-7") do
    %{
      id: :"id-spe-ac-7",
      description: "a. Встановити обмеження на [Призначення: визначену організацією кількість] послідовних неуспішних спроб входу користувача в систему впродовж [Призначення: визначеного організацією часового періоду]. b. Автоматично виконати [Вибір (один або декілька): блокування облікового запису/вузла на [Призначення: визначений організацією часовий період]; блокування облікового запису/вузла, доки він не буде розблокований адміністратором; затримання наступної команди входу в систему за [Надання: визначеним організацією алгоритмом затримки]; виконати [Призначення: визначені організацією дії]], коли перевищено максимальну кількість невдалих спроб входу в систему.",
      title: "НЕВДАЛІ СПРОБИ ВХОДУ В СИСТЕМУ (AC-7)",
      parameters: [
        {:ac_7_a,
         "Застосовано обмеження на кількість послідовних неуспішних спроб входу користувача протягом періоду часу",
         [type: :integer, default: 30]},
        {:ac_7_odp_01,
         "Визначається кількість послідовних неуспішних спроб входу користувача, дозволених протягом певного періоду часу",
         [type: :integer, default: 30]},
        {:ac_7_odp_02,
         "Визначено період часу, яким обмежується кількість послідовних неуспішних спроб входу користувача",
         [type: :integer, default: 30]},
        {:ac_7_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {заблокувати обліковий запис або вузол на період часу; заблокувати обліковий запис або вузол до зняття адміністратором; затримати наступний запит на вхід за алгоритмом затримки; повідомити системного адміністратора; виконати іншу дію}",
         [type: :string, default: "AES-256-GCM"]},
        {:ac_7_odp_04,
         "Період часу, на який буде заблоковано обліковий запис або вузол (якщо вибрано)",
         [type: :integer, default: 30]},
        {:ac_7_odp_05,
         "Визначено алгоритм затримки наступного запиту на вхід (якщо вибрано)",
         [type: :string, default: "AES-256-GCM"]},
        {:ac_7_odp_06,
         "Інша дія, яка буде виконана після перевищення максимальної кількості невдалих спроб (якщо вибрано)",
         [type: :integer, default: 3]}
      ]
    }
  end

  def spec(:"id-spe-ac-7-1") do
    %{
      id: :"id-spe-ac-7-1",
      description: "",
      title: "НЕВДАЛІ СПРОБИ ВХОДУ В СИСТЕМУ - АВТОМАТИЧНЕ БЛОКУВАННЯ ОБЛІКОВОГО ЗАПИСУ (AC-7(1))",
      parameters: [
        {:ac_7_1_01,
         "НЕВДАЛІ СПРОБИ ВХОДУ В СИСТЕМУ - АВТОМАТИЧНЕ БЛОКУВАННЯ ОБЛІКОВОГО ЗАПИСУ [Вилучено: Включено в АС-07]",
         [type: :integer, default: 3]}
      ]
    }
  end

  def spec(:"id-spe-ac-7-2") do
    %{
      id: :"id-spe-ac-7-2",
      description: "Очистити або стерти інформацію з [Призначення: визначених організацією мобільних пристроїв] на основі [Призначення: визначених організацією вимог та методик очищення чи стирання] після [Призначення: визначеної організацією кількості] послідовних невдалих спроб входу в систему з пристрою.",
      title: "НЕВДАЛІ СПРОБИ ВХОДУ В СИСТЕМУ - ОЧИЩЕННЯ АБО СТИРАННЯ МОБІЛЬНОГО ПРИСТРОЮ (AC-7(2))",
      parameters: [
        {:ac_7_2_01,
         "Інформація очищується або стирається з мобільних пристроїв на основі вимог або методів очищення або стирання після <AC-07(02)_ODP[03 кількість> послідовних, невдалих спроб входу на пристрій",
         [type: :integer, default: 3]},
        {:ac_7_2_odp_01,
         "Визначено мобільні пристрої, які підлягають очищенню або стиранню інформації",
         [type: :string, default: nil]},
        {:ac_7_2_odp_02,
         "Визначено вимоги та методи очищення чи стирання інформації з мобільних пристроїв",
         [type: :string, default: nil]},
        {:ac_7_2_odp_03,
         "Визначається кількість послідовних невдалих спроб входу в систему до того, як інформація буде очищена або стерта з мобільних пристроїв",
         [type: :integer, default: 3]}
      ]
    }
  end

  def spec(:"id-spe-ac-7-3") do
    %{
      id: :"id-spe-ac-7-3",
      description: "Обмежити кількість невдалих спроб входу за допомогою біометрики [Призначення: визначена організацією кількість].",
      title: "НЕВДАЛІ СПРОБИ ВХОДУ В СИСТЕМУ - ОБМЕЖЕННЯ НА СПРОБИ БІОМЕТРИЧНОГО ВХОДУ (AC-7(3))",
      parameters: [
        {:ac_7_3_01,
         "Визначено кількість невдалих спроб входу за допомогою біометрики обмежно кількість невдалих спроб входу за допомогою біометрики",
         [type: :integer, default: 3]}
      ]
    }
  end

  def spec(:"id-spe-ac-7-4") do
    %{
      id: :"id-spe-ac-7-4",
      description: "a) Дозволити використання [Призначення: визначені організацією фактори автентифікації], які відрізняються від основних факторів автентифікації після перевищення визначеної організацією кількості послідовних невдалих спроб входу в систему; b) Обмежити [Призначення: визначена організацією кількість] послідовних невдалих спроб входу за допомогою використання альтернативних факторів користувачем протягом [Призначення: визначеного організацією періоду часу].",
      title: "НЕВДАЛІ СПРОБИ ВХОДУ В СИСТЕМУ - ВИКОРИСТАННЯ АЛЬТЕРНАТИВНОГО ФАКТОРА (AC-7(4))",
      parameters: [
        {:ac_7_4_a,
         "Фактори автентифікації, які відрізняються від основних факторів автентифікації, дозволяється використовувати після перевищення кількості визначених організацією послідовних невдалих спроб входу; AC-07(04)(b) введено обмеження на послідовних невдализ спроб входу через використання користувачем альтернативних факторів протягом періоду часу",
         [type: :integer, default: 30]},
        {:ac_7_4_odp_01,
         "Визначено фактори автентифікації, які дозволено використовувати, але які відрізняються від основних факторів автентифікації",
         [type: :string, default: nil]},
        {:ac_7_4_odp_02,
         "Визначено кількість послідовних, недійсних спроб входу через використання альтернативних факторів",
         [type: :integer, default: 3]},
        {:ac_7_4_odp_03,
         "Визначено період часу, протягом якого користувач може спробувати увійти через альтернативні фактори",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ac-8") do
    %{
      id: :"id-spe-ac-8",
      description: "a. b. Демонструвати користувачам [Призначення: визначене організацією сповіщення або банер про використання системи] перед тим, як надавати доступ до системи, що забезпечує безпеку та приватність відповідно до чинних законів, нормативних документів, наказів, директив, політик, правил, стандартів і керівних принципів, які зазначають, що: 1. користувачі здійснюють доступ до урядової системи; 2. використання системи може контролюватися, реєструватися та підлягати аудиту; 3. несанкціоноване використання системи забороняється та приводить до кримінальної та цивільної відповідальності; 4. використання системи означає згоду на моніторинг і запис дій користувача. Зберігати сповіщення або банер на екрані, доки користувачі не визнають умови використання та не приймуть явних дій для входу в систему або подальшого доступу до системи. c. Для загальнодоступних систем: 1. демонструвати інформацію про умови використання системи [Призначення: визначені організацією умови], перш ніж надавати подальший доступ до загальнодоступної системи; 2. демонструвати посилання, якщо такі є, на моніторинг, запис або аудит, які узгоджуються з акомодацією приватності для таких систем, які зазвичай забороняють такі дії; 3. мати опис авторизованого використання системи.",
      title: "ПОПЕРЕДЖЕННЯ ПРО ВИКОРИСТАННЯ СИСТЕМИ (AC-8)",
      parameters: [
        {:ac_8_c_02,
         "Визначається сповіщення або банер про використання системи, який система буде показувати користувачам перед наданням доступу до системи; визначено умови використання системи, які система відображатиме перед наданням подальшого доступу; повідомлення про використання системи відображається користувачам перед наданням доступу до системи, яке містить повідомлення про конфіденційність і безпеку, що відповідають чинним законам, нормативним документам, наказам, директивам, політикам, правилам, стандартам і керівним принципам; у повідомленні про використання системи зазначено, що користувачі отримують доступ до урядової системи; у повідомленні про використання системи зазначено, що використання системи може контролюватися, реєструватися та підлягати аудиту; у повідомленні про використання системи зазначено, що несанкціоноване використання системи заборонено і тягне за собою кримінальну та цивільну відповідальність; у повідомленні про використання системи зазначено, що використання системи означає згоду на моніторинг і запис дій; сповіщення або банер залишається на екрані до тих пір, поки користувачі не визнають умови використання та не приймуть явні дії для входу в систему або подальшого доступу до неї; для загальнодоступних систем інформація про використання системи умови відображається перед наданням подальшого доступу до загальнодоступної системи; для загальнодоступних систем відображаються будь-які посилання на моніторинг, запис або аудит, які узгоджуються з положеннями про конфіденційність таких систем, що зазвичай забороняють ці види діяльності; для загальнодоступних систем додається опис авторизованого використання системи",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-9") do
    %{
      id: :"id-spe-ac-9",
      description: "Сповіщати користувача після успішного входу (доступу) до системи про дату та час останнього входу (доступу).",
      title: "СПОВІЩЕННЯ ПРО ПОПЕРЕДНІЙ ВХІД (ДОСТУП) (AC-9)",
      parameters: [
        {:ac_9_01,
         "Система повідомляє користувача при успішному вході (доступі) до системи про дату та час останнього входу (доступу)",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ac-9-1") do
    %{
      id: :"id-spe-ac-9-1",
      description: "",
      title: "СПОВІЩЕННЯ ПРО ПОПЕРЕДНІЙ ВХІД (ДОСТУП) - НЕВДАЛІ СПРОБИ ВХОДУ ДО СИСТЕМИ (AC-9(1))",
      parameters: [
        {:ac_9_1_01,
         "Система сповіщає користувача після успішного входу / доступу про кількість невдалих спроб входу / доступу з моменту останнього успішного входу / доступу",
         [type: :integer, default: 3]}
      ]
    }
  end

  def spec(:"id-spe-ac-9-2") do
    %{
      id: :"id-spe-ac-9-2",
      description: "Сповіщати користувача, після успішного входу/доступу до системи про кількість [Вибір: успішних спроб доступу/входу; невдалих спроб входу/доступу; обидва варіанти] за [Призначення: визначений організацією період часу].",
      title: "СПОВІЩЕННЯ ПРО ПОПЕРЕДНІЙ ВХІД (ДОСТУП) - УСПІШНІ ТА НЕВДАЛІ СПРОБИ ВХОДУ ДО СИСТЕМИ (AC-9(2))",
      parameters: [
        {:ac_9_2_01,
         "Після успішного входу в систему користувач отримує повідомлення про кількість ЗНАЧЕННЯ ВИБРАНОГО ПАРАМЕТРА протягом періоду часу",
         [type: :integer, default: 30]},
        {:ac_9_2_odp_01,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {успішних спроб доступу/входу; невдалих спроб входу/доступу; обидва варіанти}",
         [type: :integer, default: 3]},
        {:ac_9_2_odp_02,
         "Визначається період часу, протягом якого система повідомляє користувача про кількість успішних спроб входу в систему, невдалих спроб входу або про обидва випадки",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ac-9-3") do
    %{
      id: :"id-spe-ac-9-3",
      description: "Сповіщати користувача, після успішного входу/доступу, про внесення змін до [Призначення: певних характеристик/параметрів облікового запису користувача, визначених організацією] протягом [Призначення: визначеного організацією періоду часу].",
      title: "СПОВІЩЕННЯ ПРО ПОПЕРЕДНІЙ ВХІД (ДОСТУП) - ПОВІДОМЛЕННЯ ПРО ЗМІНИ В ОБЛІКОВОМУ ЗАПИСІ (AC-9(3))",
      parameters: [
        {:ac_9_3_01,
         "Визначено період часу, протягом якого система повідомляє користувача про зміни характеристик або параметрів, пов'язаних із безпекою облікового запису користувача; після успішного входу користувач отримує повідомлення про зміни характеристик або параметрів, пов'язаних із безпекою протягом періоду часу",
         [type: :integer, default: 30]},
        {:ac_9_3_odp_01,
         "Визначено зміни характеристик або параметрів, пов'язаних із безпекою облікового запису користувача, які потребують сповіщення; AC-09(03)_ODP[02]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-9-4") do
    %{
      id: :"id-spe-ac-9-4",
      description: "Повідомляти користувачеві, після успішного входу/доступу, наступну додаткову інформацію: [Призначення: інформація, визначена організацією, яка повинна бути включена на додаток до дати та часу останнього входу/доступу].",
      title: "СПОВІЩЕННЯ ПРО ПОПЕРЕДНІЙ ВХІД (ДОСТУП) – ДОДАТКОВА ІНФОРМАЦІЯ ПРО ВХІД (AC-9(4))",
      parameters: [
        {:ac_9_4_01,
         "Після успішного входу користувач отримує повідомлення додаткова інформація",
         [type: :string, default: nil]},
        {:ac_9_4_odp,
         "Визначено додаткову інформацію, про яку слід повідомити користувача",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-10") do
    %{
      id: :"id-spe-ac-10",
      description: "Обмежити кількість одночасних сеансів для кожного [Призначення: визначеного організацією облікового запису та/або типу облікового запису] до [Призначення: визначеної організацією кількості].",
      title: "УПРАВЛІННЯ ПАРАЛЕЛЬНОЮ СЕСІЄЮ (AC-10)",
      parameters: [
        {:ac_10_01,
         "Кількість одночасних сеансів для кожного облікового запису та/або типів облікових записів обмежена кількість",
         [type: :integer, default: 30]},
        {:ac_10_odp_02,
         "Визначено кількість одночасних сеансів, дозволених для кожного облікового запису та/або типу облікового запису",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ac-11") do
    %{
      id: :"id-spe-ac-11",
      description: "a. Заборонити подальший доступ до системи шляхом ініціювання блокування пристрою після [Призначення: визначеного організацією періоду] бездіяльності або після отримання запиту від користувача. b. Зберігати блокування пристрою, поки користувач не відновить доступ, використовуючи встановлені процедури ідентифікації та автентифікації.",
      title: "БЛОКУВАННЯ ПРИСТРОЮ (AC-11)",
      parameters: [
        {:ac_11_b,
         "Блокування пристрою зберігається доти, доки користувач не відновить доступ за допомогою встановлених процедур ідентифікації та автентифікації",
         [type: :string, default: nil]},
        {:ac_11_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {ініціювання блокування пристрою після періоду неактивності; вимога до користувача ініціювати блокування пристрою перед тим, як залишити систему без нагляду}",
         [type: :integer, default: 30]},
        {:ac_11_odp_02,
         "Часовий проміжок бездіяльності, після якого ініціюється блокування пристрою (якщо вибрано)",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ac-11-1") do
    %{
      id: :"id-spe-ac-11-1",
      description: "",
      title: "БЛОКУВАННЯ ПРИСТРОЮ - ПРИХОВАНІ ДИСПЛЕЇ (AC-11(1))",
      parameters: [
        {:ac_11_1_01,
         "Система приховує (через блокування сеансу) інформацію, попередньо видиму на дисплеї, загальнодоступним зображенням",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-12") do
    %{
      id: :"id-spe-ac-12",
      description: "Сеанс користувача має завершуватися автоматично після [Призначення: визначених організацією умов або тригерних подій, що вимагають припинення сеансу].",
      title: "Припинення сеансу (AC-12)",
      parameters: [
        {:ac_12_01,
         "Сеанс користувача автоматично завершується після виконання умов або подій",
         [type: :string, default: nil]},
        {:ac_12_odp,
         "Визначено умови або події, що вимагають припинення сеансу",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-12-1") do
    %{
      id: :"id-spe-ac-12-1",
      description: "Забезпечити можливість припинення сеансів зв’язку з ініціативи користувача, коли автентифікація використовується для отримання доступу до [Призначення: визначених організацією інформаційних ресурсів].",
      title: "ПРИПИНЕННЯ СЕАНСУ - ІНІЦІЙОВАНЕ КОРИСТУВАЧЕМ БЛОКУВАННЯ (AC-12(1))",
      parameters: [
        {:ac_12_1_01,
         "Для сеансів зв'язку, ініційованих користувачем, передбачено можливість виходу з системи щоразу, коли автентифікація використовується для отримання доступу до інформаційних ресурсів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-12-2") do
    %{
      id: :"id-spe-ac-12-2",
      description: "Відобразити виразне повідомлення для користувача, що вказує на достовірне припинення автентифікованих сеансів зв’язку.",
      title: "ПРИПИНЕННЯ СЕАНСУ - ПОВІДОМЛЕННЯ ПРО ПРИПИНЕННЯ СЕАНСУ (AC-12(2))",
      parameters: [
        {:ac_12_2_01,
         "Користувачам буде показано явне повідомлення про завершення сеансу автентифікованого зв'язку",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-12-3") do
    %{
      id: :"id-spe-ac-12-3",
      description: "Відобразити виразне повідомлення користувачам, що вказує, що сесія добігає кінця [Завдання: визначений організацією час до кінця сесії].",
      title: "ПРИПИНЕННЯ СЕАНСУ - ЗАСТЕРЕЖНЕ ПОВІДОМЛЕННЯ ПРО ТЕ, ЩО ЧАС СЕСІЇ ДОБІГАЄ КІНЦЯ (AC-12(3))",
      parameters: [
        {:ac_12_3_01,
         "Визначено час до кінця сесії для відображення користувачам; виводиться явне повідомлення користувачам про те, що сеанс завершиться у час",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ac-13") do
    %{
      id: :"id-spe-ac-13",
      description: "",
      title: "НАГЛЯД ТА ОГЛЯД - УПРАВЛІННЯ ДОСТУПОМ (AC-13)",
      parameters: [
        {:ac_13_01,
         "НАГЛЯД ТА ОГЛЯД - УПРАВЛІННЯ ДОСТУПОМ [Вилучено: включено в АС-02 та АU-06]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-14") do
    %{
      id: :"id-spe-ac-14",
      description: "a. Визначити [Призначення: дозволені організацією дії користувачів], які можуть виконуватися в системі без ідентифікації або автентифікації відповідно до завдань та функцій організації. b. Документувати та визначити відповідне обґрунтування в плані безпеки системи дій користувача, які не потребують ідентифікації або автентифікації.",
      title: "ДОЗВОЛЕНІ ДІЇ БЕЗ ІДЕНТИФІКАЦІЇ АБО АВТЕНТИФІКАЦІЇ (AC-14)",
      parameters: [
        {:ac_14_a,
         "Визначено дії користувача, які можуть бути виконані в системі без ідентифікації або автентифікації, що відповідають місії та функціям організації",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ac_14_a_02,
         "Обґрунтування дій користувачів, які не потребують ідентифікації або автентифікації, надається в плані захисту інформації",
         [type: :string, default: nil]},
        {:ac_14_b_01,
         "Дії користувачів, які не потребують ідентифікації або автентифікації, задокументовані в плані захисту інформації",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ac_14_odp,
         "Визначено дії користувача, які можуть бути виконані в системі без ідентифікації або автентифікації",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-14-1") do
    %{
      id: :"id-spe-ac-14-1",
      description: "",
      title: "ДОЗВОЛЕНІ ДІЇ БЕЗ ІДЕНТИФІКАЦІЇ НЕОБХІДНЕ ВИКОРИСТАННЯ (AC-14(1))",
      parameters: [
        {:ac_14_1_01,
         "ДОЗВОЛЕНІ ДІЇ БЕЗ ІДЕНТИФІКАЦІЇ НЕОБХІДНЕ ВИКОРИСТАННЯ АБО АВТЕНТИФІКАЦІЇ - [Вилучено: включено до AC-14]",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-15") do
    %{
      id: :"id-spe-ac-15",
      description: "",
      title: "АВТОМАТИЗОВАНЕ МАРКУВАННЯ (AC-15)",
      parameters: [
        {:ac_15_01,
         "АВТОМАТИЗОВАНЕ МАРКУВАННЯ [Вилучено: включено до MP-03]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-16") do
    %{
      id: :"id-spe-ac-16",
      description: "a. Визначити засоби для асоціювання (пов’язання) [Призначення: визначених організацією типів атрибутів безпеки та приватності], що приймають [Призначення: визначені організацією значення атрибутів безпеки та приватності] з інформацією, яка зберігається, обробляється та/або передається. b. Пов’язані атрибути безпеки та приватності мають створюватися і зберігатися разом з інформацією. c. Встановити дозволені [Призначення: визначені організацією атрибути безпеки] для [Призначення: систем, визначених організацією]. d. Визначити дозволені [Призначення: визначені організацією значення або діапазони] для кожного з встановлених атрибутів безпеки та приватності.",
      title: "АТРИБУТИ БЕЗПЕКИ ТА ПРИВАТНОСТІ (AC-16)",
      parameters: [
        {:ac_16_c_02,
         "Визначено типи атрибутів безпеки, які мають бути пов'язані зі значеннями атрибутів безпеки для інформації, що зберігається, обробляється та/або передається; визначено значення атрибутів конфіденційності для типів атрибутів конфіденційності; визначено системи, для яких мають бути встановлені дозволені атрибути безпеки; визначено системи, для яких мають бути встановлені дозволені атрибути конфіденційності; визначено атрибути безпеки, визначені як частина AC-16(a), які дозволені для систем; визначено атрибути конфіденційності, визначені як частина AC-16(a), які дозволені для систем; визначено значення атрибутів або діапазони для встановлених атрибутів; визначено частоту, з якою слід переглядати атрибути безпеки на предмет відповідності; визначено частоту, з якою слід переглядати атрибути конфіденційності на предмет відповідності; надано засоби для асоціювання типів атрибутів безпеки зі значеннями атрибутів безпеки для інформації, що зберігається, обробляється та/або передається надано засоби для асоціювання типів атрибутів конфіденційності зі значеннями атрибутів конфіденційності для інформації, що зберігається, обробляється та/або передається виникають зв’язки з атрибутами; зв’язки атрибутів зберігаються разом з інформацією; на основі атрибутів, визначених у AC-16_ODP[01] для систем, встановлюються наступні дозволені атрибути безпеки: атрибути безпеки; на основі атрибутів, визначених у AC-16_ODP[02] для систем, встановлюються наступні дозволені атрибути приватності: атрибути конфіденційності ; AC-16(d)",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_f_02,
         "Визначено наступні допустимі значення або діапазони атрибутів для кожного з встановлених атрибутів: значення або діапазони атрибутів; проводиться аудит змін до атрибутів; атрибути безпеки перевіряються на відповідність частота; атрибути конфіденційності перевіряються на відповідність частота",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_odp_02,
         "Визначено типи атрибутів конфіденційності, які мають бути пов'язані зі значеннями атрибутів конфіденційності для інформації, що зберігається, обробляється та/або передається",
         [type: :string, default: nil]},
        {:ac_16_odp_03,
         "Визначено значення атрибутів безпеки для типів атрибутів безпеки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-16-1") do
    %{
      id: :"id-spe-ac-16-1",
      description: "",
      title: "АТРИБУТИ БЕЗПЕКИ ТА ПРИВАТНОСТІ - ДИНАМІЧНЕ ПОВ’ЯЗАННЯ АТРИБУТІВ (AC-16(1))",
      parameters: [
        {:ac_16_1_02,
         "Атрибути безпеки динамічно пов'язуються з об'єктами відповідно до наведених нижче політик безпеки під час створення та комбінування інформації: політики безпеки",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_1_03,
         "Атрибути конфіденційності динамічно пов'язуються з суб'єктами відповідно до наведених нижче політик конфіденційності під час створення та комбінування інформації: політики конфіденційності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_1_04,
         "Атрибути конфіденційності динамічно пов'язуються з об'єктами відповідно до наведених нижче політик конфіденційності під час створення та комбінування інформації: політики конфіденційності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_1_odp_01,
         "Визначено суб'єкти, з якими атрибути безпеки повинні динамічно пов'язуватися при створенні та комбінуванні інформації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_1_odp_02,
         "Визначено об'єкти, з якими атрибути безпеки повинні динамічно пов'язуватися при створенні та комбінуванні інформації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_1_odp_03,
         "Визначені суб'єкти, з якими атрибути конфіденційності повинні динамічно пов'язуватися при створенні та комбінуванні інформації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_1_odp_04,
         "Визначені об'єкти, з якими атрибути конфіденційності повинні динамічно пов'язуватися при створенні та комбінуванні інформації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_1_odp_05,
         "Визначено політики безпеки, що вимагають динамічного пов'язування атрибутів безпеки з суб'єктами та об'єктами",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_1_odp_06,
         "Визначено політики конфіденційності, що вимагають динамічного пов'язування атрибутів безпеки з суб'єктами та об'єктами; AC-16(01)[01] атрибути безпеки динамічно пов'язуються з суб'єктами відповідно до наведених нижче політик безпеки під час створення та комбінування інформації: політики безпеки",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-16-2") do
    %{
      id: :"id-spe-ac-16-2",
      description: "Надати уповноваженим особам (або процесам, що діють від імені фізичних осіб) можливість визначати або змінювати значення відповідних атрибутів безпеки та приватності.",
      title: "АТРИБУТИ БЕЗПЕКИ ТА ПРИВАТНОСТІ - ЗМІНА ЗНАЧЕНЬ АТРИБУТІВ АВТОРИЗОВАНИМИ ОСОБАМИ (AC-16(2))",
      parameters: [
        {:ac_16_2_02,
         "Мають можливість визначати або змінювати значення пов'язаних з ними атрибутів конфіденційності",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-16-3") do
    %{
      id: :"id-spe-ac-16-3",
      description: "ПОВ’ЯЗАННЯ АТРИБУТІВ Підтримати пов’язання та цілісність [Призначення: визначених організацією атрибутів безпеки та приватності] з [Призначення: визначених організацією суб’єктів і об’єктів].",
      title: "АТРИБУТИ БЕЗПЕКИ ТА ПРИВАТНОСТІ - ПІДТРИМКА СИСТЕМОЮ ПОВ’ЯЗАННЯ АТРИБУТІВ (AC-16(3))",
      parameters: [
        {:ac_16_3_01,
         "Підтримується зв'язок та цілісність атрибутів безпеки з суб'єктами",
         [type: :string, default: nil]},
        {:ac_16_3_02,
         "Підтримується зв'язок та цілісність атрибутів безпеки з об'єктами",
         [type: :string, default: nil]},
        {:ac_16_3_03,
         "Підтримується зв'язок та цілісність атрибутів конфіденційності з суб'єктами",
         [type: :string, default: nil]},
        {:ac_16_3_04,
         "Підтримується зв'язок та цілісність атрибутів конфіденційності з об'єктами; ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: nil]},
        {:ac_16_3_odp_01,
         "Визначено атрибути безпеки, які потребують підтримки асоціацій та цілісності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_3_odp_02,
         "Визначено атрибути конфіденційності, які потребують підтримки асоціації та цілісності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_3_odp_03,
         "Визначено суб'єкти, які потребують об'єднання та збереження цілісності атрибутів безпеки, що належать до таких суб'єктів",
         [type: :string, default: nil]},
        {:ac_16_3_odp_04,
         "Визначено об'єкти, які потребують об'єднання та збереження цілісності атрибутів безпеки, що належать до таких об'єктів",
         [type: :string, default: nil]},
        {:ac_16_3_odp_05,
         "Визначено суб'єктів, які потребують об'єднання та збереження цілісності атрибутів конфіденційності щодо таких суб'єктів",
         [type: :string, default: nil]},
        {:ac_16_3_odp_06,
         "Визначено об'єктів, які потребують об'єднання та збереження цілісності атрибутів конфіденційності щодо таких об'єктів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-16-4") do
    %{
      id: :"id-spe-ac-16-4",
      description: "Впровадити можливість пов’язувати [Призначення: визначені організацією атрибути безпеки та приватності] з [Призначення: визначеними організацією суб’єктами та об’єктами] уповноваженими особами (або процесами, що діють від імені фізичних осіб).",
      title: "АТРИБУТИ БЕЗПЕКИ ТА ПРИВАТНОСТІ - ПОВ’ЯЗАННЯ АТРИБУТІВ АВТОРИЗОВАНИМИ ОСОБАМИ (AC-16(4))",
      parameters: [
        {:ac_16_4_03,
         "Визначено атрибути безпеки, які пов'язуються з суб'єктами уповноваженими особами (або процесами, що діють від імені осіб); визначено атрибути безпеки, які пов'язуються з об'єктами уповноваженими особами (або процесами, що діють від імені осіб); визначено атрибути конфіденційності, які пов'язуються з суб'єктами уповноваженими особами (або процесами, що діють від імені осіб); визначено атрибути конфіденційності, які пов'язуються з об'єктами уповноваженими особами (або процесами, що діють від імені осіб); визначено суб'єкти, що потребують пов'язання атрибутів безпеки з уповноваженими особами (або процесами, що діють від імені осіб); визначено об'єкти, що потребують пов'язання атрибутів безпеки з уповноваженими особами (або процесами, що діють від імені осіб); визначено суб'єкти, що потребують пов'язання атрибутів конфіденційності з уповноваженими особами (або процесами, що діють від імені осіб); визначено об'єкти, що потребують пов'язання атрибутів конфіденційності з уповноваженими особами (або процесами, що діють від імені осіб); уповноважені особи (або процеси, що діють від імені осіб) мають можливість пов'язувати атрибути безпеки з суб'єктами; уповноважені особи (або процеси, що діють від імені осіб) мають можливість пов'язувати атрибути безпеки з об'єктами; уповноважені особи (або процеси, що діють від імені осіб) мають можливість пов'язувати атрибути конфіденційності з AC-16(04)[04] суб'єктами; уповноважені особи (або процеси, що діють від імені осіб) мають можливість пов'язувати атрибути конфіденційності з об'єктами",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-16-5") do
    %{
      id: :"id-spe-ac-16-5",
      description: "Відображати атрибути безпеки та приватності в зручній для людини формі для кожного об’єкту, який система передає на пристрої виведення, щоб ідентифікувати [Призначення: визначені організацією спеціальні інструкції щодо поширення, обробки чи наступного розподілу інформації], використовуючи [Призначення: визначену організацією ідентифікацію, у зручній для людини формі про стандартні угоди про присвоєння імен].",
      title: "АТРИБУТИ БЕЗПЕКИ ТА ПРИВАТНОСТІ - ВІДОБРАЖЕННЯ АТРИБУТІВ НА ПРИСТРОЯХ ВИВЕДЕННЯ (AC-16(5))",
      parameters: [
        {:ac_16_5_02,
         "Для кожного об'єкта, який система передає на пристрої виведення, визначено спеціальні інструкції щодо поширення, обробки чи розподілу, які мають використовуватися; визначено стандартні угоди про ідентифікацію атрибутів безпеки та конфіденційності, які повинні відображатися в зручній для читання формі на кожному об'єкті, який система передає на пристрої виводу; атрибути безпеки відображаються у формі, зручній для читання людиною, на кожному об'єкті, який система передає на пристрої виводу для ідентифікації інструкцій з використанням угод про іменування; атрибути конфіденційності відображаються у формі, зручній для читання людиною, на кожному об'єкті, який система передає на пристрої виводу для ідентифікації інструкцій з використанням угод про іменування",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-16-6") do
    %{
      id: :"id-spe-ac-16-6",
      description: "Вимагати від персоналу пов’язувати та підтримувати асоціацію [Призначення: визначених організацією атрибутів безпеки та приватності] з [Призначенням: визначеними організацією суб’єктами та об’єктами] відповідно до [Призначення: визначеної організацією політики безпеки та приватності].",
      title: "АТРИБУТИ БЕЗПЕКИ ТА ПРИВАТНОСТІ - ПІДТРИМКА ПОВ’ЯЗАННЯ АТРИБУТІВ ОРГАНІЗАЦІЄЮ (AC-16(6))",
      parameters: [
        {:ac_16_6_01,
         "Персонал зобов'язаний пов'язувати та підтримувати зв'язок атрибутів безпеки з суб'єктами відповідно до політик безпеки; AC-16(06)[02] персонал зобов'язаний пов'язувати та підтримувати зв'язок атрибутів безпеки з об'єктами відповідно до політик безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_16_6_03,
         "Персонал зобов'язаний пов'язувати та підтримувати зв'язок атрибутів конфіденційності з суб'єктами відповідно до політик безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_16_6_04,
         "Персонал зобов'язаний пов'язувати та підтримувати зв'язок атрибутів конфіденційності з об'єктами відповідно до політик безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_16_6_odp_01,
         "Визначено атрибути безпеки, які будуть пов'язані з суб'єктами",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_6_odp_02,
         "Визначено атрибути безпеки, які будуть пов'язані з об'єктами",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_6_odp_03,
         "Визначено атрибути конфіденційності, які будуть пов'язані з суб'єктами",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_6_odp_04,
         "Визначено атрибути конфіденційності, які будуть пов'язані з об'єктами",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_6_odp_05,
         "Визначені суб'єкти, які будуть пов'язані з атрибутами безпеки",
         [type: :string, default: nil]},
        {:ac_16_6_odp_06,
         "Визначені об'єкти, які будуть пов'язані з атрибутами безпеки",
         [type: :string, default: nil]},
        {:ac_16_6_odp_07,
         "Визначені суб'єкти, які будуть пов'язані з атрибутами конфіденційності",
         [type: :string, default: nil]},
        {:ac_16_6_odp_08,
         "Визначені об'єкти, які будуть пов'язані з атрибутами конфіденційності",
         [type: :string, default: nil]},
        {:ac_16_6_odp_09,
         "Політики безпеки, які вимагають від персоналу пов'язувати та підтримувати зв'язок атрибутів безпеки та конфіденційності з суб'єктами та об'єктами",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_16_6_odp_10,
         "Політики конфіденційності, які вимагають від персоналу пов'язувати та підтримувати зв'язок атрибутів безпеки та конфіденційності з суб'єктами та об'єктами",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-16-7") do
    %{
      id: :"id-spe-ac-16-7",
      description: "Забезпечити послідовну інтерпретацію атрибутів безпеки та приватності, що передаються між розподіленими компонентами системи.",
      title: "АТРИБУТИ БЕЗПЕКИ ТА ПРИВАТНОСТІ - ПОСЛІДОВНА ІНТЕРПРЕТАЦІЯ АТРИБУТІВ (AC-16(7))",
      parameters: [
        {:ac_16_7_02,
         "Забезпечується послідовна інтерпретація атрибутів безпеки, що передаються між розподіленими компонентами системи. забезпечується послідовна інтерпретація атрибутів конфіденційності, що передаються між розподіленими компонентами системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-16-8") do
    %{
      id: :"id-spe-ac-16-8",
      description: "ПОВ’ЯЗАННЯ АТРИБУТІВ Реалізація [Призначення: методи та технології, визначені організацією] для пов’язування атрибутів безпеки та конфіденційності з інформацією.",
      title: "АТРИБУТИ БЕЗПЕКИ ТА ПРИВАТНОСТІ - ТЕХНІКИ ТА ТЕХНОЛОГІЇ ПОВ'ЯЗАННЯ АТРИБУТІВ (AC-16(8))",
      parameters: [
        {:ac_16_8_01,
         "Методи та технології застосовуються для пов'язування атрибутів безпеки з інформацією",
         [type: :string, default: nil]},
        {:ac_16_8_02,
         "Методи та технології застосовуються для пов'язування атрибутів конфіденційності з інформацією",
         [type: :string, default: nil]},
        {:ac_16_8_odp_01,
         "Визначено методи та технології, які необхідно застосувати для пов'язання інформації з атрибутами безпеки",
         [type: :string, default: nil]},
        {:ac_16_8_odp_02,
         "Визначено методи та технології, які необхідно застосувати для пов'язання інформації з атрибутами конфіденційності",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-16-9") do
    %{
      id: :"id-spe-ac-16-9",
      description: "Перепризначення атрибутів безпеки та приватності, пов’язаних з інформацією, здійснювати лише за допомогою механізмів перегляду, перевірених з використанням [Призначення: визначених організацією технік або процедур].",
      title: "АТРИБУТИ БЕЗПЕКИ ТА ПРИВАТНОСТІ - ПЕРЕПРИЗНАЧЕННЯ АТРИБУТІВ (AC-16(9))",
      parameters: [
        {:ac_16_9_01,
         "Атрибути безпеки, пов'язані з інформацією, перепризна- чаються за допомогою техніки або процедури; атрибути конфіденційності, пов'язані з інформацією, перепризначаються за допомогою техніки або процедури",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_16_9_odp_01,
         "Визначено техніки або процедури, що використовуються для перепризначення атрибутів безпеки",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ac_16_9_odp_02,
         "Визначено техніки або процедури, що використовуються для перепризначення атрибутів конфіденційності",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ac-16-10") do
    %{
      id: :"id-spe-ac-16-10",
      description: "Надати уповноваженим особам можливість визначати або змінювати тип і значення атрибутів безпеки та приватності, доступних для пов’язання із суб’єктами та об’єктами.",
      title: "АТРИБУТИ БЕЗПЕКИ ТА ПРИВАТНОСТІ - КОНФІГУРАЦІЯ АТРИБУТІВ УПОВНОВАЖЕНИМИ ОСОБАМИ (AC-16(10))",
      parameters: [
        {:ac_16_10_02,
         "Уповноваженим особам надається можливість визначати або змінювати тип і значення атрибутів безпеки, доступних для пов'язання з суб'єктами та об'єктами; уповноваженим особам надається можливість визначати або змінювати тип і значення атрибутів конфіденційності, доступних для пов'язання з суб'єктами та об'єктами",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-17") do
    %{
      id: :"id-spe-ac-17",
      description: "a. Встановити та задокументувати обмеження на використання, вимоги до конфігурації/підключення та рекомендації щодо здійснення кожного типу віддаленого доступу. b. Авторизувати віддалений доступ до системи, перш ніж будуть дозволені такі підключення.",
      title: "ВІДДАЛЕНИЙ ДОСТУП (AC-17)",
      parameters: [
        {:ac_17_a_02,
         "Для кожного типу дозволеного віддаленого доступу встановлені та задокументовані вимоги до конфігурації/підключення",
         [type: :string, default: nil]},
        {:ac_17_a_03,
         "Для кожного типу дозволеного віддаленого доступу встановлені та задокументовані рекомендації",
         [type: :string, default: nil]},
        {:ac_17_b,
         "Кожен тип віддаленого доступу до системи авторизується перед тим, як дозволити такі підключення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-17-1") do
    %{
      id: :"id-spe-ac-17-1",
      description: "",
      title: "ВІДДАЛЕНИЙ ДОСТУП - АВТОМАТИЗОВАНИЙ МОНІТОРИНГ ТА УПРАВЛІННЯ (AC-17(1))",
      parameters: [
        {:ac_17_1_01,
         "Проводиться моніторинг методами віддаленого доступу",
         [type: :string, default: nil]},
        {:ac_17_1_02,
         "Проводиться управління методами віддаленого доступу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-17-2") do
    %{
      id: :"id-spe-ac-17-2",
      description: "",
      title: "ВІДДАЛЕНИЙ ДОСТУП - ЗАХИСТ КОНФІДЕНЦІЙНОСТІ ТА ЦІЛІСНОСТІ ЗА ДОПОМОГОЮ ШИФРУВАННЯ (AC-17(2))",
      parameters: [
        {:ac_17_2_01,
         "ВІДДАЛЕНИЙ ДОСТУП - ЗАХИСТ КОНФІДЕНЦІЙНОСТІ ТА ЦІЛІСНОСТІ ЗА ДОПОМОГОЮ ШИФРУВАННЯ МЕТА ОЦІНКИ: Визначте, чи інформаційна система криптографічні механізми",
         [type: :string, default: "AES-256-GCM"]}
      ]
    }
  end

  def spec(:"id-spe-ac-17-3") do
    %{
      id: :"id-spe-ac-17-3",
      description: "",
      title: "ВІДДАЛЕНИЙ ДОСТУП - КЕРОВАНІ ТОЧКИ КОНТРОЛЮ ДОСТУПУ (AC-17(3))",
      parameters: [
        {:ac_17_3_01,
         "Віддалений доступ маршрутизується через авторизовані та керовані точки контролю доступу до мережі",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-17-4") do
    %{
      id: :"id-spe-ac-17-4",
      description: "",
      title: "ВІДДАЛЕНИЙ ДОСТУП - ПРИВІЛЕЙОВАНІ КОМАНДИ ТА ДОСТУП (AC-17(4))",
      parameters: [
        {:ac_17_4_a_01,
         "Виконання привілейованих команд за допомогою віддаленого доступу дозволено лише для наступних потреб: потреби ",
         [type: :string, default: nil]},
        {:ac_17_4_a_02,
         "Доступ до інформації, важливої для безпеки, за допомогою віддаленого доступу дозволяється лише для наступних потреб: потреби ",
         [type: :string, default: nil]},
        {:ac_17_4_b,
         "Обґрунтування віддаленого доступу задокументовано в плані захисту інформації",
         [type: :string, default: nil]},
        {:ac_17_4_odp_01,
         "Визначено потреби, що потребують виконання привілейованих команд за допомогою віддаленого доступу; AC-17(04)_ODP[02] визначено потреби, що вимагають доступу до інформації, що стосується безпеки, за допомогою віддаленого доступу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-17-5") do
    %{
      id: :"id-spe-ac-17-5",
      description: "",
      title: "ВІДДАЛЕНИЙ ДОСТУП - МОНІТОРИНГ ДЛЯ НЕАВТОРИЗОВАНИХ ПІДКЛЮЧЕНЬ (AC-17(5))",
      parameters: [
        {:ac_17_5_01,
         "ВІДДАЛЕНИЙ ДОСТУП - МОНІТОРИНГ ДЛЯ НЕАВТОРИЗОВАНИХ ПІДКЛЮЧЕНЬ [Вилучено: Включено в СІ-04]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-17-6") do
    %{
      id: :"id-spe-ac-17-6",
      description: "",
      title: "ВІДДАЛЕНИЙ ДОСТУП - ЗАХИСТ ІНФОРМАЦІЇ (AC-17(6))",
      parameters: [
        {:ac_17_6_01,
         "Інформація про механізми віддаленого доступу захищена від неавторизованого використання та розкриття",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ac-17-7") do
    %{
      id: :"id-spe-ac-17-7",
      description: "",
      title: "ВІДДАЛЕНИЙ ДОСТУП - ДОДАТКОВИЙ ЗАХИСТ ДЛЯ ДОСТУПУ ДО ФУНКЦІЙ БЕЗПЕКИ (AC-17(7))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ac-17-8") do
    %{
      id: :"id-spe-ac-17-8",
      description: "",
      title: "ВІДДАЛЕНИЙ ДОСТУП - ДЕАКТИВАЦІЯ НЕЗАХИЩЕНИХ ПРОТОКОЛІВ МЕРЕЖІ (AC-17(8))",
      parameters: [
        {:ac_17_8_01,
         "ВІДДАЛЕНИЙ ДОСТУП - ДЕАКТИВАЦІЯ НЕЗАХИЩЕНИХ ПРОТОКОЛІВ МЕРЕЖІ [Вилучено: Включено в CM-07]",
         [type: :string, default: "TLS 1.3"]}
      ]
    }
  end

  def spec(:"id-spe-ac-17-9") do
    %{
      id: :"id-spe-ac-17-9",
      description: "",
      title: "ВІДДАЛЕНИЙ ДОСТУП - ВІДКЛЮЧЕННЯ АБО ДЕАКТИВАЦІЯ ДОСТУПУ (AC-17(9))",
      parameters: [
        {:ac_17_9_01,
         "Передбачена можливість відключення або деактивації віддаленого доступу до системи протягом періоду часу",
         [type: :integer, default: 30]},
        {:ac_17_9_odp,
         "Визначено період часу, протягом якого потрібно відключити або деактивувати віддалений доступ до системи",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ac-17-10") do
    %{
      id: :"id-spe-ac-17-10",
      description: "",
      title: "ВІДДАЛЕНИЙ ДОСТУП - (10) АВТЕНТИФІКАЦІЯ ВІДДАЛЕНИХ КОМАНД (AC-17(10))",
      parameters: [
        {:ac_17_10_01,
         "Визначені механізми атентифіку- ють визначені віддалені команди",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ac_17_10_odp_01,
         "Визначено механізми, реалізовані для автентифікації віддалених команд",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ac_17_10_odp_02,
         "Визначено віддалені команди, які мають бути автентифіковані механізмами",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-18") do
    %{
      id: :"id-spe-ac-18",
      description: "a. Установити обмеження на використання, вимоги до конфігурації/підключення та рекомендації щодо здійснення бездротового доступу. b. Авторизувати бездротовий доступ до системи, перш ніж будуть дозволені такі підключення.",
      title: "БЕЗДРОТОВИЙ ДОСТУП (AC-18)",
      parameters: [
        {:ac_18_a_01,
         "Встановлено обмеження на використання щодо здійснення бездротового доступу",
         [type: :string, default: nil]},
        {:ac_18_a_02,
         "Встановлено вимоги до конфігурації або підключення щодо здійснення бездротового доступу",
         [type: :string, default: nil]},
        {:ac_18_a_03,
         "Встановлено доступу",
         [type: :string, default: nil]},
        {:ac_18_b,
         "Авторизується бездротовий доступ до системи перед тим, як дозволяти такі з'єднання. рекомендації щодо здійснення бездротового",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-18-1") do
    %{
      id: :"id-spe-ac-18-1",
      description: "",
      title: "БЕЗДРОТОВИЙ ДОСТУП - АВТЕНТИФІКАЦІЯ ТА ШИФРУВАННЯ (AC-18(1))",
      parameters: [
        {:ac_18_1_02,
         "Бездротовий доступ до системи захищений за допомогою шифрування",
         [type: :string, default: "AES-256-GCM"]}
      ]
    }
  end

  def spec(:"id-spe-ac-18-2") do
    %{
      id: :"id-spe-ac-18-2",
      description: "",
      title: "БЕЗДРОТОВИЙ ПІДКЛЮЧЕНЬ (AC-18(2))",
      parameters: [
        {:ac_18_2_01,
         "БЕЗДРОТОВИЙ ПІДКЛЮЧЕНЬ ДОСТУП - МОНІТОРИНГ НЕАВТОРИЗОВАНИХ [Вилучено: Включено в SI-04]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-18-3") do
    %{
      id: :"id-spe-ac-18-3",
      description: "",
      title: "БЕЗДРОТОВИЙ ДОСТУП - ВІДКЛЮЧЕННЯ БЕЗДРОТОВОЇ МЕРЕЖІ (AC-18(3))",
      parameters: [
        {:ac_18_3_01,
         "Відключено, у разі відсутності необхідності у використанні, вбудовані в компоненти системи можливості бездротових мереж до їх виклику та розгортання",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-18-4") do
    %{
      id: :"id-spe-ac-18-4",
      description: "",
      title: "БЕЗДРОТОВИЙ ДОСТУП СТУВАЧАМИ (AC-18(4))",
      parameters: [
        {:ac_18_4_01,
         "Встановлено користувачів, яким дозволено самостійно налаштовувати можливості бездротової мережі",
         [type: :string, default: nil]},
        {:ac_18_4_02,
         "Явно авторизуються визначені користувачі, яким дозволено самостійно налаштовувати можливості бездротової мережі",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-18-5") do
    %{
      id: :"id-spe-ac-18-5",
      description: "",
      title: "БЕЗДРОТОВИЙ ДОСТУП - АНТЕНИ ТА РІВЕНЬ ПОТУЖНОСТІ ПЕРЕДАЧІ (AC-18(5))",
      parameters: [
        {:ac_18_5_01,
         "Вибирано такі радіо антени, які зменшують ймовірність того, що корисні сигнали можуть прийматися за межами контрольованих організацією меж",
         [type: :string, default: nil]},
        {:ac_18_5_02,
         "Калібруються рівні потужності передачі, щоб зменшити ймовірність того, що корисні сигнали можуть прийматися за контрольованими організацією межами",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-19") do
    %{
      id: :"id-spe-ac-19",
      description: "a. Встановити обмеження на використання, вимоги до конфігурації, вимоги до підключення і рекомендації щодо впровадження мобільних пристроїв, контрольованих організацією. b. Авторизувати підключення мобільних пристроїв до систем, які експлуатуються організацією.",
      title: "КОНТРОЛЬ ДОСТУПУ ДЛЯ МОБІЛЬНИХ ПРИСТРОЇВ (AC-19)",
      parameters: [
        {:ac_19_a_01,
         "Встановлено вимоги до конфігурації мобільних пристроїв, що контролюються організацією, в тому числі, коли такі пристрої перебувають за межами контрольованої території",
         [type: :string, default: nil]},
        {:ac_19_a_02,
         "Встановлюються вимоги до підключення для мобільних пристроїв, що контролюються організацією, в тому числі, коли такі пристрої знаходяться за межами контрольованої території",
         [type: :string, default: nil]},
        {:ac_19_a_03,
         "Розроблено рекомендації щодо впровадження для мобільних пристроїв, які контролюються організацією, в тому числі, коли такі пристрої перебувають за межами контрольованої території",
         [type: :string, default: nil]},
        {:ac_19_b,
         "Авторизовано підключення мобільних пристроїв до систем організації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-19-1") do
    %{
      id: :"id-spe-ac-19-1",
      description: "",
      title: "КОНТРОЛЬ ДОСТУПУ ДЛЯ МОБІЛЬНИХ ПРИСТРОЇВ - ВИКОРИСТАННЯ ПИСЬМОВИХ ТА ПОРТАТИВНИЙ ПРИСТРОЇВ ДЛЯ ЗБЕРІГАННЯ ДАНИХ (AC-19(1))",
      parameters: [
        {:ac_19_1_01,
         "КОНТРОЛЬ ДОСТУПУ ДЛЯ МОБІЛЬНИХ ПРИСТРОЇВ - ВИКОРИСТАННЯ ПИСЬМОВИХ ТА ПОРТАТИВНИЙ ПРИСТРОЇВ ДЛЯ ЗБЕРІГАННЯ ДАНИХ [Вилучено: Включено в MP-07]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-19-2") do
    %{
      id: :"id-spe-ac-19-2",
      description: "",
      title: "КОНТРОЛЬ ДОСТУПУ ДЛЯ МОБІЛЬНИХ ПРИСТРОЇВ - ВИКОРИСТАННЯ ПЕРСОНАЛЬНИХ ПОРТАТИВНИХ ПРИСТРОЇВ ЗБЕРІГАННЯ ДАНИХ (AC-19(2))",
      parameters: [
        {:ac_19_2_01,
         "КОНТРОЛЬ ДОСТУПУ ДЛЯ МОБІЛЬНИХ ПРИСТРОЇВ - ВИКОРИСТАННЯ ПЕРСОНАЛЬНИХ ПОРТАТИВНИХ ПРИСТРОЇВ ЗБЕРІГАННЯ ДАНИХ [Вилучено: Включено в MP-07]. AC-19(03) КОНТРОЛЬ ДОСТУПУ ДЛЯ МОБІЛЬНИХ ПРИСТРОЇВ - ВИКОРИСТАННЯ ПОРТАТИВНИХ ПРИСТРОЇВ ЗБЕРІГАННЯ ДАНИХ З НЕІДЕНТИФІКОВАНИМ ВЛАСНИКОМ [Вилучено: Включено в MP-07]",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-19-3") do
    %{
      id: :"id-spe-ac-19-3",
      description: "",
      title: "КОНТРОЛЬ ДОСТУПУ ДЛЯ МОБІЛЬНИХ ПРИСТРОЇВ - ВИКОРИСТАННЯ ПОРТАТИВНИХ ПРИСТРОЇВ ЗБЕРІГАННЯ ДАНИХ З НЕІДЕНТИФІКОВАНИМ ВЛАСНИКОМ (AC-19(3))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ac-19-4") do
    %{
      id: :"id-spe-ac-19-4",
      description: "",
      title: "КОНТРОЛЬ ДОСТУПУ ДЛЯ МОБІЛЬНИХ ПРИСТРОЇВ - ОБМЕЖЕННЯ ДЛЯ ЗАСЕКРЕЧЕНОЇ ІНФОРМАЦІЇ (AC-19(4))",
      parameters: [
        {:ac_19_4_a,
         "Використання незахищених мобільних пристроїв на об'єктах, що містять системи, які обробляють, зберігають або передають секретну інформацію, заборонено, за винятком випадків, коли на це є спеціальний дозвіл уповноваженої посадової особи; AC-19(04)(b)(01) заборона підключення незахищених мобільних пристроїв до систем з обмеженим доступом застосовується до осіб, яким уповноважена посадова особа дозволила використовувати незахищені мобільні пристрої на об'єктах, що містять системи, які обробляють, зберігають або передають інформацію з обмеженим доступом; AC-19(04)(b)(02) дозвіл уповноваженої посадової особи на підключення незахищених мобільних пристроїв до незахищених систем вимагається від осіб, яким дозволено використовувати незахищені мобільні пристрої на об'єктах, що містять системи, які обробляють, зберігають або передають інформацію з обмеженим доступом; AC-19(04)(b)(03) заборона використання внутрішніх або зовнішніх модемів чи бездротових інтерфейсів у складі незахищених мобільних пристроїв поширюється на осіб, яким уповноваженою посадовою особою дозволено використовувати незахищені мобільні пристрої під час виконання службових обов'язків, а також на осіб, які не мають права на використання таких пристроїв AC-19(04)(b)(04)[01] вибірковий огляд та перевірка незахищених мобільних пристроїв та інформації, що зберігається на них, посадовими особами є обов'язковими; AC-19(04)(b)(04)[02] дотримання політики обробки інцидентів застосовується у разі виявлення секретної інформації під час випадкового огляду та перевірки незахищених мобільних пристроїв",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_19_4_c,
         "Підключення захищенихмобільних пристроїв до засекречених систем обмежено відповідно до політики безпеки",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_19_4_odp_01,
         "Визначено посадових осіб із захисту інформації, відповідальних за огляд та перевірку захищених мобільних пристроїв та інформації, що зберігається на цих пристроях",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_19_4_odp_02,
         "Визначено політики безпеки, що обмежують підключення захищених мобільних пристроїв до засекречених систем",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-19-5") do
    %{
      id: :"id-spe-ac-19-5",
      description: "",
      title: "КОНТРОЛЬ ДОСТУПУ ДЛЯ МОБІЛЬНИХ ПРИСТРОЇВ - ПОВНЕ ШИФРУВАННЯ ПРИСТРОЇВ ТА СХОВИЩ ІНФОРМАЦІЇ (AC-19(5))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ac-20") do
    %{
      id: :"id-spe-ac-20",
      description: "a. [Вибір (один або кілька): Встановіть [Призначення: умови, визначені організацією]; Визначте [Призначення: визначені організацією засоби контролю, які, як стверджується, будуть реалізовані на зовнішніх системах]], узгоджені з довірчими відносинами, встановленими з іншими організаціями, які володіють, експлуатують та/або обслуговують зовнішні системи, дозволяючи уповноваженим особам: 1. доступ до системи із зовнішніх систем; 2. обробляти, зберігати або передавати керовану організацією інформацію за допомогою зовнішніх систем; b. Заборонити використання [Призначення: організаційно-визначені типи зовнішніх систем].",
      title: "ВИКОРИСТАННЯ ЗОВНІШНІХ СИСТЕМ (AC-20)",
      parameters: [
        {:ac_20_odp_01,
         "Вибрано одне або більше з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {встановити умови та положення; визначити заходи захисту}",
         [type: :list, default: []]},
        {:ac_20_odp_02,
         "Визначено умови та положення, що відповідають довірчим відносинам, встановленим з іншими організаціями, які володіють, експлуатують та/або обслуговують зовнішні системи (якщо вибрано)",
         [type: :list, default: []]},
        {:ac_20_odp_03,
         "Визначено заходи захисту, які мають бути застосовані до зовнішніх систем відповідно до довірчих відносин, встановлених з іншими організаціями, що володіють, експлуатують та/або обслуговують зовнішні системи (якщо обрано)",
         [type: :string, default: nil]},
        {:ac_20_odp_04,
         "Визначено типи зовнішніх систем, заборонених до використання",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-20-1") do
    %{
      id: :"id-spe-ac-20-1",
      description: "",
      title: "ВИКОРИСТАННЯ ЗОВНІШНІХ СИСТЕМ - ОБМЕЖЕННЯ НА АВТОРИЗОВАНЕ ВИКОРИСТАННЯ (AC-20(1))",
      parameters: [
        {:ac_20_1_a,
         "Авторизовані особи мають право використовувати зовнішню систему для доступу до системи або для обробки, зберігання чи передачі інформації, що контролюється організацією, лише після перевірки виконання заходів безпеки та конфіденційності, зазначених у політиці безпеки та конфіденційності організації, а також планах безпеки та конфіденційності (якщо такі застосовуються)",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_20_1_b,
         "Авторизовані особи мають право використовувати зовнішню систему для доступу до системи або для обробки, зберігання чи передачі інформації, що контролюється організацією, лише після збереження погоджених угод про підключення або обробку системи з структурою організації, на якій розміщена зовнішня система",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-20-2") do
    %{
      id: :"id-spe-ac-20-2",
      description: "",
      title: "ВИКОРИСТАННЯ ЗОВНІШНІХ СИСТЕМ - ПЕРЕНОСНІ ПРИСТРОЇ ЗБЕРІГАННЯ ДАНИХ (AC-20(2))",
      parameters: [
        {:ac_20_2_01,
         "Використання портативних пристроїв носіїв інформації уповноваженими особами обмежено у зовнішніх системах за допомогою обмеження ",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_20_2_odp,
         "Визначено обмеження на використання авторизованими особами портативних носіїв інформації у зовнішніх системах",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-20-3") do
    %{
      id: :"id-spe-ac-20-3",
      description: "",
      title: "ВИКОРИСТАННЯ ЗОВНІШНІХ СИСТЕМ - СИСТЕМИ ТА КОМПОНЕНТИ, ЩО НЕ ЗНАХОДЯТЬСЯ У ВЛАСНОСТІ ОРГАНІЗАЦІЇ (AC-20(3))",
      parameters: [
        {:ac_20_3_01,
         "Використання систем або компонентів систем, що не належать організації, для обробки, зберігання або передачі інформації, що належить організації, обмежується за допомогою обмеження",
         [type: :string, default: nil]},
        {:ac_20_3_odp,
         "Визначено обмеження на використання систем або компонентів систем, що не належать організації, для обробки, зберігання або передачі інформації організації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-20-4") do
    %{
      id: :"id-spe-ac-20-4",
      description: "",
      title: "ВИКОРИСТАННЯ ЗОВНІШНІХ СИСТЕМ - ПРИСТРОЇ ДЛЯ ЗБЕРІГАННЯ ДАНИХ, ЯКІ МОЖУТЬ МАТИ ДОСТУП ДО МЕРЕЖІ (AC-20(4))",
      parameters: [
        {:ac_20_4_b,
         "Заборонено використання заборонені типи зовнішніх систем (якщо застосовно)",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-20-5") do
    %{
      id: :"id-spe-ac-20-5",
      description: "",
      title: "ВИКОРИСТАННЯ ЗОВНІШНІХ СИСТЕМ - ПОРТАТИВНІ ПРИСТРОЇ ДЛЯ ЗБЕРІГАННЯ ДАНИХ – ЗАБОРОНА ВИКОРИСТАННЯ (AC-20(5))",
      parameters: [
        {:ac_20_5_01,
         "Використання уповноваженими особами зовнішніх носіїв інформації, підконтрольних організації, на зовнішніх системах заборонено",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-21") do
    %{
      id: :"id-spe-ac-21",
      description: "a. Спростити обмін інформацією, надаючи авторизованим користувачам змогу визначати, чи відповідають повноваження на доступ, що призначені партнерам для обміну, обмеженням доступу та повноваженням з приватності щодо інформації для [Призначення: визначених організацією обставин обміну інформацією, коли це необхідно користувачу]. b. Використовувати [Призначення: визначені організацією автоматизовані механізми або ручні процеси], щоб допомогти користувачам в ухваленні рішень щодо обміну інформацією та співпраці.",
      title: "РОЗПОВСЮДЖЕННЯ ІНФОРМАЦІЇ (AC-21)",
      parameters: [
        {:ac_21_a,
         "Авторизованим користувачам дозволено визначати, чи відповідають повноваження доступу, призначені партнеру з обміну, обмеженням доступу та використання інформації для обставин обміну інформацією",
         [type: :string, default: nil]},
        {:ac_21_b,
         "Автоматизовані механізми використовуються для допомоги користувачам у прийнятті рішень щодо обміну інформацією та співпраці",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ac_21_odp_01,
         "Визначені обставини обміну інформацією, за яких користувач повинен на власний розсуд визначати, чи відповідають повноваження доступу, надані партнеру з обміну, обмеженням доступу та використання інформації",
         [type: :string, default: nil]},
        {:ac_21_odp_02,
         "Визначено автоматизовані механізми або ручні процеси, які допомагають користувачам у ухваленні рішень щодо обміну інформацією та співпраці",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ac-21-1") do
    %{
      id: :"id-spe-ac-21-1",
      description: "",
      title: "РОЗПОВСЮДЖЕННЯ ІНФОРМАЦІЇ - АВТОМАТИЧНА ПІДТРИМКА УХВАЛЕННЯ РІШЕНЬ (AC-21(1))",
      parameters: [
        {:ac_21_1_01,
         "Автоматизовані механізми використовуються для забезпечення виконання рішень щодо обміну інформацією уповноваженими користувачами на основі дозволів доступу партнерів з обміну та обмежень доступу до інформації, що підлягає обміну",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ac_21_1_odp,
         "Визначено автоматизовані механізми, що застосовуються для забезпечення виконання рішень про спільний доступ до інформації авторизованими користувачами",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ac-21-2") do
    %{
      id: :"id-spe-ac-21-2",
      description: "",
      title: "РОЗПОВСЮДЖЕННЯ ІНФОРМАЦІЇ (AC-21(2))",
      parameters: [
        {:ac_21_2_01,
         "Впроваджено сервіси пошуку та перевірки інформації, які застосовують e обмеження щодо обміну інформацією",
         [type: :string, default: nil]},
        {:ac_21_2_odp,
         "Визначено обмеження щодо обміну інформацією",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-22") do
    %{
      id: :"id-spe-ac-22",
      description: "a. Призначити осіб, що уповноважені на розміщення інформації в загальнодоступній системі. b. Навчати уповноважених осіб тому, щоб загальнодоступна інформація не містила інформацію з обмеженим доступом. c. Переглядати запропонований зміст інформації до публікації в загальнодоступній системі, щоб гарантувати, що там не міститься інформація з обмеженим доступом. d. Переглядати вміст загальнодоступної системи на предмет наявності там інформації з обмеженим доступом з [Призначення: визначеною організацією частотою]; така інформація має бути видалена в разі її виявлення.",
      title: "ПУБЛІЧНО ДОСТУПНИЙ КОНТЕНТ (AC-22)",
      parameters: [
        {:ac_22_a,
         "Визначені особи уповноважені на розміщення інформації в загальнодоступній системі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_22_b,
         "Уповноважені особи проходять навчання, щоб гарантувати, що загальнодоступна інформація не містить інформацію з обмеженим доступом",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ac_22_c,
         "Запропонований зміст інформації перевіряється до публікації в загальнодоступній системі, щоб гарантувати, що там не міститься інформація з обмеженим доступом",
         [type: :string, default: nil]},
        {:ac_22_d_01,
         "Зміст у загальнодоступній системі перевіряється на наявність інформації з обмеженим доступом з частотою",
         [type: :integer, default: 30]},
        {:ac_22_d_02,
         "Інформація з обмеженим доступом видаляється з загальнодоступної системи, якщо її виявлено",
         [type: :string, default: nil]},
        {:ac_22_odp,
         "Визначено частоту, з якою слід переглядати вміст загальнодоступної системи на предмет наявності там інформації з обмеженим доступом",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ac-23") do
    %{
      id: :"id-spe-ac-23",
      description: "Використовувати [Призначення: визначені організацією техніки виявлення та попередження витоку даних] для [Призначення: визначених організацією об’єктів зберігання даних] для виявлення та захисту від несанкціонованого інтелектуального аналізу даних.",
      title: "ЗАХИСТ ВІД НЕСАНКЦІОНОВАНОГО ІНТЕЛЕКТУАЛЬНОГО АНАЛІЗУ ДАНИХ (AC-23)",
      parameters: [
        {:ac_23_01,
         "Техніки використовуються для об'єктів зберігання даних для виявлення та захисту від несанкціонованого інтелектуального аналізу даних",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ac_23_odp_01,
         "Визначено техніки виявлення та попередження витоку даних",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ac_23_odp_02,
         "Визначено об'єкти зберігання даних",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-24") do
    %{
      id: :"id-spe-ac-24",
      description: "[Вибір: Встановити процедури; Запровадити механізми], щоб забезпечити застосування [Призначення: визначені організацією рішення щодо контролю доступу] до кожного запиту щодо доступу до виконання доступу.",
      title: "РІШЕННЯ ЩОДО УПРАВЛІННЯ ДОСТУПОМ (AC-24)",
      parameters: [
        {:ac_24_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {встановити процедури; запровадити механізми}",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ac_24_odp_02,
         "Визначено рішення щодо контролю доступу, які застосовуються до кожного запиту щодо доступу до виконання доступу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-24-1") do
    %{
      id: :"id-spe-ac-24-1",
      description: "",
      title: "РІШЕННЯ ЩОДО УПРАВЛІННЯ ДОСТУПОМ - ІНФОРМАЦІЯ ПРО ПЕРЕДАЧУ АВТОРИЗОВАНОГО ДОСТУПУ (AC-24(1))",
      parameters: [
        {:ac_24_1_01,
         "Інформація щодо авторизації доступу передається за допомогою заходів безпеки до систем, які забезпечують ухвалення рішень щодо управління доступом. ухвалення",
         [type: :string, default: nil]},
        {:ac_24_1_odp_01,
         "Визначено інформацію щодо авторизації доступу, яка передається до систем, які забезпечують ухвалення рішень щодо управління доступом",
         [type: :string, default: nil]},
        {:ac_24_1_odp_02,
         "Визначено заходи безпеки, які слід використовувати, коли інформація про авторизацію передається до систем, що забезпечують виконання рішень щодо управління доступом",
         [type: :string, default: nil]},
        {:ac_24_1_odp_03,
         "Визначено системи, які забезпечують рішень щодо управління доступом",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ac-24-2") do
    %{
      id: :"id-spe-ac-24-2",
      description: "Здійснювати ухвалення рішень щодо управління доступом, засновуючись на [Призначення: визначених організацією атрибутах безпеки], які не охоплюють ідентифікацію користувача або процесу, що діє від імені користувача.",
      title: "РІШЕННЯ ЩОДО УПРАВЛІННЯ ДОСТУПОМ - ВІДСУТНІСТЬ ІДЕНТИФІКАЦІЇ КОРИСТУВАЧА АБО ПРОЦЕСУ, ЩО ДІЄ ВІД ІМЕНІ КОРИСТУВАЧА (AC-24(2))",
      parameters: [
        {:ac_24_2_01,
         "Рішення щодо управління доступом здійснюються на основі атрибутів безпеки, які не охоплюють ідентифікацію користувача або процесу, що діє від імені користувача (якщо вибрано)",
         [type: :string, default: nil]},
        {:ac_24_2_02,
         "Рішення щодо управління доступом здійснюються на основі атрибутів конфіденційності, які не охоплюють ідентифікацію користувача або процесу, що діє від імені користувача (якщо вибрано)",
         [type: :string, default: nil]},
        {:ac_24_2_odp_01,
         "Визначено атрибути безпеки, які не охоплюють ідентифікацію користувача або процесу, що діє від імені користувача (якщо вибрано)",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_24_2_odp_02,
         "Визначено атрибути конфіденційності, які не охоплюють ідентифікацію користувача або процесу, що діє від імені користувача (якщо вибрано)",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ac-25") do
    %{
      id: :"id-spe-ac-25",
      description: "Впровадити диспетчер доступу для [Призначення: визначеної організацією політики контролю доступу], який захищений від несанкціонованого доступу, завжди був доступний для виклику та досить компактний, щоб бути підданим аналізу й тестуванню, надійність якого може бути гарантована.",
      title: "ДИСПЕТЧЕР ДОСТУПУ (AC-25)",
      parameters: [
        {:ac_25_01,
         "Реалізовано диспетчер доступу для політики контролю доступу, який захищений від несанкціонованого доступу, завжди доступний для виклику та досить компактний, щоб бути підданим аналізу й тестуванню, надійність якого може бути гарантована",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ac_25_odp,
         "Визначено політики контролю доступу, для яких реалізовано диспетчер доступу",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-at-1") do
    %{
      id: :"id-spe-at-1",
      description: "a. Розробити, задокументувати та поширити [Призначення: серед визначеного організацією персоналу або ролей]: 1. [Вибір (один або декілька): Рівень організації; Рівень місії/бізнес-процесу; рівень системи] політики обізнаності та навчання у сфері забезпечення безпеки та приватності, яка: (a) містить мету, сферу застосування, ролі, обов’язки, відповідальність керівництва, координацію між організаційними підрозділами та систему контролю відповідності (complaince); (b) відповідає чинним законам, нормативним документам, директивам, нормам, політикам, стандартам та керівним документам. 2. Процедури, що сприяють реалізації політики підвищення обізнаності та професійної підготовки в галузі безпеки, приватності, а також пов’язаних з ними заходів захисту інформації та персональних даних. b. Призначити [Призначення: визначену організацією посадову особу] для управління політикою та процедурами підвищення обізнаності та навчання у сфері забезпечення безпеки та приватності. c. Переглядати та оновлювати: 1. Поточну політика [Призначення: частота, визначена організацією] і наступне [Призначення: події, визначені організацією]; 2. Процедури [Призначення: частота, визначена організацією] та наступні [Призначення: події, визначені організацією].",
      title: "ПОЛІТИКА ТА ПРОЦЕДУРИ ПІДВИЩЕННЯ ОБІЗНАНОСТІ ТА НАВЧАННЯ (AT-1)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-at-2") do
    %{
      id: :"id-spe-at-2",
      description: "Впровадити базові тренінги з підвищення обізнаності у сфері безпеки та приватності для користувачів системи (включно з менеджерами, керівниками компаній і підрядниками): a. Забезпечити навчання грамотності з питань безпеки та конфіденційності для користувачів системи (включаючи менеджерів, керівників вищої ланки та підрядників): 1. як частину початкового навчання для нових користувачів і [Призначення: частота, визначена організацією] після цього; 2. якщо цього потребують системні зміни або наступні [Призначення: події, визначені організацією]. b. Використовувати наведені нижче методи, щоб підвищити рівень безпеки та конфіденційності користувачів системи [Завдання: визначені організацією методи поінформованості]; c. Оновлювати навчання грамотності та зміст обізнаності [Завдання: частота, визначена організацією] і наступні [Завдання: події, визначені організацією]; d. Включити уроки, отримані з внутрішніх або зовнішніх інцидентів безпеки або порушень, у навчання грамотності та методи підвищення обізнаності.",
      title: "НАВЧАННЯ З ПІДВИЩЕННЯ ОБІЗНАНОСТІ (AT-2)",
      parameters: [
        {:at_2_b,
         "Методи застосовуються для підвищення обізнаності користувачів системи щодо безпеки та конфіденційності",
         [type: :string, default: nil]},
        {:at_2_c_01,
         "Оновлюється зміст навчання грамотності та підвищення обізнаності з частотою",
         [type: :integer, default: 30]},
        {:at_2_c_02,
         "Оновлюється зміст навчання грамотності та підвищення обізнаності після подій",
         [type: :string, default: nil]},
        {:at_2_d,
         "Уроки, отримані в результаті внутрішніх або зовнішніх інцидентів або порушень безпеки, включені в методи навчання та підвищення обізнаності",
         [type: :string, default: nil]},
        {:at_2_odp_01,
         "Визначено періодичність проведення навчання грамотності з питань безпеки для користувачів системи (в тому числі менеджерів, вищого керівництва та підрядників) після початкового тренінгу",
         [type: :string, default: "щорічно"]},
        {:at_2_odp_02,
         "Визначено періодичність проведення навчання грамотності з питань конфіденційності для користувачів системи (в тому числі менеджерів, вищого керівництва та підрядників) після початкового тренінгу",
         [type: :string, default: "щорічно"]},
        {:at_2_odp_03,
         "Визначено події, які потребують навчання користувачів системи грамотності з питань безпеки",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:at_2_odp_05,
         "Визначено методи, які слід застосовувати для підвищення обізнаності користувачів системи щодо безпеки та конфіденційністі",
         [type: :string, default: nil]},
        {:at_2_odp_06,
         "Визначено частоту оновлення навчання грамотності та змісту обізнаності; AT-02_ODP[07] визначено події після яких необхідне оновлення навчання грамотності та змісту обізнаності; AT-02(a)[01][01] навчання з грамотності з питань безпеки надається користувачам системи (включаючи менеджерів, керівників вищої ланки та підрядників) як частина початкового навчання для нових користувачів; AT-02(a)[01][02] навчання з грамотності з питань конфіденційності надається користувачам системи (включаючи менеджерів, керівників вищої ланки та підрядників) як частина початкового навчання для нових користувачів; AT-02(a)[01][03] для користувачів системи (включно з менеджерами, вищим керівництвом та підрядниками) проводиться навчання з безпеки з періодичністю після цього; AT-02(a)[01][04] для користувачів системи (включно з менеджерами, вищим керівництвом та підрядниками) проводиться навчання з конфіденційності з періодичністю після цього; AT-02(a)[02][01] тренінги з грамотності з питань безпеки проводяться для користувачів системи (включаючи менеджерів, керівників вищої ланки та підрядників), коли цього вимагають зміни в системі або після подій; AT-02(a)[02][02] тренінги з грамотності з питань конфіденціності проводяться для користувачів системи (включаючи менеджерів, керівників вищої ланки та підрядників), коли цього вимагають зміни в системі або після подій",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:at_2_odp_4,
         "Визначено події, які потребують навчання користувачів системи грамотності з питань конфіденційності",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-at-3") do
    %{
      id: :"id-spe-at-3",
      description: "a. Забезпечити проведення навчання з питань безпеки та приватності на основі ролей для працівників з ролями та обов’язками: [Призначення: визначені організацією ролі та обов’язки]: 1. перед авторизацією доступу до системи, інформації або виконанням призначених обов’язків і [Призначення: частота, визначена організацією] після цього; 2. коли цього потребують системні зміни. b. Оновити навчальний контент на основі ролей [Призначення: частота, визначена організацією] і наступні [Призначення: події, визначені організацією]; c. Включіть у рольове навчання, інформацію, отриману з внутрішніх або зовнішніх інцидентів та порушень безпеки.",
      title: "РОЛЬОВЕ НАВЧАННЯ (AT-3)",
      parameters: [
        {:at_3_b_01,
         "Оновлюється вміст навчання на основі ролей з частотою",
         [type: :integer, default: 30]},
        {:at_3_b_02,
         "Оновлюється вміст навчання на основі ролей після подій",
         [type: :string, default: nil]},
        {:at_3_c,
         "Інформація отримана з внутрішніх чи зовнішніх інцидентів або порушень безпеки, включається в навчання на основі ролей",
         [type: :string, default: nil]},
        {:at_3_odp_01,
         "Визначено ролі та обов'язки для тренінгів з безпеки на основі ролей",
         [type: :list, default: ["admin", "security_officer"]]},
        {:at_3_odp_02,
         "Визначено ролі та обов'язки для тренінгів з конфіденційності на основі ролей",
         [type: :list, default: ["admin", "security_officer"]]},
        {:at_3_odp_03,
         "Визначено частоту проведення тренінгів на основі ролей з безпеки та конфіденційності для призначеного персоналу після початкової підготовки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:at_3_odp_04,
         "Визначено частоту оновлення змісту навчання на основі ролей",
         [type: :integer, default: 30]},
        {:at_3_odp_05,
         "Визначено події, які потребують оновлення змісту навчання на основі ролей; AT-03(a)[01][01] навчання з безпеки на основі ролей проводиться для ролей та обов'язків перед авторизацією доступу до системи, інформації або виконанням призначених обов'язків; AT-03(a)[01][02] навчання з конфіденційності на основі ролей проводиться для ролей та обов'язків перед авторизацією доступу до системи, інформації або виконанням призначених обов'язків; AT-03(a)[01][03] навчання з безпеки на основі ролей проводиться для ролей та обов'язків з частотою після цього; AT-03(a)[01][04] навчання з конфіденційності на основі ролей проводиться для ролей та обов'язків з частотою після цього; AT-03(a)[02][01] навчання з питань безпеки на основі ролей проводиться для персоналу, який виконує певні ролі та обов'язки у сфері безпеки, коли цього вимагають зміни в системі; AT-03(a)[02][02] навчання з питань конфіденційності на основі ролей проводиться для персоналу, який виконує певні ролі та обов'язки у сфері безпеки, коли цього вимагають зміни в системі",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-at-3-1") do
    %{
      id: :"id-spe-at-3-1",
      description: "",
      title: "ЗАБЕЗПЕЧУЄТЬСЯ ПІДВИЩЕННЯМ КВАЛІФІКАЦІЇ В ГАЛУЗІ ЗАЙНЯТОСТІ ТА ФУНКЦІОНУВАННЯ ЗАХОДІВ ЗАХИСТУ РОБОЧОГО СЕРЕДОВИЩА З (AT-3(1))",
      parameters: [
        {:at_3_1_01,
         "Персонал або ролі забезпечується підвищенням кваліфікації в галузі зайнятості та функціонування заходів захисту робочого середовища з частотою",
         [type: :list, default: ["admin", "security_officer"]]},
        {:at_3_1_odp_01,
         "Визначено персонал або ролі, які мають бути забезпечені початковим навчанням та підвищенням кваліфікації з питань застосування та експлуатації заходів захисту робочого середовища",
         [type: :list, default: ["admin", "security_officer"]]},
        {:at_3_1_odp_02,
         "Визначено частоту проведення підвищення кваліфікації в галузі операцій та функціонування заходів захисту робочого середовища",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-at-3-2") do
    %{
      id: :"id-spe-at-3-2",
      description: "Надати [Призначення: визначеним організацією персоналу чи ролям] з початку роботи та з [Призначення: визначеною організацією частотою] підготовку з питань застосування та експлуатації заходів фізичної безпеки.",
      title: "ЗАБЕЗПЕЧУЮТЬСЯ ПІДГОТОВКОЮ З ПИТАНЬ ЗАСТОСУВАННЯ ТА ЕКСПЛУАТАЦІЇ ЗАХОДІВ (AT-3(2))",
      parameters: [
        {:at_3_2_01,
         "Персонал або ролі забезпечуються підготовкою з питань застосування та експлуатації заходів фізичної безпеки з частотою",
         [type: :list, default: ["admin", "security_officer"]]},
        {:at_3_2_odp_01,
         "Визначаено персонал або ролі, які мають бути забезпечені підготовкою з питань застосування та експлуатації заходів фізичної безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:at_3_2_odp_02,
         "Визначаеночастоту проведення підготовки з питань застосування та експлуатації заходів фізичної безпеки",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-at-4") do
    %{
      id: :"id-spe-at-4",
      description: "a. Документувати та відстежувати індивідуальні навчальні заходи із забезпечення безпеки та приватності, включно з базовою підготовкою з питань безпеки та приватності, а також спеціальною підготовкою з питань безпеки та приватності визначених посадових осіб. b. Зберігати індивідуальні записи про навчання впродовж [Призначення: визначеного організацією періоду часу].",
      title: "НАВЧАЛЬНІ ЗАПИСИ (AT-4)",
      parameters: [
        {:at_4_a_01,
         "Задокументовані індивідуальні навчальні заходи із забезпечення безпеки та конфіденційності інформації, включно з базовою підготовкою з питань безпеки та конфіденційності, а також спеціальною підготовкою з безпеки та конфіденційності",
         [type: :string, default: nil]},
        {:at_4_a_02,
         "Відстежуються індивідуальні навчальні заходи із забезпечення безпеки та конфіденційності інформації, включно з базовою підготовкою з питань безпеки та конфіденційності, а також спеціальною підготовкою з безпеки та конфіденційності",
         [type: :string, default: nil]},
        {:at_4_b,
         "Індивідуальні записи про навчання зберігаються протягом період часу",
         [type: :integer, default: 30]},
        {:at_4_odp,
         "Визначено період зберігання індивідуальних записів про навчання",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-at-5") do
    %{
      id: :"id-spe-at-5",
      description: "",
      title: "КОНТАКТИ З ГРУПАМИ БЕЗПЕКИ ТА АСОЦІАЦІЯМИ (AT-5)",
      parameters: [
        {:at_5_01,
         "КОНТАКТИ З ГРУПАМИ БЕЗПЕКИ ТА АСОЦІАЦІЯМИ Вилучено: включено в PM-15",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-at-6") do
    %{
      id: :"id-spe-at-6",
      description: "Надати відгук про результати організаційного навчання наступному персоналу [Призначення: з визначеною організацією частотою та визначеному організацією персоналу]",
      title: "ВІДГУКИ ПРО ПРОВЕДЕНІ НАВЧАННЯ (AT-6)",
      parameters: [
        {:at_6_01,
         "Відгуки про результати навчання надаютсья з визначеною частотою до персоналу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:at_6_odp_01,
         "Визначено частоту надання відгуків щодо результатів навчання в організації",
         [type: :integer, default: 30]},
        {:at_6_odp_02,
         "Призначено персонал, якому надаватиметься відгуки щодо результатів навчання в організації",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-au-1") do
    %{
      id: :"id-spe-au-1",
      description: "a. Розробити, задокументувати та поширити [Призначення: серед персоналу або ролей, що їх визначила організація]: 1. [Вибір (один або декілька): Рівень організації; Рівень місії/бізнес-процесу; рівень системи] політика аудиту та підзвітності, яка: (a) містить мету, сферу застосування, ролі, обов’язки, відповідальність керівництва, координацію між організаційними підрозділами та систему контролю відповідності (complaince); (b) відповідає чинним законам, нормативним документам, директивам, нормам, політикам, стандартам та керівним документам. 2. Процедури, що сприяють здійсненню політики аудиту та підзвітності, а також пов’язані з ними заходи аудиту та підзвітності. b. Призначити [Призначення: визначену організацією старшу посадову особу] для управління політикою та процедурами аудиту та підзвітності. c. Переглядати та оновлювати поточний аудит та підзвітність: 1. політику [Призначення: частота, визначена організацією] та наступне [Призначення: події, визначені організацією]; 2. процедури аудиту [Призначення: визначеною організацією частотою] та [Завдання: події, визначені організацією].",
      title: "Політика та процедури аудиту та підзвітності (AU-1)",
      parameters: [
        {:au_1_a_01,
         "Розроблено та задокументовано політику аудиту та підзвітності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:au_1_a_02,
         "Політика аудиту та підзвітності доведена до персонал або ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_1_a_03,
         "Розроблені та задокументовані процедури аудиту та підзвітності, що сприяють впровадженню політики аудиту та підзвітності, а також відповідні заходи контролю аудиту та підзвітності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:au_1_b,
         "Посадова особа призначається для управління політикою та процедурами аудиту та підзвітності AU-01(c)[01][01] переглядається та оновлюється поточна політика аудиту та підзвітності з частота; AU-01(c)[01][02] переглядається та оновлюється поточна політика аудиту та підзвітності після подій; AU-01(c)[02][01] переглядається та оновлюється поточні процедури аудиту та підзвітності з частота; AU-01(c)[02][02] переглядається та оновлюється поточні процедури аудиту та підзвітності після подій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_1_odp_01,
         "Визначено персонал або ролі, до яких має бути доведена політика аудиту та підзвітності",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_1_odp_02,
         "Визначено персонал або ролі, на які поширюються процедури аудиту та підзвітності",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнес-процесу; рівень системи}",
         [type: :string, default: nil]},
        {:au_1_odp_04,
         "Визначено посадову особу, яка управлятиме політикою та процедурами аудиту та підзвітності",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_1_odp_05,
         "Визначено частоту, з якою переглядається та оновлюється поточна політика аудиту та підзвітності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:au_1_odp_06,
         "Визначено події, які потребують перегляду та оновлення поточної політики аудиту та підзвітності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:au_1_odp_07,
         "Визначено частоту, з якою переглядаються та оновлюються поточні процедури аудиту та підзвітності",
         [type: :integer, default: 30]},
        {:au_1_odp_08,
         "Визначено події, які потребують перегляду та оновлення поточної процедури аудиту та підзвітності",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-au-2") do
    %{
      id: :"id-spe-au-2",
      description: "a. Визначити типи подій, які система може реєструвати для підтримки функції аудиту: [Призначення: типи подій, визначені організацією, які система здатна реєструвати]; b. Координувати функції аудиту безпеки з іншими організаційними підрозділами, які вимагають інформації, пов’язаної з аудитом, для посилення взаємної підтримки та допомоги у виборі типів подій, що перевіряються; c. Визначити, які типи подій підлягають аудиту: [Призначення: визначені організацією події, що підлягають аудиту (підмножина подій, що підлягають аудиту, визначених в AU-2 a.), а також частота (або ситуація, що вимагає) проведення аудиту для кожної ідентифікованої події] d. Обґрунтувати, чому типи подій, що перевіряються, вважаються достатніми для підтримки розслідувань інцидентів (постфактум), пов’язаних з безпекою та приватністю; e. Перегляньте й оновіть типи подій, вибрані для журналювання [Призначення: частота, визначена організацією].",
      title: "ПОДІЇ АУДИТУ (AU-2)",
      parameters: [
        {:au_2_a,
         "Типи подій, які система здатна реєструвати, визначено для підтримки функції аудиту",
         [type: :string, default: nil]},
        {:au_2_b,
         "Функція аудиту безпеки координується з іншими підрозділами організації, які вимагають інформації, пов'язаної з аудитом, длдля посилення взаємної підтримки та допомоги у виборі типів подій, що перевіряються",
         [type: :string, default: nil]},
        {:au_2_c_01,
         "Типи подій (підмножина 02_ODP[01]) визначаються для реєстрації у системі; AU-",
         [type: :string, default: nil]},
        {:au_2_c_02,
         "Зазначені типи подій реєструються 02_ODP[03] частота або ситуація>; <AU-",
         [type: :string, default: "щорічно"]},
        {:au_2_d,
         "Надається обґрунтування, чому типи подій, що перевіряються, вважаються достатніми для підтримки розслідувань інцидентів (постфактум), пов’язаних з безпекою та конфіденційністю",
         [type: :string, default: nil]},
        {:au_2_e,
         "Переглядаються та оновлюються типи подій, вибрані для реєстрації, частота. у системі",
         [type: :string, default: "щорічно"]},
        {:au_2_odp_01,
         "Визначено типи подій, які система може реєструвати для підтримки функції аудиту",
         [type: :string, default: nil]},
        {:au_2_odp_02,
         "Визначено типи подій (підмножина AU-02_ODP[01]) що підлягають аудиту у системі",
         [type: :string, default: nil]},
        {:au_2_odp_03,
         "Визначено частоту або ситуацію, що вимагає проведення аудиту для кожної ідентифікованої події",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:au_2_odp_04,
         "Частота перегляду та оновлення типів подій, обраних для журналювання",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-au-2-1") do
    %{
      id: :"id-spe-au-2-1",
      description: "",
      title: "ПОДІЇ АУДИТУ - УЗАГАЛЬНЕННЯ ЗАПИСІВ ПРО АУДИТ З ДЕКІЛЬКОХ ДЖЕРЕЛ (AU-2(1))",
      parameters: [
        {:au_2_1_01,
         "ПОДІЇ АУДИТУ - УЗАГАЛЬНЕННЯ ЗАПИСІВ ПРО АУДИТ З ДЕКІЛЬКОХ ДЖЕРЕЛ [Вилучено: Включено в АU-12]. AU-02(02) ПОДІЇ АУДИТУ - ВИБІР ПОДІЇ АУДИТУ ЗА КОМПОНЕНТАМИ [Вилучено: Включено в АU-12]",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-au-2-2") do
    %{
      id: :"id-spe-au-2-2",
      description: "",
      title: "ПОДІЇ АУДИТУ - ВИБІР ПОДІЇ АУДИТУ ЗА КОМПОНЕНТАМИ (AU-2(2))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-au-2-3") do
    %{
      id: :"id-spe-au-2-3",
      description: "",
      title: "ПОДІЇ АУДИТУ - ПЕРЕГЛЯД ТА ОНОВЛЕННЯ (AU-2(3))",
      parameters: [
        {:au_2_3_01,
         "ПОДІЇ АУДИТУ - ПЕРЕГЛЯД ТА ОНОВЛЕННЯ [Вилучено: Включено в АU-02]",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-au-2-4") do
    %{
      id: :"id-spe-au-2-4",
      description: "",
      title: "ПОДІЇ АУДИТУ - ПРИВІЛЕЙОВАНІ ФУНКЦІЇ (AU-2(4))",
      parameters: [
        {:au_2_4_01,
         "ПОДІЇ АУДИТУ - ПРИВІЛЕЙОВАНІ ФУНКЦІЇ [Вилучено: Включено в AC-06(09)]",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-au-3") do
    %{
      id: :"id-spe-au-3",
      description: "Переконатися, що записи аудиту містять інформацію, яка встановлює наступне: a. який тип події стався; b. коли відбулася подія; c. де відбулася подія; d. джерело події; e. наслідки події; f. результат події та ідентифікатор будь-яких осіб або суб’єктів, пов’язаних з подією.",
      title: "ЗМІСТ ЗАПИСІВ АУДИТУ (AU-3)",
      parameters: [
        {:au_3_a,
         "Записи аудиту містять інформацію, яка встановлює який тип події стався",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:au_3_b,
         "Записи аудиту містять інформацію, яка встановлює коли подія сталася",
         [type: :string, default: nil]},
        {:au_3_c,
         "Записи аудиту містять інформацію, яка встановлює де відбулася подія",
         [type: :string, default: nil]},
        {:au_3_d,
         "Записи аудиту містять інформацію, яка встановлює джерело події",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:au_3_e,
         "Записи аудиту містять інформацію, яка встановлює наслідки події",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:au_3_f,
         "Записи аудиту містять інформацію, яка встановлює результат події та ідентифікатор будь-яких осіб або суб’єктів, пов’язаних з подією",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-au-3-1") do
    %{
      id: :"id-spe-au-3-1",
      description: "",
      title: "ЗМІСТ ЗАПИСІВ АУДИТУ - ДОДАТКОВА ІНФОРМАЦІЯ ПРО АУДИТ (AU-3(1))",
      parameters: [
        {:au_3_1_01,
         "ЗМІСТ ЗАПИСІВ АУДИТУ - ДОДАТКОВА ІНФОРМАЦІЯ ПРО АУДИТ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:au_3_1_odp,
         "Визначено додаткову інформацію, яка має бути включена до записів аудиту",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-3-2") do
    %{
      id: :"id-spe-au-3-2",
      description: "",
      title: "ЗМІСТ ЗАПИСІВ АУДИТУ - ЦЕНТРАЛІЗОВАНЕ УПРАВЛІННЯ ПЛАНОВАНИМ ЗМІСТОМ ЗАПИСІВ АУДИТУ (AU-3(2))",
      parameters: [
        {:au_3_2_01,
         "ЗМІСТ ЗАПИСІВ АУДИТУ - ЦЕНТРАЛІЗОВАНЕ УПРАВЛІННЯ ПЛАНОВАНИМ ЗМІСТОМ ЗАПИСІВ АУДИТУ [Вилучено: Включено до PL-09]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-3-3") do
    %{
      id: :"id-spe-au-3-3",
      description: "Обмежити персональні дані, що міститься в записах аудиту, до таких елементів, які визначені в оцінці ризику приватності: [Призначення: визначені організацією елементи].",
      title: "ЗМІСТ ЗАПИСІВ АУДИТУ - ОБМЕЖЕННЯ ЕЛЕМЕНТІВ ПЕРСОНАЛЬНИХ ДАНИХ (AU-3(3))",
      parameters: [
        {:au_3_3_01,
         "Інформація, що ідентифікує особу, яка міститься в записах аудиту, обмежується елементами, визначеними в оцінці ризиків конфіденційності",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_3_3_odp,
         "Визначаються елементи, визначені конфіденційності; в оцінці ризику",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-4") do
    %{
      id: :"id-spe-au-4",
      description: "Розподіляти місткість сховища записів аудиту у відповідності до [Призначення: визначених організацією вимог до зберігання записів аудиту].",
      title: "МІСТКІСТЬ СХОВИЩА ЗАПИСІВ АУДИТУ (AU-4)",
      parameters: [
        {:au_4_01,
         "Розподілено ємність для зберігання записів аудиту відповідно до вимог",
         [type: :string, default: nil]},
        {:au_4_odp,
         "Визначено вимоги до зберігання записів аудиту",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-4-1") do
    %{
      id: :"id-spe-au-4-1",
      description: "",
      title: "МІСТКІСТЬ СХОВИЩА ЗАПИСІВ АУДИТУ - ПЕРЕДАЧА ДО АЛЬТЕРНАТИВНОГО СХОВИЩА (AU-4(1))",
      parameters: [
        {:au_4_1_01,
         "Записи аудиту вивантажуються на іншу систему або носій інформації, з системи, що перевіряється, з частотою",
         [type: :integer, default: 30]},
        {:au_4_1_odp,
         "Визначено частоту завантаження записів аудиту на іншу систему чи носій інформації, з системи що перевіряється",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-au-5") do
    %{
      id: :"id-spe-au-5",
      description: "a. Сповіщати [Призначення: визначені організацією персонал або посади] у разі збою обробки даних аудиту в [Призначення: визначений організацією період часу]. b. Виконати наступні додаткові дії: [Призначення: визначені організацією дії, які необхідно зробити].",
      title: "РЕАГУВАННЯ НА ВІДМОВИ ОБРОБКИ ДАНИХ АУДИТУ (AU-5)",
      parameters: [
        {:au_5_a,
         "Персонал або ролі отримують сповіщення у разі збою процесу обробки даних аудиту періоду часу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_5_b,
         "Додаткові дії виконуються у разі збою процесу обробки даних аудиту",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:au_5_odp_01,
         "Визначено персонал або ролі, які отримують сповіщення про збої в процесі обробки даних аудиту ",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_5_odp_02,
         "Визначено період часу, протягом якого персонал або ролі отримують сповіщення про збої в процесі обробки даних аудиту",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_5_odp_03,
         "Визначено додаткові дії, яких слід вжити у випадку збою в процесі обробки даних аудиту ",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-au-5-1") do
    %{
      id: :"id-spe-au-5-1",
      description: "",
      title: "РЕАГУВАННЯ НА ВІДМОВИ ОБРОБКИ ДАНИХ АУДИТУ - МІСТКІСТЬ СХОВИЩА ЗАПИСІВ АУДИТУ (AU-5(1))",
      parameters: [
        {:au_5_1_01,
         "Попередження надається персоналу або ролям протягом періоду часу, коли виділений обсяг сховища журналів аудиту досягає відсотків від максимального обсягу сховища журналів аудиту",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_5_1_odp_01,
         "Визначено персонал або ролі, які мають бути попереджені, коли обсяг записів аудиту, що зберігаються, досягає максимуму місткості сховища. AU-05(01)_ODP[02] визначено період часу, протягом якого визначений персонал або ролі будуть попереджені",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_5_1_odp_03,
         "Визначено відсоток максимальної ємності сховища для зберігання журналів аудиту",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-5-2") do
    %{
      id: :"id-spe-au-5-2",
      description: "Забезпечити сповіщення в [Призначення: визначений організацією період реального часу] [Призначення: визначених організацією персоналу, ролей та/або місць], коли відбуваються такі події збою аудиту: [Призначення: визначені організацією події, пов’язані зі збоями та помилками аудиту, які вимагають тривоги в реальному часі].",
      title: "РЕАГУВАННЯ НА ВІДМОВИ ОБРОБКИ ДАНИХ АУДИТУ - ТРИВОЖНЕ СПОВІЩЕННЯ В РЕАЛЬНОМУ ЧАСІ (AU-5(2))",
      parameters: [
        {:au_5_2_01,
         "Протягом періоду реального часу надається сповіщення персоналу або ролям, коли виникають події",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_5_2_odp_01,
         "Визначено період реального часу, за який потрібно надсилати сповіщення при виникненні подій збою аудиту (визначених у AU-05(02)_ODP[03])",
         [type: :integer, default: 30]},
        {:au_5_2_odp_02,
         "Визначено персонал або ролі, які мають бути сповіщені при виникненні подій збоїв в аудиті (визначених в AU05(02)_ODP[03])",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_5_2_odp_03,
         "Визначено події, пов’язані зі збоями та помилками аудиту",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-au-5-3") do
    %{
      id: :"id-spe-au-5-3",
      description: "Здійснювати налаштування порогових значень обсягу трафіку комунікаційних мереж, що відображають обмеження на можливості аудиту та [Вибір: відхиляти; затримувати] мережевий трафік, якщо він перевищує цей поріг.",
      title: "РЕАГУВАННЯ НА ВІДМОВИ ОБРОБКИ ДАНИХ АУДИТУ - НАЛАШТУВАННЯ ПОРОГОВОГО ОБСЯГУ ТРАФІКУ (AU-5(3))",
      parameters: [
        {:au_5_3_01,
         "Застосовуються налаштовані порогові значення обсягу трафіку комунікаційних мереж, що відображають обмеження на можливості аудиту",
         [type: :string, default: nil]},
        {:au_5_3_odp,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {відхилити; затримати}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-5-4") do
    %{
      id: :"id-spe-au-5-4",
      description: "Застосовувати [Вибір: повне вимикання системи; часткове вимикання системи; знижений режим роботи з обмеженням доступної/цільової функціональності] у разі [Призначення: визначених організацією збоїв аудиту], якщо немає альтернативної можливості аудиту.",
      title: "РЕАГУВАННЯ НА ВІДМОВИ ОБРОБКИ ДАНИХ АУДИТУ - ВИМКНЕННЯ У РАЗІ ВІДМОВИ (AU-5(4))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-au-5-5") do
    %{
      id: :"id-spe-au-5-5",
      description: "Надання альтернативної можливості журналювання аудиту в разі збою основної можливості журналювання аудиту, яка реалізується [Призначення: визначена організацією функція альтернативного журналювання аудиту]",
      title: "РЕАГУВАННЯ НА ВІДМОВИ ОБРОБКИ ДАНИХ АУДИТУ - МОЖЛИВІСТЬ АЛЬТЕРНАТИВНОГО ЖУРНАЛЮВАННЯ АУДИТУ (AU-5(5))",
      parameters: [
        {:au_5_5_01,
         "Альтернативна можливість ведення журналу аудиту надається на випадок відмови основної можливості ведення журналу аудиту, який реалізує визначений альтернативний функціонал ведення журналу аудиту",
         [type: :string, default: nil]},
        {:au_5_5_odp,
         "Визначено альтернативний функціонал ведення журналу аудиту на випадок збою в роботі основної функції ведення журналу аудиту",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-6") do
    %{
      id: :"id-spe-au-6",
      description: "a. Переглядати та аналізувати записи системного аудиту [Призначення: з визначеною організацією частотою] для виявлення [Призначення: визначеної організацією неналежної або незвичайної діяльності]. b. Відправляти звіт про аудит [Призначення: визначеним організацією персоналу або посадам]. c. Налаштувати рівні огляду аудиту, аналізу та звітності в рамках системи, коли змінюється рівень ризику на основі інформації від правоохоронних органів, розвідувальної інформації або від інших достовірних джерел інформації.",
      title: "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ (AU-6)",
      parameters: [
        {:au_6_01,
         "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:au_6_a,
         "Записи аудиту системи переглядаються та аналізуються частота для виявлення ознак неналежної або незвичної діяльності та потенційного впливу неналежної або незвичної діяльності",
         [type: :string, default: "щотижня"]},
        {:au_6_b,
         "Звіт аудиту відправляється персоналу або ролям",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_6_c,
         "Рівень перевірки, аналізу та звітування записів аудиту в системі коригується у разі зміни ризиків на основі інформації правоохоронних органів, розвідувальної інформації або інших достовірних джерел інформації",
         [type: :string, default: nil]},
        {:au_6_odp_01,
         "Визначено частоту, з якою переглядаються та аналізуються записи аудиту системи",
         [type: :integer, default: 30]},
        {:au_6_odp_02,
         "Визначена неналежна або незвична діяльність",
         [type: :string, default: nil]},
        {:au_6_odp_03,
         "Визначено персонал або ролі які отримують результати оглядів та аналізів системних записів",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-au-6-1") do
    %{
      id: :"id-spe-au-6-1",
      description: "",
      title: "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ - АВТОМАТИЗОВАНА ІНТЕГРАЦІЯ ПРОЦЕСІВ (AU-6(1))",
      parameters: [
        {:au_6_1_01,
         "Процеси перегляду, аналізу та звітності інтегровані з використанням автоматизованих механізмів",
         [type: :string, default: nil]},
        {:au_6_1_odp,
         "Визначено автоматизовані механізми, що використовуються для інтеграції процесів перегляду, аналізу та звітності записів аудиту",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-au-6-2") do
    %{
      id: :"id-spe-au-6-2",
      description: "",
      title: "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ СПОВІЩЕННЯ ПРО ПОРУШЕННЯ БЕЗПЕКУ (AU-6(2))",
      parameters: [
        {:au_6_2_01,
         "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ СПОВІЩЕННЯ ПРО ПОРУШЕННЯ БЕЗПЕКУ - АВТОМАТИЗОВАНІ [Вилучено: Включено до SI-4]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-6-3") do
    %{
      id: :"id-spe-au-6-3",
      description: "Аналізувати та зіставляти записи аудиту в різних сховищах задля забезпечення ситуативної обізнаності в масштабах організації.",
      title: "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ - ЗІСТАВЛЯННЯ СХОВИЩ АУДИТУ (AU-6(3))",
      parameters: [
        {:au_6_3_01,
         "Аналізуєються та зіставляються записи аудиту в різних сховищах, задля забезпечення ситуативної обізнаності в масштабах організації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-6-4") do
    %{
      id: :"id-spe-au-6-4",
      description: "Забезпечити та впровадити можливість централізованого перегляду та аналізу записів аудиту з декількох компонентів у системі.",
      title: "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ - ЦЕНТРАЛІЗОВАНИЙ ПЕРЕГЛЯД ТА АНАЛІЗ (AU-6(4))",
      parameters: [
        {:au_6_4_01,
         "Забезпечино можливість централізованого перегляду та аналізу записів аудиту з декількох компонентів у системі",
         [type: :string, default: nil]},
        {:au_6_4_02,
         "Впроваджено можливість централізованого перегляду та аналізу записів аудиту з декількох компонентів у системі",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-6-5") do
    %{
      id: :"id-spe-au-6-5",
      description: "Інтегрувати аналіз записів аудиту з аналізом [Вибір (один або більше): інформації про сканування уразливостей; даних про продуктивність; інформації про моніторинг системи; [Призначення: визначених організацією даних/інформації, зібраних з інших джерел]] для подальшого підвищення здатності виявляти неприйнятну або незвичайну діяльність.",
      title: "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ - ІНТЕГРОВАНИЙ АНАЛІЗ ЗАПИСІВ АУДИТУ (AU-6(5))",
      parameters: [
        {:au_6_5_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {інформація про сканування вразливостей; дані про продуктивність; інформація про моніторинг системи; дані/інформація, зібрана з інших джерел}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-6-6") do
    %{
      id: :"id-spe-au-6-6",
      description: "Зіставляти інформацію із записів аудиту з інформацією, отриманою від моніторингу фізичного доступу, для подальшого підвищення здатності ідентифікувати підозрілу, неприйнятну, незвичайну або зловмисну діяльність.",
      title: "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ - КОРЕЛЯЦІЯ З ФІЗИЧНИМ МОНІТОРИНГОМ (AU-6(6))",
      parameters: [
        {:au_6_6_01,
         "Інформація з записів аудиту співвідноситься з інформацією, отриманою в результаті моніторингу фізичного доступу, для подальшого посилення здатності виявляти підозрілу, невідповідну, незвичну або зловмисну діяльність",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-6-7") do
    %{
      id: :"id-spe-au-6-7",
      description: "Визначити дозволені дії для кожного [Вибір (один або кілька): системного процесу; ролі; користувача], пов’язаного з переглядом, аналізом та поданням інформації про аудит.",
      title: "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ - ДОЗВОЛЕНІ ДІЇ (AU-6(7))",
      parameters: [
        {:au_6_7_odp,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {процес системи; роль; користувач}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-6-8") do
    %{
      id: :"id-spe-au-6-8",
      description: "Виконувати повний аналіз тексту привілейованих команд аудиту у фізично окремому компоненті чи підсистемі або іншій системі, яка може виконувати такий аналіз.",
      title: "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ - АНАЛІЗ ПОВНОГО ТЕКСТУ ПРИВІЛЕЙОВАНИХ КОМАНД (AU-6(8))",
      parameters: [
        {:au_6_8_01,
         "У фізично окремому компоненті чи підсистемі або іншій системі, яка може виконувати такий аналіз. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-6-10") do
    %{
      id: :"id-spe-au-6-10",
      description: "",
      title: "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ - РЕГУЛЮВАННЯ РІВНЯ АУДИТУ (AU-6(10))",
      parameters: [
        {:au_6_10_01,
         "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ - РЕГУЛЮВАННЯ РІВНЯ АУДИТУ [Вилучено: Включено до AU-06]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-7") do
    %{
      id: :"id-spe-au-7",
      description: "Забезпечити та реалізувати можливості скорочення записів перевірок аудитом і звітів, до рівня, який: a. підтримує перевірку, аналіз і звітність аудиту на вимогу та розслідування (постфактум) інцидентів безпеки; b. не змінює оригінальний вміст або час упорядкування записів аудиту.",
      title: "СКОРОЧЕННЯ ЗАПИСІВ АУДИТУ ТА ФОРМУВАННЯ ЗВІТУ (AU-7)",
      parameters: [
        {:au_7_a_02,
         "Реалізовано можливість скорочення записів перевірок аудитом та звітів, до рінвня що підтримує перевірку, аналіз і звітність аудиту на вимогу та розслідування (постфактум) інцидентів безпеки",
         [type: :string, default: nil]},
        {:au_7_b_01,
         "Забезпечено можливість скорочення записів перевірок аудитом та звітів, які не змінюють оригінальний зміст або час упорядкування записів аудиту",
         [type: :integer, default: 30]},
        {:au_7_b_02,
         "Реалізовано можливість скорочення записів перевірок аудитом та звітів, які не змінюють оригінальний зміст або час упорядкування записів аудиту",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-au-7-1") do
    %{
      id: :"id-spe-au-7-1",
      description: "",
      title: "СКОРОЧЕННЯ АУДИТУ ТА ФОРМУВАННЯ ЗВІТУ - АВТОМАТИЧНА ОБРОБКА (AU-7(1))",
      parameters: [
        {:au_7_1_01,
         "Забезпечити можливість обробки записів аудиту для подій, що представляють інтерес, на основі полей в записах аудиту",
         [type: :string, default: nil]},
        {:au_7_1_02,
         "Реалізувати можливість обробки записів аудиту для подій, що представляють інтерес, на основі полей в записах аудиту",
         [type: :string, default: nil]},
        {:au_7_1_odp,
         "Визначено поля в записах аудиту, які можна обробляти, сортувати або шукати",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-7-2") do
    %{
      id: :"id-spe-au-7-2",
      description: "",
      title: "СКОРОЧЕННЯ АУДИТУ ТА ФОРМУВАННЯ ЗВІТУ - АВТОМАТИЧНЕ СОРТУВАННЯ ТА ПОШУК (AU-7(2))",
      parameters: [
        {:au_7_2_01,
         "СКОРОЧЕННЯ АУДИТУ ТА ФОРМУВАННЯ ЗВІТУ - АВТОМАТИЧНЕ СОРТУВАННЯ ТА ПОШУК [Вилучено: Включено до AU-07(01)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-8") do
    %{
      id: :"id-spe-au-8",
      description: "a. Використовувати внутрішньосистемний годинник для створення позначок часу для записів аудиту. b. Застосовувати позначки часу, які відповідають [Призначення: деталізація вимірювання часу, визначена організацією] і використовують всесвітній координований час, мають фіксоване зміщення місцевого часу відносно всесвітнього координованого часу або включають зміщення місцевого часу як частину позначки часу.",
      title: "ПОЗНАЧКА ЧАСУ (AU-8)",
      parameters: [
        {:au_8_a,
         "Внутрішній системний годинник використовується для створення позначок часу для записів аудиту",
         [type: :integer, default: 30]},
        {:au_8_b,
         "Позначки часу застосовуються для записів аудиту, які відповідають деталізація вимірювання часу і які використовують всесвітній координований час, мають фіксоване місцеве зміщення місцевого часу від всесвітнього координованого часу або включають зміщення місцевого часу як частину позначки часу",
         [type: :integer, default: 30]},
        {:au_8_odp,
         "Визначено деталізацію вимірювання часу для часових позначок записів аудиту",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-au-8-1") do
    %{
      id: :"id-spe-au-8-1",
      description: "",
      title: "ПОЗНАЧКА ЧАСУ - СИНХРОНІЗАЦІЯ З АВТОРИТЕТНИМ ДЖЕРЕЛОМ ЧАСУ (AU-8(1))",
      parameters: [
        {:au_8_1_01,
         "ПОЗНАЧКА ЧАСУ - СИНХРОНІЗАЦІЯ З АВТОРИТЕТНИМ ДЖЕРЕЛОМ ЧАСУ [Вилучено: Включено до SC-45(01)]",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-au-8-2") do
    %{
      id: :"id-spe-au-8-2",
      description: "",
      title: "ПОЗНАЧКА ЧАСУ - ВТОРИННЕ АВТОРИТЕТНЕ ДЖЕРЕЛО ЧАСУ (AU-8(2))",
      parameters: [
        {:au_8_2_01,
         "ПОЗНАЧКА ЧАСУ - ВТОРИННЕ АВТОРИТЕТНЕ ДЖЕРЕЛО ЧАСУ [Вилучено: Включено до SC-45(02)]",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-au-9") do
    %{
      id: :"id-spe-au-9",
      description: "a. Захист інформації аудиту та інструментів несанкціонованого доступу, зміни та видалення; журналювання аудиту від b. Сповіщення [Призначення: персонал або ролі, визначені організацією] у разі виявлення несанкціонованого доступу, зміни або видалення інформації аудиту.",
      title: "ЗАХИСТ ІНФОРМАЦІЇ АУДИТУ (AU-9)",
      parameters: [
        {:au_9_01,
         "ЗАХИСТ ІНФОРМАЦІЇ АУДИТУ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:au_9_a,
         "Інформація про аудит та інструменти журналювання аудиту захищені від несанкціонованого доступу, зміни та видалення",
         [type: :string, default: nil]},
        {:au_9_b,
         "Персонал або ролі отримують сповіщення при виявленні несанкціонованого доступу, зміни або видалення інформації аудиту",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_9_odp,
         "Визначено персонал або ролі, які мають бути сповіщені при виявленні несанкціонованого доступу, зміни або видалення інформації аудиту",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-au-9-1") do
    %{
      id: :"id-spe-au-9-1",
      description: "",
      title: "ЗАХИСТ ІНФОРМАЦІЇ АУДИТУ - АПАРАТНІ НОСІЇ ІНФОРМАЦІЇ ОДНОРАЗОВОГО ЗАПИСУ (AU-9(1))",
      parameters: [
        {:au_9_1_01,
         "Журнали аудиту записані на апаратні носії інформації з одноразовим записом",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-9-2") do
    %{
      id: :"id-spe-au-9-2",
      description: "Зберігати записи аудиту з [Призначення: визначеною організацією з частотою] у репозиторії, який є частиною фізично іншої системи або компонента системи, ніж система або компонент, який перевіряється.",
      title: "ЗАХИСТ ІНФОРМАЦІЇ АУДИТУ - ЗБЕРІГАННЯ НА ОКРЕМИХ ФІЗИЧНИХ СИСТЕМАХ АБО КОМПОНЕНТАХ (AU-9(2))",
      parameters: [
        {:au_9_2_01,
         "Зберігати записи аудиту з частотою у репозиторії, який є частиною іншої системи або компонента системи, не частиною системи або компонента системи, який перевіряється",
         [type: :integer, default: 30]},
        {:au_9_2_odp,
         "Визначено частоту з якою необхідно зберігати записи аудиту",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-au-9-3") do
    %{
      id: :"id-spe-au-9-3",
      description: "Запровадити криптографічні механізми для захисту цілісності інформації аудиту та інструментів аудиту.",
      title: "ЗАХИСТ ІНФОРМАЦІЇ АУДИТУ - КРИПТОГРАФІЧНИЙ ЗАХИСТ (AU-9(3))",
      parameters: [
        {:au_9_3_01,
         "Впроваджено криптографічні механізми для захисту цілісності інформації аудиту",
         [type: :string, default: "AES-256-GCM"]}
      ]
    }
  end

  def spec(:"id-spe-au-9-4") do
    %{
      id: :"id-spe-au-9-4",
      description: "Авторизувати доступ до управління функціональністю аудиту тільки для [Призначення: визначеної організацією підмножини привілейованих користувачів].",
      title: "ЗАХИСТ ІНФОРМАЦІЇ АУДИТУ - ДОСТУП, ЯКИЙ НАДАЄТЬСЯ ЧЕРЕЗ ЧЛЕНСТВО В ПІДМНОЖИНИ ПРИВІЛЕЙОВАНИХ КОРИСТУВАЧІВ (AU-9(4))",
      parameters: [
        {:au_9_4_01,
         "Авторизувати доступ до управління функціональністю аудиту тільки для підмножини привілейованих користувачів",
         [type: :string, default: nil]},
        {:au_9_4_odp,
         "Визначено підмножину привілейованих користувачів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-9-5") do
    %{
      id: :"id-spe-au-9-5",
      description: "Здійснювати подвійну авторизацію для [Вибір (один або кілька): переміщення; видалення] [Призначення: визначеної організацією інформації аудиту].",
      title: "ЗАХИСТ ІНФОРМАЦІЇ АУДИТУ - ПОДВІЙНА АВТОРИЗАЦІЯ (AU-9(5))",
      parameters: [
        {:au_9_5_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {переміщення; видалення}",
         [type: :string, default: nil]},
        {:au_9_5_odp_02,
         "Визначено інформацію аудиту, для якої має бути застосована подвійна авторизація",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-9-6") do
    %{
      id: :"id-spe-au-9-6",
      description: "Авторизувати доступ лише для читання інформації аудиту для [Призначення: визначеної організацією підмножини привілейованих користувачів].",
      title: "ЗАХИСТ ІНФОРМАЦІЇ АУДИТУ - ДОСТУП ТІЛЬКИ ДЛЯ ЧИТАННЯ (AU-9(6))",
      parameters: [
        {:au_9_6_01,
         "Авторизувати доступ лише для читання інформації аудиту для підмножини привілейованих користувачів",
         [type: :string, default: nil]},
        {:au_9_6_odp,
         "Визначено підмножину привілейованих користувачів для яких доступ авторизовано тільки для читання",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-9-7") do
    %{
      id: :"id-spe-au-9-7",
      description: "Зберігати інформацію про аудит на компоненті, що працює з іншою операційною системою, ніж система або компонент, який проходить аудит.",
      title: "ЗАХИСТ ІНФОРМАЦІЇ АУДИТУ - ЗБЕРІГАННЯ НА КОМПОНЕНТІ ІНШОЇ ОПЕРАЦІЙНОЇ СИСТЕМИ (AU-9(7))",
      parameters: [
        {:au_9_7_01,
         "Інформація про аудит зберігається на компоненті, що працює з іншою операційною системою, ніж система або компонент, який проходить аудит",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-10") do
    %{
      id: :"id-spe-au-10",
      description: "Надавайте неспростовні докази того, що особа (або процес, який діє від імені особи) виконала [Призначення: дії, визначені організацією, на які поширюється принцип неспростовності].",
      title: "НЕСПРОСТОВНІСТЬ (AU-10)",
      parameters: [
        {:au_10_01,
         "Надаються неспростовні докази того, що особа (або процес, що діє від імені особи) виконала дії",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_10_odp,
         "Визначено дії, на які поширюється принцип неспростовності",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-au-10-1") do
    %{
      id: :"id-spe-au-10-1",
      description: "",
      title: "НЕСПРОСТОВНІСТЬ - АСОЦІАЦІЯ ІДЕНТИЧНОСТІ (AU-10(1))",
      parameters: [
        {:au_10_1_a,
         "Особистість джерела інформації зв'язується з інформацією з сила зв'язування",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_10_1_b,
         "Впроваджено засоби, якими уповноважені особи можуть визначити особу виробника інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_10_1_odp,
         "Визначено міцність зв'язку між особистістю джерела інформації та інформацією",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-au-10-2") do
    %{
      id: :"id-spe-au-10-2",
      description: "a) Підтвердити прив’язку інформації про ідентичність джерела до інформації з [Призначення: визначеною організацією частотою]. b) Виконати [Призначення: визначені організацією дії] у разі помилки перевірки.",
      title: "НЕСПРОСТОВНІСТЬ - РАТИФІКАЦІЯ ПРИВ'ЯЗКИ ІНФОРМАЦІЇ ПРО ІДЕНТИЧНІСТЬ ВИРОБНИКА (AU-10(2))",
      parameters: [
        {:au_10_2_01,
         "НЕСПРОСТОВНІСТЬ - РАТИФІКАЦІЯ ПРИВ'ЯЗКИ ІНФОРМАЦІЇ ПРО ІДЕНТИЧНІСТЬ ВИРОБНИКА МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:au_10_2_a,
         "Прив'язка інформації про ідентичність джерела до інформації підтвержується з частотою",
         [type: :integer, default: 30]},
        {:au_10_2_b,
         "Виконуються дії у разі помилки перевірки",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:au_10_2_odp_01,
         "Визначено частоту, з якою необхідно підтверджувати прив'язку інформації про ідентичність джерела до інформації",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-au-10-3") do
    %{
      id: :"id-spe-au-10-3",
      description: "Підтримувати перегляд і випуск ідентичності та повноважень у межах встановленого ланцюжка збереження доказів для всієї переглянутої або оприлюдненої інформації.",
      title: "НЕСПРОСТОВНІСТЬ - ЛАНЦЮЖОК ЗБЕРЕЖЕННЯ ДОКАЗІВ (AU-10(3))",
      parameters: [
        {:au_10_3_01,
         "Підтримується перегляд і випуск ідентичності та повноважень у межах встановленого ланцюжка збереження доказів для всієї переглянутої або оприлюдненої інформації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-10-4") do
    %{
      id: :"id-spe-au-10-4",
      description: "ЗВ’ЯЗКУ ІДЕНТИЧНОСТІ a) Підтвердити прив’язку особистості рецензента до інформації в точках передачі або видачі до її випуску або передачі між [Призначення: визначеними організацією домени безпеки]. b) Виконати [Призначення: визначені організацією дії] у разі помилки перевірки.",
      title: "НЕСПРОСТОВНІСТЬ - ВАЛІДАЦІЯ ЗВ'ЯЗКУ ІДЕНТИЧНОСТІ ПЕРЕГЛЯ- (AU-10(4))",
      parameters: [
        {:au_10_4_a,
         "Прив'язка особистості рецензента інформації до інформації в точках передачі або видачі до її випуску або передачі між доменами безпеки підтверджується",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_10_4_b,
         "Дії виконуються у випадку помилки перевірки",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:au_10_4_odp_01,
         "Визначено домени безпеки, для яких прив'язка особи рецензента інформації до інформації повинна бути підтверджена в точках передачі або видачі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_10_4_odp_02,
         "Визначено дії, які мають бути виконані у випадку помилки перевірки",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-au-10-5") do
    %{
      id: :"id-spe-au-10-5",
      description: "",
      title: "НЕСПРОСТОВНІСТЬ - ЦИФРОВІ ПІДПИСИ (AU-10(5))",
      parameters: [
        {:au_10_5_01,
         "НЕСПРОСТОВНІСТЬ - ЦИФРОВІ ПІДПИСИ [Вилучено: Включено до SI-07]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-11") do
    %{
      id: :"id-spe-au-11",
      description: "Зберігати записи аудиту впродовж [Призначення: визначеного організацією періоду часу, відповідно політиці зберігання записів], щоб забезпечити підтримку розслідувань (постфактум) інцидентів безпеки та приватності, а також для задоволення вимог нормативних і документів організації щодо збереження даних аудиту.",
      title: "ЗБЕРЕЖЕННЯ ЗАПИСІВ АУДИТУ (AU-11)",
      parameters: [
        {:au_11_01,
         "Записи аудиту зберігаються впродовж період часу, щоб забезпечити підтримку розслідування (постфактум) інцидентів безпеки та конфіденційності, а також відповідати нормативним та вимогам організації щодо збереження даних аудиту",
         [type: :integer, default: 30]},
        {:au_11_odp,
         "Визначено період часу для зберігання записів аудиту, який узгоджується з політикою зберігання записів",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-au-11-1") do
    %{
      id: :"id-spe-au-11-1",
      description: "",
      title: "ЗБЕРЕЖЕННЯ ЗАПИСІВ АУДИТУ - ДОВГОСТРОКОВА МОЖЛИВІСТЬ ОТРИМАННЯ (AU-11(1))",
      parameters: [
        {:au_11_1_01,
         "Впровадити заходи, щоб гарантувати, що довгострокові записи аудиту, можуть бути отримані",
         [type: :string, default: nil]},
        {:au_11_1_odp,
         "Визначено заходи, необхідні для реалізації довгострокової можливості отримання записів аудиту",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-12") do
    %{
      id: :"id-spe-au-12",
      description: "a. Забезпечити генерацію даних аудиту для типів подій, що перевіряються в AU-2а в [Призначення: визначених організацією компонентах системи]. b. Дозволити [Призначення: визначеному організацією персоналу або посадам] вибирати, які типи подій, що перевіряються, повинні перевірятися окремими компонентами системи; c. Генерувати записи аудиту для типів подій, визначених в AU-2с. з вмістом згідно з AU-3.",
      title: "ГЕНЕРАЦІЯ ДАНИХ АУДИТУ (AU-12)",
      parameters: [
        {:au_12_a,
         "Можливість генерації записів аудиту для типів подій, які система здатна перевіряти (визначених у AU-02_ODP[01]), забезпечується компонентами системи",
         [type: :string, default: nil]},
        {:au_12_b,
         "Персонал або ролі може/можуть вибирати типи подій, які будуть реєструватися певними компонентами системи; AU-12(c) згенеровано записи аудиту для типів подій, визначених у AU02_ODP[02], які включають вміст записів аудиту, визначений у AU03",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_12_odp_01,
         "Визначено компоненти системи, які забезпечують можливість генерації записів аудиту для типів подій (визначених у AU02_ODP[02])",
         [type: :string, default: nil]},
        {:au_12_odp_02,
         "Визначено персонал або ролі, яким дозволено обирати типи подій, що мають реєструватися певними компонентами системи",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-au-12-1") do
    %{
      id: :"id-spe-au-12-1",
      description: "",
      title: "ГЕНЕРАЦІЯ ДАНИХ АУДИТУ - ЗАГАЛЬНОСИСТЕМНИЙ ТА СИНХРОНІЗОВАНИЙ ЗА ЧАСОМ ЖУРНАЛУ АУДИТУ (AU-12(1))",
      parameters: [
        {:au_12_1_01,
         "Записи аудиту з компонентів системи збираються у загальносистемний (логічний або фізичний) журнал аудиту, який синхронізується у часі в межах рівня взаємозв'язку",
         [type: :integer, default: 30]},
        {:au_12_1_odp_01,
         "Визначено компоненти системи, з яких записи аудиту мають бути зібрані в загальносистемний (логічний або фізичний) журнал аудиту",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-12-2") do
    %{
      id: :"id-spe-au-12-2",
      description: "Створити загальносистемний (логічний або фізичний) журнал аудиту, що складається із записів аудиту в стандартизованому форматі.",
      title: "ГЕНЕРАЦІЯ ДАНИХ АУДИТУ - СТАНДАРТИЗОВАНІ ФОРМАТИ (AU-12(2))",
      parameters: [
        {:au_12_2_01,
         "Створюється загальносистемний (логічний) журнал аудиту, що складається з записів аудиту в стандартизованому форматі",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-12-3") do
    %{
      id: :"id-spe-au-12-3",
      description: "Забезпечити та реалізувати можливість для [Призначення: визначених організацією окремих осіб або ролей] змінити аудит, який виконуватиметься на [Призначення: визначених організацією компонентах системи] на основі [Призначення: визначених організацією критеріїв вибору подій] у межах [Призначення: визначених організацією часових порогів].",
      title: "ГЕНЕРАЦІЯ ДАНИХ АУДИТУ - ЗМІНИ, ЩО ВНОСЯТЬ АВТОРИЗОВАНІ ОСОБИ (AU-12(3))",
      parameters: [
        {:au_12_3_01,
         "Забезпечено можливість особам або ролям змінювати аудит на компонентах системи на основі обраних критеріїв події у межах часових порогів",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_12_3_02,
         "Реалізовано можливість особам або ролям змінювати аудит на компонентах системи на основі обраних критеріїв події у межах часових порогів",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_12_3_odp_01,
         "Визначено осіб або ролі, яким дозволено змінювати аудит компонентів системи",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_12_3_odp_02,
         "Визначено компоненти системи, на яких має виконуватися аудит",
         [type: :string, default: nil]},
        {:au_12_3_odp_03,
         "Визначено критерії вибору подій",
         [type: :list, default: []]},
        {:au_12_3_odp_04,
         "Визначено часові пороги, в яких мають змінюватися аудит",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-au-12-4") do
    %{
      id: :"id-spe-au-12-4",
      description: "Забезпечити та реалізувати можливості аудиту параметрів подій запитів користувачів для наборів даних, що містять персональні дані.",
      title: "ГЕНЕРАЦІЯ ДАНИХ АУДИТУ - АУДИТ ЗАПИТІВ ПЕРСОНАЛЬНИХ ДАНИХ (AU-12(4))",
      parameters: [
        {:au_12_4_01,
         "Забезпечена можливості аудиту параметрів подій запитів користувачів для наборів даних, що містять персональну ідентифікаційну інформацію",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_12_4_02,
         "Реалізувана можливості аудиту параметрів подій запитів користувачів для наборів даних, що містять персональну ідентифікаційну інформацію",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-au-13") do
    %{
      id: :"id-spe-au-13",
      description: "a. Моніторинг [Завдання: визначена організацією інформація з відкритих джерел та/або інформаційних сайтів] [Завдання: частота, визначена організацією] на наявність доказів неавторизованого розголошення конфіденційної інформації; b. Якщо виявлено розголошення інформації: 1. Повідомити [Призначення: персонал або ролі, визначені організацією]; 2. Виконайте такі додаткові дії: [Призначення: додаткові дії, визначені організацією].",
      title: "МОНІТОРИНГ РОЗКРИТТЯ ІНФОРМАЦІЇ (AU-13)",
      parameters: [
        {:au_13_a,
         "Інформація з відкритих джерел та/або інформаційні сайти відстежуються частота на наявність доказів неавторизованого розголошення конфіденційної інформації",
         [type: :string, default: "щорічно"]},
        {:au_13_b_01,
         "Персонал або ролі буде повідомлено, якщо буде виявлено розголошення інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_13_b_02,
         "Додаткові дії вживаються, якщо виявлено розголошення інформації",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:au_13_odp_01,
         "Визначено інформацію з відкритих джерел та/або інформаційні сайти, що підлягають моніторингу на наявність доказів неавторизованого розголошення конфіденційної інформації",
         [type: :string, default: nil]},
        {:au_13_odp_02,
         "Визначено частоту моніторингу інформації з відкритих джерел та/або інформаційних сайтів на наявність доказів неавторизованого розголошення конфіденційної інформації",
         [type: :integer, default: 30]},
        {:au_13_odp_03,
         "Визначено персонал або ролі, які мають бути повідомлені в разі виявлення розголошення інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_13_odp_04,
         "Визначено додаткові дії, які необхідно вжити у разі виявлення розголошення інформації",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-au-13-1") do
    %{
      id: :"id-spe-au-13-1",
      description: "",
      title: "МОНІТОРИНГ РОЗКРИТТЯ ІНФОРМАЦІЇ - ВИКОРИСТАННЯ АВТОМАТИЧНИХ ЗАСОБІВ (AU-13(1))",
      parameters: [
        {:au_13_1_01,
         "Моніторинг інформації з відкритих джерел та інформаційних сайтів здійснюється за допомогою автоматизовані механізми",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:au_13_1_odp,
         "Визначено автоматизовані механізми моніторингу інформації з відкритих джерел та інформаційних сайтів",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-au-13-2") do
    %{
      id: :"id-spe-au-13-2",
      description: "Проводити огляд відкритих інформаційних сайтів, що підлягають моніторингу [Призначення: з визначеною організацією частотою].",
      title: "МОНІТОРИНГ РОЗКРИТТЯ ІНФОРМАЦІЇ - ОГЛЯД САЙТІВ, ЩО ПІДЛЯГАЮТЬ МОНІТОРИНГУ (AU-13(2))",
      parameters: [
        {:au_13_2_odp,
         "Визначено частоту з якою проводять огляд відкритих інформаційних сайтів, що підлягають моніторингу проводиться огляд відкритих інформаційних сайтів, що підлягають моніторингу з частотою",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-au-13-3") do
    %{
      id: :"id-spe-au-13-3",
      description: "Використовуйте методи виявлення, процеси та інструменти, щоб визначити, чи зовнішні суб’єкти копіюють організаційну інформацію неавторизованим способом.",
      title: "МОНІТОРИНГ РОЗКРИТТЯ ІНФОРМАЦІЇ - АВТОРИЗОВАНЕ КОПІЮВАННЯ ІНФОРМАЦІЇ (AU-13(3))",
      parameters: [
        {:au_13_3_01,
         "Застосовуються методи, процеси та інструменти виявлення, щоб визначити, чи не копіюють зовнішні суб'єкти інформацію організації в несанкціонований спосіб",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-14") do
    %{
      id: :"id-spe-au-14",
      description: "a. Надавати та реалізувати можливість для [Призначення: користувачів або ролей, визначених організацією] для [Вибору (одного або кількох): збору/запису або перегляду/прослуховування] вмісту сесії користувача в [Призначення: обставини, визначені організацією]; b. Розробляти, інтегрувати та використовувати діяльність з аудиту сесії, консультуючись із юрисконсультантом щодо її відповідності до чинних законів, розпоряджень, директив, нормативних актів, політик, стандартів і вказівок.",
      title: "АУДИТ СЕСІЇ (AU-14)",
      parameters: [
        {:au_14_b_01,
         "Діяльність з аудиту сесій розробляється після консультацій з юристом та відповідно до чинних законів, розпоряджень, директив, нормативних актів, політик, стандартів та вказівок",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:au_14_b_02,
         "Діяльність з аудиту сесій інтегрується після консультацій з юристом та відповідно до чинних законів, розпоряджень, директив, нормативних актів, політик, стандартів та вказівок",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:au_14_b_03,
         "Діяльність з аудиту сесій використовується після консультацій з юристом та відповідно до чинних законів, розпоряджень, директив, нормативних актів, політик, стандартів та вказівок",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:au_14_odp_01,
         "Визначено користувачів або ролі, які можуть перевіряти вміст сесії користувача",
         [type: :list, default: ["admin", "security_officer"]]},
        {:au_14_odp_02,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {збору/запису або перегляду/прослуховування}",
         [type: :string, default: nil]},
        {:au_14_odp_03,
         "Визначено обставини, за яких вміст сесії користувача може бути перевірено",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-14-1") do
    %{
      id: :"id-spe-au-14-1",
      description: "",
      title: "АУДИТ СЕСІЇ - СИСТЕМА ЗАПУСКУ (AU-14(1))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-au-14-2") do
    %{
      id: :"id-spe-au-14-2",
      description: "[Вилучено: Включено до AU-14]",
      title: "АУДИТ СЕСІЇ - ЗАХОПЛЕННЯ ТА ЗАПИС ІНФОРМАЦІЇ (AU-14(2))",
      parameters: [
        {:au_14_2_01,
         "АУДИТ СЕСІЇ - ЗАХОПЛЕННЯ ТА ЗАПИС ІНФОРМАЦІЇ [Вилучено: Включено до AU-14]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-14-3") do
    %{
      id: :"id-spe-au-14-3",
      description: "Забезпечити та реалізувати можливість авторизованих користувачів віддалено переглядати та прослуховувати вміст, пов’язаний із встановленою сесією користувача, у режимі реального часу.",
      title: "АУДИТ СЕСІЇ - ВІДДАЛЕНИЙ ПЕРЕГЛЯД ТА ПРОСЛУХОВУВАННЯ (AU-14(3))",
      parameters: [
        {:au_14_3_01,
         "Забезпечується можливість для авторизованих користувачів віддалено переглядати та прослуховувати вміст, пов'язаний із встановленою сесією користувача, в режимі реального часу",
         [type: :integer, default: 30]},
        {:au_14_3_02,
         "Реалізовано можливість для авторизованих користувачів віддалено переглядати та прослуховувати вміст, пов'язаний із встановленою сесією користувача, в режимі реального часу",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-au-15") do
    %{
      id: :"id-spe-au-15",
      description: "",
      title: "АЛЬТЕРНАТИВНА МОЖЛИВІСТЬ АУДИТУ (AU-15)",
      parameters: [
        {:au_15_01,
         "АЛЬТЕРНАТИВНА МОЖЛИВІСТЬ АУДИТУ [Вилучено: Включено до AU-05(05)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-16") do
    %{
      id: :"id-spe-au-16",
      description: "Використовувати [Призначення: визначені організацією методи] для координації [Призначення: визначеної організацією інформації] серед зовнішніх організацій, коли інформація аудиту передається за межі організації.",
      title: "МІЖОРГАНІЗАЦІЙНИЙ АУДИТ (AU-16)",
      parameters: [
        {:au_16_01,
         "Організація використовує методи для координації інформації серед зовнішніх організацій, коли інформація аудиту передається через (за) межі організації (системи)",
         [type: :string, default: nil]},
        {:au_16_odp_01,
         "Визначено методи для координації інформації серед зовнішніх організацій, коли інформація аудиту передається через (за) межі організації (системи)",
         [type: :string, default: nil]},
        {:au_16_odp_02,
         "Визначено інформацію для координації інформації серед зовнішніх організацій, коли інформація аудиту передається через (за) межі організації (системи);",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-16-1") do
    %{
      id: :"id-spe-au-16-1",
      description: "",
      title: "МІЖОРГАНІЗАЦІЙНИЙ АУДИТ - ЗБЕРЕЖЕННЯ ІДЕНТИЧНОСТІ (AU-16(1))",
      parameters: [
        {:au_16_1_01,
         "Вимагається, щоб ідентичність особистості зберігалася в міжорганізаційних журналах аудиту",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-au-16-2") do
    %{
      id: :"id-spe-au-16-2",
      description: "Надавати інформацію про міжорганізаційний аудит до [Призначення: організацій, визначених організацією] на основі [Призначення: визначеної організацією міжорганізаційної угоди про обмін].",
      title: "МІЖОРГАНІЗАЦІЙНИЙ АУДИТ - ОБМІН ІНФОРМАЦІЄЮ АУДИТУ (AU-16(2))",
      parameters: [
        {:au_16_2_01,
         "Надати інформацію про міжорганізаційний аудит до організацій організацією на основі угоди про розподіл",
         [type: :string, default: nil]},
        {:au_16_2_odp_01,
         "Визначено організації до яких надають інформацію про міжорганізаційний аудит",
         [type: :string, default: nil]},
        {:au_16_2_odp_02,
         "Визначено міжорганізаційну угоду про розподіл",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-au-16-3") do
    %{
      id: :"id-spe-au-16-3",
      description: "Запровадити [Призначення: заходи, визначені організацією], щоб розмежувати людей від інформації аудиту, що передається в межах організації.",
      title: "МІЖОРГАНІЗАЦІЙНИЙ АУДИТ - РОЗМЕЖУВАННЯ (AU-16(3))",
      parameters: [
        {:au_16_3_01,
         "Заходи впроваджуються для того, щоб розмежування окремих осіб від інформації аудиту, що передається в межах організації",
         [type: :string, default: nil]},
        {:au_16_3_odp,
         "Визначено заходи для розмежування окремих осіб від інформації аудиту, що передається в межах організації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-1") do
    %{
      id: :"id-spe-ca-1",
      description: "a. Розробити, задокументувати та поширити серед [Призначення: визначеного організацією персоналу або посад]: 1. [Вибір (один або декілька): Рівень організації; Рівень місії/бізнес-процесу; рівень системи] політика оцінювання, авторизації та моніторингу, яка: (a) містить мету, сферу застосування, ролі, обов’язки, відповідальність керівництва, координацію між організаційними підрозділами та систему контролю відповідності (complaince); (b) відповідає чинним законам, нормативним документам, наказам, положенням, політиці, стандартам і керівним принципам. 2. Процедури, що сприяють реалізації політики оцінювання, авторизації та моніторингу безпеки та приватності, а також пов’язаних з ними заходів оцінювання, авторизації та моніторингу безпеки та приватності. b. Призначити [Призначення: посадова особа, визначена організацією] для управління розробкою, документуванням і розповсюдженням політики та процедур оцінювання, авторизації та моніторингу; c. Переглядати та оновлювати поточне оцінювання, авторизацію та моніторинг: 1. Політику [Призначення: частота, визначена організацією] та наступне [Призначення: події, визначені організацією]; 2. Процедури [Призначення: частота, визначена організацією] та наступні [Призначення: події, визначені організацією].",
      title: "ПОЛІТИКА І ПРОЦЕДУРИ ОЦІНЮВАННЯ, АКРЕДИТАЦІЯ ТА МОНІТОРИНГ БЕЗПЕКИ (CA-1)",
      parameters: [
        {:ca_1_a_01,
         "Розроблено та задокументовано політику оцінювання, авторизації та моніторингу",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ca_1_a_02,
         "Політика оцінювання, авторизації та моніторингу поширюється серед персоналу або ролей",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_1_a_03,
         "Розроблені та задокументовані процедури оцінювання, авторизації та моніторингу, що сприяють впровадженню політики оцінювання, авторизації та моніторингу, а також пов'язані з ними засоби контролю оцінювання, авторизації та моніторингу",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ca_1_b,
         "Посадова особа призначається для управління розробкою, документуванням та розповсюдженням політики та процедур оцінювання, авторизації та моніторингу; CA-01(c)[01][01] переглядається та оновлюється поточна політика оцінки, авторизації та моніторингу з частотою; CA-01(c)[01][02] переглядається та оновлюється поточна політика оцінки, авторизації та моніторингу після подій; CA-01(c)[02][01] переглядаються та оновлюються поточні процедури оцінки, авторизації та моніторингу з частотою; CA-01(c)[02][02] переглядаються та оновлюються поточні процедури оцінки, авторизації та моніторингу після подій; ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_1_odp_01,
         "Визначено персонал або ролі, серед яких має бути поширена політика оцінювання, авторизації та моніторингу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_1_odp_02,
         "Визначено персонал або ролі, серед яких мають бути поширені процедури оцінювання, авторизації та моніторингу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнес-процесу; рівень системи}",
         [type: :string, default: nil]},
        {:ca_1_odp_04,
         "Визначено посадову особу, яка управлятиме розробкою, документуванням і розповсюдженням політики та процедур оцінювання, авторизації та моніторингу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_1_odp_05,
         "Визначено частоту, з якою переглядається та оновлюється поточна політика оцінювання, авторизації та моніторингу",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ca_1_odp_06,
         "Визначено події, які потребують перегляду та оновлення поточної політики оцінки, авторизації та моніторингу",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ca_1_odp_07,
         "Визначено частоту, з якою переглядається та оновлюється поточні процедури оцінювання, авторизації та моніторингу",
         [type: :integer, default: 30]},
        {:ca_1_odp_08,
         "Визначено події, які потребують перегляду та оновлення поточні процедури оцінки, авторизації та моніторингу",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ca-2") do
    %{
      id: :"id-spe-ca-2",
      description: "a. Виберіть відповідного оцінювача або команду з оцінки для типу оцінювання, яке буде проводитися; b. Розробіть план контрольної оцінки, який описує обсяг оцінки, в тому числі: 1. заходи захисту та посилені заходи, що підлягають оцінюванню; 2. процедури оцінювання, ефективності заходів; які використовуватимуться для визначення 3. середовище оцінювання, групу оцінювання, ролі й обов’язки з оцінювання. c. Забезпечити розгляд і затвердження плану оцінювання уповноваженою офіційною особою або призначеним для проведення оцінювання представником; d. Оцінити заходи захисту в системі та в її середовищі функціонування з [Призначення: визначеною організацією частотою] для визначення, наскільки коректно реалізовані заходи безпеки і чи працюють вони за призначенням і дають бажаний результат щодо дотримання встановлених вимог безпеки та приватності; e. Підготовити звіт оцінювання безпеки, який документує результати оцінювання; f. Надати результати оцінювання з безпеки [Призначення: особам або ролям, визначеним організацією].",
      title: "ОЦІНЮВАННЯ (CA-2)",
      parameters: [
        {:ca_2_a,
         "Обрано відповідного оцінювача або команду оцінювачів для проведення оцінювання",
         [type: :string, default: nil]},
        {:ca_2_b_01,
         "Розроблено план контрольної оцінки, який описує обсяг оцінки, включаючи заходи захисту та посилені заходи, що підлягають оцінюванню. CA-02(b)[02] розроблено план контрольної оцінки, який описує обсяг оцінки, включаючи процедури оцінювання, які використовуватимуться для визначення ефективності заходів. CA-02(b)[03][01] розроблено план контрольної оцінки, який описує обсяг оцінки, включаючи середовище оцінювання. CA-02(b)[03][02] розроблено план контрольної оцінки, який описує обсяг оцінки, включаючи групу оцінювання. CA-02(b)[03][03] розроблено план контрольної оцінки, який описує обсяг оцінки, включаючи ролі й обов’язки з оцінювання",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_2_b_02,
         "Розроблено план контрольної оцінки, який описує обсяг оцінки, включаючи процедури оцінювання, які використовуватимуться для визначення ефективності заходів. CA-02(b)[03][01] розроблено план контрольної оцінки, який описує обсяг оцінки, включаючи середовище оцінювання. CA-02(b)[03][02] розроблено план контрольної оцінки, який описує обсяг оцінки, включаючи групу оцінювання. CA-02(b)[03][03] розроблено план контрольної оцінки, який описує обсяг оцінки, включаючи ролі й обов’язки з оцінювання",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_2_c,
         "План оцінки заходів захисту розглядається та затверджується уповноваженою посадовою особою або призначеним представником перед проведенням оцінки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_2_d_01,
         "Заходи захисту оцінюються в системі та середовищі її функціонування частота оцінки, щоб визначити, наскільки коректно реалізовані заходи захисту, чи працюють вони за призначенням і чи дають бажаний результат щодо дотримання встановлених вимог до безпеки",
         [type: :string, default: "щорічно"]},
        {:ca_2_d_02,
         "Заходи захисту оцінюються в системі та середовищі її функціонування частота оцінки, щоб визначити, наскільки коректно реалізовані заходи захисту, чи працюють вони за призначенням і чи дають бажаний результат щодо дотримання встановлених вимог до конфіденційності; CA-02(e) готується звіт оцінювання",
         [type: :string, default: "щорічно"]},
        {:ca_2_f,
         "Результати оцінювання з безпеки надаються особам або ролям. оцінювання , який документує результати",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_2_odp_01,
         "Визначено частоту, з якою слід оцінювати засоби контролю в системі та середовищі її функціонування",
         [type: :integer, default: 30]},
        {:ca_2_odp_02,
         "Визначені особи або ролі, яким мають бути надані результати оцінювання з безпеки",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ca-2-1") do
    %{
      id: :"id-spe-ca-2-1",
      description: "",
      title: "ОЦІНЮВАННЯ - НЕЗАЛЕЖНІ ЕКСПЕРТИ (CA-2(1))",
      parameters: [
        {:ca_2_1_01,
         "Для проведення контрольних оцінок залучаються незалежні експерти або групи експертів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-2-2") do
    %{
      id: :"id-spe-ca-2-2",
      description: "Ввести як частину оцінювання заходів безпеки та приватності, [Призначення: з визначеною організацією частотою], [Вибір: з попередженням; без попередження], [Вибір (один або кілька): поглиблений моніторинг; сканування уразливостей; тестування на шкідливих користувачів; оцінювання внутрішньої загрози; тестування продуктивності та навантаження; [Призначення: організаційно визначені інші форми оцінювання]].",
      title: "ВКЛЮЧАЮТЬСЯ ЯК ЧАСТИНА ОЦІНЮВАННЯ ЗАХОДІВ БЕЗПЕКИ ТА КОНФІДЕНЦІЙНОСТІ; (CA-2(2))",
      parameters: [
        {:ca_2_2_odp_01,
         "Визначено частоту, з якою слід включати спеціалізовані оцінки як частину оцінювання безпеки та конфіденційності",
         [type: :integer, default: 30]},
        {:ca_2_2_odp_02,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {з попередженням; без попередження}",
         [type: :string, default: nil]},
        {:ca_2_2_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {поглиблений моніторинг; сканування уразливостей; тестування на шкідливих користувачів; оцінювання внутрішньої загрози; тестування продуктивності та навантаження; }",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-2-3") do
    %{
      id: :"id-spe-ca-2-3",
      description: "Використовуйте результати контрольного оцінювання, які виконує [Призначення: зовнішня організація, визначена організацією] на [Призначення: система, визначена організацією], коли оцінювання відповідає [Завдання: вимоги, визначені організацією].",
      title: "ОЦІНЮВАННЯ - ЗОВНІШНІ ОРГАНІЗАЦІЇ (CA-2(3))",
      parameters: [
        {:ca_2_3_01,
         "Визначено організацію, яка надає результати оцінок заходів захисту інформації та персональних даних визначено систему, яка приймає результати оцінок заходів захисту інформації та персональних даних визначено вимоги до результатів оцінок заходів захисту інформації та персональних даних прийняти результати оцінок заходів захисту інформації та персональних даних організаціями., що надані, на систему, коли оцінювання відповідає вимогам",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ca-3") do
    %{
      id: :"id-spe-ca-3",
      description: "a. схвалити та керувати обміном інформацією між системою та іншими системами за допомогою [Вибір (один або кілька): угоди безпеки взаємозв’язку; договори безпеки обміну інформацією; меморандуми про взаєморозуміння; угоди про рівень обслуговування; угоди користувача; угоди про нерозголошення; [Доручення: тип договору, визначений організацією]];. b. документувати, як частину угоди про обмін, характеристики інтерфейсу, вимоги до безпеки та приватності, засоби контролю та відповідальність для кожної системи, а також характер переданої інформації; c. здійснювати перегляд та оновлення угод з [Призначення: визначеною організацією частотою].",
      title: "ВЗАЄМОДІЯ СИСТЕМ (CA-3)",
      parameters: [
        {:ca_3_b_01,
         "Характеристики інтерфейсу задокументовані як частина кожної угоди про обмін",
         [type: :integer, default: 30]},
        {:ca_3_b_02,
         "Вимоги до безпеки задокументовані як частина кожної угоди про обмін",
         [type: :integer, default: 30]},
        {:ca_3_b_03,
         "Вимоги щодо конфіденційності задокументовані як частина кожної угоди про обмін",
         [type: :integer, default: 30]},
        {:ca_3_b_04,
         "Заходи захисту задокументовані як частина кожної угоди про обмін",
         [type: :integer, default: 30]},
        {:ca_3_b_05,
         "Відповідальність за кожну систему задокументована як частина кожної угоди про обмін",
         [type: :integer, default: 30]},
        {:ca_3_b_06,
         "Характер переданої інформації документується як частина кожної угоди про обмін",
         [type: :integer, default: 30]},
        {:ca_3_c,
         "Угоди переглядаються та оновлюються частота",
         [type: :string, default: "щорічно"]},
        {:ca_3_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {): угоди безпеки взаємозв’язку; договори безпеки обміну інформацією; меморандуми про взаєморозуміння; угоди про рівень обслуговування; угоди користувача; угоди про нерозголошення; тип угоди}",
         [type: :string, default: nil]},
        {:ca_3_odp_02,
         "Визначено тип угоди, який використовується для схвалення та керування обміном інформацією (якщо вибрано)",
         [type: :string, default: nil]},
        {:ca_3_odp_03,
         "Визначено частоту, з якою необхідно переглядати та оновлювати угоди",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ca-3-1") do
    %{
      id: :"id-spe-ca-3-1",
      description: "",
      title: "ВЗАЄМОДІЯ СИСТЕМ- НЕЗАХИЩЕНІ З’ЄДНАННЯ СИСТЕМИ (CA-3(1))",
      parameters: [
        {:ca_3_1_01,
         "ВЗАЄМОДІЯ СИСТЕМ- НЕЗАХИЩЕНІ З’ЄДНАННЯ СИСТЕМИ [Вилучено: Включено до SC-07(25)]. CA-03(02) ВЗАЄМОДІЯ СИСТЕМ - ЗАХИЩЕНІ З’ЄДНАННЯ СИСТЕМИ [Вилучено: Включено до SC-07(26)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-3-2") do
    %{
      id: :"id-spe-ca-3-2",
      description: "",
      title: "ВЗАЄМОДІЯ СИСТЕМ - ЗАХИЩЕНІ З’ЄДНАННЯ СИСТЕМИ (CA-3(2))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ca-3-3") do
    %{
      id: :"id-spe-ca-3-3",
      description: "",
      title: "ВЗАЄМОДІЯ СИСТЕМ - НЕСЕКРЕТНІ З’ЄДНАННЯ СИСТЕМИ БЕЗПЕКИ, ЩО НЕ Є НАЦІОНАЛЬНИМИ (CA-3(3))",
      parameters: [
        {:ca_3_3_01,
         "ВЗАЄМОДІЯ СИСТЕМ - НЕСЕКРЕТНІ З’ЄДНАННЯ СИСТЕМИ БЕЗПЕКИ, ЩО НЕ Є НАЦІОНАЛЬНИМИ [Вилучено: Включено до SC-07(27)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-3-4") do
    %{
      id: :"id-spe-ca-3-4",
      description: "",
      title: "ВЗАЄМОДІЯ СИСТЕМ - ПІДКЛЮЧЕННЯ ДО ЗАГАЛЬНОДОСТУПНИХ МЕРЕЖ (CA-3(4))",
      parameters: [
        {:ca_3_4_01,
         "ВЗАЄМОДІЯ СИСТЕМ - ПІДКЛЮЧЕННЯ ДО ЗАГАЛЬНОДОСТУПНИХ МЕРЕЖ [Вилучено: Включено до SC-07(28)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-3-5") do
    %{
      id: :"id-spe-ca-3-5",
      description: "",
      title: "ВЗАЄМОДІЯ СИСТЕМ - ОБМЕЖЕННЯ ЗВ'ЯЗКУ ІЗ ЗОВНІШНІМИ СИСТЕМАМИ (CA-3(5))",
      parameters: [
        {:ca_3_5_01,
         "ВЗАЄМОДІЯ СИСТЕМ - ОБМЕЖЕННЯ ЗВ'ЯЗКУ ІЗ ЗОВНІШНІМИ СИСТЕМАМИ [Вилучено: Включено до SC-07(05)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-3-6") do
    %{
      id: :"id-spe-ca-3-6",
      description: "Переконатися, що особи або системи, які передають дані між взаємопов’язаними системами, мають необхідні повноваження (тобто дозволи на запис або привілеї), до прийняття таких даних.",
      title: "ВЗАЄМОДІЯ СИСТЕМ - ПЕРЕДАЧА ДОЗВОЛІВ (CA-3(6))",
      parameters: [
        {:ca_3_6_01,
         "Особи або системи, які передають дані між системами, що з'єднуються, мають необхідні повноваження (тобто дозволи на запис або привілеї) перед тим, як приймати такі дані",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ca-3-7") do
    %{
      id: :"id-spe-ca-3-7",
      description: "a) Визначити транзитивний (низхідний) обмін інформацією з іншими системами через системи, визначені в CA-3a; b) Вжити заходів для забезпечення припинення транзитивного (низхідного) обміну інформацією, коли засоби контролю ідентифікованих транзитивних (низхідних) систем не можуть бути перевірені або підтверджені.",
      title: "ВЗАЄМОДІЯ СИСТЕМ - ТРАНЗИТИВНИЙ ОБМІН ІНФОРМАЦІЄЮ (CA-3(7))",
      parameters: [
        {:ca_3_7_b,
         "Вживаються заходи для забезпечення припинення транзитного обміну інформацією, коли засоби контролю над ідентифікованими транзитними системами не можуть бути перевірені або підтверджені",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ca-4") do
    %{
      id: :"id-spe-ca-4",
      description: "",
      title: "СЕРТИФІКАЦІЯ БЕЗПЕКИ (CA-4)",
      parameters: [
        {:ca_4_01,
         "СЕРТИФІКАЦІЯ БЕЗПЕКИ [Вилучено: Включено до CA-02]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-5") do
    %{
      id: :"id-spe-ca-5",
      description: "a. Розробити для системи план усунення недоліків та контрольні показники з метою документування запланованих коригувальних дій організації для усунення недоліків і зауважень, які виявлені в ході оцінювання заходів захисту, а також для зменшення або усунення відомих вразливостей у системі. b. Оновлювати чинний план усунення недоліків та контрольні показники з [Призначення: визначеною організацією частотою] на основі результатів оцінювання заходів, незалежних аудитів та постійного моніторингу.",
      title: "ПЛАН УСУНЕННЯ НЕДОЛІКІВ ТА КОНТРОЛЬНІ ПОКАЗНИКИ (CA-5)",
      parameters: [
        {:ca_5_a,
         "Розроблено план усунення недоліків та контрольні показники для системи, та задокументувано заплановані дії організації з коригування, спрямовані на усунення недоліків та зауважень, виявлених під час оцінки заходів захисту, а також на зменшення або усунення відомих вразливостей в системі",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ca_5_b,
         "Існуючий план оновлюються частота на основі результатів оцінювання заходів, незалежних аудитів та постійного моніторингу",
         [type: :string, default: "щорічно"]},
        {:ca_5_odp,
         "Визначено частоту оновлення чинного плану усунення недоліків та контрольних показників на основі результатів оцінювання заходів захисту, незалежних аудитів та постійного моніторингу",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ca-5-1") do
    %{
      id: :"id-spe-ca-5-1",
      description: "",
      title: "ПЛАН УСУНЕННЯ НЕДОЛІКІВ ТА КОНТРОЛЬНІ ПОКАЗНИКИ - АВТОМАТИЗАЦІЯ ПІДТРИМКИ ЗАДЛЯ ТОЧНОСТІ ТА ВЖИВАНОСТІ (CA-5(1))",
      parameters: [
        {:ca_5_1_01,
         "Автоматизовані механізми використовуються для забезпечення точності, актуальності та доступності плану усунення недоліків і основних етапів для системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ca_5_1_odp,
         "Визначено автоматизовані механізми, які використовуються для забезпечення точності, актуальності та доступності плану усунення недоліків і основних етапів для системи",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ca-6") do
    %{
      id: :"id-spe-ca-6",
      description: "a. Призначити старшого керівника, який відповідає за систему; b. Призначити старшого керівника, відповідального за систему, та будь-які загальні заходи захисту, успадковані системою. c. Переконатися перед початком функціонування системи, що посадова особа: 1. акредитує загальні заходи захисту, що успадковані системою; 2. акредитує систему на функціонування за призначенням. d. Переконайтеся, що посадова особа, яка акредитує засоби захисту, дозволяє використання цих засобів захисту для успадкування організаційними системами; e. Оновлювати акредитацію [Призначення: з визначеною організацією частотою].",
      title: "АКРЕДИТАЦІЯ (CA-6)",
      parameters: [
        {:ca_6_a,
         "Призначено старшого керівника, який відповідає за систему; CA-06(b) призначено старшого керівника, відповідального за систему, та будь-які загальні заходи захисту, успадковані системою",
         [type: :string, default: nil]},
        {:ca_6_c_01,
         "Перед початком функціонування системи посадова особа, яка відповідає за систему, акредитує загальні заходи захисту, що успадковані системою",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_6_c_02,
         "Перед початком функціонування системи посадова особа, яка відповідає за систему, акредитує систему на функціонування за призначенням",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_6_d,
         "Посадова особа, яка акредитує заходи захисту, дозволяє використання цих заходів захисту для успадкування системами організації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_6_e,
         "Акредитації оновлюються частота",
         [type: :string, default: "щорічно"]},
        {:ca_6_odp,
         "Визначено частоту, з якою потрібно оновлювати акредитації",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ca-6-1") do
    %{
      id: :"id-spe-ca-6-1",
      description: "",
      title: "АКРЕДИТАЦІЯ - СПІЛЬНА АКРЕДИТАЦІЯ - ОДНА І ТА САМА ОРГАНІЗАЦІЯ (CA-6(1))",
      parameters: [
        {:ca_6_1_01,
         "Для системи впроваджено спільний процес акредитації",
         [type: :string, default: nil]},
        {:ca_6_1_02,
         "Спільний процес акредитації, який використовується в системі, включає в себе кілька посадових осіб з однієї організації, які надають акредитацію",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ca-6-2") do
    %{
      id: :"id-spe-ca-6-2",
      description: "Впровадити спільний процес акредитації для системи, що має кількох уповноважених посадових осіб з принаймні однією уповноваженою посадовою особою з організації, яка є зовнішньою організацією, що здійснює акредитацію.",
      title: "АКРЕДИТАЦІЯ - СПІЛЬНА АКРЕДИТАЦІЯ - РІЗНІ ОРГАНІЗАЦІЇ (CA-6(2))",
      parameters: [
        {:ca_6_2_01,
         "Для системи впроваджено спільний процес акредитації",
         [type: :string, default: nil]},
        {:ca_6_2_02,
         "Спільний процес акредитації, що використовується в системі, передбачає наявність кількох посадових осіб, які надають акредитації, принаймні одна з яких є посадовою особою з організації, що не належить до організації, яка здійснює акредитацію",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ca-7") do
    %{
      id: :"id-spe-ca-7",
      description: "Розробити стратегію безперервного моніторингу безпеки та приватності й упровадити програму безперервного моніторингу безпеки та приватності, яка охоплює: a. встановлення показників безпеки та приватності, які необхідно відстежувати: [Призначення: визначені організацією метрики]; b. встановлення [Призначення: визначена організацією частота] для моніторингу та [Призначення: визначена організацією частота] для безперервного оцінювання ефективності заходів захисту; c. поточні оцінювання заходів захисту відповідно до стратегії безперервного моніторингу організації; d. постійний моніторинг стану безпеки та приватності відповідно до встановлених організацією метрик і відповідно до стратегії безперервного моніторингу організації; e. зіставлення та аналіз інформації, отриманої в результаті оцінювання та моніторингу безпеки та приватності; f. дії реагування за результатами аналізу інформації, пов’язаної з безпекою та приватністю; g. повідомлення про статус безпеки та приватності системи [Призначення: визначені організацією персонал або ролі] з [Призначення: визначеною організацією частотою].",
      title: "БЕЗПЕРЕРВНИЙ МОНІТОРИНГ (CA-7)",
      parameters: [
        {:ca_7_01,
         "Розроблено стратегію безперервного моніторингу на системному рівні; CA-07[02] безперервний моніторинг на рівні системи здійснюється відповідно до стратегії безперервного моніторингу на рівні організації",
         [type: :string, default: nil]},
        {:ca_7_a,
         "Безперервний моніторинг на рівні системи включає встановлення наступних метрик на рівні системи, які підлягають моніторингу: метрики системного рівня",
         [type: :string, default: nil]},
        {:ca_7_b_01,
         "Безперервний моніторинг на рівні системи включає встановлені частоти для моніторингу ефективності заходів захисту",
         [type: :integer, default: 30]},
        {:ca_7_b_02,
         "Безперервний моніторинг на рівні системи включає встановлені частоти для оцінки ефективності заходів захисту",
         [type: :integer, default: 30]},
        {:ca_7_c,
         "Безперервний моніторинг на рівні системи включає поточні контрольні оцінки відповідно до стратегії безперервного моніторингу",
         [type: :string, default: nil]},
        {:ca_7_d,
         "Безперервний моніторинг на рівні системи включає постійний моніторинг визначених системою та організацією показників відповідно до стратегії безперервного моніторингу",
         [type: :string, default: nil]},
        {:ca_7_e,
         "Безперервний моніторинг на рівні системи включає зіставлення та аналіз інформації, отриманої в результаті оцінювання та моніторингу",
         [type: :string, default: nil]},
        {:ca_7_f,
         "Безперервний моніторинг на рівні системи включає в себе дії з реагування на результати аналізу інформації, пов’язаної з безпекою та приватністю",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ca_7_g_01,
         "Безперервний моніторинг на рівні системи включає повідомлення про статус безпеки системи для персоналу або ролей частота",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_7_g_02,
         "Безперервний моніторинг на рівні системи включає повідомлення про стан конфіденційності системи персоналу або ролям частота",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_7_odp_01,
         "Визначено метрики системного рівня, які підлягають моніторингу",
         [type: :string, default: nil]},
        {:ca_7_odp_02,
         "Визначено частоту, з якою слід моніторити ефективність заходів захисту",
         [type: :integer, default: 30]},
        {:ca_7_odp_03,
         "Визначено частоту, з якою слід оцінювати ефективність заходів захисту",
         [type: :integer, default: 30]},
        {:ca_7_odp_04,
         "Визначено персонал або ролі, яким повідомляється про стан безпеки системи",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_7_odp_05,
         "Визначено частоту, з якою повідомляється про стан безпеки системи",
         [type: :integer, default: 30]},
        {:ca_7_odp_06,
         "Визначено персонал або ролі, яким повідомляється про стан конфіденційності системи",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ca_7_odp_07,
         "Визначено частоту, з якою повідомляється про стан конфіденційності системи",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ca-7-1") do
    %{
      id: :"id-spe-ca-7-1",
      description: "",
      title: "БЕЗПЕРЕРВНИЙ МОНІТОРИНГ - НЕЗАЛЕЖНЕ ОЦІНЮВАННЯ (CA-7(1))",
      parameters: [
        {:ca_7_1_01,
         "Для постійного моніторингу заходів захисту в системі залучаються незалежні експертів або групи з оцінювання",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-7-2") do
    %{
      id: :"id-spe-ca-7-2",
      description: "",
      title: "БЕЗПЕРЕРВНИЙ МОНІТОРИНГ - ВИДИ ОЦІНОК (CA-7(2))",
      parameters: [
        {:ca_7_2_01,
         "БЕЗПЕРЕРВНИЙ МОНІТОРИНГ - ВИДИ ОЦІНОК [Вилучено: Включено до CA-02]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-7-3") do
    %{
      id: :"id-spe-ca-7-3",
      description: "Впровадити аналіз тенденцій, щоб визначити, чи потрібно змінювати реалізацію заходу захисту, частоту постійних моніторингових заходів і види діяльності, що використовуються в процесі безперервного моніторингу, на основі емпіричних даних.",
      title: "БЕЗПЕРЕРВНИЙ МОНІТОРИНГ - АНАЛІЗ ТЕНДЕНЦІЇ (CA-7(3))",
      parameters: [
        {:ca_7_3_01,
         "Аналіз тенденцій використовується для визначення того, чи потрібно змінювати реалізацію заходів захисту, які використовуються в процесі безперервного моніторингу, на основі емпіричних даних",
         [type: :string, default: nil]},
        {:ca_7_3_02,
         "Аналіз тенденцій застосовується для того, щоб на основі емпіричних даних визначити, чи потрібно змінювати частоту постійного моніторингу",
         [type: :integer, default: 30]},
        {:ca_7_3_03,
         "Аналіз тенденцій застосовується для того, щоб на основі емпіричних даних визначити, чи потрібно змінювати види діяльності, які використовуються в процесі безперервного моніторингу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-7-4") do
    %{
      id: :"id-spe-ca-7-4",
      description: "Забезпечити моніторинг ризиків, що є невід’ємною частиною стратегії постійного моніторингу та включає: (a) моніторинг ефективності; (b) моніторинг відповідності; (c) моніторинг змін.",
      title: "БЕЗПЕРЕРВНИЙ МОНІТОРИНГ - МОНІТОРИНГ РИЗИКУ (CA-7(4))",
      parameters: [
        {:ca_7_4_01,
         "Моніторинг ризиків є невід'ємною частиною стратегії безперервного моніторингу",
         [type: :integer, default: 30]},
        {:ca_7_4_a,
         "Моніторинг ефективності включено до моніторингу ризиків",
         [type: :string, default: nil]},
        {:ca_7_4_b,
         "Моніторинг відповідності включено до моніторингу ризиків",
         [type: :string, default: nil]},
        {:ca_7_4_c,
         "Моніторинг змін включений до моніторингу ризиків",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-7-5") do
    %{
      id: :"id-spe-ca-7-5",
      description: "Застосуйте наступні дії, щоб перевірити, що політики встановлені, а запроваджені заходи захисту працюють узгоджено: [Призначення: дії, визначені організацією].",
      title: "БЕЗПЕРЕРВНИЙ МОНІТОРИНГ - УЗГОДЖЕНИЙ АНАЛІЗ (CA-7(5))",
      parameters: [
        {:ca_7_5_01,
         "Дії використовуються для перевірки того, що політики встановлено",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ca_7_5_02,
         "Дії використовуються для перевірки того, що впроваджені заходи захисту працюють узгоджено",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ca_7_5_odp_01,
         "Визначені дії для підтвердження того, що політики встановлені",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ca_7_5_odp_02,
         "Визначені дії для підтвердження того, що впроваджені заходи захисту працюють узгоджено",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ca-7-6") do
    %{
      id: :"id-spe-ca-7-6",
      description: "Забезпечити точність, актуальність і доступність результатів моніторингу для системи за допомогою [Завдання: автоматизовані механізми, визначені організацією]",
      title: "БЕЗПЕРЕРВНИЙ МОНІТОРИНГУ (CA-7(6))",
      parameters: [
        {:ca_7_6_01,
         "Автоматизовані механізми використовуються для забезпечення точності, актуальності та доступності результатів моніторингу системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ca_7_6_odp,
         "Визначено автоматизовані механізми забезпечення точності, актуальності та доступності результатів моніторингу системи",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ca-8") do
    %{
      id: :"id-spe-ca-8",
      description: "Проводити тестування на проникнення з [Призначення: визначеною організацією частотою] у [Призначення: визначеній організацією інформаційній системі чи системному компоненті].",
      title: "ТЕСТУВАННЯ НА ПРОНИКНЕННЯ (CA-8)",
      parameters: [
        {:ca_8_01,
         "Проводиться тестування на проникнення з частотою у системі",
         [type: :integer, default: 30]},
        {:ca_8_odp_01,
         "Визначено частоту з якою проводить тестування на проникнення",
         [type: :integer, default: 30]},
        {:ca_8_odp_02,
         "Визначено систему у якій проводить тестування на проникнення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-8-1") do
    %{
      id: :"id-spe-ca-8-1",
      description: "",
      title: "ТЕСТУВАННЯ НА ПРОНИКНЕННЯ - НЕЗАЛЕЖНА КОМАНДА АБО АГЕНТ НА ПРОНИКНЕННЯ (CA-8(1))",
      parameters: [
        {:ca_8_1_01,
         "Для проведення тестування на проникнення в систему або компонентів системи залучається незалежний агент або команда з тестування на проникнення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-8-2") do
    %{
      id: :"id-spe-ca-8-2",
      description: "Використовувати наступні вправи червоної команди, для імітації спроб супротивників скомпрометувати системи організації відповідно до прийнятих правил ведення бойових дій: [Завдання: визначені організацією вправи червоної команди].",
      title: "ТЕСТУВАННЯ НА ПРОНИКНЕННЯ - ЧЕРВОНА КОМАНДА (CA-8(2))",
      parameters: [
        {:ca_8_2_01,
         "Залучити вправи червоної команди, щоб імітувати спроби супротивників скомпрометувати системи організації",
         [type: :integer, default: 3]},
        {:ca_8_2_odp,
         "Визначено вправи червоної команди для імітації спроби супротивників скомпрометувати системи організації",
         [type: :integer, default: 3]}
      ]
    }
  end

  def spec(:"id-spe-ca-8-3") do
    %{
      id: :"id-spe-ca-8-3",
      description: "Впровадити процес тестування на проникнення, який охоплює [Призначення: визначену організацією частоту] [Вибір: з попередженням; без попередження] спроб обійти чи зламати заходи захисту, пов’язані з фізичними точками доступу до об’єкта.",
      title: "ТЕСТУВАННЯ НА ПРОНИКНЕННЯ - МОЖЛИВОСТІ ПЕРЕВІРКИ НА ПРОНИКНЕННЯ (CA-8(3))",
      parameters: [
        {:ca_8_3_odp_01,
         "Визначено частоту спроби обійти або зламати заходи захисту, пов'язані з фізичними точками доступу до об'єкта в тестуванні на проникнення",
         [type: :integer, default: 30]},
        {:ca_8_3_odp_02,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {з попередженням; без попередження}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ca-9") do
    %{
      id: :"id-spe-ca-9",
      description: "a. Авторизувати внутрішні підключення [Призначення: системні компоненти або класи компонентів, що організація визначила] до системи; b. Задокументувати, для кожного внутрішнього з’єднання, характеристики інтерфейсу, вимоги безпеки та приватності, а також характер переданої інформації; c. Розірвати внутрішні системні підключення після [Призначення: умови, визначені організацією]; d. Переглядати [Призначення: частота, визначена організацією] постійну потребу в кожному внутрішньому з’єднанні.",
      title: "ВНУТРІШНІ З’ЄДНАННЯ СИСТЕМИ (CA-9)",
      parameters: [
        {:ca_9_a,
         "Внутрішні підключення компонентів системи до системи є авторизовані",
         [type: :string, default: nil]},
        {:ca_9_b_01,
         "Для кожного внутрішнього з'єднання задокументовані характеристики інтерфейсу",
         [type: :string, default: nil]},
        {:ca_9_b_02,
         "Для кожного внутрішнього з'єднання задокументовані вимоги безпеки",
         [type: :string, default: nil]},
        {:ca_9_b_03,
         "Для кожного внутрішнього з'єднання задокументовані вимоги конфіденційності",
         [type: :string, default: nil]},
        {:ca_9_b_04,
         "Для кожного внутрішнього з'єднання задокументовані характер переданої інформації",
         [type: :string, default: nil]},
        {:ca_9_c,
         "Внутрішні з'єднання системи розриваються після виконання умов",
         [type: :string, default: nil]},
        {:ca_9_d,
         "Переглядається подальша потреба у кожному внутрішньому з'єднанні частота",
         [type: :string, default: "щорічно"]},
        {:ca_9_odp_01,
         "Визначено компоненти системи або класи компонентів, що потребують внутрішніх підключень до системи",
         [type: :string, default: nil]},
        {:ca_9_odp_02,
         "Визначено умови, за яких необхідно розірвати внутрішні підключення",
         [type: :list, default: []]},
        {:ca_9_odp_03,
         "Визначено частоту, з якою необхідно переглядати постійну потребу в кожному внутрішньому з'єднанні",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cm-1") do
    %{
      id: :"id-spe-cm-1",
      description: "a. Розробити, задокументувати та поширити серед [Призначення: визначених організацією персоналу або ролей]: 1. [Вибір (один або декілька): Рівень організації; Рівень місії/бізнес-процесу; рівень системи] політики управління конфігурацією, яка: 2. (a) містить мету, сферу застосування, ролі, обов’язки, відповідальність керівництва, координацію між організаційними підрозділами та систему контролю відповідності (complaince); (b) відповідає чинним законам, нормативним документам, наказам, положенням, політикам, стандартам і керівним принципам; процедури, що сприяють реалізації політики управління конфігурацією та пов’язаних з нею заходів управління конфігурацією. b. Призначити [Призначення: посадова особа, визначена організацією] для управління розробкою, документуванням і розповсюдженням політики та процедур керування конфігурацією. c. Переглядати та оновлювати поточну політику управління конфігурацією: 1. Політика [Призначення: частота, визначена організацією] та наступні [Призначення: події, визначені організацією]; 2. Процедури [Призначення: частота, визначена організацією] та наступні [Призначення: події, визначені організацією].",
      title: "Політика та процедури управління конфігурацією (CM-1)",
      parameters: [
        {:cm_1_a_01,
         "Розроблено та задокументовано політику управління конфігурацією",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_1_a_02,
         "Політика управління конфігурацією поширюється на персонал або ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_1_a_03,
         "Розроблені та задокументовані процедури управління , що сприяють реалізації політики управління конфігурацією та пов’язаних з нею заходів управління конфігурацією",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_1_b,
         "Посадова особа призначається для управління розробкою, документуванням і розповсюдженням політики та процедур керування конфігурацією; CM-01(c)[01][01] переглядається та оновлюється поточна політика управління конфігурацією частота; CM-01(c)[01][02] переглядається та оновлюється поточна політика управління конфігурацією після події; CM-01(c)[02][01] переглядаються та оновлюються поточні процедури управління конфігурацією частота; CM-01(c)[02][02] переглядаються та оновлюються поточні процедури управління конфігурацією після події; ЗНАЧЕННЯ конфігурацією",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_1_odp_01,
         "Визначено персонал або ролі, на яких поширюється політика управління конфігурацією",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_1_odp_02,
         "Визначено персонал або ролі, на яких поширюється процедури управління конфігурацією",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнес-процесу; рівень системи}",
         [type: :string, default: nil]},
        {:cm_1_odp_04,
         "Визначено посадову особу, яка управляє розробкою, документуванням і розповсюдженням політики та процедур керування конфігурацією",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_1_odp_05,
         "Визначено частоту, з якою переглядається та оновлюється поточна політика управління конфігурацією",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_1_odp_06,
         "Визначено події, після яких переглядається та оновлюється поточна політика управління конфігурацією",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_1_odp_07,
         "Визначено частоту, з якою переглядаються та оновлюються поточні процедури управління конфігурацією",
         [type: :integer, default: 30]},
        {:cm_1_odp_08,
         "Визначено події, після яких переглядаються та оновлюються поточні процедури управління конфігурацією",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-cm-2") do
    %{
      id: :"id-spe-cm-2",
      description: "a. Розробити, задокументувати та підтримувати за допомогою заходів конфігурації поточні базові налаштування системи. b. Переглядати та оновлювати базові налаштування системи: 1. з [Призначення: визначеною організацією частотою]; 2. за потреби внаслідок [Призначення: визначених організацією обставин]; 3. коли встановлені нові або оновлені компоненти системи.",
      title: "БАЗОВА КОНФІГУРАЦІЯ (CM-2)",
      parameters: [
        {:cm_2_a_01,
         "Розроблено та задокументовано поточні базові налаштування системи",
         [type: :string, default: nil]},
        {:cm_2_a_02,
         "Поточні базові налаштування системи підтримуються за допомогою заходів конфігурації",
         [type: :string, default: nil]},
        {:cm_2_b_01,
         "Переглядаються та оновлюються базові налаштування системи частота",
         [type: :string, default: "щорічно"]},
        {:cm_2_b_02,
         "Переглядаються та оновлюються базові налаштування системи після подій",
         [type: :string, default: nil]},
        {:cm_2_b_03,
         "Переглядаються та оновлюються базові налаштування системи коли встановлюються або модернізуються компоненти системи",
         [type: :string, default: nil]},
        {:cm_2_odp_01,
         "Визначено частоту налаштувань; перегляду та оновлення базових",
         [type: :integer, default: 30]},
        {:cm_2_odp_02,
         "Визначено обставини, що вимагають перегляду та оновлення базових налаштувань",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-2-1") do
    %{
      id: :"id-spe-cm-2-1",
      description: "",
      title: "БАЗОВА КОНФІГУРАЦІЯ - ПЕРЕГЛЯД ТА ОНОВЛЕННЯ (CM-2(1))",
      parameters: [
        {:cm_2_1_01,
         "БАЗОВА КОНФІГУРАЦІЯ - ПЕРЕГЛЯД ТА ОНОВЛЕННЯ [Вилучено: Включено до CM-02]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-2-2") do
    %{
      id: :"id-spe-cm-2-2",
      description: "Підтримувати актуальність, повноту, точність і доступність базової конфігурації системи за допомогою [Призначення: автоматизовані механізми, визначені організацією].",
      title: "БАЗОВА КОНФІГУРАЦІЯ - АВТОМАТИЗАЦІЯ ПІДТРИМКИ ЗАДЛЯ ТОЧНОСТІ ТА ВЖИВАНОСТІ (CM-2(2))",
      parameters: [
        {:cm_2_2_02,
         "Повнота базової конфігурації системи підтримується за допомогою автоматизовані механізми",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_2_2_03,
         "Точність базової конфігурації системи підтримується за допомогою автоматизовані механізми",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_2_2_04,
         "Доступність базової конфігурації системи підтримується за допомогою автоматизовані механізми",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_2_2_odp,
         "Визначено автоматизовані механізми підтримки базової конфігурації системи; CM-02(02)[01] актуальність базової конфігурації системи підтримується за допомогою автоматизовані механізми",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-cm-2-3") do
    %{
      id: :"id-spe-cm-2-3",
      description: "Зберігати [Призначення: кількість, визначена організацією] попередніх версій базових конфігурацій системи для підтримки відкату.",
      title: "БАЗОВА КОНФІГУРАЦІЯ - ЗБЕРІГАННЯ ПОПЕРЕДНІХ ВЕРСІЙ КОНФІГУРАЦІЙ (CM-2(3))",
      parameters: [
        {:cm_2_3_01,
         "Визначено попередні версії базових конфігурацій системи необхідні для підтримки відкату зберігати попередні версії для підтримки відкату",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-2-4") do
    %{
      id: :"id-spe-cm-2-4",
      description: "",
      title: "БАЗОВА КОНФІГУРАЦІЯ - НЕАВТОРИЗОВАНЕ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ (CM-2(4))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-cm-2-5") do
    %{
      id: :"id-spe-cm-2-5",
      description: "",
      title: "БАЗОВА КОНФІГУРАЦІЯ - АВТОРИЗОВАНЕ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ (CM-2(5))",
      parameters: [
        {:cm_2_5_01,
         "БАЗОВА КОНФІГУРАЦІЯ - АВТОРИЗОВАНЕ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ [Вилучено: Включено до CM-07(05)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-2-6") do
    %{
      id: :"id-spe-cm-2-6",
      description: "Підтримувати базову конфігурацію для розробки системи та тестових середовищ, які керуються окремо від робочої базової конфігурації.",
      title: "БАЗОВА КОНФІГУРАЦІЯ - РОЗРОБКА ТА СЕРЕДОВИЩЕ ТЕСТУВАННЯ (CM-2(6))",
      parameters: [
        {:cm_2_6_01,
         "Підтримується базова конфігурація для розробки системи, які керуються окремо від робочої базової конфігурації",
         [type: :string, default: nil]},
        {:cm_2_6_02,
         "Підтримується базова конфігурація для розробки тестових середовищ, які керуються окремо від робочої базової конфігурації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-2-7") do
    %{
      id: :"id-spe-cm-2-7",
      description: "(a) Видавати [Призначення: визначених організацією систем або компонентів систем] з [Призначенням: визначеними організацією конфігураціями] особам, що перебувають у місцях, які організація вважає місцями зі значним ризиком; (b) Застосувати [Призначення: визначені організацією запобіжні заходи безпеки] до компонентів, коли особи повертаються з поїздки.",
      title: "БАЗОВА КОНФІГУРАЦІЯ - КОНФІГУРАЦІЯ СИСТЕМ ТА КОМПОНЕНТІВ ДЛЯ СФЕР З ВИСОКИМ РИЗИКОМ (CM-2(7))",
      parameters: [
        {:cm_2_7_a,
         "Системи або компоненти системи з конфігураціями видаються особам, що перебувають у місцях, які організація вважає, становлять значний ризик",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_2_7_b,
         "Заходи безпеки застосовуються до систем або компонентів системи, коли особи повертаються з поїздки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_2_7_odp_01,
         "Визначено системи або компоненти систем, які мають видаватися особам, що перебувають у місцях зі значним ризиком",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-cm-3") do
    %{
      id: :"id-spe-cm-3",
      description: "a. Визначити типи змін у системі, які контролюються конфігурацією. b. Переглядати запропоновані зміни в конфігурації, контрольовані системою, і схвалити або відхилити ці зміни з явним урахуванням аналізу наслідків безпеки. c. Документувати рішення зі зміни конфігурації системи. d. Впровадити схвалені зміни конфігурації в систему. e. Зберігати записи змін конфігурації системі впродовж [Призначення: певного періоду часу, визначеного організацією]. f. Здійснювати моніторинг і аналіз дій, пов’язаних зі змінами конфігурації системи. g. Координувати та впроваджувати нагляд за діяльністю з управління змінами конфігурації за допомогою [Призначення: елементу управління змінами конфігурації, визначеного організацією], який викликається [Вибір (один або кілька): [Призначення: з визначеною організацією частотою]; [Призначення: визначені організацією умови зміни конфігурації]].",
      title: "УПРАВЛІННЯ ЗМІНАМИ КОНФІГУРАЦІЇ (CM-3)",
      parameters: [
        {:cm_3_b_01,
         "Розглядаються запропоновані зміни в конфігурації, що контролюються системою",
         [type: :string, default: nil]},
        {:cm_3_b_02,
         "Запропоновані зміни в конфігурації, що контролюються системою, схвалюються або відхиляються з урахуванням аналізу наслідків безпеки",
         [type: :string, default: nil]},
        {:cm_3_c,
         "Рішення про зміну конфігурації системи документуються",
         [type: :string, default: nil]},
        {:cm_3_d,
         "Впроваджуються схвалені зміни до конфігурації в систему",
         [type: :string, default: nil]},
        {:cm_3_e,
         "Записи про зміни конфігурації у системі зберігаються протягом <період часу CM-03_ODP[01]>",
         [type: :integer, default: 30]},
        {:cm_3_f_01,
         "Здійснюється моніторинг конфігурації системи",
         [type: :string, default: nil]},
        {:cm_3_f_02,
         "Здійснюється аналіз дій, пов'язаних зі змінами конфігурації системи",
         [type: :string, default: nil]},
        {:cm_3_g_01,
         "Діяльність з управління змінами конфігурації координується та контролюється елемент управління",
         [type: :string, default: nil]},
        {:cm_3_odp_01,
         "Визначено період часу, протягом якого зберігатимуться записи про зміни конфігурації",
         [type: :integer, default: 30]},
        {:cm_3_odp_02,
         "Визначено елементи управління змінами конфігурації, відповідальні за координацію та нагляд за діяльністю з управління змінами",
         [type: :string, default: nil]},
        {:cm_3_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {частота; коли умови}",
         [type: :list, default: []]},
        {:cm_3_odp_04,
         "Визначено частоту, з якою викликаються елементи управління змінами конфігурації (якщо вибрано)",
         [type: :integer, default: 30]},
        {:cm_3_odp_05,
         "Визначено умови, за яких викликаються елементи управління змінами конфігурації (якщо вибрано); CM-03(a) визначено та задокументовано типи змін до системи, які контролюються конфігурацією",
         [type: :list, default: []]}
      ]
    }
  end

  def spec(:"id-spe-cm-3-1") do
    %{
      id: :"id-spe-cm-3-1",
      description: "",
      title: "УПРАВЛІННЯ ЗМІНАМИ КОНФІГУРАЦІЇ - АВТОМАТИЗОВАНЕ ДОКУМЕНТУВАННЯ, ПОВІДОМЛЕННЯ ТА ЗАБОРОНА ВНЕСЕННЯ ЗМІН (CM-3(1))",
      parameters: [
        {:cm_3_1_a,
         "Автоматизовані механізми використовуються для документування запропонованих змін до системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_3_1_b,
         "Автоматизовані механізми використовуються для повідомлення уповноважені органи про запропоновані зміни в системі та запиту на затвердження змін",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_3_1_c,
         "Автоматизовані механізми використовуються для виділення запропонованих змін до системи, які не були схвалені або відхилені протягом період часу",
         [type: :integer, default: 30]},
        {:cm_3_1_d,
         "Автоматизовані механізми використовуються для заборони внесення змін до системи до отримання відповідних погоджень",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_3_1_e,
         "Автоматизовані механізми використовуються для документування всіх змін в системі",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_3_1_f,
         "Автоматизовані механізми використовуються для повідомлення персоналу про завершення погоджених змін у системі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_3_1_odp_01,
         "Визначено механізми, що використовуються для ав- томатизації управління змінами конфігурації",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_3_1_odp_02,
         "Визначені уповноважені органи, про які необхідно повідомляти та узгоджувати пропоновані зміни в системі",
         [type: :string, default: nil]},
        {:cm_3_1_odp_03,
         "Визначено період часу, після якого слід виділяти зміни, які не були схвалені або відхилені",
         [type: :integer, default: 30]},
        {:cm_3_1_odp_04,
         "Визначено персонал, який буде повідомлений про завершення затверджених змін",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-cm-3-2") do
    %{
      id: :"id-spe-cm-3-2",
      description: "Тестувати, перевіряти та документувати зміни в системі до повної їх реалізації.",
      title: "УПРАВЛІННЯ ЗМІНАМИ КОНФІГУРАЦІЇ - ТЕСТУВАННЯ, ВАЛІДАЦІЯ ТА ДОКУМЕНТУВАННЯ ЗМІН (CM-3(2))",
      parameters: [
        {:cm_3_2_01,
         "Зміни в системі тестуються перед повним впровадженням змін",
         [type: :string, default: nil]},
        {:cm_3_2_02,
         "Зміни в системі перевіряються перед повним впровадженням змін",
         [type: :string, default: nil]},
        {:cm_3_2_03,
         "Зміни в системі документуються перед повним впровадженням змін",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-3-3") do
    %{
      id: :"id-spe-cm-3-3",
      description: "Внести зміни в поточний базову план системи та розгорнути оновлений базовий план на встановленій базі за допомогою [Призначення: автоматизовані механізми, визначені організацією].",
      title: "УПРАВЛІННЯ ЗМІНАМИ КОНФІГУРАЦІЇ - АВТОМАТИЗОВАНА РЕАЛІЗАЦІЯ ЗМІН (CM-3(3))",
      parameters: [
        {:cm_3_3_01,
         "Зміни до поточного базового плану системи реалізуються за допомогою автоматизовані механізми",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_3_3_02,
         "Оновлений базовий план розгортається по всій встановленій базі за допомогою автоматизовані механізми",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_3_3_odp,
         "Визначено автоматизовані механізми для внесення змін та розгортання оновленого базового плану по всій встановленій базі",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-cm-3-4") do
    %{
      id: :"id-spe-cm-3-4",
      description: "Вимагати від [Призначення: визначеного організацією представника з інформаційної безпеки] бути членом [Призначення: визначеного організацією елементу керування зміною конфігурацій].",
      title: "УПРАВЛІННЯ ЗМІНАМИ КОНФІГУРАЦІЇ - ПРЕДСТАВНИК БЕЗПЕКИ (CM-3(4))",
      parameters: [
        {:cm_3_4_01,
         "Представники безпеки повинні бути членами елемента керування змінами конфігурації",
         [type: :string, default: nil]},
        {:cm_3_4_02,
         "Представники конфіденційності повинні бути членами елемента керування змінами конфігурації",
         [type: :string, default: nil]},
        {:cm_3_4_odp_01,
         "Визначено представника з безпеки, який має бути членом елементу керування змінами конфігурації",
         [type: :string, default: nil]},
        {:cm_3_4_odp_02,
         "Визначено представника з конфіденційності, який має бути членом елементу керування змінами конфігурації",
         [type: :string, default: nil]},
        {:cm_3_4_odp_03,
         "Визначено елемент керування змінами конфігурації, членами якого мають бути представники безпеки та конфіденційності",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-3-5") do
    %{
      id: :"id-spe-cm-3-5",
      description: "Реалізувати автоматичне [Призначення: визначене організацією реагування безпеки], якщо базова конфігурація системи змінюється несанкціонованим чином.",
      title: "УПРАВЛІННЯ ЗМІНАМИ КОНФІГУРАЦІЇ - АВТОМАТИЧНЕ РЕАГУВАННЯ БЕЗПЕКИ (CM-3(5))",
      parameters: [
        {:cm_3_5_01,
         "Реагування безпеки автоматично застосовуються, якщо базова конфігурація системи змінюється несанкціонованим чином",
         [type: :string, default: nil]},
        {:cm_3_5_odp,
         "Визначено реагування безпеки, які мають бути застосовані автоматично",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-3-6") do
    %{
      id: :"id-spe-cm-3-6",
      description: "Забезпечити, щоб криптографічні механізми, які використовуються для забезпечення відповідних заходів захисту перебували під управлінням конфігурацією [Призначення: визначених організацією заходів безпеки].",
      title: "УПРАВЛІННЯ ЗМІНАМИ КОНФІГУРАЦІЇ - УПРАВЛІННЯ ЗАСОБАМИ КРИПТОГРАФІЧНОГО ЗАХИСТУ (CM-3(6))",
      parameters: [
        {:cm_3_6_01,
         "Криптографічні механізми, які використовуються для забезпечення відповідних заходів захисту перебувають під управлінням конфігурацією заходи захисту",
         [type: :string, default: "AES-256-GCM"]},
        {:cm_3_6_odp,
         "Визначено заходи захисту",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-3-7") do
    %{
      id: :"id-spe-cm-3-7",
      description: "Перегляньте зміни в системі [Призначення: частота, визначена організацією] або коли [Призначення: обставини, визначені організацією], щоб визначити, чи відбулися неавторизовані зміни.",
      title: "УПРАВЛІННЯ ЗМІНАМИ КОНФІГУРАЦІЇ - ПЕРЕГЛЯД ЗМІН У СИСТЕМІ (CM-3(7))",
      parameters: [
        {:cm_3_7_01,
         "Зміни в системі переглядаються частота або за обставин, щоб визначити, чи відбулися неавторизовані зміни",
         [type: :string, default: "щорічно"]},
        {:cm_3_7_odp_01,
         "Визначено частоту, з якою необхідно переглядати зміни",
         [type: :integer, default: 30]},
        {:cm_3_7_odp_02,
         "Визначено обставини, за яких зміни мають бути переглянуті",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-3-8") do
    %{
      id: :"id-spe-cm-3-8",
      description: "Запобігати або обмежити зміни конфігурації системи за таких обставин: [Призначення: обставини, визначені організацією].",
      title: "УПРАВЛІННЯ ЗМІНАМИ КОНФІГУРАЦІЇ - ЗАПОБІГАННЯ ЧИ ОБМЕЖЕННЯ ЗМІН КОНФІГУРАЦІЇ (CM-3(8))",
      parameters: [
        {:cm_3_8_01,
         "Зміни конфігурації системи запобігають або обмежують за обставин",
         [type: :string, default: nil]},
        {:cm_3_8_odp,
         "Визначено обставини, за яких зміни мають бути запобіжені або обмежені",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-4") do
    %{
      id: :"id-spe-cm-4",
      description: "Аналізувати зміни в системі, щоб визначити потенційну загрозу безпеці та приватності перед реалізацією змін.",
      title: "АНАЛІЗ ВПЛИВУ НА БЕЗПЕКУ ТА ПРИВАТНІСТЬ (CM-4)",
      parameters: [
        {:cm_4_01,
         "Аналізуються зміни в системі, щоб визначити потенційну загрозу безпеці перед реалізацією змін",
         [type: :string, default: nil]},
        {:cm_4_02,
         "Аналізуються зміни в системі, щоб визначити потенційну загрозу конфіденційності перед реалізацією змін",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-4-1") do
    %{
      id: :"id-spe-cm-4-1",
      description: "",
      title: "АНАЛІЗ ВПЛИВУ НА БЕЗПЕКУ ТА ПРИВАТНІСТЬ - ВІДОКРЕМЛЕНІ ВИПРОБУВАЛЬНІ СЕРЕДОВИЩА (CM-4(1))",
      parameters: [
        {:cm_4_1_01,
         "Зміни в системі аналізуються в окремому тестовому середовищі перед впровадженням в операційному середовищі",
         [type: :string, default: nil]},
        {:cm_4_1_02,
         "Зміни в системі аналізуються на предмет впливу на безпеку через недоліки",
         [type: :string, default: nil]},
        {:cm_4_1_03,
         "Зміни в системі аналізуються на предмет впливу на конфіденційність через недоліки",
         [type: :string, default: nil]},
        {:cm_4_1_04,
         "Зміни в системі аналізуються на предмет впливу на безпеку через слабкості",
         [type: :string, default: nil]},
        {:cm_4_1_05,
         "Зміни в системі аналізуються на предмет впливу на конфіденційність через слабкості",
         [type: :string, default: nil]},
        {:cm_4_1_06,
         "Зміни в системі аналізуються на предмет впливу на безпеку через несумістність",
         [type: :string, default: nil]},
        {:cm_4_1_07,
         "Зміни в системі аналізуються на предмет впливу на конфіденційність через несумістність",
         [type: :string, default: nil]},
        {:cm_4_1_08,
         "Зміни в системі аналізуються на предмет впливу на безпеку через навмисне спричинення шкоди",
         [type: :string, default: nil]},
        {:cm_4_1_09,
         "Зміни в системі аналізуються на предмет впливу на конфіденційність через навмисне спричинення шкоди",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-4-2") do
    %{
      id: :"id-spe-cm-4-2",
      description: "Після змін у системі переконайтеся, що відповідні заходи захисту реалізовано правильно і вони функціонують належним чином та дають бажаний результат щодо дотримання вимог безпеки та приватності для системи.",
      title: "АНАЛІЗ ВПЛИВУ НА БЕЗПЕКУ ТА ПРИВАТНІСТЬ - ВЕРИФІКАЦІЯ ФУНКЦІЙ БЕЗПЕКИ ТА ПРИВАТНОСТІ (CM-4(2))",
      parameters: [
        {:cm_4_2_01,
         "Заходи захисту, на які було здійснено вплив, реалізовані правильно з точки зору відповідності вимогам безпеки системи після внесення змін до системи",
         [type: :string, default: nil]},
        {:cm_4_2_02,
         "Заходи захисту, на які було здійснено вплив, реалізовані правильно з точки зору відповідності вимогам конфіденційності системи після внесення змін до системи",
         [type: :string, default: nil]},
        {:cm_4_2_03,
         "Заходи захисту, на які було здійснено вплив, функціонують належним чином з точки зору відповідності вимогам безпеки системи після внесення змін до системи",
         [type: :string, default: nil]},
        {:cm_4_2_04,
         "Заходи захисту, на які було здійснено вплив, функціонують належним чином з точки зору відповідності вимогам конфіденційності системи після внесення змін до системи",
         [type: :string, default: nil]},
        {:cm_4_2_05,
         "Заходи захисту, на які було здійснено вплив, дають бажаний результат з точки зору відповідності вимогам безпеки системи після внесення змін до системи",
         [type: :string, default: nil]},
        {:cm_4_2_06,
         "Заходи захисту, на які було здійснено вплив, дають бажаний результат з точки зору відповідності вимогам конфіденційності системи після внесення змін до системи; ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-5") do
    %{
      id: :"id-spe-cm-5",
      description: "Визначити, задокументувати, затвердити та забезпечити застосування фізичних і логічних обмежень доступу, пов’язаних зі змінами в системі.",
      title: "ОБМЕЖЕННЯ ДОСТУПУ ДО ЗМІНИ (CM-5)",
      parameters: [
        {:cm_5_01,
         "Визначені та задокументовані фізичні обмеження доступу, пов'язані зі змінами в системі",
         [type: :string, default: nil]},
        {:cm_5_02,
         "Затверджені фізичні обмеження доступу, пов'язані зі змінами в системі",
         [type: :string, default: nil]},
        {:cm_5_03,
         "Застосовуються фізичні обмеження доступу, пов'язані зі змінами в системі",
         [type: :string, default: nil]},
        {:cm_5_04,
         "Визначені та задокументовані логічні обмеження доступу, пов'язані зі змінами в системі",
         [type: :string, default: nil]},
        {:cm_5_05,
         "Затверджені логічні обмеження доступу, пов'язані зі змінами в системі",
         [type: :string, default: nil]},
        {:cm_5_06,
         "Застосовуються логічні обмеження доступу, пов'язані зі змінами в системі",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-5-1") do
    %{
      id: :"id-spe-cm-5-1",
      description: "",
      title: "ОБМЕЖЕННЯ ДОСТУПУ ДО ЗМІНИ - АУДИТ І ЗДІЙСНЕННЯ АВТОМАТИЧНОГО ДОСТУПУ (CM-5(1))",
      parameters: [
        {:cm_5_1_a,
         "Обмеження доступу до змін застосовуються за допомогою автоматизованих механізмів",
         [type: :string, default: nil]},
        {:cm_5_1_b,
         "Автоматично формуються записи аудиту для виконаних дій",
         [type: :string, default: nil]},
        {:cm_5_1_odp,
         "Визначено механізми, що використовуються для автоматизації застосування обмежень доступу",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-cm-5-2") do
    %{
      id: :"id-spe-cm-5-2",
      description: "",
      title: "ОБМЕЖЕННЯ ДОСТУПУ ДО ЗМІНИ - ПЕРЕГЛЯД ЗМІН У СИСТЕМІ (CM-5(2))",
      parameters: [
        {:cm_5_2_01,
         "ОБМЕЖЕННЯ ДОСТУПУ ДО ЗМІНИ - ПЕРЕГЛЯД ЗМІН У СИСТЕМІ [Вилучено: перенесено до СМ-03(07)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-5-3") do
    %{
      id: :"id-spe-cm-5-3",
      description: "",
      title: "ОБМЕЖЕННЯ ДОСТУПУ ДО ЗМІНИ - ПІДПИСАНІ КОМПОНЕНТИ (CM-5(3))",
      parameters: [
        {:cm_5_3_01,
         "ОБМЕЖЕННЯ ДОСТУПУ ДО ЗМІНИ - ПІДПИСАНІ КОМПОНЕНТИ [Вилучено: перенесено до СМ-14]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-5-4") do
    %{
      id: :"id-spe-cm-5-4",
      description: "Здійснювати подвійну авторизацію для внесення змін до [Призначення: компонентів системи та інформації на рівні системи, визначених організацією].",
      title: "ОБМЕЖЕННЯ ДОСТУПУ ДО ЗМІНИ - ПОДВІЙНА АВТОРИЗАЦІЯ (CM-5(4))",
      parameters: [
        {:cm_5_4_01,
         "Запроваджено подвійну авторизацію для внесення змін до компонентів системи",
         [type: :string, default: nil]},
        {:cm_5_4_02,
         "Запроваджено подвійну авторизацію для внесення змін до інформації",
         [type: :string, default: nil]},
        {:cm_5_4_odp_01,
         "Визначено компоненти системи, що потребують подвійної авторизації для внесення змін",
         [type: :string, default: nil]},
        {:cm_5_4_odp_02,
         "Визначено інформацію на рівні системи, що потребують подвійної авторизації для внесення змін",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-5-5") do
    %{
      id: :"id-spe-cm-5-5",
      description: "(a) обмежити повноваження для зміни компонентів системи та інформації, пов’язаної із системою, у виробничому або операційному середовищі; (b) переглядати та переоцінювати повноваження [Призначення: визначеною організацією з частотою].",
      title: "ОБМЕЖЕННЯ ДОСТУПУ ДО ЗМІНИ - ОБМЕЖЕННЯ ПОВНОВАЖЕНЬ ДЛЯ ВИРОБНИЦТВА ТА ЕКСПЛУАТАЦІЇ (CM-5(5))",
      parameters: [
        {:cm_5_5_a_01,
         "Повноваження для зміни компонентів системи у виробничому або операційному середовищі обмежені",
         [type: :string, default: nil]},
        {:cm_5_5_a_02,
         "Повноваження для зміни інформації, пов'язаної із системою у виробничому або операційному середовищі обмежені",
         [type: :string, default: nil]},
        {:cm_5_5_b_01,
         "Переглядаються частота>",
         [type: :string, default: "щорічно"]},
        {:cm_5_5_b_02,
         "Переоцінюються повноваження частота; повноваження <CM-05(05)_ODP[01]",
         [type: :string, default: "щорічно"]},
        {:cm_5_5_odp_01,
         "Визначено частоту перегляду повноважень",
         [type: :integer, default: 30]},
        {:cm_5_5_odp_02,
         "Визначено частоту переоцінення повноважень",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cm-5-6") do
    %{
      id: :"id-spe-cm-5-6",
      description: "Обмежити повноваження для зміни програмного забезпечення, яке перебуває в бібліотеках програмного забезпечення.",
      title: "ОБМЕЖЕННЯ ДОСТУПУ ДО ЗМІНИ - ОБМЕЖЕННЯ ПОВНОВАЖЕНЬ ДЛЯ БІБЛІОТЕК (CM-5(6))",
      parameters: [
        {:cm_5_6_01,
         "Обмежено повноваження для зміни програмного забезпечення, яке перебуває в бібліотеках програмного забезпечення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-5-7") do
    %{
      id: :"id-spe-cm-5-7",
      description: "",
      title: "ОБМЕЖЕННЯ ДОСТУПУ ДО ЗМІНИ ВАДЖЕННЯ ЗАХОДІВ ЗАХИСТУ (CM-5(7))",
      parameters: [
        {:cm_5_7_01,
         "ОБМЕЖЕННЯ ДОСТУПУ ДО ЗМІНИ ВАДЖЕННЯ ЗАХОДІВ ЗАХИСТУ - АВТОМАТИЧНЕ ВПРО- [Вилучено: включено до SI-07]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-6") do
    %{
      id: :"id-spe-cm-6",
      description: "a. Встановити та задокументувати параметри конфігурації компонентів, які застосовуються в системі, які відображають найбільш обмежений режим, що відповідає експлуатаційним вимогам, використовуючи [Призначення: визначені організацією загальні безпечні конфігурації]. b. Реалізувати конфігураційні установки. c. Визначити, задокументувати та затвердити будь-які відхилення від встановлених конфігураційних параметрів конфігурації для [Призначення: визначених організацією компонентів системи] на основі [Призначення: визначених організацією експлуатаційних вимог]. d. Відстежувати та керувати змінами конфігураційних параметрів відповідно до організаційної політики та процедур.",
      title: "НАЛАШТУВАННЯ КОНФІГУРАЦІЇ (CM-6)",
      parameters: [
        {:cm_6_a,
         "Налаштування конфігурації, які відображають найбільш обмежувальний режим, що відповідає експлуатаційним вимогам, встановлені та задокументовані для компонентів, що застосовуються в системі з використанням безпечні конфігурації",
         [type: :string, default: nil]},
        {:cm_6_b,
         "Реалізовано установки конфігурації, задокументовані в CM-06a",
         [type: :string, default: nil]},
        {:cm_6_c_01,
         "Будь-які відхилення від встановлених параметрів конфігурації для компонентів системи визначаються та документуються на основі експлуатаційних вимог",
         [type: :string, default: nil]},
        {:cm_6_c_02,
         "Будь-які відхилення від встановлених налаштувань конфігурації для компонентів системи затверджуються",
         [type: :string, default: nil]},
        {:cm_6_d_01,
         "Зміни в налаштуваннях конфігурації відстежуються відповідно до політики та процедур організації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_6_d_02,
         "Зміни налаштувань конфігурації керуються відповідно до політики та процедур організації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_6_odp_01,
         "Визначено загальні безпечні конфігурації для встановлення та документування параметрів конфігурації компонентів, які застосовуються в системі; CM-06_ODP[02] визначено компоненти системи, для яких необхідно затвердити відхилення",
         [type: :string, default: nil]},
        {:cm_6_odp_03,
         "Визначені експлуатаційні вимоги, що вимагають затвердження відхилень",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-6-1") do
    %{
      id: :"id-spe-cm-6-1",
      description: "",
      title: "НАЛАШТУВАННЯ КОНФІГУРАЦІЇ - АВТОМАТИЗОВАНЕ УПРАВЛІННЯ, ЗАСТОСУВАННЯ ТА ВЕРИФІКАЦІЯ (CM-6(1))",
      parameters: [
        {:cm_6_1_01,
         "Налаштування конфігурації для компонентів системи керуються за допомогою автоматизованих механізмів",
         [type: :string, default: nil]},
        {:cm_6_1_02,
         "Налаштування конфігурації для компонентів системи застосовуються за допомогою автоматизованих механізмів",
         [type: :string, default: nil]},
        {:cm_6_1_03,
         "Налаштування конфігурації для компонентів системи перевіряються за допомогою автоматизованих механізмів; механізми керування перевірки",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_6_1_odp_02,
         "Визначено автоматизовані механізми налаштуваннями конфігурації",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_6_1_odp_03,
         "Визначено автоматизовані механізми застосування налаштувань конфігурації",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_6_1_odp_04,
         "Визначено автоматизовані налаштувань конфігурації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-6-2") do
    %{
      id: :"id-spe-cm-6-2",
      description: "Виконайте такі дії у відповідь на неавторизовані зміни в [Призначення: параметри конфігурації, визначені організацією]: [Призначення: дії, визначені організацією].",
      title: "НАЛАШТУВАННЯ КОНФІГУРАЦІЇ САНКЦІОНОВАНІ ЗМІНИ (CM-6(2))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-cm-6-4") do
    %{
      id: :"id-spe-cm-6-4",
      description: "",
      title: "НАЛАШТУВАННЯ КОНФІГУРАЦІЇ - ДЕМОНСТРАЦІЯ ВІДПОВІДНОСТІ (CM-6(4))",
      parameters: [
        {:cm_6_4_01,
         "НАЛАШТУВАННЯ КОНФІГУРАЦІЇ - ДЕМОНСТРАЦІЯ ВІДПОВІДНОСТІ [Вилучено: Включено до CM-04]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-7") do
    %{
      id: :"id-spe-cm-7",
      description: "a. Налаштуйте систему для забезпечення лише [Призначення: основні функції, визначені організацією для місії]; b. Заборонити або обмежити використання таких функцій, портів, протоколів, програмного забезпечення та/або служб: [Призначення: визначені організацією заборонені або обмежені функції, системні порти, протоколи, програмне забезпечення та/або служби].",
      title: "МІНІМАЛЬНО НЕОБХІДНА ФУНКЦІОНАЛЬНІСТЬ (CM-7)",
      parameters: [
        {:cm_7_a,
         "Система налаштована на забезпечення лише основні функції системи ",
         [type: :string, default: nil]},
        {:cm_7_b_01,
         "Використання функцій заборонено або обмежено",
         [type: :string, default: nil]},
        {:cm_7_b_02,
         "Використання порти заборонено або обмежено",
         [type: :string, default: nil]},
        {:cm_7_b_03,
         "Використання протоколи заборонено або обмежено",
         [type: :string, default: "TLS 1.3"]},
        {:cm_7_b_04,
         "Використання програмне забезпечення заборонено або обмежено",
         [type: :string, default: nil]},
        {:cm_7_b_05,
         "Використання служби заборонено або обмежено",
         [type: :string, default: nil]},
        {:cm_7_odp_01,
         "Визначено основні функції системи, необхідні для виконання місії",
         [type: :string, default: nil]},
        {:cm_7_odp_02,
         "Визначено функції, які необхідно заборонити або обмежити",
         [type: :string, default: nil]},
        {:cm_7_odp_03,
         "Визначено системні порти, які необхідно заборонити або обмежити",
         [type: :string, default: nil]},
        {:cm_7_odp_04,
         "Визначено протоколи, які необхідно заборонити або обмежити; CM-07_ODP[05] визначено програмне забезпечення, яке необхідно заборонити або обмежити",
         [type: :string, default: "TLS 1.3"]},
        {:cm_7_odp_06,
         "Визначено служби, які необхідно заборонити або обмежити",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-7-1") do
    %{
      id: :"id-spe-cm-7-1",
      description: "",
      title: "МІНІМАЛЬНО НЕОБХІДНА ФУНКЦІОНАЛЬНІСТЬ - ПЕРІОДИЧНИЙ ПЕРЕГЛЯД (CM-7(1))",
      parameters: [
        {:cm_7_1_a,
         "Система переглядається частота для виявлення непотрібних та/або незахищених функцій, портів, протоколів і послуг",
         [type: :string, default: "TLS 1.3"]},
        {:cm_7_1_b_01,
         "Функції, які вважаються непотрібними та/або незахищеними, вимкнено",
         [type: :string, default: nil]},
        {:cm_7_1_b_02,
         "Порти, які вважаються непотрібними та/або незахищеними, вимкнено",
         [type: :string, default: nil]},
        {:cm_7_1_b_03,
         "Протоколи, які вважаються непотрібними та/або незахищеними, вимкнено",
         [type: :string, default: "TLS 1.3"]},
        {:cm_7_1_b_04,
         "Послуги, які вважаються непотрібними та/або незахищеними, вимкнено",
         [type: :string, default: nil]},
        {:cm_7_1_odp_01,
         "Визначено частоту, з якою слід переглядати систему для виявлення непотрібних та/або незахищених функцій, портів, протоколів і послуг",
         [type: :string, default: "TLS 1.3"]},
        {:cm_7_1_odp_02,
         "Визначено функції, які слід вимкнути, якщо вони вважаються непотрібними або незахищеними; CM-07(01)_ODP[03] визначено порти, які слід вимкнути, якщо вони вважаються непотрібними або незахищеними",
         [type: :string, default: nil]},
        {:cm_7_1_odp_04,
         "Визначено протоколи, які слід вимкнути, якщо вони вважаються непотрібними або незахищеними",
         [type: :string, default: "TLS 1.3"]},
        {:cm_7_1_odp_05,
         "Визначено послуги, які слід вимкнути, якщо вони вважаються непотрібними або незахищеними",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-7-2") do
    %{
      id: :"id-spe-cm-7-2",
      description: "Заборонити виконання програми відповідно до [Вибір (один або кілька): [Призначення: визначеної організацією політики, правил поведінки та/або угод про доступ щодо використання програмного забезпечення та обмежень]; правил, що встановлюють терміни та умови використання програмного забезпечення].",
      title: "МІНІМАЛЬНО НЕОБХІДНА ФУНКЦІОНАЛЬНІСТЬ - ЗАБОРОНА ВИКОНАННЯ ПРОГРАМИ (CM-7(2))",
      parameters: [
        {:cm_7_2_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {політики, правил поведінки та/або угод про доступ щодо викори- стання програмного забезпечення та обмежень; правила, що встановлюють терміни та умови використання програмного забезпечення}",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_7_2_odp_02,
         "Визначені політики, правил поведінки та/або угод про доступ щодо використання програмного забезпечення та обмежень (якщо вибрано)",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-cm-7-3") do
    %{
      id: :"id-spe-cm-7-3",
      description: "Забезпечити відповідність [Призначення: визначеним організацією вимогам до реєстрації для функцій, портів, протоколів і послуг].",
      title: "МІНІМАЛЬНО НЕОБХІДНА ФУНКЦІОНАЛЬНІСТЬ - ВІДПОВІДНІСТЬ РЕЄСТРАЦІЇ (CM-7(3))",
      parameters: [
        {:cm_7_3_01,
         "Вимоги до реєстрації дотримано",
         [type: :string, default: nil]},
        {:cm_7_3_odp,
         "Визначено вимоги до реєстрації функцій, портів, протоколів та сервісів",
         [type: :string, default: "TLS 1.3"]}
      ]
    }
  end

  def spec(:"id-spe-cm-7-4") do
    %{
      id: :"id-spe-cm-7-4",
      description: "(a) Визначити [Призначення: визначені організацією програмне забезпечення, що не має дозволу виконуватися в системі]. (b) Впровадити політику «дозволу всього, за винятком деяких» для заборони виконання неавторизованих програм у системі (c) Переглядати та оновлювати список неавторизованих програм [Призначення: з визначеною організацією частотою].",
      title: "МІНІМАЛЬНО НЕОБХІДНА ФУНКЦІОНАЛЬНІСТЬ - НЕАВТОРИЗОВАНЕ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ - ЧОРНИЙ СПИСОК (CM-7(4))",
      parameters: [
        {:cm_7_4_a,
         "Визначено програмне забезпечення",
         [type: :string, default: nil]},
        {:cm_7_4_b,
         "Політика \"дозволу всього, за винятком деяких\" застосовується для заборони виконання неавторизованих програм у системі",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_7_4_c,
         "Переглядається та оновлюється список неавторизованих програм частота",
         [type: :list, default: []]},
        {:cm_7_4_odp_01,
         "Визначено програмне забезпечення, яке не має дозволу на виконання в системі",
         [type: :string, default: nil]},
        {:cm_7_4_odp_02,
         "Визначено частоту, з якою слід переглядати та оновлювати список неавторизованих програм",
         [type: :list, default: []]}
      ]
    }
  end

  def spec(:"id-spe-cm-7-5") do
    %{
      id: :"id-spe-cm-7-5",
      description: "(a) Визначити [Призначення: визначені організацією програмне забезпечення, яке авторизовано виконується в системі] (b) Впровадити політику «заборони всього, за винятком деяких», щоб дозволити виконання авторизованих програм у системі. (c) Переглядати та оновлювати список авторизованих програм [Призначення: з визначеною організацією частотою].",
      title: "МІНІМАЛЬНО НЕОБХІДНА ФУНКЦІОНАЛЬНІСТЬ - АВТОРИЗОВАНЕ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ – БІЛИЙ СПИСОК (CM-7(5))",
      parameters: [
        {:cm_7_5_a,
         "Визначено програмне забезпечення",
         [type: :string, default: nil]},
        {:cm_7_5_b,
         "Політика \"заборонити все, дозволити за винятком\" застосовуэться, щоб дозволити виконання авторизованих програм у системі",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_7_5_c,
         "Переглядається та оновлюється список авторизованих програм частота",
         [type: :list, default: []]},
        {:cm_7_5_odp_01,
         "Визначено програмне забезпечення, яке авторизовано для виконання в системі",
         [type: :string, default: nil]},
        {:cm_7_5_odp_02,
         "Визначено частоту перегляду та оновлення списку авторизованих програм",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cm-7-6") do
    %{
      id: :"id-spe-cm-7-6",
      description: "Вимагайте, щоб визначене програмне забезпечення, встановлене користувачем, виконувалося в обмеженому середовищі фізичної або віртуальної машини з обмеженими привілеями: [Призначення: програмне забезпечення, встановлене користувачем, визначене організацією]",
      title: "МІНІМАЛЬНО НЕОБХІДНА ФУНКЦІОНАЛЬНІСТЬ - ЗАМКНУТІ СЕРЕДОВИЩА З ОБМЕЖЕНИМИ ПРИВІЛЕЯМИ (CM-7(6))",
      parameters: [
        {:cm_7_6_01,
         "Програмне забезпечення, встановлене користувачем має виконуватися в обмеженому середовищі фізичної або віртуальної машини з обмеженими привілеями",
         [type: :string, default: nil]},
        {:cm_7_6_odp,
         "Визначено встановлене користувачем програмне забезпечення, яке потрібно виконувати в обмеженому середовищі",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-7-7") do
    %{
      id: :"id-spe-cm-7-7",
      description: "Дозволити виконання двійкового або машинно-виконуваного коду лише в обмеженому фізичному або віртуальному машинному середовищі та за явного дозволу [Призначення: персонал або ролі, визначені організацією], якщо такий код: a) Отримано з джерел з обмеженою гарантією або без неї; та/або b) Без надання вихідного коду.",
      title: "МІНІМАЛЬНО НЕОБХІДНА ФУНКЦІОНАЛЬНІСТЬ - ВИКОНУВАНИЙ КОД У ЗАХИЩЕНОМУ СЕРЕДОВИЩІ (CM-7(7))",
      parameters: [
        {:cm_7_7_01,
         "Виконання двійкового або машинного коду дозволено лише в обмеженому середовищі фізичної або віртуальної машини",
         [type: :string, default: nil]},
        {:cm_7_7_a,
         "Виконання двійкового або машинного коду, отриманого з джерел з обмеженою гарантією або без неї, дозволяється лише з явного дозволу персонал або ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_7_7_b,
         "Виконання двійкового або машинного коду без надання вихідного коду дозволяється лише з явного дозволу персонал або ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_7_7_odp,
         "Визначено персонал або ролі для явного дозволу на виконання двійкового або машинно-виконуваного коду",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-cm-7-8") do
    %{
      id: :"id-spe-cm-7-8",
      description: "a) Заборонити використання двійкового або машинно-виконуваного коду з джерел з обмеженою гарантією або без неї або без надання вихідного коду; і b) Дозволяти винятки лише для обов’язкових місій або оперативних вимог і за погодженням з уповноваженою посадовою особою.",
      title: "МІНІМАЛЬНО НЕОБХІДНА ФУНКЦІОНАЛЬНІСТЬ - БІНАРНИЙ АБО МАШИННИЙ ВИКОНУВАНИЙ КОД (CM-7(8))",
      parameters: [
        {:cm_7_8_a,
         "Використання двійкового або машинного коду заборонено, якщо він походить з джерел з обмеженою гарантією або без неї, або без надання вихідного коду",
         [type: :string, default: nil]},
        {:cm_7_8_b_01,
         "Винятки із заборони на використання двійкового або машинного коду з джерел з обмеженою гарантією або без неї, або без надання вихідного коду допускаються лише для обов’язкових місій або оперативних вимог",
         [type: :string, default: nil]},
        {:cm_7_8_b_02,
         "Винятки із заборони на використання двійкового або машинного коду з джерел з обмеженою гарантією або без неї, або без надання вихідного коду допускаються лише у разі погодження з уповноваженою посадовою особою",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-cm-7-9") do
    %{
      id: :"id-spe-cm-7-9",
      description: "a. b. c. - ЗАБОРОНА Визначити [Призначення: апаратні компоненти, визначені організацією, авторизовані для використання в системі]; Заборонити використання або підключення неавторизованих апаратних компонентів; Перегляд та оновлення списку авторизованих апаратних компонентів [Призначення: частота, визначена організацією].",
      title: "МІНІМАЛЬНО НЕОБХІДНА ФУНКЦІОНАЛЬНІСТЬ - ЗАБОРОНА ВИКОРИСТАННЯ НЕАВТОРИЗОВАНОГО ОБЛАДНАННЯ (CM-7(9))",
      parameters: [
        {:cm_7_9_a,
         "Ідентифіковано апаратні компоненти",
         [type: :string, default: nil]},
        {:cm_7_9_b,
         "Використання або підключення несанкціонованих апаратних компонентів заборонено",
         [type: :string, default: nil]},
        {:cm_7_9_c,
         "Список дозволених апаратних компонентів переглядається та оновлюється з частота;",
         [type: :list, default: []]},
        {:cm_7_9_odp_01,
         "Визначено апаратні компоненти, дозволені для використання в системі; CM-07(09)_ODP[02 визначено періодичність перегляду та оновлення переліку дозволених апаратних компонентів",
         [type: :list, default: []]}
      ]
    }
  end

  def spec(:"id-spe-cm-8") do
    %{
      id: :"id-spe-cm-8",
      description: "a. b. Розробити та задокументувати процес інвентаризації компонентів системи, який: 1. точно описує поточну систему; 2. охоплює всі компоненти в межах акредитації системи; 3. не включає повторний облік компонентів або компонентів, будь-якої іншої системи; 4. визначає рівень деталізації, який є необхідним для відстеження та звітування; 5. включає інформацію для досягнення підзвітності компонентів системи: [Призначення: визначена організацією інформація, необхідна для досягнення ефективної підзвітності компонентів системи]. Переглядати та оновлювати опис компонентів системи з [Призначення: визначеною організацією частотою].",
      title: "ІНВЕНТАРИЗАЦІЯ КОМПОНЕНТІВ СИСТЕМИ (CM-8)",
      parameters: [
        {:cm_8_a_01,
         "Розроблено та задокументовано процес інвентаризації компонентів системи, який точно описує поточну систему",
         [type: :string, default: nil]},
        {:cm_8_a_02,
         "Розроблено та задокументовано процес інвентаризації компонентів системи, який охоплює всі компоненти в межах акредитації системи",
         [type: :string, default: nil]},
        {:cm_8_a_03,
         "Розроблено та задокументовано процес інвентаризації компонентів системи, який не включає повторний облік компонентів або компонентів, будь-якої іншої системи",
         [type: :string, default: nil]},
        {:cm_8_a_04,
         "Розроблено та задокументовано процес інвентаризації компонентів системи, який визначає рівень деталізації, який є необхідним для відстеження та звітування",
         [type: :string, default: nil]},
        {:cm_8_a_05,
         "Розроблено та задокументовано процес інвентаризації компонентів системи, який включає інформацію",
         [type: :string, default: nil]},
        {:cm_8_b,
         "Переглядається та оновлюється опис компонентів системи частота",
         [type: :string, default: "щорічно"]},
        {:cm_8_odp_01,
         "Визначено інформацію, яка вважається необхідною для досягнення ефективної підзвітності компонентів системи",
         [type: :string, default: nil]},
        {:cm_8_odp_02,
         "Визначено частоту перегляду та оновлення опису компонентів системи",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cm-8-1") do
    %{
      id: :"id-spe-cm-8-1",
      description: "",
      title: "ІНВЕНТАРИЗАЦІЯ КОМПОНЕНТІВ СИСТЕМИ - ОНОВЛЕННЯ ПІД ЧАС ВСТАНОВЛЕННЯ ТА ВИДАЛЕННЯ (CM-8(1))",
      parameters: [
        {:cm_8_1_01,
         "Інвентаризація компонентів системи оновлюється в рамках інсталяцій компонентів системи",
         [type: :string, default: nil]},
        {:cm_8_1_02,
         "Інвентаризація компонентів системи оновлюється в рамках видалення компонентів системи",
         [type: :string, default: nil]},
        {:cm_8_1_03,
         "Інвентаризація компонентів системи оновлюється в рамках оновлення компонентів системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-8-2") do
    %{
      id: :"id-spe-cm-8-2",
      description: "",
      title: "ІНВЕНТАРИЗАЦІЯ КОМПОНЕНТІВ СИСТЕМИ - АВТОМАТИЗОВАНА ПІДТРИМКА (CM-8(2))",
      parameters: [
        {:cm_8_2_01,
         "Автоматизовані механізми використовуються для підтримки актуальності інвентаризації компонентів системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_8_2_02,
         "Автоматизовані механізми використовуються для підтримки повноти інвентаризації компонентів системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_8_2_03,
         "Автоматизовані механізми використовуються для підтримки точності інвентаризації компонентів системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_8_2_04,
         "Автоматизовані механізми використовуються для підтримки доступності інвентаризації компонентів системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_8_2_odp_01,
         "Визначено автоматизовані механізми підтримки актуальності інвентаризації компонентів системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_8_2_odp_02,
         "Визначено автоматизовані механізми підтримки повноти інвентаризації компонентів системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_8_2_odp_03,
         "Визначено автоматизовані механізми підтримки точності інвентаризації компонентів системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_8_2_odp_04,
         "Визначено автоматизовані механізми підтримки доступності інвентаризації компонентів системи",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-cm-8-3") do
    %{
      id: :"id-spe-cm-8-3",
      description: "",
      title: "ІНВЕНТАРИЗАЦІЯ КОМПОНЕНТІВ СИСТЕМИ - АВТОМАТИЗОВАНЕ ВИЯВЛЕННЯ НЕАВТОРИЗОВАНИХ КОМПОНЕНТІВ (CM-8(3))",
      parameters: [
        {:cm_8_3_a_01,
         "Наявність несанкціонованого обладнання в системі виявляється за допомогою автоматизованих механізмів частота",
         [type: :string, default: "щорічно"]},
        {:cm_8_3_a_02,
         "Наявність несанкціонованого програмного забезпечення в системі виявляється за допомогою автоматизованих механізмів частота",
         [type: :string, default: "щорічно"]},
        {:cm_8_3_a_03,
         "Наявність несанкціонованих мікропрограмних компонентів в системі виявляється за допомогою автоматизованих механізмів частота",
         [type: :string, default: "щорічно"]},
        {:cm_8_3_odp_01,
         "Визначено автоматизовані механізми, що використовуються для виявлення наявності несанкціонованого обладнання в системі",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_8_3_odp_02,
         "Визначено автоматизовані механізми, що використовуються для виявлення наявності несанкціонованого програмного забезпечення в системі",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_8_3_odp_03,
         "Визначено автоматизовані механізми, що використовуються для виявлення наявності несанкціонованих мікропрограмних компонентів в системі",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_8_3_odp_04,
         "Визначено частоту, з якою використовуються автоматизовані механізми для виявлення присутності несанкціонованих компонентів системи в системі",
         [type: :integer, default: 30]},
        {:cm_8_3_odp_05,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {відключення доступу до мережі такими компонентами; ізолювати компоненти; повідомити персонал або ролі}",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_8_3_odp_06,
         "Визначено персонал або ролі, які мають бути повідомлені при виявленні несанкціонованих компонентів (якщо вибрано)",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-cm-8-4") do
    %{
      id: :"id-spe-cm-8-4",
      description: "",
      title: "ІНВЕНТАРИЗАЦІЯ КОМПОНЕНТІВ СИСТЕМИ - ІНФОРМАЦІЯ ПРО ПІДЗВІТНІСТЬ (CM-8(4))",
      parameters: [
        {:cm_8_4_odp,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {ім'я; позиція; роль}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-8-5") do
    %{
      id: :"id-spe-cm-8-5",
      description: "",
      title: "ІНВЕНТАРИЗАЦІЯ КОМПОНЕНТІВ СИСТЕМИ ДУБЛЮВАННЯ КОМПОНЕНТІВ ОБЛІКУ (CM-8(5))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-cm-8-6") do
    %{
      id: :"id-spe-cm-8-6",
      description: "",
      title: "ІНВЕНТАРИЗАЦІЯ КОМПОНЕНТІВ СИСТЕМИ - ПЕРЕВІРЕНІ НАЛАШТУВАННЯ ТА ЗАТВЕРДЖЕНІ ВІДХИЛЕННЯ (CM-8(6))",
      parameters: [
        {:cm_8_6_01,
         "Включено перевірені налаштування компонентів до поточних розгорнутих конфігурацій в інвентаризаційний облік компонентів системи",
         [type: :string, default: nil]},
        {:cm_8_6_02,
         "Включено будь-які затверджені відхилення до поточних розгорнутих конфігурацій в інвентаризаційний облік компонентів системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-8-7") do
    %{
      id: :"id-spe-cm-8-7",
      description: "Впровадити централізоване компонентів системи. сховище СИСТЕМИ для - ЦЕНТРАЛІЗОВАНЕ інвентаризаційного обліку",
      title: "ІНВЕНТАРИЗАЦІЯ КОМПОНЕНТІВ СИСТЕМИ - ЦЕНТРАЛІЗОВАНЕ СХОВИЩЕ (CM-8(7))",
      parameters: [
        {:cm_8_7_01,
         "Впроваджено централізоване сховище для інвентаризаційного обліку компонентів системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-8-8") do
    %{
      id: :"id-spe-cm-8-8",
      description: "",
      title: "ІНВЕНТАРИЗАЦІЯ КОМПОНЕНТІВ СИСТЕМИ - АВТОМАТИЗОВАНЕ ВІДСТЕЖЕННЯ МІСЦЯ РОЗТАШУВАННЯ (CM-8(8))",
      parameters: [
        {:cm_8_8_01,
         "Використовуютья автоматизовані механізми для підтримки відстеження компонентів системи за географічним розташуванням",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cm_8_8_odp,
         "Визначено автоматизовані механізми відстеження компонентів",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-cm-8-9") do
    %{
      id: :"id-spe-cm-8-9",
      description: "",
      title: "ІНВЕНТАРИЗАЦІЯ КОМПОНЕНТІВ СИСТЕМИ - ПРИЗНАЧЕННЯ КОМПОНЕНТІВ СИСТЕМАМ (CM-8(9))",
      parameters: [
        {:cm_8_9_a,
         "Компоненти системи призначаються системі",
         [type: :string, default: nil]},
        {:cm_8_9_b,
         "Отримано підтвердження призначення компонента від персонал або ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_8_9_odp,
         "Визначено персонал або ролі, від яких слід отримувати підтвердження",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-cm-9") do
    %{
      id: :"id-spe-cm-9",
      description: "Унікально ідентифікувати та автентифікувати користувачів або процеси, що діють від імені користувачів.",
      title: "ПЛАН УПРАВЛІННЯ КОНФІГУРАЦІЄЮ (CM-9)",
      parameters: [
        {:cm_9_01,
         "Розроблено та задокументовано план управління конфігурацією системи",
         [type: :string, default: nil]},
        {:cm_9_a_01,
         "План управління конфігурацією описує ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_9_a_02,
         "План управління конфігурацією описує відповідальність",
         [type: :string, default: nil]},
        {:cm_9_a_03,
         "План управління конфігурацією описує процеси та процедури управління конфігурацією",
         [type: :string, default: nil]},
        {:cm_9_b_01,
         "План управління конфігурацією встановлює процес ідентифікації елементів конфігурації протягом всього життєвого циклу розробки системи",
         [type: :string, default: nil]},
        {:cm_9_b_02,
         "План управління конфігурацією встановлює процес управління конфігурацією елементів",
         [type: :string, default: nil]},
        {:cm_9_c_01,
         "План управління конфігурацією визначає елементи конфігурації системи",
         [type: :string, default: nil]},
        {:cm_9_c_02,
         "План управління конфігурацією розміщує елементи конфігурації під управлінням конфігурацією",
         [type: :string, default: nil]},
        {:cm_9_d,
         "План управління конфігурацією розглянуто та затверджено персонал або ролі; CM-09(e)[01] план управління конфігурацією захищений від несанкціонованого розкриття",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_9_e_02,
         "План управління конфігурацією захищений від несанкціонованої модифікації",
         [type: :string, default: nil]},
        {:cm_9_odp,
         "Визначено персонал або ролі для розгляду та затвердження плану управління конфігурацією",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-cm-9-1") do
    %{
      id: :"id-spe-cm-9-1",
      description: "",
      title: "ПЛАН УПРАВЛІННЯ КОНФІГУРАЦІЄЮ - ВСТАНОВЛЕННЯ ВІДПОВІДАЛЬНОСТІ (CM-9(1))",
      parameters: [
        {:cm_9_1_01,
         "Встановлено відповідальність за реалізацію процесу управління конфігурацією персоналу, який безпосередньо не бере участь у розробці системи",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-cm-10") do
    %{
      id: :"id-spe-cm-10",
      description: "",
      title: "ОБМЕЖЕННЯ ВИКОРИСТАННЯ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ (CM-10)",
      parameters: [
        {:cm_10_b,
         "Використання програмного забезпечення та пов'язаної з ним документації, захищеної ліцензіями, відстежується для контролю за копіюванням та розповсюдженням",
         [type: :string, default: nil]},
        {:cm_10_c,
         "Використання технології однорангового обміну файлами контролюється та документується, щоб гарантувати, що одноранговий обмін файлами не використовується для несанкціонованого розповсюдження, відображення, виконання або відтворення програмного забезпечення, захищеного авторським правом",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-10-1") do
    %{
      id: :"id-spe-cm-10-1",
      description: "",
      title: "ОБМЕЖЕННЯ ВИКОРИСТАННЯ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ З ВІДКРИТИМ ВИХІДНИМ КОДОМ (CM-10(1))",
      parameters: [
        {:cm_10_1_01,
         "Встановлено обмеження на використання програмного забезпечення з відкритим вихідним кодом",
         [type: :string, default: nil]},
        {:cm_10_1_odp,
         "Визначено обмеження на використання програмного забезпечення з відкритим вихідним кодом",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-11") do
    %{
      id: :"id-spe-cm-11",
      description: "",
      title: "ВСТАНОВЛЕНЕ КОРИСТУВАЧЕМ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ (CM-11)",
      parameters: [
        {:cm_11_a,
         "Встановлено правила (політики), що регулюють встановлення програмного забезпечення користувачами",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_11_b,
         "Правила (політики) встановлення програмного забезпечення застосовуються за допомогою методів",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_11_c,
         "Дотримання політик контролюється частота",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_11_odp_01,
         "Визначено правила (політики), що регулюють встановлення програмного забезпечення користувачами",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_11_odp_02,
         "Визначено методи, що використовуються для забезпечення дотримання правил (політик) встановлення програмного забезпечення",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_11_odp_03,
         "Визначено частоту, з якою слід контролювати відповідність правил (політик)",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-cm-11-1") do
    %{
      id: :"id-spe-cm-11-1",
      description: "",
      title: "ВСТАНОВЛЕНЕ КОРИСТУВАЧЕМ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ ПОПЕРЕДЖЕННЯ ПРО НЕСАНКЦІОНОВАНУ ІНСТАЛЯЦІЮ (CM-11(1))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-cm-11-2") do
    %{
      id: :"id-spe-cm-11-2",
      description: "",
      title: "ВСТАНОВЛЕНЕ КОРИСТУВАЧЕМ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ ВСТАНОВЛЕННЯ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ З ПРИВІЛЕЙОВАНИМ СТАТУСОМ (CM-11(2))",
      parameters: [
        {:cm_11_2_01,
         "Встановлювати програмне забезпечення дозволено користувачеві лише при наявності привілейованого статусу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-11-3") do
    %{
      id: :"id-spe-cm-11-3",
      description: "",
      title: "ВСТАНОВЛЕНЕ КОРИСТУВАЧЕМ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ АВТОМАТИЧНЕ ВИКОНАННЯ І МОНІТОРИНГ (CM-11(3))",
      parameters: [
        {:cm_11_3_01,
         "Дотримання політик виконання програмного забезпечення забезпечується за допомогою автоматизованих механізмів; дотримання політик контролю програмного забезпечення контролюється за допомогою автоматизованих механізмів",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_11_3_odp_01,
         "Визначено автоматизовані механізми для забезпечення дотримання політик виконання програмного забезпечення",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cm_11_3_odp_02,
         "Визначено автоматизовані механізми для забезпечення дотримання політик контролю програмного забезпечення",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-cm-12") do
    %{
      id: :"id-spe-cm-12",
      description: "",
      title: "РОЗТАШУВАННЯ ІНФОРМАЦІЇ (CM-12)",
      parameters: [
        {:cm_12_a_01,
         "Місцезнаходження інформація визначено та задокументовано",
         [type: :string, default: nil]},
        {:cm_12_a_02,
         "Визначено та задокументовано конкретні компоненти системи, на яких обробляється інформація",
         [type: :string, default: nil]},
        {:cm_12_a_03,
         "Визначено та задокументовано конкретні компоненти системи, на яких зберігається інформація",
         [type: :string, default: nil]},
        {:cm_12_b_01,
         "Визначено та задокументовано користувачів, які мають доступ до системи та компонентів системи, де обробляється інформація",
         [type: :string, default: nil]},
        {:cm_12_b_02,
         "Визначено та задокументовано користувачів, які мають доступ до системи та компонентів системи, де зберігається інформація; CM-12(c)[01] задокументовано зміни розташування ( наприклад, системи або компонентів системи), де обробляється інформація",
         [type: :string, default: nil]},
        {:cm_12_c_02,
         "Задокументовано зміни розташування ( наприклад, системи або компонентів системи), де зберігається інформація",
         [type: :string, default: nil]},
        {:cm_12_odp,
         "Визначено інформацію, місцезнаходження якої має бути визначено та задокументовано",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-12-1") do
    %{
      id: :"id-spe-cm-12-1",
      description: "",
      title: "РОЗТАШУВАННЯ ІНФОРМАЦІЇ - АВТОМАТИЗОВАНІ ІНСТРУМЕНТИ ПІДТРИМКИ РОЗТАШУВАННЯ ІНФОРМАЦІЇ (CM-12(1))",
      parameters: [
        {:cm_12_1_01,
         "Автоматизовані інструменти використовуються для ідентифікації інформації за типом на компонентах системи, щоб забезпечити впровадження належних заходів захисту щодо інформації про організацію і персональних даних",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cm_12_1_odp_01,
         "Інформація визначена за типом",
         [type: :string, default: nil]},
        {:cm_12_1_odp_02,
         "Визначено компоненти системи, де знаходиться інформація",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-13") do
    %{
      id: :"id-spe-cm-13",
      description: "",
      title: "ВІДОБРАЖЕННЯ ДІЙ ДАНИХ (CM-13)",
      parameters: [
        {:cm_13_01,
         "Розроблено та задокументовано карту дій з даними системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cm-14") do
    %{
      id: :"id-spe-cm-14",
      description: "",
      title: "ПІДПИСАНІ КОМПОНЕНТИ (CM-14)",
      parameters: [
        {:cm_14_01,
         "Інсталяція програмне забезпечення попередньо запобігається, якщо не буде перевірено, що програмне забезпечення було підписано цифровим підписом за допомогою сертифіката, визнаного та затвердженого організацією",
         [type: :string, default: nil]},
        {:cm_14_02,
         "Інсталяція мікропрограмні компоненти попередньо запобігається, якщо не буде перевірено, що мікропрограмні компоненти були підписані цифровим підписом за допомогою сертифіката, визнаного та затвердженого організацією",
         [type: :string, default: nil]},
        {:cm_14_odp_01,
         "Визначено програмне забезпечення, яке потребує перевірки сертифікату з цифровим підписом перед встановленням",
         [type: :string, default: nil]},
        {:cm_14_odp_02,
         "Визначено мікропрограмні компоненти, які потребує перевірки сертифікату з цифровим підписом перед встановленням",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-1") do
    %{
      id: :"id-spe-cp-1",
      description: "",
      title: "ПОЛІТИКА ТА ПРОЦЕДУРИ ПЛАНУВАННЯ БЕЗПЕРЕРВНОЇ РОБОТИ (CP-1)",
      parameters: [
        {:cp_1_a_01,
         "Розроблено та задокументовано політику планування безперервної роботи на випадок надзвичайних ситуацій",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cp_1_a_02,
         "Політика планування безперервної роботи на випадок надзвичайних ситуацій поширюється на персонал або посади",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_1_a_03,
         "Розроблені та задокументовані процедури планування безперервної роботи на випадок надзвичайних ситуацій, що сприяють впровадженню політики планування безперервної роботи на випадок надзвичайних ситуацій та пов'язаних з нею заходів захисту на випадок надзвичайних ситуацій",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cp_1_b,
         "Посадова особа призначається для управління , документуванням та розповсюдженням політики та процедур планування безперервної роботи на випадок надзвичайних ситуацій; CP-01(c)[01][01] переглядається та оновлюється поточна політика планування безперервної роботи на випадок надзвичайних ситуацій частота; CP-01(c)[01][02] переглядається та оновлюється поточна політика планування безперервної роботи на випадок надзвичайних ситуацій після подій; CP-01(c)[02][01] переглядаються та оновлюються поточні процедури планування безперервної роботи на випадок надзвичайних ситуацій частота; CP-01(c)[02][02] переглядаються та оновлюються поточні процедури планування безперервної роботи на випадок надзвичайних ситуацій після подій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_1_odp_01,
         "Визначено персонал або посади, на які поширюється політика планування безперервної роботи на випадок надзвичайних ситуацій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_1_odp_02,
         "Визначено персонал або посади, на які поширюється процедури планування безперервної роботи на випадок надзвичайних ситуацій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнес-процесу; рівень системи}",
         [type: :string, default: nil]},
        {:cp_1_odp_04,
         "Визначено посадову особу, яка керуватиме політикою та процедурами планування безперервної роботи на випадок надзвичайних ситуацій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_1_odp_05,
         "Визначено частоту, з якою переглядається та оновлюється поточна політика",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cp_1_odp_06,
         "Визначено події, після яких переглядається та оновлюється поточна політика",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:cp_1_odp_07,
         "Визначено частоту, з якою переглядаються та оновлюються поточні процедури",
         [type: :integer, default: 30]},
        {:cp_1_odp_08,
         "Визначено події, після яких переглядаються та оновлюються поточні процедури",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-cp-2") do
    %{
      id: :"id-spe-cp-2",
      description: "",
      title: "ПЛАН ЗАБЕЗПЕЧЕННЯ БЕЗПЕРЕРВНОЇ РОБОТИ ТА ВІДНОВЛЕННЯ ФУНКЦІОНУВАННЯ (CP-2)",
      parameters: [
        {:cp_2_a_01,
         "Розроблено план забезпечення безперервної роботи у надзвичайних ситуаціях для системи, який визначає основні завдання, функції та пов’язані з ними вимоги щодо безперервної роботи; CP-02(a)[02][01] розроблено план забезпечення безперервної роботи у надзвичайних ситуаціях для системи, який забезпечує цілі; CP-02(a)[02][02] розроблено план забезпечення безперервної роботи у надзвичайних ситуаціях для системи, який забезпечує пріорітети; CP-02(a)[02][03] розроблено план забезпечення безперервної роботи у надзвичайних ситуаціях для системи, який забезпечує відповідні показники; CP-02(a)[03][01] розроблено план забезпечення безперервної роботи на випадок надзвичайних ситуацій для системи, в якому визначено ролі; CP-02(a)[03][02] розроблено план забезпечення безперервної роботи на випадок надзвичайних ситуацій для системи, в якому визначено обов'язки; CP-02(a)[03][03] розроблено план забезпечення безперервної роботи на випадок надзвичайних ситуацій для системи, в якому визначено відповідальних осіб з контактною інформацією",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_2_a_04,
         "Розроблено план забезпечення безперервної роботи на випадок непередбачених обставин для системи, який спрямований на підтримку основних завдань і функції, попри системні збої, компрометації або помилки",
         [type: :string, default: nil]},
        {:cp_2_a_05,
         "Розроблено план забезпечення безперервної роботи у надзвичайних ситуаціях для системи, який спрямований на повне відновлення функціонування системи без погіршення запланованих і реалізованих заходів захисту інформації та персональних даних",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_2_a_06,
         "Розроблено план забезпечення безперервної роботи на випадок надзвичайних ситуацій для системи, який вирішує питання обміну інформацією про надзвичайні ситуації; CP-02(a)[07][01] розроблено план забезпечення безперервної роботи у надзвичайних ситуаціях для системи, який переглядається персоналом або ролями; CP-02(a)[07][02] розроблено план забезпечення безперервної роботи у надзвичайних ситуаціях для системи, який затверджено персоналом або ролями",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_2_b_01,
         "Копії плану забезпечення безперервної роботи на випадок надзвичайних ситуацій розповсюджуються серед персоналу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_2_b_02,
         "Копії плану забезпечення безперервної роботи на випадок надзвичайних ситуацій розповсюджуються серед елементів",
         [type: :string, default: nil]},
        {:cp_2_c,
         "Діяльність з планування безперервної роботи координується з діяльністю із заходами по усуненню інцидентів; CP-02(d) переглядається план забезпечення безперервної роботи у надзвичайних ситуаціях для системи частота",
         [type: :string, default: "щорічно"]},
        {:cp_2_e_01,
         "План забезпечення безперервної роботи на випадок надзвичайних ситуацій оновлюється з урахуванням змін в організації, системі або середовищі функціонування",
         [type: :string, default: nil]},
        {:cp_2_e_02,
         "План забезпечення безперервної роботи на випадок надзвичайних ситуацій оновлюється для вирішення проблем, що виникають під час впровадження, виконання або тестування плану дій на випадок надзвичайних ситуацій",
         [type: :integer, default: 30]},
        {:cp_2_f_01,
         "Зміни в плані забезпечення безперервної роботи на випадок надзвичайних ситуацій повідомляються персоналу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_2_f_02,
         "Зміни в плані забезпечення безперервної роботи на випадок надзвичайних ситуацій повідомляються елементам",
         [type: :string, default: nil]},
        {:cp_2_g_01,
         "Уроки, отримані під час тестування планів забезпечення безперервної роботи у надзвичайних ситуаціях або фактичних дій у надзвичайних ситуаціях, включаються в навчання",
         [type: :integer, default: 30]},
        {:cp_2_g_02,
         "Уроки, отримані під час тестування планів забезпечення безперервної роботи у надзвичайних ситуаціях або фактичних дій у надзвичайних ситуаціях, включаються в тестування",
         [type: :integer, default: 30]},
        {:cp_2_h_01,
         "План забезпечення безперервної роботи у надзвичайних ситуаціях захищений від несанкціонованого доступу",
         [type: :string, default: nil]},
        {:cp_2_h_02,
         "План забезпечення безперервної роботи у надзвичайних ситуаціях захищений від несанкціонованих змін",
         [type: :string, default: nil]},
        {:cp_2_odp_01,
         "Визначено персонал або ролі для перегляду плану забезпечення безперервної роботи у надзвичайних ситуаціях",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_2_odp_02,
         "Визначено персонал або ролі для затвердження плану забезпечення безперервної роботи у надзвичайних ситуаціях",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_2_odp_03,
         "Визначено ключовий резервний персонал (ідентифікований за іменами та/або за ролями), якому поширюються копії плану забезпечення безперервної роботи на випадок надзвичайних ситуацій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_2_odp_04,
         "Визначено ключові елементи, на які поширюються копії плану забезпечення безперервної роботи на випадок надзвичайних ситуацій",
         [type: :string, default: nil]},
        {:cp_2_odp_05,
         "Визначено періодичність перегляду плану забезпечення безперервної роботи у надзвичайних ситуаціях",
         [type: :string, default: "щорічно"]},
        {:cp_2_odp_06,
         "Визначено ключовий резервний персонал (ідентифікований за іменами та/або ролями), якому необхідно повідомити про зміни",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_2_odp_07,
         "Визначено ключові елементи організації, і які необхідно повідомити про зміни",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-2-1") do
    %{
      id: :"id-spe-cp-2-1",
      description: "",
      title: "ПЛАН ЗАБЕЗПЕЧЕННЯ БЕЗПЕРЕРВНОЇ РОБОТИ ТА ВІДНОВЛЕННЯ ФУНКЦІОНУВАННЯ - КООРДИНАЦІЯ З ПОВ’ЯЗАНИМИ ПЛАНАМИ (CP-2(1))",
      parameters: [
        {:cp_2_1_01,
         "Розробка плану забезпечення безперервної роботи у надзвичайних ситуаціях координується зі структурними підрозділами, які відповідають за розробку та реалізацію пов’язаних планів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-3") do
    %{
      id: :"id-spe-cp-3",
      description: "",
      title: "НАВЧАННЯ ІЗ ЗАБЕЗПЕЧЕННЯ БЕЗПЕРЕРВНОЇ РОБОТИ (CP-3)",
      parameters: [
        {:cp_3_a_01,
         "Підготовка на випадок надзвичайних ситуацій надається користувачам системи відповідно до призначених ролей та обов'язків протягом періоду часу з моменту прийняття на себе надзвичайної ролі або обов'язку",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_3_a_02,
         "Навчання на випадок надзвичайних ситуацій проводиться для користувачів системи відповідно до призначених ролей та обов'язків, якщо цього вимагають зміни в системі",
         [type: :string, default: nil]},
        {:cp_3_a_03,
         "Користувачам системи надається навчання на випадок надзвичайних ситуацій відповідно до призначених ролей та обов'язків частота",
         [type: :string, default: "щорічно"]},
        {:cp_3_b_01,
         "Переглядається та оновлюється зміст тренувань за планом реагування на надзвичайні ситуації частота",
         [type: :string, default: "щорічно"]},
        {:cp_3_b_02,
         "Зміст тренувань за планом реагування на надзвичайні ситуації переглядається та оновлюється після наступних події",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:cp_3_odp_01,
         "Визначено період часу, протягом якого необхідно провести тренінг з підготовки до дій в умовах надзвичайних ситуацій після прийняття на себе ролі або відповідальності в умовах надзвичайних ситуацій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_3_odp_02,
         "Визначено частоту проведення тренінгів для користувачів системи, які виконують непередбачувану роль або несуть відповідальність",
         [type: :integer, default: 30]},
        {:cp_3_odp_03,
         "Визначено частоту, з якою необхідно переглядати та оновлювати зміст тренувань на випадок надзвичайних ситуацій",
         [type: :integer, default: 30]},
        {:cp_3_odp_04,
         "Визначено події, які потребують перегляду та оновлення тренувань на випадок надзвичайних ситуацій",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-cp-4") do
    %{
      id: :"id-spe-cp-4",
      description: "",
      title: "ТЕСТУВАННЯ ПЛАНУ ЗАБЕЗПЕЧЕННЯ БЕЗПЕРЕРВНОЇ РОБОТИ ТА ВІДНОВЛЕННЯ ФУНКЦІОНУВАННЯ (CP-4)",
      parameters: [
        {:cp_4_a_01,
         "Тестується план забезпечення безперервної роботи у надзвичайних ситуаціях для системи частота",
         [type: :string, default: "щорічно"]},
        {:cp_4_a_02,
         "Тести використовуються для визначення ефективності плану",
         [type: :string, default: nil]},
        {:cp_4_a_03,
         "Тести використовуються для визначення готовності до виконання плану",
         [type: :string, default: nil]},
        {:cp_4_b,
         "Переглядаються результати тестування плану забезпечення безперервної роботи у надзвичайних ситуаціях",
         [type: :string, default: nil]},
        {:cp_4_c,
         "За необхідності ініціюються коригувальні дії",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:cp_4_odp_01,
         "Визначено частоту тестування плану забезпечення безперервної роботи у надзвичайних ситуаціях для системи",
         [type: :integer, default: 30]},
        {:cp_4_odp_02,
         "Визначено тести для визначення ефективності плану забезпечення безперервної роботи у надзвичайних ситуаціях",
         [type: :string, default: nil]},
        {:cp_4_odp_03,
         "Визначені тести для визначення готовності до виконання плану забезпечення безперервної роботи у надзвичайних ситуаціях",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-4-2") do
    %{
      id: :"id-spe-cp-4-2",
      description: "",
      title: "ТЕСТУВАННЯ ПЛАНУ ЗАБЕЗПЕЧЕННЯ БЕЗПЕРЕРВНОЇ РОБОТИ ТА ВІДНОВЛЕННЯ ФУНКЦІОНУВАННЯ - АЛЬТЕРНАТИВНА ПЛАТФОРМА ТЕСТУВАННЯ (CP-4(2))",
      parameters: [
        {:cp_4_2_a,
         "План забезпечення безперервної роботи у надзвичайних ситуаціях тестується на альтернативній платформі для ознайомлення персоналу з об'єктом та наявними ресурсами",
         [type: :list, default: ["admin", "security_officer"]]},
        {:cp_4_2_b,
         "План забезпечення безперервної роботи у надзвичайних ситуаціях тестується на альтернативній платформі для оцінки можливостей альтернативної платформи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-4-3") do
    %{
      id: :"id-spe-cp-4-3",
      description: "",
      title: "ТЕСТУВАННЯ ПЛАНУ ЗАБЕЗПЕЧЕННЯ БЕЗПЕРЕРВНОЇ РОБОТИ ТА ВІДНОВЛЕННЯ ФУНКЦІОНУВАННЯ - АВТОМАТИЧНЕ ТЕСТУВАННЯ (CP-4(3))",
      parameters: [
        {:cp_4_3_01,
         "ТЕСТУВАННЯ ПЛАНУ ЗАБЕЗПЕЧЕННЯ БЕЗПЕРЕРВНОЇ РОБОТИ ТА ВІДНОВЛЕННЯ ФУНКЦІОНУВАННЯ - АВТОМАТИЧНЕ ТЕСТУВАННЯ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:cp_4_3_odp,
         "Визначено автоматизовані механізми тестування планів забезпечення безперервної роботи у надзвичайних ситуаціях",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-cp-4-4") do
    %{
      id: :"id-spe-cp-4-4",
      description: "",
      title: "ТЕСТУВАННЯ ПЛАНУ ЗАБЕЗПЕЧЕННЯ БЕЗПЕРЕРВНОЇ РОБОТИ ТА ВІДНОВЛЕННЯ ФУНКЦІОНУВАННЯ - ПОВНЕ ВІДНОВЛЕННЯ (CP-4(4))",
      parameters: [
        {:cp_4_4_01,
         "Включено повне відновлення системи до відомого стану як частину тестування плану забезпечення безперервної роботи та відновлення функціонування",
         [type: :integer, default: 30]},
        {:cp_4_4_02,
         "Включено повне повернення системи до відомого стану як частину тестування плану забезпечення безперервної роботи та відновлення функціонування",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cp-4-5") do
    %{
      id: :"id-spe-cp-4-5",
      description: "",
      title: "ЗАСТОСОВУЮТЬСЯ ДЛЯ ПОРУШЕННЯ ТА НЕГАТИВНОГО ВПЛИВУ НА (CP-4(5))",
      parameters: [
        {:cp_4_5_01,
         "Механізми застосовуються для порушення та негативного впливу на систему або компонент системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cp_4_5_odp_01,
         "Визначено механізми, що застосовуються для порушення та негативного впливу на систему або на компонент системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cp_4_5_odp_02,
         "Визначено систему або компонент системи, до яких застосовуються механізми порушення та негативного впливу",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-cp-5") do
    %{
      id: :"id-spe-cp-5",
      description: "",
      title: "ОНОВЛЕННЯ ПЛАНУ ЗАБЕЗПЕЧЕННЯ БЕЗПЕРЕРВНОЇ РОБОТИ ТА ВІДНОВЛЕННЯ ФУНКЦІОНУВАННЯ (CP-5)",
      parameters: [
        {:cp_5_01,
         "ОНОВЛЕННЯ ПЛАНУ ЗАБЕЗПЕЧЕННЯ БЕЗПЕРЕРВНОЇ РОБОТИ ТА ВІДНОВЛЕННЯ ФУНКЦІОНУВАННЯ [Вилучено: Включено до СР-02]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-6") do
    %{
      id: :"id-spe-cp-6",
      description: "",
      title: "АЛЬТЕРНАТИВНЕ МІСЦЕ ЗБЕРІГАННЯ (CP-6)",
      parameters: [
        {:cp_6_01,
         "АЛЬТЕРНАТИВНЕ МІСЦЕ ЗБЕРІГАННЯ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:cp_6_a_01,
         "Створено альтернативне місце зберігання",
         [type: :string, default: nil]},
        {:cp_6_a_02,
         "Створення альтернативного місця зберігання включає в себе необхідні угоди, що дозволяють зберігати та видавати інформацію резервного копіювання системи",
         [type: :string, default: nil]},
        {:cp_6_b,
         "В альтернативному місці зберігання впроваджені заходи захисту, аналогічні заходам захисту основної локації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-6-1") do
    %{
      id: :"id-spe-cp-6-1",
      description: "",
      title: "АЛЬТЕРНАТИВНЕ МІСЦЕ ЗБЕРІГАННЯ - ВІДДІЛЕННЯ ВІД ПЕРВИННОГО СХОВИЩА (CP-6(1))",
      parameters: [
        {:cp_6_1_01,
         "Визначено альтернативне місце зберігання, яке відокремлено від основного місця зберігання, щоб зменшити сприйнятливість до тих самих загроз",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-6-2") do
    %{
      id: :"id-spe-cp-6-2",
      description: "",
      title: "АЛЬТЕРНАТИВНЕ МІСЦЕ ЗБЕРІГАННЯ - ЧАС ВІДНОВЛЕННЯ ТА ВСТАНОВЛЕННЯ ЦІЛЕЙ ВІДНОВЛЕННЯ (CP-6(2))",
      parameters: [
        {:cp_6_2_01,
         "Налаштувати альтернативне місце зберігання для полегшення операцій відновлення відповідно до часу відновлення",
         [type: :integer, default: 30]},
        {:cp_6_2_02,
         "Налаштувати альтернативне місце зберігання для полегшення операцій відновлення відповідно до встановлених цілей відновлення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-6-3") do
    %{
      id: :"id-spe-cp-6-3",
      description: "",
      title: "АЛЬТЕРНАТИВНЕ МІСЦЕ ЗБЕРІГАННЯ - ДОСТУПНІСТЬ (CP-6(3))",
      parameters: [
        {:cp_6_3_01,
         "Визначено потенційні проблеми доступності для альтернативного місця зберігання в разі збоїв або стихійних лих по всьому регіоні",
         [type: :string, default: nil]},
        {:cp_6_3_02,
         "В загальних рисах окреслено дії щодо пом'якшення наслідків",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-cp-7") do
    %{
      id: :"id-spe-cp-7",
      description: "",
      title: "АЛЬТЕРНАТИВНИЙ МАЙДАНЧИК РОБОТИ (CP-7)",
      parameters: [
        {:cp_7_a,
         "Альтернативний майданчик для роботи, включно з необхідними угодами, які дозволяють передачу та відновлення операцій системи для виконання основних завдань та функцій, створюється протягом періоду часу, коли можливості основного майданчика недоступні",
         [type: :integer, default: 30]},
        {:cp_7_b_01,
         "Обладнання та прилади, необхідні для передачі, доступні на альтернативному місці роботи або якщо укладені контракти на підтримку доставки на це місце протягом періоду часу для передачі",
         [type: :integer, default: 30]},
        {:cp_7_b_02,
         "Обладнання та прилади, необхідні для відновлення, доступні на альтернативному місці роботи або якщо укладені контракти на підтримку доставки на це місце протягом періоду часу для передачі",
         [type: :integer, default: 30]},
        {:cp_7_c,
         "Впроваджено на альтернативному майданчику роботи заходи захисту, еквівалентні тим, що впровадженні на основному майданчику",
         [type: :string, default: nil]},
        {:cp_7_odp_01,
         "Визначені операції системи для основних завдань і функцій",
         [type: :string, default: nil]},
        {:cp_7_odp_02,
         "Визначено період часу, відповідно термінам відновлення та встановленим цілям відновлення",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cp-7-1") do
    %{
      id: :"id-spe-cp-7-1",
      description: "",
      title: "АЛЬТЕРНАТИВНИЙ МАЙДАНЧИК ДЛЯ РОБОТИ - ВІДДІЛЕННЯ ВІД ОСНОВНОГО МАЙДАНЧИКА (CP-7(1))",
      parameters: [
        {:cp_7_1_01,
         "АЛЬТЕРНАТИВНИЙ МАЙДАНЧИК ДЛЯ РОБОТИ - ВІДДІЛЕННЯ ВІД ОСНОВНОГО МАЙДАНЧИКА МЕТА ОЦІНКИ: Визначити, чи: визначено альтернативний майданчик для роботи, який відокремCP-07(01) лений від основного майданчика, з метою зменшення сприйнятливості до тих самих загроз",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-7-2") do
    %{
      id: :"id-spe-cp-7-2",
      description: "",
      title: "АЛЬТЕРНАТИВНИЙ МАЙДАНЧИК ДЛЯ РОБОТИ - ДОСТУПНІСТЬ (CP-7(2))",
      parameters: [
        {:cp_7_2_01,
         "Визначено потенційні проблеми доступності для альтернативного майданчика для роботи в разі збоїв або катастрофи по всьому регіону",
         [type: :string, default: nil]},
        {:cp_7_2_02,
         "Окреслено чіткі заходи щодо пом'якшення наслідків",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-7-3") do
    %{
      id: :"id-spe-cp-7-3",
      description: "",
      title: "АЛЬТЕРНАТИВНИЙ МАЙДАНЧИК ДЛЯ РОБОТИ - ПРІОРИТЕТ ОБСЛУГОВУВАННЯ (CP-7(3))",
      parameters: [
        {:cp_7_3_01,
         "Розроблено угоди про альтернативний майданчик для роботи, які містять положення щодо пріоритету обслуговування відповідно до вимог стосовно доступності (включно з вимогами щодо часу відно- влення)",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cp-7-4") do
    %{
      id: :"id-spe-cp-7-4",
      description: "",
      title: "АЛЬТЕРНАТИВНИЙ МАЙДАНЧИК ДЛЯ РОБОТИ - ПІДГОТОВКА ДЛЯ ВИКОРИСТАННЯ (CP-7(4))",
      parameters: [
        {:cp_7_4_01,
         "Підготовлено альтернативний майданчик для роботи таким чином, щоб майданчик був готовий до використання як оперативний майданчик, що підтримує виконання основних завдань та функцій",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-7-6") do
    %{
      id: :"id-spe-cp-7-6",
      description: "",
      title: "АЛЬТЕРНАТИВНИЙ МАЙДАНЧИК ДЛЯ РОБОТИ - НЕЗДАТНІСТЬ ПОВЕРНУТИСЯ НА ОСНОВНИЙ МАЙДАНЧИК (CP-7(6))",
      parameters: [
        {:cp_7_6_02,
         "Підготувалися до обставин, які виключають повернення на основне місце роботи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-8") do
    %{
      id: :"id-spe-cp-8",
      description: "",
      title: "КОМУНІКАЦІЙНІ ПОСЛУГИ (CP-8)",
      parameters: [
        {:cp_8_01,
         "Альтернативні комунікаційні послуги, включно з необхідними угодами, що дозволяють відновити операції системи, створюються для основних завдань та функцій протягом періоду часу, коли основні комунікаційні можливості недоступні на основному або альтернативному місцях роботи або зберігання",
         [type: :integer, default: 30]},
        {:cp_8_odp_01,
         "Визначено операції системи, які необхідно відновити для виконання основних завдань та функцій",
         [type: :string, default: nil]},
        {:cp_8_odp_02,
         "Визначено період часу, протягом якого необхідно відновити основні завдання та функції, коли основні комунікаційні можливості недоступні",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cp-8-1") do
    %{
      id: :"id-spe-cp-8-1",
      description: "",
      title: "КОМУНІКАЦІЙНІ ПОСЛУГИ - ПРІОРИТЕТ ПОСТАЧАННЯ ПОСЛУГ (CP-8(1))",
      parameters: [
        {:cp_8_1_01,
         "КОМУНІКАЦІЙНІ ПОСЛУГИ - ПРІОРИТЕТ ПОСТАЧАННЯ ПОСЛУГ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:cp_8_1_a_01,
         "Розроблено угоди про надання основних комунікаційних послуг, які містять пріоритетні положення про надання послуг відповідно до вимог щодо доступності (включно з вимогами щодо часу відновлення)",
         [type: :integer, default: 30]},
        {:cp_8_1_a_02,
         "Розроблено альтернативні угоди про надання комунікаційних послуг, які містять положення про пріоритетність надання послуг відповідно до вимог доступності (включно з вимогами щодо часу відновлення)",
         [type: :integer, default: 30]},
        {:cp_8_1_b,
         "Надсилається запит про пріоритети комунікаційних послуг для всіх комунікаційних послуг, що використовуються для забезпечення безперервності роботи, якщо основні та/або альтернативні комунікаційні послуги надаються загальним оператором",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-8-2") do
    %{
      id: :"id-spe-cp-8-2",
      description: "",
      title: "КОМУНІКАЦІЙНІ ПОСЛУГИ - ЄДИНІ ТОЧКИ ВІДМОВИ (CP-8(2))",
      parameters: [
        {:cp_8_2_01,
         "Отримано альтернативні комунікаційні послуги з метою зменшення ймовірності спільного використання єдиної точки відмови з основними комунікаційними послугами",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-8-3") do
    %{
      id: :"id-spe-cp-8-3",
      description: "",
      title: "КОМУНІКАЦІЙНІ ПОСЛУГИ - ВІДДІЛЕННЯ ОСНОВНИХ ТА АЛЬТЕРНАТИВНИХ ПРОВАЙДЕРІВ (CP-8(3))",
      parameters: [
        {:cp_8_3_01,
         "Отримуються альтернативні комунікаційні послуги від постачальників, які відокремлені від основних постачальників послуг, щоб зменшити сприйнятливості до тих самих загроз",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-8-4") do
    %{
      id: :"id-spe-cp-8-4",
      description: "",
      title: "КОМУНІКАЦІЙНІ ПОСЛУГИ - ПЛАН ЗАБЕЗПЕЧЕННЯ БЕЗПЕРЕРВНОЇ РОБОТИ ПОСТАЧАЛЬНИКА КОМУНІКАЦІЙНИХ ПОСЛУГ (CP-8(4))",
      parameters: [
        {:cp_8_4_a_01,
         "Постачальники основних комунікаційних послуг зобов'язані мати плани забезпечення безперервної роботи",
         [type: :string, default: nil]},
        {:cp_8_4_a_02,
         "Постачальники альтернативних комунікаційних послуг зобов'язані мати плани забезпечення безперервної роботи",
         [type: :string, default: nil]},
        {:cp_8_4_b,
         "Переглядаються плани забезпечення безперервної роботи постачальників комунікаційних послуг для забезпечення відповідності планам забезпечення безперервної роботи організації",
         [type: :string, default: nil]},
        {:cp_8_4_c_01,
         "Отримано свідчення про тестування планів забезпечення безперервної роботи частота",
         [type: :string, default: "щорічно"]},
        {:cp_8_4_c_02,
         "Отримано свідчення про тренування з планів забезпечення безперервної роботи частота",
         [type: :string, default: "щорічно"]},
        {:cp_8_4_odp_01,
         "Визначено частоту, з якою постачальники послуг повинні надавати свідчення про тестування планів забезпечення безперервної роботи",
         [type: :integer, default: 30]},
        {:cp_8_4_odp_02,
         "Визначено частоту, з якою постачальники послуг повинні надавати свідчення про тренування з планів забезпечення безперервної роботи",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cp-8-5") do
    %{
      id: :"id-spe-cp-8-5",
      description: "",
      title: "КОМУНІКАЦІЙНІ ПОСЛУГИ - ТЕСТУВАННЯ АЛЬТЕРНАТИВНИХ КОМУНІКАЦІЙНИХ ПОСЛУГ (CP-8(5))",
      parameters: [
        {:cp_8_5_01,
         "Тестування надання альтернативних комунікаційних послуг з частотою",
         [type: :integer, default: 30]},
        {:cp_8_5_odp,
         "Визначено частоту з якою необхідно тестувати надання альтернативних комунікаційних послуг",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cp-9") do
    %{
      id: :"id-spe-cp-9",
      description: "",
      title: "РЕЗЕРВНЕ КОПІЮВАННЯ (CP-9)",
      parameters: [
        {:cp_9_01,
         "РЕЗЕРВНЕ КОПІЮВАННЯ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:cp_9_a,
         "Резервне копіювання інформації користувача, що міститься в компонентах системи, здійснюється частота",
         [type: :string, default: "щорічно"]},
        {:cp_9_b,
         "Виконується резервне копіювання інформації системи, що міститься в системі частота; CP-09(с) створюються резервні копії документації системи, включаючи документацію, пов'язану з безпекою та конфіденційністю частота",
         [type: :string, default: "щорічно"]},
        {:cp_9_d_01,
         "Конфіденційність резервних копій інформації захищена",
         [type: :string, default: nil]},
        {:cp_9_d_02,
         "Цілісність резервних копій інформації захищена",
         [type: :string, default: nil]},
        {:cp_9_d_03,
         "Доступність резервних копій інформації захищена",
         [type: :string, default: nil]},
        {:cp_9_odp_01,
         "Визначено компоненти системи, для яких необхідно проводити резервне копіювання інформації користувачів",
         [type: :string, default: nil]},
        {:cp_9_odp_02,
         "Визначено частоту, з якою слід проводити резервне копіювання інформації користувача відповідно до часу відновлення та цілей відновлення",
         [type: :integer, default: 30]},
        {:cp_9_odp_03,
         "Визначено частоту проведення резервного копіювання інформації системи, що відповідає завдань відновлення і встановлених цілей відновлення",
         [type: :integer, default: 30]},
        {:cp_9_odp_04,
         "Визначено частоту, з якою слід проводити резервне копіювання документації системи відповідно до часу відновлення та цілей точки відновлення",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cp-9-1") do
    %{
      id: :"id-spe-cp-9-1",
      description: "",
      title: "РЕЗЕРВНЕ КОПІЮВАННЯ - ВИПРОБУВАННЯ НА НАДІЙНІСТЬ ТА ЦІЛІСНІСТЬ (CP-9(1))",
      parameters: [
        {:cp_9_1_01,
         "Носії резервних копій інформації тестується 09(01)_ODP[01] частота> для перевірки надійності; <CP-",
         [type: :string, default: "щорічно"]},
        {:cp_9_1_02,
         "Носії резервних копій інформації тестується 09(01)_ODP[02] частота> для перевірки цілісності; <CP-",
         [type: :string, default: "щорічно"]},
        {:cp_9_1_odp_01,
         "Визначено частоту тестування на надійність носіїв резервних копій інформації",
         [type: :integer, default: 30]},
        {:cp_9_1_odp_02,
         "Визначено частоту тестування на цілісність носіїв резервних копій інформації",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cp-9-2") do
    %{
      id: :"id-spe-cp-9-2",
      description: "",
      title: "РЕЗЕРВНЕ КОПІЮВАННЯ - ТЕСТУВАННЯ ВІДНОВЛЕННЯ З ВИКОРИСТАННЯМ ЗРАЗКІВ (CP-9(2))",
      parameters: [
        {:cp_9_2_01,
         "Використовується зразок резервної копії інформації при відновленні вибраних функцій системи як частину тестування плану забезпечення безперервної роботи та відновлення функціонування",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cp-9-3") do
    %{
      id: :"id-spe-cp-9-3",
      description: "",
      title: "РЕЗЕРВНЕ КОПІЮВАННЯ - ВІДОКРЕМЛЕНЕ СХОВИЩЕ КРИТИЧНОЇ ІНФОРМАЦІЇ (CP-9(3))",
      parameters: [
        {:cp_9_3_01,
         "Резервні копії критичного системного програмного забезпечення та іншої інформації, пов'язаної з безпекою зберігаються в окремому сховищі або у вогнетривкому контейнері, не пов'язаному з системою",
         [type: :string, default: nil]},
        {:cp_9_3_odp,
         "Визначено критичного системного програмного забезпечення та іншої інформації, пов’язаної з безпекою яке має зберігатися в окремому сховищі або у вогнетривкому контейнері",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-9-5") do
    %{
      id: :"id-spe-cp-9-5",
      description: "",
      title: "РЕЗЕРВНЕ КОПІЮВАННЯ - ПЕРЕДАЧА НА АЛЬТЕРНАТИВНЕ СХОВИЩЕ ЗБЕРІГАННЯ (CP-9(5))",
      parameters: [
        {:cp_9_5_01,
         "Інформація резервної копії системи передається до альтернативного сховища протягом періоду часу; CP-09(05)[02] інформація резервної копії системи передається до альтернативного сховища з швидкість передачі ",
         [type: :integer, default: 30]},
        {:cp_9_5_odp_01,
         "Визначено період часу, що відповідає часу відновлення та цілям відновлення",
         [type: :integer, default: 30]},
        {:cp_9_5_odp_02,
         "Визначено швидкість передачі даних, що відповідає часу відновлення та цілям відновлення",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cp-9-6") do
    %{
      id: :"id-spe-cp-9-6",
      description: "",
      title: "РЕЗЕРВНЕ КОПІЮВАННЯ - НАДЛИШКОВА ВТОРИННА СИСТЕМА (CP-9(6))",
      parameters: [
        {:cp_9_6_01,
         "Резервне копіювання системи здійснюється шляхом підтримки надлишкової вторинної системи, яка не пов'язана з первинною системою",
         [type: :string, default: nil]},
        {:cp_9_6_02,
         "Резервне копіювання системи здійснюється шляхом підтримки резервної вторинної системи, яка може бути активована без втрати інформації або порушення роботи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-9-7") do
    %{
      id: :"id-spe-cp-9-7",
      description: "",
      title: "РЕЗЕРВНЕ КОПІЮВАННЯ - ПОДВІЙНА АВТОРИЗАЦІЯ (CP-9(7))",
      parameters: [
        {:cp_9_7_01,
         "Застосовано подвійну авторизацію для видалення або знищення резервної інформації",
         [type: :string, default: nil]},
        {:cp_9_7_odp,
         "Визначено резервну інформацію, для якої необхідно застосувати подвійну авторизацію з метою видалення або знищення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-9-8") do
    %{
      id: :"id-spe-cp-9-8",
      description: "",
      title: "РЕЗЕРВНЕ КОПІЮВАННЯ - КРИПТОГРАФІЧНИЙ ЗАХИСТ (CP-9(8))",
      parameters: [
        {:cp_9_8_01,
         "Реалізовано криптографічні механізми для запобігання несанкціонованому розкриттю та зміні резервної інформації",
         [type: :string, default: "AES-256-GCM"]},
        {:cp_9_8_odp,
         "Визначено резервні копії інформації для захисту від несанкціонованого розкриття та змін",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-10") do
    %{
      id: :"id-spe-cp-10",
      description: "",
      title: "ВІДНОВЛЕННЯ ТА ВІДТВОРЕННЯ СИСТЕМИ (CP-10)",
      parameters: [
        {:cp_10_01,
         "Відновлення системи до відомого стану забезпечується протягом часу після збою, компрометації або помилки",
         [type: :integer, default: 30]},
        {:cp_10_02,
         "Відтворення системи до відомого стану забезпечується протягом часу після збою, компрометації або помилки",
         [type: :integer, default: 30]},
        {:cp_10_odp_02,
         "Визначено період часу для відновлення, часу та цілям відновлення системи; визначено період часу для відтворення, часу та цілям відновлення системи",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cp-10-2") do
    %{
      id: :"id-spe-cp-10-2",
      description: "",
      title: "ВІДНОВЛЕННЯ ТА ВІДТВОРЕННЯ СИСТЕМИ - ВІДНОВЛЕННЯ ТРАНЗАКЦІЙ (CP-10(2))",
      parameters: [
        {:cp_10_2_01,
         "Реалізовано відновлення транзакцій для систем, що базуються на транзакціях",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-10-4") do
    %{
      id: :"id-spe-cp-10-4",
      description: "",
      title: "ВІДНОВЛЕННЯ ТА ВІДТВОРЕННЯ СИСТЕМИ - ВІДНОВЛЕННЯ В МЕЖАХ ЧАСОВОГО ПЕРІОДУ (CP-10(4))",
      parameters: [
        {:cp_10_4_01,
         "Забезпечено можливість відновлення компонентів системи протягом період часу відновлення з інформації управління конфігурацією та захищеною цілісністю, яка описує відомий робочий стан компонентів",
         [type: :integer, default: 30]},
        {:cp_10_4_odp,
         "Визначено період часу відновлення, протягом якого компоненти системи відновлюються до відомого, робочого стану",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-cp-10-5") do
    %{
      id: :"id-spe-cp-10-5",
      description: "",
      title: "ВІДНОВЛЕННЯ ТА ВІДТВОРЕННЯ СИСТЕМИ - ЗДАТНІСТЬ ВІДМОВОСТІЙКОСТІ (CP-10(5))",
      parameters: [
        {:cp_10_5_01,
         "ВІДНОВЛЕННЯ ТА ВІДТВОРЕННЯ СИСТЕМИ - ЗДАТНІСТЬ ВІДМОВОСТІЙКОСТІ [Вилучено: Включено до SI-13]. CP10(06) ВІДНОВЛЕННЯ ТА ВІДТВОРЕННЯ СИСТЕМИ - ЗАХИСТ КОМПОНЕНТУ",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-11") do
    %{
      id: :"id-spe-cp-11",
      description: "",
      title: "АЛЬТЕРНАТИВНІ ПРОТОКОЛИ ЗВ’ЯЗКУ (CP-11)",
      parameters: [
        {:cp_11_01,
         "Організація забезпечує можливість застосування альтернативних протоколів зв'язку для підтримки збереження безперервності функціонування",
         [type: :string, default: "TLS 1.3"]}
      ]
    }
  end

  def spec(:"id-spe-cp-12") do
    %{
      id: :"id-spe-cp-12",
      description: "",
      title: "БЕЗПЕЧНИЙ РЕЖИМ (CP-12)",
      parameters: [
        {:cp_12_01,
         "При виявлені умови, вводиться безпечний режим роботи з обмеженням",
         [type: :list, default: []]},
        {:cp_12_odp_01,
         "Визначено умови, за яких організація вводить безпечний режим роботи",
         [type: :list, default: []]},
        {:cp_12_odp_02,
         "Визначено обмеження в безпечному режимі роботи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-cp-13") do
    %{
      id: :"id-spe-cp-13",
      description: "",
      title: "АЛЬТЕРНАТИВНІ МЕХАНІЗМИ БЕЗПЕКИ (CP-13)",
      parameters: [
        {:cp_13_01,
         "Альтернативні або додаткові механізми безпеки використовуються для реалізації функцій безпеки, коли основні засоби реалізації функцій безпеки недоступні або скомпрометовані",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cp_13_odp_01,
         "Визначені альтернативні або додаткові механізми безпеки",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:cp_13_odp_02,
         "Визначені функції безпеки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-1") do
    %{
      id: :"id-spe-ia-1",
      description: "",
      title: "Політика та процедури ідентифікації та автентифікації (IA-1)",
      parameters: [
        {:ia_1_a_01,
         "Розроблено та задокументовано політику ідентифікації та автентифікації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ia_1_a_02,
         "Політика ідентифікації та автентифікації поширюється на персонал або ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_1_a_03,
         "Розроблені та задокументовані процедури ідентифікації та автентифікації, що сприяють впровадженню політики ідентифікації та автентифікації, а також відповідні заходи ідентифікації та перевірки автентичності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ia_1_b,
         "Посадова особа призначається для управління політикою та процедурами ідентифікації та автентифікації; IA-01(c)[01][01] переглядається та оновлюється поточна політика ідентифікації та автентифікації частота; IA-01(c)[01][02] переглядається та оновлюється поточна політика ідентифікації та автентифікації після подій; IA-01(c)[02][01] переглядаються та оновлюються поточні процедури ідентифікації та автентифікації частота; IA-01(c)[02][02] переглядаються та оновлюються поточні процедури ідентифікації та автентифікації після подій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_1_odp_01,
         "Визначено персонал або ролі, на які поширюється політика ідентифікації та автентифікації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_1_odp_02,
         "Визначено персонал або ролі, на які поширюються процедури ідентифікації та автентифікації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнес-процесів; рівень системи}",
         [type: :string, default: nil]},
        {:ia_1_odp_04,
         "Визначено посадову особу, яка управляє політикою та процедурами ідентифікації та автентифікації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_1_odp_05,
         "Визначено частоту, з якою переглядається та оновлюється поточна політика ідентифікації та автентифікації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ia_1_odp_06,
         "Визначено події, які потребують перегляду та оновлення поточної політики ідентифікації та автентифікації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ia_1_odp_07,
         "Визначено частоту, з якою переглядаються та оновлюються поточні процедури ідентифікації та автентифікації",
         [type: :integer, default: 30]},
        {:ia_1_odp_08,
         "Визначено події, які потребують перегляду та оновлення процедур ідентифікації та автентифікації",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-2") do
    %{
      id: :"id-spe-ia-2",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ КОРИСТУВАЧІВ (IA-2)",
      parameters: [
        {:ia_2_01,
         "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:ia_2_02,
         "Процеси що діють від імені користувачів унікально ідентифіковані та автентифіковані",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-2-1") do
    %{
      id: :"id-spe-ia-2-1",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - БАГАТОФАКТОРНА АВТЕНТИФІКАЦІЯ ПРИВІЛЕЙОВАНИХ ОБЛІКОВИХ ЗАПИСІВ (IA-2(1))",
      parameters: [
        {:ia_2_1_01,
         "Реалізувано багатофакторну автентифікацію для доступу до привілейованих облікових записів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-2-2") do
    %{
      id: :"id-spe-ia-2-2",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - БАГАТОФАКТОРНА АВТЕНТИФІКАЦІЯ НЕПРИВІЛЕЙОВАНИХ (IA-2(2))",
      parameters: [
        {:ia_2_2_01,
         "Реалізовано багатофакторну автентифікацію для доступу до непривілейованих облікових записів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-2-3") do
    %{
      id: :"id-spe-ia-2-3",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - ЛОКАЛЬНИЙ ДОСТУП ДО ПРИВІЛЕЙОВАНИХ ОБЛІКОВИХ ЗАПИСІВ (IA-2(3))",
      parameters: [
        {:ia_2_3_01,
         "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - ЛОКАЛЬНИЙ ДОСТУП ДО ПРИВІЛЕЙОВАНИХ ОБЛІКОВИХ ЗАПИСІВ [Вилучено: Включено до ІА-02(01)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-2-4") do
    %{
      id: :"id-spe-ia-2-4",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - ЛОКАЛЬНИЙ ДОСТУП ДО НЕПРИВІЛЕЙОВАНИХ ОБЛІКОВИХ ЗАПИСІВ (IA-2(4))",
      parameters: [
        {:ia_2_4_01,
         "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - ЛОКАЛЬНИЙ ДОСТУП ДО НЕПРИВІЛЕЙОВАНИХ ОБЛІКОВИХ ЗАПИСІВ [Вилучено: Включено до ІА-02(02)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-2-5") do
    %{
      id: :"id-spe-ia-2-5",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - ІНДИВІДУАЛЬНА АВТЕНТИФІКАЦІЯ З ГРУПОВОЮ АВТЕНТИФІКАЦІЄЮ (IA-2(5))",
      parameters: [
        {:ia_2_5_01,
         "Користувачі повинні пройти індивідуальну автентифікацію перед наданням доступу до спільних облікових записів або ресурсів, якщо використовуються спільні облікові записи або автентифікатори",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-2-7") do
    %{
      id: :"id-spe-ia-2-7",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - МЕРЕЖЕВИЙ ДОСТУП ДО НЕПРИВІЛЕЙОВАНИХ ОБЛІКОВИХ ЗАПИСІВ – ОКРЕМИЙ ПРИСТРІЙ (IA-2(7))",
      parameters: [
        {:ia_2_7_01,
         "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - МЕРЕЖЕВИЙ ДОСТУП ДО НЕПРИВІЛЕЙОВАНИХ ОБЛІКОВИХ ЗАПИСІВ – ОКРЕМИЙ ПРИСТРІЙ [Вилучено: Включено до ІА-02(01)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-2-8") do
    %{
      id: :"id-spe-ia-2-8",
      description: "",
      title: "Ідентифікація та автентифікація (користувачів організації) - Доступ до облікових записів — стійкість до відтворення (IA-2(8))",
      parameters: [
        {:ia_2_8_odp,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {привілейовані облікові записи; непривілейовані облікові записи}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-2-9") do
    %{
      id: :"id-spe-ia-2-9",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - ДОСТУП ДО НЕПРИВІЛЕЙОВАНИХ ОБЛІКОВИХ ЗАПИСІВ – СТІЙКІСТЬ ДО ВІДТВОРЕННЯ (IA-2(9))",
      parameters: [
        {:ia_2_9_01,
         "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - ДОСТУП ДО НЕПРИВІЛЕЙОВАНИХ ОБЛІКОВИХ ЗАПИСІВ – СТІЙКІСТЬ ДО ВІДТВОРЕННЯ [Вилучено: Включено до ІА-02(08)]. IA-02(10) ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - ЄДИНА ТОЧКА ВХОДУ",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-2-10") do
    %{
      id: :"id-spe-ia-2-10",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - ЄДИНА ТОЧКА ВХОДУ (IA-2(10))",
      parameters: [
        {:ia_2_10_odp,
         "Визначено облікові записи та послуги системи, для яких має бути забезпечена можливість єдиного входу; забезпечено можливість єдиного входу для облікових записів і послуг системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-2-11") do
    %{
      id: :"id-spe-ia-2-11",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - ВІДДАЛЕНИЙ ДОСТУП - ОКРЕМИЙ ПРИСТРІЙ (IA-2(11))",
      parameters: [
        {:ia_2_11_01,
         "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - ВІДДАЛЕНИЙ ДОСТУП - ОКРЕМИЙ ПРИСТРІЙ [Вилучено: Включено до ІА-02(06)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-2-12") do
    %{
      id: :"id-spe-ia-2-12",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - ПРИЙНЯТТЯ ПОВНОВАЖЕНЬ ДЛЯ ВЕРИФІКАЦІЇ ОСОБИСТОЇ ІНФОРМАЦІЇ (PIV CREDENTIALS) (IA-2(12))",
      parameters: [
        {:ia_2_12_01,
         "Приймаються та електронним шляхом підтверджуються повноваження облікових даних особистої ідентифікації",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-2-13") do
    %{
      id: :"id-spe-ia-2-13",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІВ ОРГАНІЗАЦІЇ) - АВТЕНТИФІКАЦІЯ ПО ЗОВНІШНЬОМУ КАНАЛУ (IA-2(13))",
      parameters: [
        {:ia_2_13_01,
         "Механізми зовнішньої автентифікації застосовано за умов",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ia_2_13_odp_01,
         "Визначено механізми зовнішньої автентифікації",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ia_2_13_odp_02,
         "Визначено умови, за яких має бути реалізована зовнішня автентифікація",
         [type: :list, default: []]}
      ]
    }
  end

  def spec(:"id-spe-ia-3") do
    %{
      id: :"id-spe-ia-3",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ ПРИСТРОЇВ (IA-3)",
      parameters: [
        {:ia_3_odp_01,
         "Визначені пристрої та/або типи пристроїв, які повинні бути унікально ідентифіковані та автентифіковані перед установкою підключення",
         [type: :string, default: nil]},
        {:ia_3_odp_02,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {локальний; віддалений; мережевий}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-3-1") do
    %{
      id: :"id-spe-ia-3-1",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ ПРИСТРОЇВ - КРИПТОГРАФІЧНА ДВОБІЧНА АВТЕНТИФІКАЦІЯ (IA-3(1))",
      parameters: [
        {:ia_3_1_odp_01,
         "Визначено пристрої та/або типи пристроїв, які потребують використання двобічної автентифікації яка заснована на криптографічних механізмах для автентифікації перед встановленням підключення",
         [type: :string, default: "AES-256-GCM"]},
        {:ia_3_1_odp_02,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {локальний; віддалений; мережевий}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-3-2") do
    %{
      id: :"id-spe-ia-3-2",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ ПРИСТРОЇВ - КРИПТОГРАФІЧНИЙ ДВОБІЧНА МЕРЕЖА АВТЕНТИФІКАЦІЯ [Виключено: включено до ІА-03(01)]. (IA-3(2))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ia-3-3") do
    %{
      id: :"id-spe-ia-3-3",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ ПРИСТРОЇВ - ДИНАМІЧНИЙ РОЗПОДІЛ АДРЕСИ (IA-3(3))",
      parameters: [
        {:ia_3_3_a_01,
         "Інформація про оренду динамічного розподілу адрес, що призначається пристроям з динамічним розподілом адрес, стандартизована відповідно до інформація про оренду",
         [type: :string, default: nil]},
        {:ia_3_3_a_02,
         "Тривалість оренди динамічного виділення адреси, що призначається пристроям з динамічним виділенням адреси, стандартизовано відповідно до тривалість оренди",
         [type: :string, default: nil]},
        {:ia_3_3_b,
         "Інформація про оренду перевіряється, коли її призначено пристрою",
         [type: :string, default: nil]},
        {:ia_3_3_odp_01,
         "Визначено інформацію про оренду, яку буде використано для стандартизації динамічного розподілу адрес для пристроїв",
         [type: :string, default: nil]},
        {:ia_3_3_odp_02,
         "Визначено тривалість оренди, яка буде використовуватися для стандартизації динамічного виділення адрес для пристроїв",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-3-4") do
    %{
      id: :"id-spe-ia-3-4",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ ПРИСТРОЮ ВИКОНУЄТЬСЯ НА ОСНОВІ АТЕСТАЦІЇ ЗА ДОПОМОГОЮ (IA-3(4))",
      parameters: [
        {:ia_3_4_01,
         "Ідентифікація та автентифікація пристрою виконується на основі атестації за допомогою процес управління конфігурацією",
         [type: :string, default: nil]},
        {:ia_3_4_odp,
         "Визначено процес управління конфігурацією, який буде використовуватися для ідентифікації та автентифікації пристроїв на основі атестації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-4") do
    %{
      id: :"id-spe-ia-4",
      description: "",
      title: "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ (IA-4)",
      parameters: [
        {:ia_4_a,
         "Управління ідентифікаторами здійснюється шляхом отримання дозволу від персоналу або ролей на призначення ідентифікатора особі, групі, ролі або пристрою",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_4_b,
         "Управління ідентифікаторами здійснюється шляхом вибору ідентифікатора, який ідентифікує окрему особу, групу, ролі або пристрій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_4_c,
         "Управління ідентифікаторами здійснюється шляхом призначення ідентифікатора особі, групі, ролі або пристрою; IA-04(d) ідентифікатори управляються шляхом запобігання повторному використанню ідентифікаторів впродовж період часу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_4_odp_01,
         "Визначено персонал або ролі, від яких необхідно отримати дозвіл на призначення ідентифікатора",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_4_odp_02,
         "Визначено період часу для запобігання повторному використанню ідентифікаторів",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ia-4-1") do
    %{
      id: :"id-spe-ia-4-1",
      description: "",
      title: "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ - ЗАБОРОНА ВИКОРИСТАННЯ ІДЕНТИФІКАТОРІВ ОБЛІКОВИХ ЗАПИСІВ ТАКИ САМИХ, ЯК Й ПУБЛІЧНІ ІДЕНТИФІКАТОРИ (IA-4(1))",
      parameters: [
        {:ia_4_1_01,
         "Заборонено використання ідентифікаторів облікових записів системи, які збігаються із загальнодоступними ідентифікаторами для індивідуальних облікових записів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-4-2") do
    %{
      id: :"id-spe-ia-4-2",
      description: "",
      title: "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ - АВТОРИЗАЦІЯ СУПЕРВАЙЗЕРА [Виключено: Включено до ІА-12(01)]. (IA-4(2))",
      parameters: [
        {:ia_4_2_01,
         "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ - АВТОРИЗАЦІЯ СУПЕРВАЙЗЕРА [Виключено: Включено до ІА-12(01)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-4-3") do
    %{
      id: :"id-spe-ia-4-3",
      description: "",
      title: "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ - МНОЖИННІ ФОРМИ СЕРТИФІКАЦІЇ (IA-4(3))",
      parameters: [
        {:ia_4_3_01,
         "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ - МНОЖИННІ ФОРМИ СЕРТИФІКАЦІЇ [Виключено: Включено до ІА-12(02)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-4-4") do
    %{
      id: :"id-spe-ia-4-4",
      description: "",
      title: "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ - ІДЕНТИФІКАЦІЯ СТАТУСУ КОРИСТУВАЧА (IA-4(4))",
      parameters: [
        {:ia_4_4_01,
         "Управління індивідуальними ідентифікаторами, однозначно ідентифікуючи кожного індивідуума ознака, що ідентифікує індивідуальний статус",
         [type: :string, default: nil]},
        {:ia_4_4_odp,
         "Визначено ознаку, що ідентифікує індивідуальний статус",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-4-5") do
    %{
      id: :"id-spe-ia-4-5",
      description: "",
      title: "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ - ДИНАМІЧНЕ УПРАВЛІННЯ (IA-4(5))",
      parameters: [
        {:ia_4_5_01,
         "Індивідуальні ідентифікатори динамічно управляються відповідно до політика динамічних ідентифікаторів",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ia_4_5_odp,
         "Визначено політику динамічних ідентифікаторів управління індивідуальними ідентифікаторами",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-4-6") do
    %{
      id: :"id-spe-ia-4-6",
      description: "",
      title: "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ - КРОС-ОРГАНІЗАЦІЙНЕ УПРАВЛІННЯ (IA-4(6))",
      parameters: [
        {:ia_4_6_odp,
         "Визначено зовнішні організації з якими необхідно здійснювати координацію для крос-організаційного управління ідентифікаторами; здійснюється координація з зовнішні організації для крос-організаційного управління ідентифікаторами",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-4-7") do
    %{
      id: :"id-spe-ia-4-7",
      description: "",
      title: "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ - ОСОБИСТА РЕЄСТРАЦІЯ [Виключено: Включено до ІА-12(04)]. (IA-4(7))",
      parameters: [
        {:ia_4_7_01,
         "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ - ОСОБИСТА РЕЄСТРАЦІЯ [Виключено: Включено до ІА-12(04)]",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-4-8") do
    %{
      id: :"id-spe-ia-4-8",
      description: "",
      title: "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ - ПОПАРНІ ПСЕВДОНІМНІ ІДЕНТИФІКАТОРИ (IA-4(8))",
      parameters: [
        {:ia_4_8_01,
         "Створено попарні псевдонімні ідентифікатори",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-4-9") do
    %{
      id: :"id-spe-ia-4-9",
      description: "",
      title: "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ - ПОПАРНІ ПСЕВДОНІМНІ ІДЕНТИФІКАТОРИ (IA-4(9))",
      parameters: [
        {:ia_4_9_odp,
         "Визначено захищене центральне сховище, яке використовується для зберігання атрибутів для кожної унікально ідентифікованої особи, пристрою або служби; атрибути для кожної унікально ідентифікованої особи, пристрою або служби зберігаються у захищеному центральному сховищі",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-1") do
    %{
      id: :"id-spe-ia-5-1",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - АВТЕНТИФІКАЦІЯ НА ОСНОВІ ПАРОЛЯ (IA-5(1))",
      parameters: [
        {:ia_5_1_a,
         "Для автентифікації на основі паролів підтримується та оновлюється список часто використовуваних, очікуваних або скомпрометованих паролів частота, а також коли є підозра, що паролі організації були скомпрометовані прямо чи опосередковано",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_5_1_b,
         "Для автентифікації на основі паролів, коли паролі створюються або оновлюються користувачами, паролі перевіряються на відсутність у списку загальновживаних, очікуваних або скомпрометованих паролів в IA-05(01)(a)",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_5_1_c,
         "Для автентифікації на основі паролів, паролі передаються лише криптографічно захищеними каналами",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_5_1_d,
         "Для автентифікації на основі паролів паролі зберігаються за допомогою затвердженого алгоритму гешування, переважно використовуючи ключову геш-функцію",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_5_1_e,
         "Для автентифікації на основі пароля після відновлення облікового запису потрібно негайно вибрати новий пароль",
         [type: :string, default: nil]},
        {:ia_5_1_f,
         "Для автентифікації на основі пароля дозволяється вибір користувачем довгих паролів і фраз, що включають пробіли та всі друковані символи",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_5_1_g,
         "Для автентифікації на основі пароля використовуються автоматизовані інструменти, які допомагають користувачеві у виборі надійних автентифікаторів паролів",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_5_1_h,
         "Для автентифікації на основі пароля застосовуються склад та правила складності",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ia_5_1_odp_01,
         "Визначено частоту оновлення списку часто використовуваних, очікуваних або скомпрометованих паролів",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_5_1_odp_02,
         "Визначено склад та правила складності автентифікатора",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-2") do
    %{
      id: :"id-spe-ia-5-2",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - АВТЕНТИФІКАЦІЯ НА ОСНОВІ ВІДКРИТОГО КЛЮЧА (IA-5(2))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ia-5-3") do
    %{
      id: :"id-spe-ia-5-3",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - ОСОБИСТА АБО ДОВІРЧА АВТЕНТИФІКАЦІЯ ЗОВНІШНЬОЇ СТОРОНИ [Виключено: Включено до ІА-12(04)]. (IA-5(3))",
      parameters: [
        {:ia_5_3_01,
         "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - ОСОБИСТА АБО ДОВІРЧА АВТЕНТИФІКАЦІЯ ЗОВНІШНЬОЇ СТОРОНИ [Виключено: Включено до ІА-12(04)]",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-4") do
    %{
      id: :"id-spe-ia-5-4",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - АВТОМАТИЗОВАНА ПІДТРИМКА ДЛЯ ВИЗНАЧЕННЯ МІЦНОСТІ ПАРОЛЯ [Виключено: Включено до ІА-05(01)]. (IA-5(4))",
      parameters: [
        {:ia_5_4_01,
         "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - АВТОМАТИЗОВАНА ПІДТРИМКА ДЛЯ ВИЗНАЧЕННЯ МІЦНОСТІ ПАРОЛЯ [Виключено: Включено до ІА-05(01)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-5") do
    %{
      id: :"id-spe-ia-5-5",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - ЗМІНА АВТЕНТИФІКАТОРІВ ДО ДОСТАВКИ (IA-5(5))",
      parameters: [
        {:ia_5_5_01,
         "Розробники та інсталятори компонентів системи зобов'язані надавати унікальні автентифікатори або змінювати автентифікатори за замовчуванням до доставки та встановлення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-6") do
    %{
      id: :"id-spe-ia-5-6",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - ЗАХИСТ АВТЕНТИФІКАТОРІВ (IA-5(6))",
      parameters: [
        {:ia_5_6_01,
         "Автентифікатори захищені відповідно до категорії безпеки інформації, до якої дозволяє доступ використання автентифікатора",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-7") do
    %{
      id: :"id-spe-ia-5-7",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - ВІДСУТНІСТЬ ВБУДОВАНИХ НЕЗАШИФРОВАНИХ СТАТИЧНИХ АВТЕНТИФІКАТОРІВ (IA-5(7))",
      parameters: [
        {:ia_5_7_01,
         "Незашифровані статичні автентифікатори не вбудовуються в застосунки або сценарії доступу та не збережені на функціональній клавіші",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-8") do
    %{
      id: :"id-spe-ia-5-8",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - БАГАТОСИСТЕМНІ ОБЛІКОВІ ЗАПИСИ (IA-5(8))",
      parameters: [
        {:ia_5_8_01,
         "Заходи захисту впроваджені для управління ризиком компрометації через наявність облікових записів у декількох системах",
         [type: :string, default: nil]},
        {:ia_5_8_odp,
         "Визначено заходи захисту, впроваджені для управління ризиком компрометації через те, що користувачі мають облікові записи в декількох системах",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-9") do
    %{
      id: :"id-spe-ia-5-9",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - УПРАВЛІННЯ ОБ’ЄДНАННЯМ АВТЕНТИФІКАТОРІВ (IA-5(9))",
      parameters: [
        {:ia_5_9_01,
         "Зовнішні організації використовуються для об'єднання автентифікаторів",
         [type: :string, default: nil]},
        {:ia_5_9_odp,
         "Визначено зовнішні організації, які будуть використовуватися для об'єднання автентифікаторів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-10") do
    %{
      id: :"id-spe-ia-5-10",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - ДИНАМІЧНЕ ЗВ’ЯЗУВАННЯ МАНДАТІВ (IA-5(10))",
      parameters: [
        {:ia_5_10_01,
         "Ідентифікатори та автентифікатори динамічно зв'язуються за допомогою правила для динамічного зв'язування ",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ia_5_10_odp,
         "Визначено правила для динамічного зв'язування ідентифікаторів та автентифікаторів",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-11") do
    %{
      id: :"id-spe-ia-5-11",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - АВТЕНТИФІКАЦІЯ НА ОСНОВІ АПАРАТНИХ ТОКЕНІВ (IA-5(11))",
      parameters: [
        {:ia_5_11_01,
         "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - АВТЕНТИФІКАЦІЯ НА ОСНОВІ АПАРАТНИХ ТОКЕНІВ [Вилучено: Включено до ІА-02(01), ІА-02(02)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-12") do
    %{
      id: :"id-spe-ia-5-12",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - ЕФЕКТИВНІСТЬ БІОМЕТРИЧНОЇ АВТЕНТИФІКАЦІЇ (IA-5(12))",
      parameters: [
        {:ia_5_12_odp,
         "Визначено вимоги до якості біометрії; для біометричної автентифікації використовувати механізми, які задовольняють вимоги",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-13") do
    %{
      id: :"id-spe-ia-5-13",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - ЗАКІНЧЕННЯ ТЕРМІНУ ШУВАННЯ АВТЕНТИФІКАТОРІВ (IA-5(13))",
      parameters: [
        {:ia_5_13_odp,
         "Визначено періоду часу після якого необхідно заборонити використання кешованих автентифікаторів забороняється використання кешованих автентифікаторів після періоду часу",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-14") do
    %{
      id: :"id-spe-ia-5-14",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - УПРАВЛІННЯ ЗМІСТОМ ДОВІРЧИХ СХОВИЩ ІНФРАСТРУКТУРИ ВІДКРИТИХ КЛЮЧІВ (IA-5(14))",
      parameters: [
        {:ia_5_14_01,
         "Для автентифікації на основі інфраструктури з відкритим ключем використовується загальноорганізаційна методологія управління вмістом довірених сховищ інфраструктури відкритого ключа, встановлених на всіх платформах, включно з мережами, операційними системами, браузерами та застосунками",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-15") do
    %{
      id: :"id-spe-ia-5-15",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - ПРОДУКТИ ТА ПОСЛУГИ, ЗАТВЕРДЖЕНІ УПОВНОВАЖЕНИМ ОРГАНОМ (IA-5(15))",
      parameters: [
        {:ia_5_15_01,
         "Використовуються лише схвалені та затверджені уповноваженим органом продукти та послуги",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-16") do
    %{
      id: :"id-spe-ia-5-16",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - ПЕРЕДАЧА ОСОБИСТОЇ АБО ДОВІРЧОЇ АВТЕНТИФІКАЦІЇ ЗОВНІШНЬОЇ СТОРОНИ (IA-5(16))",
      parameters: [
        {:ia_5_16_01,
         "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - ПЕРЕДАЧА ОСОБИСТОЇ АБО ДОВІРЧОЇ АВТЕНТИФІКАЦІЇ ЗОВНІШНЬОЇ СТОРОНИ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_5_16_odp_01,
         "Визначено типи та/або конкретні автентифікатори, які будуть передаватися",
         [type: :string, default: nil]},
        {:ia_5_16_odp_02,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {особисто; довіреною зовнішньою стороною}",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_5_16_odp_03,
         "Визначено зареєстрований орган, який приймає автентифікатори",
         [type: :string, default: nil]},
        {:ia_5_16_odp_04,
         "Визначено персонал або ролі, які уповноважують передачу автентифікаторів",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-17") do
    %{
      id: :"id-spe-ia-5-17",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - АВТОМАТИЗОВАНІ ЗАСОБИ ВИЯВЛЕННЯ АТАК ІЗ ВИКОРИСТАННЯМ БІОМЕТРИЧНИХ АВТЕНТИФІКАТОРІВ (IA-5(17))",
      parameters: [
        {:ia_5_17_01,
         "Використовуються механізми виявлення атак із використанням штучно виготовлених артефактів для біометричних автентифікаторів",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ia-5-18") do
    %{
      id: :"id-spe-ia-5-18",
      description: "",
      title: "УПРАВЛІННЯ АВТЕНТИФІКАТОРОМ - МЕНЕДЖЕР ПАРОЛІВ (IA-5(18))",
      parameters: [
        {:ia_5_18_a,
         "Менеджери паролів використовуються для створення та керування паролями",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_5_18_b,
         "Паролі захищені за допомогою елементи керування",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_5_18_odp_01,
         "Визначено менеджери паролів, які використовуються для створення та керування паролями",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_5_18_odp_02,
         "Визначено елементи керування для захисту паролів",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-7") do
    %{
      id: :"id-spe-ia-7",
      description: "",
      title: "АВТЕНТИФІКАЦІЯ КРИПТОГРАФІЧНОГО МОДУЛЯ (IA-7)",
      parameters: [
        {:ia_7_01,
         "Впроваджено механізми автентифікації в криптографічний модуль, який відповідає вимогам чинних законів, виконавчих розпоряджень, директив, політик, правил, стандартів та рекомендацій для такої автентифікації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-8") do
    %{
      id: :"id-spe-ia-8",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІ, ЩО НЕ НАЛЕЖАТЬ ДО ОРГАНІЗАЦІЇ) (IA-8)",
      parameters: [
        {:ia_8_01,
         "Унікально ідентифікуються та автентифікуються користувачі, що не належать до організації або процеси (що не належать організації), які діють від імені користувачів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-8-3") do
    %{
      id: :"id-spe-ia-8-3",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІ, ЩО НЕ НАЛЕЖАТЬ ДО ОРГАНІЗАЦІЇ) - ВИКОРИСТАННЯ ЗАТВЕРДЖЕНИХ ПРОДУКТІВ (IA-8(3))",
      parameters: [
        {:ia_8_3_01,
         "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІ, ЩО НЕ НАЛЕЖАТЬ ДО ОРГАНІЗАЦІЇ) - ВИКОРИСТАННЯ ЗАТВЕРДЖЕНИХ ПРОДУКТІВ [Вилучено: Включено до ІА-08(02)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-8-5") do
    %{
      id: :"id-spe-ia-8-5",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІ, ЩО НЕ НАЛЕЖАТЬ ДО ОРГАНІЗАЦІЇ) - ВИЗНАННЯ ПОСВІДЧЕНЬ ОСОБИ (PIV-I) (IA-8(5))",
      parameters: [
        {:ia_8_5_01,
         "Приймаються облікові дані або дані PKI, які відповідають політика",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ia_8_5_02,
         "Підтверджуються облікові дані або дані PKI, які відповідають політика",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ia_8_5_odp,
         "Визначено політику використання ативних облікових даних або облікових даних PKI",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-8-6") do
    %{
      id: :"id-spe-ia-8-6",
      description: "",
      title: "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (КОРИСТУВАЧІ, ЩО НЕ НАЛЕЖАТЬ ДО ОРГАНІЗАЦІЇ) - РОЗМЕЖУВАННЯ (IA-8(6))",
      parameters: [
        {:ia_8_6_odp,
         "Визначено заходи, щоб розмежувати атрибути користувача або зв’язки підтвердження ідентифікатора між окремими особами, постачальниками облікових даних і довіреними сторонами; впроваджено заходи щоб розмежувати атрибути користувача або зв’язки підтвердження ідентифікатора між окремими особами, постачальниками облікових даних і довіреними сторонами",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-9") do
    %{
      id: :"id-spe-ia-9",
      description: "",
      title: "ПОСЛУГИ ІДЕНТИФІКАЦІЇ ТА АВТЕНТИФІКАЦІЇ (IA-9)",
      parameters: [
        {:ia_9_01,
         "Системні служби та застосунки унікально ідентифікуються та автентифікуються перед встановленням зв'язку з пристроями, користувачами або іншими службами чи застосунками",
         [type: :string, default: nil]},
        {:ia_9_odp,
         "Визначено системні служби та застосунки, які мають бути унікально ідентифіковані та автентифіковані",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-9-1") do
    %{
      id: :"id-spe-ia-9-1",
      description: "",
      title: "ПОСЛУГИ ІДЕНТИФІКАЦІЇ ТА АВТЕНТИФІКАЦІЇ - ОБМІН ІНФО- (IA-9(1))",
      parameters: [
        {:ia_9_1_01,
         "ПОСЛУГИ ІДЕНТИФІКАЦІЇ ТА АВТЕНТИФІКАЦІЇ - ОБМІН ІНФО- РМАЦІЄЮ [Виключено: перенесено до IA-09]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-9-2") do
    %{
      id: :"id-spe-ia-9-2",
      description: "",
      title: "ПОСЛУГИ ІДЕНТИФІКАЦІЇ ТА АВТЕНТИФІКАЦІЇ - ПЕРЕДАЧА РІШЕНЬ [Виключено: перенесено до IA-09] (IA-9(2))",
      parameters: [
        {:ia_9_2_01,
         "ПОСЛУГИ ІДЕНТИФІКАЦІЇ ТА АВТЕНТИФІКАЦІЇ - ПЕРЕДАЧА РІШЕНЬ [Виключено: перенесено до IA-09]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-10") do
    %{
      id: :"id-spe-ia-10",
      description: "",
      title: "АДАПТИВНА АВТЕНТИФІКАЦІЯ (IA-10)",
      parameters: [
        {:ia_10_01,
         "Особи, які отримують доступ до системи, повинні використовувати додаткові методи або механізми автентифікації за певних обставин або ситуацій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_10_odp_01,
         "Визначені обставини або ситуації, які вимагають від осіб, що отримують доступ до системи, використання додаткових методів або механізмів автентифікації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-11") do
    %{
      id: :"id-spe-ia-11",
      description: "",
      title: "ПОВТОРНА АВТЕНТИФІКАЦІЯ (IA-11)",
      parameters: [
        {:ia_11_01,
         "Користувачі повинні повторно автентифікуватися, коли обставини або ситуації",
         [type: :string, default: nil]},
        {:ia_11_odp,
         "Визначено обставини або ситуації, що вимагають повторної автен- тифікації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-12") do
    %{
      id: :"id-spe-ia-12",
      description: "",
      title: "ПЕРЕВІРКА СПРАВЖНОСТІ (ІДЕНТИЧНОСТІ) (IA-12)",
      parameters: [
        {:ia_12_a,
         "Користувачі, яким потрібні облікові записи для логічного доступу до систем на основі вимог гарантій відповідного рівня, як це зазначено у відповідних стандартах і рекомендаціях, мають підтверджену ідентичність",
         [type: :string, default: nil]},
        {:ia_12_b,
         "Встановлені ідентифікатори користувачів унікальні для особи",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_12_c_01,
         "Збираються докази ідентичності особи",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_12_c_02,
         "Затверджуються докази ідентичності особи",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_12_c_03,
         "Перевіряються докази ідентичності особи",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-12-1") do
    %{
      id: :"id-spe-ia-12-1",
      description: "",
      title: "ПЕРЕВІРКА СПРАВЖНОСТІ (ІДЕНТИЧНОСТІ) - АВТОРИЗАЦІЯ СУПЕРВАЙЗЕРА (IA-12(1))",
      parameters: [
        {:ia_12_1_01,
         "Процес реєстрації для отримання облікового запису для логічного доступу включає авторизацію супервайзера",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-12-2") do
    %{
      id: :"id-spe-ia-12-2",
      description: "",
      title: "ПЕРЕВІРКА СПРАВЖНОСТІ (ІДЕНТИЧНОСТІ) - ПОСВІДЧЕННЯ ОСОБИ (IA-12(2))",
      parameters: [
        {:ia_12_2_01,
         "Документи, що посвідчують особу пред’являються до реєстраційного органу",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-12-4") do
    %{
      id: :"id-spe-ia-12-4",
      description: "",
      title: "ПЕРЕВІРКА СПРАВЖНОСТІ (ІДЕНТИЧНОСТІ) - ОЧНА ПЕРЕВІРКА ТА ВЕРИФІКАЦІЯ (IA-12(4))",
      parameters: [
        {:ia_12_4_01,
         "Підтвердження та перевірка посвідчення особи проводиться особисто в призначеному органі реєстрації",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ia-12-5") do
    %{
      id: :"id-spe-ia-12-5",
      description: "",
      title: "ПЕРЕВІРКА СПРАВЖНОСТІ (ІДЕНТИЧНОСТІ) - ПІДТВЕРДЖЕННЯ АДРЕСИ (IA-12(5))",
      parameters: [
        {:ia_12_5_01,
         "ПЕРЕВІРКА СПРАВЖНОСТІ (ІДЕНТИЧНОСТІ) - ПІДТВЕРДЖЕННЯ АДРЕСИ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:ia_12_5_odp,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {реєстраційний код; повідомлення про перевірку}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-12-6") do
    %{
      id: :"id-spe-ia-12-6",
      description: "",
      title: "ПЕРЕВІРКА СПРАВЖНОСТІ (ІДЕНТИЧНОСТІ) - ПРИЙНЯТТЯ ІДЕНТИФІКАЦІЙ СХВАЛЕНИХ ТРЕТЬОЮ СТОРОНОЮ (IA-12(6))",
      parameters: [
        {:ia_12_6_01,
         "Приймаються зовнішньо підтверджені ідентифікатори рівень гарантії ідентичності",
         [type: :string, default: nil]},
        {:ia_12_6_odp,
         "Визначено рівень гарантії ідентичності для прийняття зовнішньо підтверджених ідентифікаторів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-1") do
    %{
      id: :"id-spe-ir-1",
      description: "",
      title: "Політика та процедури реагування на інциденти (IR-1)",
      parameters: [
        {:ir_1_a_01,
         "Розроблено та задокументовано політику реагування на інциденти",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ir_1_a_02,
         "Політика реагування на інциденти поширюється серед персоналу або ролей",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_1_a_03,
         "Розроблені та задокументовані процедури реагування на інциденти, що сприяють впровадженню політики реагування на інциденти та пов'язаних з нею заходів захисту з реагування на інциденти",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ir_1_b,
         "Посадова особа призначається для управління розробкою, документуванням та розповсюдженням політики та процедур реагування на інциденти; IR-01(c)[01][01] переглядається та оновлюється поточна політика реагування на інциденти частота; IR-01(c)[01][02] поточна політика реагування на інциденти переглядається та оновлюється після подій; IR-01(c)[02][01] переглядаються та оновлюються поточні процедури реагування на інциденти частота; IR-01(c)[02][02] поточні процедури реагування на інциденти переглядаються та оновлюються після подій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_1_odp_01,
         "Визначено персонал або ролі, до яких має бути доведена політика реагування на інциденти",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_1_odp_02,
         "Визначено персонал або ролі, до яких мають бути доведені процедури реагування на інциденти",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнес-процесу; рівень системи}",
         [type: :string, default: nil]},
        {:ir_1_odp_04,
         "Визначено посадову особу, яка керуватиме політикою та процедурами реагування на інциденти",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_1_odp_05,
         "Визначено частоту, з якою переглядається та оновлюється поточна політика реагування на інциденти",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ir_1_odp_06,
         "Визначаються події, які потребують перегляду та оновлення поточної політики реагування на інциденти",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ir_1_odp_07,
         "Визначено частоту, з якою переглядаються та оновлюються поточні процедури реагування на інциденти",
         [type: :integer, default: 30]},
        {:ir_1_odp_08,
         "Визначено події, які потребують перегляду та оновлення процедур реагування на інциденти",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ir-2") do
    %{
      id: :"id-spe-ir-2",
      description: "",
      title: "НАВЧАННЯ З РЕАГУВАННЯ НА ІНЦИДЕНТИ (IR-2)",
      parameters: [
        {:ir_2_a_01,
         "Навчання з реагування на інциденти надається користувачам системи відповідно до призначених ролей та обов'язків протягом періоду часу з моменту прийняття на себе ролі або обов'язків з реагування на інциденти або отримання доступу до системи",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_2_a_02,
         "Навчання з реагування на інциденти надається користувачам системи відповідно до призначених ролей та обов'язків, коли цього вимагають зміни в системі",
         [type: :string, default: nil]},
        {:ir_2_a_03,
         "Користувачам системи надається навчання з реагування на інциденти відповідно до призначених ролей та обов'язків частота",
         [type: :string, default: "щорічно"]},
        {:ir_2_b_01,
         "Зміст навчання з реагування на інциденти переглядається та оновлюється частота",
         [type: :string, default: "щорічно"]},
        {:ir_2_b_02,
         "Зміст навчання з реагування на інциденти переглядається та оновлюється після подій",
         [type: :string, default: nil]},
        {:ir_2_odp_02,
         "Визначено частоту, з якою користувачі повинні проходити навчання з реагування на інциденти",
         [type: :integer, default: 30]},
        {:ir_2_odp_03,
         "Визначено частоту перегляду та оновлення змісту навчання з реагування на інциденти",
         [type: :integer, default: 30]},
        {:ir_2_odp_04,
         "Визначено події, які ініціюють перегляд змісту навчання з реагування на інциденти",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ir-2-1") do
    %{
      id: :"id-spe-ir-2-1",
      description: "",
      title: "НАВЧАННЯ З РЕАГУВАННЯ НА ІНЦИДЕНТИ - МОДЕЛЮВАННЯ ПОДІЙ (IR-2(1))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ir-2-3") do
    %{
      id: :"id-spe-ir-2-3",
      description: "",
      title: "НАВЧАННЯ З РЕАГУВАННЯ НА ІНЦИДЕНТИ - ЗЛАМ (IR-2(3))",
      parameters: [
        {:ir_2_3_01,
         "Проводиться навчання з реагування на інциденти щодо виявлення та реагу IR-02(03)[02] проводиться навчання з реагування на інциденти щодо процесу повідомлення п",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-3") do
    %{
      id: :"id-spe-ir-3",
      description: "",
      title: "ПЕРЕВІРКА РЕАГУВАНЬ НА ІНЦИДЕНТИ (IR-3)",
      parameters: [
        {:ir_3_01,
         "Ефективність реагування системи на інциденти перевіряється частота за допомогою тестів",
         [type: :string, default: "щорічно"]},
        {:ir_3_odp_01,
         "Визначено частоту, з якою необхідно перевіряти ефективність реагування системи на інциденти",
         [type: :integer, default: 30]},
        {:ir_3_odp_02,
         "Визначено тести, що використовуються для перевірки ефективності реагування на інциденти в системі",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-3-2") do
    %{
      id: :"id-spe-ir-3-2",
      description: "",
      title: "ПЕРЕВІРКА РЕАГУВАНЬ НА ІНЦИДЕНТИ - КООРДИНАЦІЯ З ПОВ'ЯЗАНИМИ ПЛАНАМИ (IR-3(2))",
      parameters: [
        {:ir_3_2_01,
         "Тестування реагування на інциденти координується з елементами організації, відповідальними за пов'язані плани",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-3-3") do
    %{
      id: :"id-spe-ir-3-3",
      description: "",
      title: "ПЕРЕВІРКА РЕАГУВАНЬ НА ІНЦИДЕНТИ - ПОСТІЙНЕ ПОКРАЩЕННЯ (IR-3(3))",
      parameters: [
        {:ir_3_3_a_01,
         "Якісні дані тестування використовуються для визначення ефективності процесів реагування на інциденти; IR-03(03)(a)[02] кількісні дані тестування використовуються для визначення ефективності процесів реагування на інциденти",
         [type: :string, default: nil]},
        {:ir_3_3_b_01,
         "Якісні дані тестування використовуються для постійного вдосконалення процесів реагування на інциденти",
         [type: :string, default: nil]},
        {:ir_3_3_b_02,
         "Кількісні дані тестування використовуються для постійного вдосконалення процесів реагування на інциденти",
         [type: :string, default: nil]},
        {:ir_3_3_c_01,
         "Якісні дані, отримані за результатами тестування , використовуються для забезпечення точних показників та метрик реагування на інциденти",
         [type: :string, default: nil]},
        {:ir_3_3_c_02,
         "Кількісні дані, отримані за результатами тестування , використовуються для забезпечення точних показників та метрик реагування на інциденти",
         [type: :string, default: nil]},
        {:ir_3_3_c_03,
         "Якісні дані, отримані за результатами тестування , використовуються для забезпечення послідовності показників та метрик реагування на інциденти",
         [type: :string, default: nil]},
        {:ir_3_3_c_04,
         "Кількісні дані, отримані за результатами тестування , використовуються для забезпечення послідовності показників та метрик реагування на інциденти",
         [type: :string, default: nil]},
        {:ir_3_3_c_05,
         "Якісні дані, отримані за результатами тестування , використовуються для забезпечення відтворюваносні показників та метрик реагування на інциденти",
         [type: :string, default: nil]},
        {:ir_3_3_c_06,
         "Кількусні дані, отримані за результатами тестування , використовуються для забезпечення відтворюваносні показників та метрик реагування на інциденти",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-4") do
    %{
      id: :"id-spe-ir-4",
      description: "",
      title: "Обробка інциденту (IR-4)",
      parameters: [
        {:ir_4_a_02,
         "Впроваджено можливість обробки інцидентів безпеки включно з виявленням",
         [type: :string, default: nil]},
        {:ir_4_a_03,
         "Впроваджено можливість обробки інцидентів безпеки включно з аналізом",
         [type: :string, default: nil]},
        {:ir_4_a_04,
         "Впроваджено можливість обробки інцидентів безпеки включно з локалізацією",
         [type: :string, default: nil]},
        {:ir_4_a_05,
         "Впроваджено можливість обробки інцидентів безпеки включно з ліквідацією",
         [type: :string, default: nil]},
        {:ir_4_a_06,
         "Впроваджено можливість обробки інцидентів безпеки включно з відновленням",
         [type: :string, default: nil]},
        {:ir_4_b,
         "Діяльність з обробки інцидентів координується із заходами із забезпечення безперервності функціонування",
         [type: :string, default: nil]},
        {:ir_4_c_01,
         "Уроки, отримані з поточних дій з обробки інцидентів, включаються в процедури реагування на інциденти, навчання та тестування",
         [type: :string, default: nil]},
        {:ir_4_c_02,
         "Зміни, що випливають відповідним чином",
         [type: :string, default: nil]},
        {:ir_4_d_01,
         "Строгість заходів з обробки інцидентів передбачуваною в межах всієї організації",
         [type: :string, default: nil]},
        {:ir_4_d_02,
         "Інтенсивність заходів з обробки інцидентів є порівнянною та передбачуваною в межах всієї організації",
         [type: :string, default: nil]},
        {:ir_4_d_03,
         "Обсяг заходів з обробки інцидентів є порівнянною та передбачуваною в межах всієї організації",
         [type: :string, default: nil]},
        {:ir_4_d_04,
         "Результати діяльності заходів з обробки інцидентів є порівнянною та передбачуваною в межах всієї організації; з отриманих уроків, є впроваджуються порівнянною",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-4-2") do
    %{
      id: :"id-spe-ir-4-2",
      description: "",
      title: "ОБРОБКА ІНЦИДЕНТУ - ДИНАМІЧНА РЕКОНФІГУРАЦІЯ (IR-4(2))",
      parameters: [
        {:ir_4_2_01,
         "Типи динамічної реконфігурації для компонентів системи включені як частина здатності реагування на інциденти",
         [type: :integer, default: 30]},
        {:ir_4_2_odp_01,
         "Визначено типи динамічної реконфігурації для компонентів системи",
         [type: :string, default: nil]},
        {:ir_4_2_odp_02,
         "Визначено компоненти системи, які потребують динамічної реконфігурації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-4-3") do
    %{
      id: :"id-spe-ir-4-3",
      description: "",
      title: "ОБРОБКА ІНЦИДЕНТУ - БЕЗПЕРЕРВНІСТЬ ОПЕРАЦІЙ (IR-4(3))",
      parameters: [
        {:ir_4_3_01,
         "Ідентифіковано класи інцидентів",
         [type: :string, default: nil]},
        {:ir_4_3_02,
         "Дії вживаються у відповідь на ці інциденти (визначені в IR-04(03)_ODP[01]) для забезпечення продовження виконання завдань та функцій організації",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ir_4_3_odp_01,
         "Визначено класи інцидентів, що вимагають вживання дій, визначених організацією (визначених в IR04(03)_ODP[02])",
         [type: :string, default: nil]},
        {:ir_4_3_odp_02,
         "Визначено дії, які необхідно вжити у відповідь на визначені організацією класи інцидентів",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ir-4-4") do
    %{
      id: :"id-spe-ir-4-4",
      description: "",
      title: "ОБРОБКА ІНЦИДЕНТУ - ІНФОРМАЦІЙНА КОРЕЛЯЦІЯ (IR-4(4))",
      parameters: [
        {:ir_4_4_01,
         "Інформація про інциденти та індивідуальне реагування на інциденти зіставляється з метою досягнення загальноорганізаційного бачення на обізнаність про інциденти та реагування на них",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-4-6") do
    %{
      id: :"id-spe-ir-4-6",
      description: "",
      title: "ОБРОБКА ІНЦИДЕНТУ - ВНУТРІШНІ ЗАГРОЗИ - ОСОБЛИВІ МОЖЛИВОСТІ (IR-4(6))",
      parameters: [
        {:ir_4_6_01,
         "Реалізовано можливість обробки інцидентів, пов'язаних з внутрішніми загрозами",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-4-8") do
    %{
      id: :"id-spe-ir-4-8",
      description: "",
      title: "ОБРОБКА ІНЦИДЕНТУ - КООРДИНАЦІЯ З ЗОВНІШНІМИ ОРГАНІЗАЦІЯМИ (IR-4(8))",
      parameters: [
        {:ir_4_8_01,
         "Здійснюється координація з зовнішніми організаціями для кореляції та обміну інформацією про інциденти для досяг- нення міжорганізаційного бачення щодо обізнаності про інциденти та більш ефективного реагування на інциденти",
         [type: :string, default: nil]},
        {:ir_4_8_odp_01,
         "Визначено зовнішні організації, з якими необхідно координувати та обмінюватися інформацією про інциденти в організації",
         [type: :string, default: nil]},
        {:ir_4_8_odp_02,
         "Визначено інформацію про інциденти, яку необхідно зіставляти та поширювати із зовнішніми організаціями",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-4-9") do
    %{
      id: :"id-spe-ir-4-9",
      description: "",
      title: "ОБРОБКА ІНЦИДЕНТУ - ЗДАТНІСТЬ ДИНАМІЧНОГО РЕАГУВАННЯ (IR-4(9))",
      parameters: [
        {:ir_4_9_odp,
         "Визначено можливості динамічного реагування для ефективного реагування на інциденти безпеки. використуються можливості динамічного реагування для ефективного реагування на інциденти безпеки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-4-10") do
    %{
      id: :"id-spe-ir-4-10",
      description: "",
      title: "ОБРОБКА ІНЦИДЕНТУ - КООРДИНАЦІЯ ЛАНЦЮГА ПОСТАЧАННЯ (IR-4(10))",
      parameters: [
        {:ir_4_10_01,
         "Координується діяльність з обробки інцидентів, пов'язана з подіями ланцюжка постачання, з іншими організаціями, що беруть участь у ланцюжку постачання",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ir-4-11") do
    %{
      id: :"id-spe-ir-4-11",
      description: "",
      title: "ОБРОБКА ІНЦИДЕНТУ - ІНТЕГРОВАНА ГРУПА РЕАГУВАННЯ НА ІНЦЕДЕНТИ (IR-4(11))",
      parameters: [
        {:ir_4_11_01,
         "Створена та підтримується інтегрована група реагування на інциденти",
         [type: :string, default: nil]},
        {:ir_4_11_02,
         "Інтегрована група реагування на інциденти може бути розгорнута в будь-якому місці, визначеному організацією протягом часового періоду",
         [type: :integer, default: 30]},
        {:ir_4_11_odp,
         "Визначено період часу, протягом якого може бути розгорнута інтегрована група реагування на інцидент",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ir-4-12") do
    %{
      id: :"id-spe-ir-4-12",
      description: "",
      title: "ОБРОБКА ІНЦИДЕНТУ - ЗЛОВМИСНИЙ КОД ТА КРИМІНАЛІСТИЧНИЙ АНАЛІЗ (IR-4(12))",
      parameters: [
        {:ir_4_12_01,
         "Шкідливий код, що залишився в системі, аналізується після інциденту",
         [type: :string, default: nil]},
        {:ir_4_12_02,
         "Інші залишкові артефакти, що залишилися в системі (якщо такі є), аналізуються після інциденту. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-4-13") do
    %{
      id: :"id-spe-ir-4-13",
      description: "",
      title: "ОБРОБКА ІНЦИДЕНТУ - АНАЛІЗ ПОВЕДІНКИ (IR-4(13))",
      parameters: [
        {:ir_4_13_01,
         "Аналізується аномальна або підозрювана ворожа поведінка в середовищах або ресурсах або пов'язана з ними",
         [type: :string, default: nil]},
        {:ir_4_13_odp,
         "Визначаються середовища або ресурси, які можуть містити або можуть бути пов'язані з аномальною або підозрілою ворожою поведінкою",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-4-14") do
    %{
      id: :"id-spe-ir-4-14",
      description: "",
      title: "ОБРОБКА ІНЦИДЕНТУ - ЦЕНТР БЕЗПЕКИ (IR-4(14))",
      parameters: [
        {:ir_4_14_01,
         "Створено оперативний центр безпеки",
         [type: :string, default: nil]},
        {:ir_4_14_02,
         "Підтримується оперативний центр безпеки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-4-15") do
    %{
      id: :"id-spe-ir-4-15",
      description: "",
      title: "ОБРОБКА ІНЦИДЕНТУ - ЗВʼЯЗКИ З ГРОМАДКІСТЮ ТА ВІДНОВЛЕННЯ РЕПУТАЦІЇ (IR-4(15))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ir-5") do
    %{
      id: :"id-spe-ir-5",
      description: "",
      title: "Моніторинг інциденту (IR-5)",
      parameters: [
        {:ir_5_01,
         "Відстежуються інциденти безпеки та приватності",
         [type: :string, default: nil]},
        {:ir_5_02,
         "Документуються інциденти безпеки та приватності. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-5-1") do
    %{
      id: :"id-spe-ir-5-1",
      description: "",
      title: "МОНІТОРИНГ ІНЦИДЕНТУ - АВТОМАТИЗОВАНЕ ВІДСТЕЖЕННЯ, ЗБІР ДАНИХ І АНАЛІЗ (IR-5(1))",
      parameters: [
        {:ir_5_1_01,
         "Інциденти відстежуються за допомогою 05(01)_ODP[01] автоматизованих механізмів>",
         [type: :string, default: nil]},
        {:ir_5_1_02,
         "Інформація про інциденти збирається за допомогою автоматизованих механізмів",
         [type: :string, default: nil]},
        {:ir_5_1_03,
         "Інформація про інциденти аналізується за допомогою автоматизованих механізмів. <IR-",
         [type: :string, default: nil]},
        {:ir_5_1_odp_01,
         "Визначено автоматизовані механізми відстеження інцидентів",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ir_5_1_odp_02,
         "Визначено автоматизовані механізми збору інформації про інциденти",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ir_5_1_odp_03,
         "Визначено автоматизовані механізми аналізу інформації про інциденти",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ir-6") do
    %{
      id: :"id-spe-ir-6",
      description: "",
      title: "ЗВІТНІСТЬ ПРО ІНЦИДЕНТИ (IR-6)",
      parameters: [
        {:ir_6_a,
         "Персонал зобов'язаний повідомляти про підозрілі інциденти протягом періоду часу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_6_b,
         "Інформацію про інцидент повідомляється органам",
         [type: :string, default: nil]},
        {:ir_6_odp_01,
         "Визначено період часу, протягом якого персонал повинен повідомляти про підозрілі інциденти до уповноваженого органу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_6_odp_02,
         "Визначені органи, до яких слід повідомляти інформацію про інцидент",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-6-1") do
    %{
      id: :"id-spe-ir-6-1",
      description: "",
      title: "ЗВІТНІСТЬ ПРО ІНЦИДЕНТИ - АВТОМАТИЧНЕ ЗВІТУВАННЯ (IR-6(1))",
      parameters: [
        {:ir_6_1_01,
         "Використовуються автоматичні механізми звітування про інциденти",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ir_6_1_odp,
         "Визначені автоматичні механізми звітування про інциденти",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ir-6-3") do
    %{
      id: :"id-spe-ir-6-3",
      description: "",
      title: "ЗВІТНІСТЬ ПРО ІНЦИДЕНТИ - КООРДИНАЦІЯ ЛАНЦЮЖКА ПОСТАЧАННЯ (IR-6(3))",
      parameters: [
        {:ir_6_3_01,
         "Інформація про інцидент надається постачальнику продукту або послуги та іншим організаціям, які беруть участь у ланцюжку постачання систем або компонентів системи, пов’язаних з інцидентом",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ir-7") do
    %{
      id: :"id-spe-ir-7",
      description: "",
      title: "ПІДТРИМКА РЕАГУВАННЯ НА ІНЦИДЕНТИ (IR-7)",
      parameters: [
        {:ir_7_01,
         "Ресурс підтримки реагування на інциденти містить поради та допомогу користувачам системи для обробки та формування звітності про інциденти",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-7-1") do
    %{
      id: :"id-spe-ir-7-1",
      description: "",
      title: "ПІДТРИМКА РЕАГУВАННЯ НА ІНЦИДЕНТИ - АВТОМАТИЗАЦІЯ ПІДТРИМКИ ДЛЯ ЗАБЕЗПЕЧЕННЯ ДОСТУПНОСТІ ІНФОРМАЦІЇ ТА ПІДТРИМКИ (IR-7(1))",
      parameters: [
        {:ir_7_1_01,
         "Підвищено доступність інформації та підтримки реагування на інциденти з використанням автоматизованих механізмів",
         [type: :string, default: nil]},
        {:ir_7_1_odp,
         "Визначено автоматизовані механізми, що використовуються для збільшення доступності інформації та підтримки при реагуванні на інциденти",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ir-7-2") do
    %{
      id: :"id-spe-ir-7-2",
      description: "",
      title: "ПІДТРИМКА РЕАГУВАННЯ НА ІНЦИДЕНТИ - КООРДИНАЦІЯ З ЗОВНІШНІМИ ПОСТАЧАЛЬНИКАМИ (IR-7(2))",
      parameters: [
        {:ir_7_2_a,
         "Встановлено прямі відносини кооперації між здатністю реагування на інциденти та зовнішніми постачальниками можливостей захисту системи",
         [type: :string, default: nil]},
        {:ir_7_2_b,
         "Визначено членів команди реагування на інциденти в організації для зовнішніх постачальників послуг",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-8") do
    %{
      id: :"id-spe-ir-8",
      description: "",
      title: "План реагування на інциденти (IR-8)",
      parameters: [
        {:ir_8_a_01,
         "Розроблено план реагування на інциденти, який надає організації дорожню карту для впровадження її можливостей реагування на інциденти",
         [type: :string, default: nil]},
        {:ir_8_a_02,
         "Розроблено план реагування на інциденти, який описує структуру та організацію спроможності реагування на інциденти",
         [type: :string, default: nil]},
        {:ir_8_a_03,
         "Розроблено план реагування на інциденти, який надає високорівневий підхід до того, як здатність реагування на інциденти вписується в загальну практику організації",
         [type: :string, default: nil]},
        {:ir_8_a_04,
         "Розроблено план реагування на інциденти, який відповідає унікальним вимогам організації, які пов’язані із завданнями, розміром, структурою і функціями",
         [type: :string, default: nil]},
        {:ir_8_a_05,
         "Розроблено план реагування на інциденти, який визначає підзвітні інциденти",
         [type: :string, default: nil]},
        {:ir_8_a_06,
         "Розроблено план реагування на інциденти, який надає показники для вимірювання можливостей реагування на інциденти всередині організації",
         [type: :string, default: nil]},
        {:ir_8_a_07,
         "Розроблено план реагування на інциденти, який визначає ресурси та управлінську підтримку, необхідну для ефективної підтримки та розвитку можливостей реагування на інциденти",
         [type: :string, default: nil]},
        {:ir_8_a_08,
         "Розроблено план реагування на інциденти, який вирішує питання обміну інформацією про інциденти",
         [type: :string, default: nil]},
        {:ir_8_a_09,
         "Розроблено план реагування на інцидент, який розглядається та затверджується персоналом або ролями частота",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_8_a_10,
         "Розроблено план реагування на інциденти, в якому чітко визначено відповідальність за реагування на інциденти для організацій, персоналу або ролей",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_8_b_01,
         "Копії плану реагування на інцидент розповсюджуються серед <IR- 08_ODP[04] персоналу з реагування на інциденти>",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_8_b_02,
         "Копії плану реагування на інцидент розповсюджуються серед елементів організації",
         [type: :string, default: nil]},
        {:ir_8_c,
         "План реагування на інциденти оновлюється з урахуванням змін у системі та організації або проблем, що виникають під час впровадження, виконання або тестування плану",
         [type: :integer, default: 30]},
        {:ir_8_d_01,
         "Зміни в плані реагування на інцидент повідомляються персоналу з реагування на інциденти",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_8_d_02,
         "Зміни в плані реагування на інциденти надсилаються до елементів організації",
         [type: :string, default: nil]},
        {:ir_8_e_01,
         "План реагування на інциденти захищений від несанкціонованого розкриття",
         [type: :string, default: nil]},
        {:ir_8_e_02,
         "План реагування на інциденти захищений від несанкціонованої модифікації",
         [type: :string, default: nil]},
        {:ir_8_odp_01,
         "Визначено персонал або ролі, які переглядають та затверджують план реагування на інциденти",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_8_odp_02,
         "Визначено періодичність перегляду та затвердження плану реагування на інциденти",
         [type: :string, default: "щорічно"]},
        {:ir_8_odp_03,
         "Визначені організації, персонал або ролі, які несуть відповідальність за реагування на інциденти; IR-08_ODP[04] визначено персонал з реагування на інцидент (ідентифікований за іменами та/або за ролями), якому мають бути роздані копії плану реагування на інцидент",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_8_odp_05,
         "Визначено елементи організації, серед яких мають розповсюджені копії плану реагування на інцидент; бути",
         [type: :string, default: nil]},
        {:ir_8_odp_06,
         "Визначено персонал з реагування на інцидент (ідентифікований за іменами та/або ролями), якому повідомляються зміни до плану реагування на інцидент",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_8_odp_07,
         "Визначено елементи організації, яким повідомляється про зміни в плані реагування на інцидент",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ir-8-1") do
    %{
      id: :"id-spe-ir-8-1",
      description: "",
      title: "ПЛАН РЕАГУВАННЯ НА ІНЦИДЕНТИ - ОБРОБКА ПЕРСОНАЛЬНИХ ДАНИХ (IR-8(1))",
      parameters: [
        {:ir_8_1_a,
         "План реагування на інциденти для інцидентів, пов’язаних з персональними даними, включає процес визначення доцільності повідомлення наглядових організацій і надання такого повідомлення, якщо це доречно",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_8_1_b,
         "План реагування на інциденти для інцидентів, пов’язаних з персональними даними, включає процес оцінювання для визначення ступеня шкоди, труднощів, незручностей або несправедливості щодо постраждалих осіб та будь-які механізми пом’якшення такої шкоди",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_8_1_c,
         "План реагування на інциденти для інцидентів, пов’язаних з персональними даними, включає ідентифікацію застосовних вимог щодо конфіденційності. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ir-9") do
    %{
      id: :"id-spe-ir-9",
      description: "",
      title: "РЕАГУВАННЯ НА ВИТІК ІНФОРМАЦІЇ (IR-9)",
      parameters: [
        {:ir_9_a,
         "Персонал або ролі призначено відповідальним за реагування на витоки інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_9_b,
         "У відповідь на витік інформації визначається конкретна інформація, пов’язана з джерелом витоку в системі",
         [type: :string, default: nil]},
        {:ir_9_c,
         "Персонал або ролі попереджається про витік інформації за допомогою методу зв'язку, не пов'язаного з витоком",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_9_d,
         "Ізоляцюється система або компонент системи де відбувся витік інформації",
         [type: :string, default: nil]},
        {:ir_9_e,
         "Інформація видаляється із зараженої системи або компонента у відповідь на витік інформації",
         [type: :string, default: nil]},
        {:ir_9_f,
         "У відповідь на витік інформації визначаються інші системи або компоненти системи, які могли бути згодом джерелом витоку інформації",
         [type: :string, default: nil]},
        {:ir_9_g,
         "Дії виконуються у відповідь на витік інформації",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ir_9_odp_01,
         "Визначено персонал або ролі, на які покладено відповідальність за реагування на витоки інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_9_odp_02,
         "Визначено персонал або ролі, які мають бути сповіщені про витік інформації за допомогою методу зв'язку, не пов'язаного з витоком",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_9_odp_03,
         "Визначені дії, які необхідно виконати",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ir-9-1") do
    %{
      id: :"id-spe-ir-9-1",
      description: "",
      title: "РЕАГУВАННЯ НА ВИТІК ІНФОРМАЦІЇ - ВІДПОВІДАЛЬНИЙ ПЕРСОНАЛ (IR-9(1))",
      parameters: [
        {:ir_9_1_01,
         "РЕАГУВАННЯ НА ВИТІК ІНФОРМАЦІЇ - ВІДПОВІДАЛЬНИЙ ПЕРСОНАЛ [Вилучено: включено до IR-09]",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ir-9-2") do
    %{
      id: :"id-spe-ir-9-2",
      description: "",
      title: "РЕАГУВАННЯ НА ВИТІК ІНФОРМАЦІЇ - ТРЕНУВАННЯ (IR-9(2))",
      parameters: [
        {:ir_9_2_01,
         "Забезпечено навчання з реагування на витік інформації частота",
         [type: :string, default: "щорічно"]},
        {:ir_9_2_odp,
         "Визначено частоту навчання з реагування на витік інформації",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ir-9-3") do
    %{
      id: :"id-spe-ir-9-3",
      description: "",
      title: "РЕАГУВАННЯ НА ВИТІК ІНФОРМАЦІЇ - РОБОТА ПІСЛЯ ВИТОКУ (IR-9(3))",
      parameters: [
        {:ir_9_3_01,
         "Реалізувано процедури, з метою забезпечення спроможності для персоналу організації, на який впливає витік інформації, продовжувати виконувати поставлені завдання, у той час, як постраждалі системи зазнають коригу- вальних дій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_9_3_odp,
         "Визначено процедури з метою забезпечення спроможності персоналу організації, на який впливає витік інформації, продовжувати виконувати поставлені завдання, у той час, як постраждалі системи зазнають коригувальних дій",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ir-9-4") do
    %{
      id: :"id-spe-ir-9-4",
      description: "",
      title: "РЕАГУВАННЯ НА ВИТІК ІНФОРМАЦІЇ - ВИКРИТТЯ НЕАВТОРИЗОВАНОГО ПЕРСОНАЛУ (IR-9(4))",
      parameters: [
        {:ir_9_4_01,
         "Застосовуються механізми захисту для персоналу, що має доступ до інформації, яка не відповідає призначеним правам доступу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ir_9_4_odp,
         "Визначено механізми захисту для персоналу, що має доступ до інформації, яка не відповідає призначеним правам доступу",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ir-10") do
    %{
      id: :"id-spe-ir-10",
      description: "",
      title: "ІНТЕГРОВАНА КОМАНДА АНАЛІЗУ ІНФОРМАЦІЙНОЇ БЕЗПЕКИ (IR-10)",
      parameters: [
        {:ir_10_01,
         "ІНТЕГРОВАНА КОМАНДА АНАЛІЗУ ІНФОРМАЦІЙНОЇ БЕЗПЕКИ [Вилучено: перенесено до IR-04(11)] IX. КЛАС ЗАХОДІВ ЗАХИСТУ MA – ТЕХНІЧНЕ ОБСЛУГОВУВАННЯ",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ma-1") do
    %{
      id: :"id-spe-ma-1",
      description: "a. Планувати, документувати та переглядати записи з технічного обслуговування, ремонту або заміни компонентів системи відповідно до вимог виробника та постачальників та/або вимог організації. b. Затвердити та здійснювати моніторинг усіх заходів з технічного обслуговування, незалежно від того, виконуються вони на місці або віддалено, а також чи обслуговуються системи або системні компоненти на місці, чи переміщуються в інше місце. c. Вимагати, щоб [Призначення: визначені організацією персонал чи ролі] явно схвалили видалення системи або компоненту системи з організаційного обладнання для технічного обслуговування, ремонту чи заміни поза об’єктами експлуатації. d. Очищати обладнання з погляду видалення всієї інформації з носіїв до вилучення обладнання організації для технічного обслуговування, ремонту чи заміни поза об’єктами експлуатації. e. Перевірити всі потенційно порушені заходи захисту, щоб переконатися, що вони, як і раніше, працюють належним чином після дій з обслуговування, ремонту або заміни. f. Вносити [Призначення: визначену організацією інформацію, пов’язану з технічним обслуговуванням] до записів з технічного обслуговування.",
      title: "ПОЛІТИКА ТА ПРОЦЕДУРИ ТЕХНІЧНОГО ОБСЛУГОВУВАННЯ (MA-1)",
      parameters: [
        {:ma_1_a_01,
         "Розроблено та задокументовано політику технічного обслуговування",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ma_1_a_02,
         "Політика технічного обслуговування поширюється на персонал або ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_1_a_03,
         "Розроблені та задокументовані процедури технічного обслуговування, що сприяють впровадженню політики технічного обслуговування та пов'язаних з нею заходів технічного обслуговування",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ma_1_b,
         "Посадова особа призначається для управління розробкою, документуванням та розповсюдженням політики та процедур технічного обслуговування; MA-01(c)[01][01] переглядається та оновлюється поточна політика обслуговування частота; MA-01(c)[01][02] переглядається та оновлюється поточна політика обслуговування після подій; MA-01(c)[02][01] переглядаються та оновлюються поточні процедури технічного обслуговування частота; MA-01(c)[02][02] переглядаються та оновлюються поточні процедури технічного обслуговування після подій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_1_odp_01,
         "Визначено персонал або ролі, на які поширюється політика технічного обслуговування",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_1_odp_02,
         "Визначено персонал або ролі, на які поширюються процедури технічного обслуговування",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнес-процесу; рівень системи}",
         [type: :string, default: nil]},
        {:ma_1_odp_04,
         "Визначено посадову особу, яка керуватиме політикою та процедурами технічного обслуговування",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_1_odp_05,
         "Визначено частоту, з якою переглядається та оновлюється поточна політика технічного обслуговування",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ma_1_odp_06,
         "Визначено події, які потребують перегляду та оновлення поточної політики технічного обслуговування",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ma_1_odp_07,
         "Визначено частоту, з якою переглядаються та оновлюються поточні процедури технічного обслуговування",
         [type: :integer, default: 30]},
        {:ma_1_odp_08,
         "Визначено події, які потребують перегляду та оновлення процедур технічного обслуговування",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ma-2-1") do
    %{
      id: :"id-spe-ma-2-1",
      description: "",
      title: "КОНТРОЛЬОВАНЕ ОБСЛУГОВУВАННЯ - ЗМІСТ ЗАПИСУ (MA-2(1))",
      parameters: [
        {:ma_2_1_01,
         "КОНТРОЛЬОВАНЕ ОБСЛУГОВУВАННЯ - ЗМІСТ ЗАПИСУ [Вилучено: Включено до МА-02]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ma-2-2") do
    %{
      id: :"id-spe-ma-2-2",
      description: "",
      title: "КОНТРОЛЬОВАНЕ ОБСЛУГОВУВАННЯ - АВТОМАТИЗОВАНА ТЕХНІЧНА ДІЯЛЬНІСТЬ (MA-2(2))",
      parameters: [
        {:ma_2_2_a_01,
         "Автоматизовані механізми використовуються для планування дій з технічного обслуговування, ремонту та заміни системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ma_2_2_a_02,
         "Автоматизовані механізми використовуються для проведення дій з технічного обслуговування, ремонту та заміни системи; MA-02(02)(a)[03] автоматизовані механізми використовуються для документування дій з технічного обслуговування, ремонту та заміни системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ma_2_2_b_01,
         "Надаються актуальні, точні та повні записи про всі замовлені, заплановані, виконувані та завершені дії з технічного обслуговування",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ma_2_2_b_02,
         "Надаються актуальні, точні та повні записи про всі замовлені, заплановані, виконувані та завершені дії ремонту",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ma_2_2_b_03,
         "Надаються актуальні, точні та повні записи про всі замовлені, заплановані, виконувані та завершені дії з заміни",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ma_2_2_odp_01,
         "Визначено автоматизовані механізми, що використовуються для планування дій з технічного обслуговування, ремонту та заміни системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ma_2_2_odp_02,
         "Визначено автоматизовані механізми, що використовуються для проведення дій з технічного обслуговування, ремонту та заміни системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ma_2_2_odp_03,
         "Визначено автоматизовані механізми, що використовуються для документування дій з технічного обслуговування, ремонту та заміни системи",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ma-3") do
    %{
      id: :"id-spe-ma-3",
      description: "a. Затвердити, контролювати та відстежувати використання засобів технічного обслуговування. b. Переглядати раніше затверджені інструменти технічного [Призначення: з частотою, визначеною організацією]. обслуговування",
      title: "ІНСТРУМЕНТИ ДЛЯ ОБСЛУГОВУВАННЯ (MA-3)",
      parameters: [
        {:ma_3_a_01,
         "Використання засобів технічного обслуговування затверджено",
         [type: :string, default: nil]},
        {:ma_3_a_02,
         "Використання засобів технічного обслуговування контролюється",
         [type: :string, default: nil]},
        {:ma_3_a_03,
         "Використання засобів технічного обслуговування відстажуються",
         [type: :string, default: nil]},
        {:ma_3_b,
         "Переглядаються раніше затверджені інструменти технічного обслуговування частота",
         [type: :string, default: "щорічно"]},
        {:ma_3_odp,
         "Визначено частоту, з якою слід переглядати раніше затверджені інструменти технічного обслуговування",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ma-3-1") do
    %{
      id: :"id-spe-ma-3-1",
      description: "",
      title: "ІНСТРУМЕНТИ ДЛЯ ОБСЛУГОВУВАННЯ - ПЕРЕВІРКА ІНСТРУМЕНТІВ (MA-3(1))",
      parameters: [
        {:ma_3_1_01,
         "Оглядаються інструменти для технічного обслуговування, які доставлені на об'єкт обслуговуючим персоналом, на предмет неправильних або несанкціонованих модифікацій",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ma-3-2") do
    %{
      id: :"id-spe-ma-3-2",
      description: "Перед використанням носіїв у системі перевірити носії, що містять діагностичні та тестові програми на наявність шкідливого коду.",
      title: "ІНСТРУМЕНТИ ДЛЯ ОБСЛУГОВУВАННЯ - ПЕРЕВІРКА НОСІЇВ ІНФОРМАЦІЇ (MA-3(2))",
      parameters: [
        {:ma_3_2_01,
         "Перед використанням носіїв у системі перевіряються носії, що містять діагностичні та тестові програми на наявність шкідливого коду",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ma-3-3") do
    %{
      id: :"id-spe-ma-3-3",
      description: "Запобігти переміщенню обладнання для технічного обслуговування, що містить організаційну інформацію, шляхом: (a) перевірки відсутності організаційної інформації, розміщеної на обладнанні; (b) очищення або знищення обладнання; (c) утримання обладнання на об’єкті; (d) отримання дозволу від [Призначення: визначених організацією персоналу чи ролей], які явно дозволяють переміщення обладнання з об’єкта.",
      title: "ІНСТРУМЕНТИ ДЛЯ ОБСЛУГОВУВАННЯ - ЗАПОБІГАННЯ НЕСАНКЦІОНОВАНОМУ ПЕРЕМІЩЕННЮ (MA-3(3))",
      parameters: [
        {:ma_3_3_a,
         "Переміщення обладнання для технічного обслуговування, що містить інформацію організації, запобігається шляхом перевірки того, що на обладнанні не міститься ніякої інформації організації; або",
         [type: :string, default: nil]},
        {:ma_3_3_b,
         "Переміщення обладнання для технічного обслуговування, що містить інформацію організації, запобігається шляхом очищення або знищення обладнання; або",
         [type: :string, default: nil]},
        {:ma_3_3_c,
         "Переміщення обладнання для технічного обслуговування, що містить інформацію організації, запобігається шляхом утримання обладнання на об'єкті; або",
         [type: :string, default: nil]},
        {:ma_3_3_d,
         "Переміщення обладнання для технічного обслуговування, що містить інформацію організації, запобігається шляхом отримання дозволу від персонал або ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_3_3_odp,
         "Визначено персонал або ролі, які можуть надавати дозвіл на переміщення обладнання з об'єкту",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ma-3-4") do
    %{
      id: :"id-spe-ma-3-4",
      description: "Обмежити використання інструментів авторизованим персоналом. - технічного ОБМЕЖЕННЯ обслуговування лише",
      title: "ІНСТРУМЕНТИ ДЛЯ ОБСЛУГОВУВАННЯ - ОБМЕЖЕННЯ ВИКОРИСТАННЯ ІНСТРУМЕНТА (MA-3(4))",
      parameters: [
        {:ma_3_4_01,
         "Обмежено використання інструментів технічного обслуговування лише авторизованим персоналом",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ma-3-5") do
    %{
      id: :"id-spe-ma-3-5",
      description: "(a) вимагати схвалення кожного віддаленого сеансу технічного обслуговування [Призначення: персоналом або роллю, що визначила організація]; (b) повідомити [Призначення: персонал або ролі, що визначила організація] про дату та час запланованого віддаленого обслуговування.",
      title: "ІНСТРУМЕНТИ ДЛЯ ОБСЛУГОВУВАННЯ - ПРИВІЛЕЙОВАНЕ ВИКОНАННЯ (MA-3(5))",
      parameters: [
        {:ma_3_5_01,
         "Відстежується використання інструментів обслуговування, які виконуються з підвищеними привілеями",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ma-3-6") do
    %{
      id: :"id-spe-ma-3-6",
      description: "Запровадити криптографічні механізми для захисту цілісності та конфіденційності віддаленого обслуговування та діагностичних комунікацій.",
      title: "ІНСТРУМЕНТИ ДЛЯ ОБСЛУГОВУВАННЯ - ОНОВЛЕННЯ ПРОГРАМ- (MA-3(6))",
      parameters: [
        {:ma_3_6_01,
         "Інструменти технічного обслуговування перевіряються, щоб переконатися, що встановлені найновіші оновлення програмного забезпечення та патчі",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ma-4") do
    %{
      id: :"id-spe-ma-4",
      description: "",
      title: "ВІДДАЛЕНЕ ОБСЛУГОВУВАННЯ (MA-4)",
      parameters: [
        {:ma_4_a_01,
         "Впроваджено віддалені дії з обслуговування та діагностики",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ma_4_a_02,
         "Відстежуються віддалені дії з обслуговування та діагностики",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ma_4_b_01,
         "Використання віддалених засобів технічного обслуговування та діагностики дозволено лише відповідно до політики організації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ma_4_b_02,
         "Використання віддалених засобів технічного обслуговування та діагностики задокументовано в плані захисту інформації",
         [type: :string, default: nil]},
        {:ma_4_c,
         "Надійна автентифікація використовується при встановленні віддалених технічних та діагностичних сеансів",
         [type: :string, default: nil]},
        {:ma_4_d,
         "Ведеться облік віддалених дій з обслуговування та діагностики",
         [type: :string, default: nil]},
        {:ma_4_e_01,
         "Сесія припиняється, коли завершено віддалене обслуговування",
         [type: :string, default: nil]},
        {:ma_4_e_02,
         "Мережеве з’єднання припиняється, коли завершено віддалене обслуговування",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ma-4-1") do
    %{
      id: :"id-spe-ma-4-1",
      description: "",
      title: "ВІДДАЛЕНЕ ОБСЛУГОВУВАННЯ - АУДИТ ТА ОГЛЯД (MA-4(1))",
      parameters: [
        {:ma_4_1_a_01,
         "Події аудиту журналюються для віддалених сеансів обслуговування",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ma_4_1_a_02,
         "Події аудиту журналюються для віддалених сеансів діагностики",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ma_4_1_b_01,
         "Здійснюється огляд записів про сеанси віддаленого обслуговування",
         [type: :string, default: nil]},
        {:ma_4_1_b_02,
         "Здійснюється огляд записів про сеанси віддаленої діагностики",
         [type: :string, default: nil]},
        {:ma_4_1_odp_01,
         "Визначено події аудиту, які слід журналювати для віддалених сеансів обслуговування",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ma_4_1_odp_02,
         "Визначено події аудиту, які слід журналювати для віддалених сеансів діагностики",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ma-4-2") do
    %{
      id: :"id-spe-ma-4-2",
      description: "",
      title: "ВІДДАЛЕНЕ ОБСЛУГОВУВАННЯ - ДОКУМЕНТУВАННЯ ВІДДАЛЕНОГО ОБСЛУГОВУВАННЯ (MA-4(2))",
      parameters: [
        {:ma_4_2_01,
         "ВІДДАЛЕНЕ ОБСЛУГОВУВАННЯ - ДОКУМЕНТУВАННЯ ВІДДАЛЕНОГО ОБСЛУГОВУВАННЯ [Вилучено: включено до MA-01 та МА-04]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ma-4-3") do
    %{
      id: :"id-spe-ma-4-3",
      description: "",
      title: "ВІДДАЛЕНЕ ОБСЛУГОВУВАННЯ - ПОРІВНЯЛЬНА БЕЗПЕКА І ОЧИЩЕННЯ (MA-4(3))",
      parameters: [
        {:ma_4_3_a_01,
         "Віддалені послуги з технічного обслуговування повинні виконуватися з системи, яка реалізує заходи захисту, співставні з заходами захисту, реалізованими в системі, що обслуговується",
         [type: :string, default: nil]},
        {:ma_4_3_a_02,
         "Віддалені послуги з діагностики повинні виконуватися з системи, яка реалізує заходи захисту, співставні з заходами захисту, реалізованими в системі, що обслуговується",
         [type: :string, default: nil]},
        {:ma_4_3_b_01,
         "Компонент, що підлягає обслуговуванню, видаляється з системи перед проведенням віддаленого технічного обслуговування або діагностики",
         [type: :string, default: nil]},
        {:ma_4_3_b_02,
         "Компонент, що підлягає обслуговуванню, пройшов процедуру очищення (від інф ормації організації)",
         [type: :string, default: nil]},
        {:ma_4_3_b_03,
         "Компонент перевіряється та очищується (на наявність потенційно шкідливого програмного забезпечення) після виконання послуги та перед повторним підключенням компонента до системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ma-4-5") do
    %{
      id: :"id-spe-ma-4-5",
      description: "",
      title: "ВІДДАЛЕНЕ ОБСЛУГОВУВАННЯ - СХВАЛЕННЯ ТА ПОВІДОМЛЕННЯ (MA-4(5))",
      parameters: [
        {:ma_4_5_a,
         "Схвалення кожного віддаленого сеансу обслуговування від персонал або ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_4_5_b,
         "Персонал і ролі повідомлено про дату і час запланованого віддаленого технічного обслуговування",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_4_5_odp_01,
         "Визначено персонал або ролі, необхідні для затвердження кожного віддаленого сеансу технічного обслуговування; MA-04(05)_ODP[02] визначено персонал та ролі, які мають бути повідомлені про дату та час запланованого віддаленого технічного обслуговування",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ma-4-7") do
    %{
      id: :"id-spe-ma-4-7",
      description: "",
      title: "ВІДДАЛЕНЕ ОБСЛУГОВУВАННЯ РОЗ’ЄДНАННЯ (MA-4(7))",
      parameters: [
        {:ma_4_7_01,
         "Реалізувано перевірку роз’єднання у разі припинення віддалених сеансів обслуговування",
         [type: :string, default: nil]},
        {:ma_4_7_02,
         "Реалізувано перевірку роз’єднання у разі припинення віддалених сеансів діагностики",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ma-5") do
    %{
      id: :"id-spe-ma-5",
      description: "a. Встановити процедуру авторизації технічного персоналу та вести перелік авторизованих організацій технічного обслуговування або персоналу. b. Перевіряти, що персонал, який не супроводжується та виконує технічне обслуговування в системі, має необхідні дозволи на доступ. c. Визначити персонал організації з необхідними повноваженнями щодо доступу та технічною компетенцією для нагляду за персоналом з технічного обслуговування, який не має необхідних дозволів на доступ.",
      title: "ТЕХНІЧНИЙ ПЕРСОНАЛ (MA-5)",
      parameters: [
        {:ma_5_a_01,
         "Запроваджено процес авторизації технічного персоналу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_5_a_02,
         "Ведеться перелік авторизованих організацій або персоналу з технічного обслуговування",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_5_b,
         "Персонал без супроводу, який виконує технічне обслуговування системи, має необхідні дозволи на доступ",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_5_c,
         "Персонал організації з необхідними повноваженнями доступу та технічною компетентністю призначений/призначені для нагляду за діяльністю з технічного обслуговування персоналу, який не має необхідних дозволів на доступ",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ma-5-1") do
    %{
      id: :"id-spe-ma-5-1",
      description: "",
      title: "ТЕХНІЧНИЙ ПЕРСОНАЛ - ОСОБИ БЕЗ НАЛЕЖНОГО ДОСТУПУ (MA-5(1))",
      parameters: [
        {:ma_5_1_a_01,
         "Впроваджені процедури залучення персоналу з технічного обслуговування, який не має відповідних дозволів (допуску) або не є громадянами України, містять вимогу: обслуговуючий персонал, що не має необхідних прав доступу, рівня допуску, або офіційного затвердженого доступу,повинен супроводжуватися та бути під наглядом уповноваженого організацією персоналу, з необхідним рівнем допуску, а також мати відповідну технічну кваліфікацію для виконання технічного обслуговування та діагностичних заходів у системі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_5_1_a_02,
         "Впроваджені процедури залучення персоналу з технічного обслуговування, який не має відповідних дозволів (допуску) або не є громадянами України, містять вимогу: перед тим, як розпочати технічне обслуговування або діагностику персоналом, який не має необхідних прав допуску, рівня допуску або офіційного затвердженого доступу,упевнитися, що всі компоненти енергонезалежного зберігання інформації в системі очищуються, а всі енергонезалежні носії видаляються або фізично відключаються від системи та надійно захищаються",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_5_1_b,
         "Альтернативні заходи захисту розробляються і впроваджуються у випадку, якщо систему неможливо очистити, вилучити або відключити від систе- ми",
         [type: :string, default: nil]},
        {:ma_5_1_odp,
         "Визначені альтернативні заходи захисту, які мають бути розроблені та впроваджені на випадок, якщо компонент системи не може бути очищений, вилучений або відключений від системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ma-5-2") do
    %{
      id: :"id-spe-ma-5-2",
      description: "Переконатися, що персонал, який виконує технічне обслуговування та діагностику в системі, що обробляє, зберігає або передає інформацію з обмеженим доступом, має рівень допуску та офіційне схвалення на доступ для найвищого рівня секретності та для всієї інформації в системі.",
      title: "ТЕХНІЧНИЙ ПЕРСОНАЛ - ОФОРМЛЕННЯ ДОПУСКУ ДЛЯ СИСТЕМ, ЩО ОБРОБЛЯЮТЬ ІНФОРМАЦІЮ З ОБМЕЖЕНИМ ДОСТУПОМ (MA-5(2))",
      parameters: [
        {:ma_5_2_01,
         "Персонал, який виконує роботи з технічного обслуговування та діагностики в системі, що обробляє, зберігає або передає інформацію з обмеженим доступом, має відповідний рівень допуску",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ma_5_2_02,
         "Персонал, який виконує роботи з технічного обслуговування та діагностики в системі, що обробляє, зберігає або передає інформацію з обмеженим доступом, має офіційне схвалення на допуск",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ma-5-3") do
    %{
      id: :"id-spe-ma-5-3",
      description: "Переконатися, що працівники, які виконують технічне обслуговування та діагностичні заходи з обробки, зберігання або передачі таємної інформації, є громадянами України.",
      title: "ТЕХНІЧНИЙ ПЕРСОНАЛ - ВИМОГИ ДО ГРОМАДЯНСТВА (MA-5(3))",
      parameters: [
        {:ma_5_3_01,
         "Працівники, які виконують технічне обслуговування та діагностичні заходи з обробки, зберігання або передачі інформації з обмеженим доступом, є громадянами України",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ma-5-4") do
    %{
      id: :"id-spe-ma-5-4",
      description: "Переконайтеся, що: (a) іноземні громадяни з відповідним рівнем допуску залучаються для проведення технічного обслуговування та діагностичних робіт у системах, що обробляють інформацію з обмеженим доступом тільки тоді, коли ці системи спільно належать і експлуатуються урядами України та закордонних союзників, або належать та експлуатуються виключно іноземними союзними урядами; (b) схвалення, згоди та додаткові умови експлуатації, що стосуються залучення іноземних громадян для проведення робіт з технічного обслуговування та діагностики систем, що обробляють інформацію з обмеженим доступом, повністю задокументовані в Меморандумі про угоду.",
      title: "ТЕХНІЧНИЙ ПЕРСОНАЛ - ІНОЗЕМНІ ГРОМАДЯНИ (MA-5(4))",
      parameters: [
        {:ma_5_4_a,
         "Іноземні громадяни з відповідним рівнем допуску залучаються для проведення технічного обслуговування та діагностичних робіт у системах, що обробляють інформацію з обмеженим доступом тільки тоді, коли ці системи спільно належать і експлуатуються урядами України та закордонних союзників, або належать та експлуатуються виключно іноземними союзними урядами",
         [type: :string, default: nil]},
        {:ma_5_4_b_01,
         "Схвалення, що стосуються залучення іноземних громадян для проведення робіт з технічного обслуговування та діагностики систем, що обробляють інформацію з обмеженим доступом, повністю задокументовані в Меморандумі про угоду",
         [type: :string, default: nil]},
        {:ma_5_4_b_02,
         "Згоди, що стосуються залучення іноземних громадян для проведення робіт з технічного обслуговування та діагностики систем, що обробляють інформацію з обмеженим доступом, повністю задокументовані в Меморандумі про угоду",
         [type: :string, default: nil]},
        {:ma_5_4_b_03,
         "Додаткові умови експлуатації, що стосуються залучення іноземних громадян для проведення робіт з технічного обслуговування та діагностики систем, що обробляють інформацію з обмеженим доступом, повністю задокументовані в Меморандумі про угоду",
         [type: :list, default: []]}
      ]
    }
  end

  def spec(:"id-spe-ma-5-5") do
    %{
      id: :"id-spe-ma-5-5",
      description: "Переконатися, що персонал, який не супроводжується та здійснює ремонтні роботи, не пов’язаний безпосередньо із системою, але перебуває фізично близько від системи, має необхідні дозволи на доступ.",
      title: "ТЕХНІЧНИЙ ПЕРСОНАЛ - НЕСИСТЕМНЕ ОБСЛУГОВУВАННЯ (MA-5(5))",
      parameters: [
        {:ma_5_5_01,
         "Персонал, який не супроводжується, що здійснює ремонтні роботи, не пов'язаний безпосередньо з системою, але знаходиться фізично близько від системи, має необхідні дозволи на доступ",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ma-6") do
    %{
      id: :"id-spe-ma-6",
      description: "Отримати технічну підтримку та/або запасні частини для [Призначення: визначених організацією компонентів системи] в межах [Призначення: визначеного організацією періоду часу] у разі відмови.",
      title: "СВОЄЧАСНЕ ОБСЛУГОВУВАННЯ (MA-6)",
      parameters: [
        {:ma_6_01,
         "Технічна підтримка та/або запасні частини отримуються для компонентів системи протягом періоду часу після відмови. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :integer, default: 30]},
        {:ma_6_odp_01,
         "Визначено компоненти системи, для яких отримується технічна підтримка та/або запасні частини",
         [type: :integer, default: 30]},
        {:ma_6_odp_02,
         "Визначено період часу, протягом якого можна отримати технічну підтримку та/або запасні частини у разі відмови",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ma-6-1") do
    %{
      id: :"id-spe-ma-6-1",
      description: "",
      title: "СВОЄЧАСНЕ ОБСЛУГОВУВАННЯ - ПРОФІЛАКТИЧНЕ ОБСЛУГОВУВАННЯ (MA-6(1))",
      parameters: [
        {:ma_6_1_01,
         "Здійснюється профілактичне обслуговування 06(01)_ODP[01] компонентів системи> у 06(01)_ODP[02] часові інтервали>. <MA<MA-",
         [type: :integer, default: 30]},
        {:ma_6_1_odp_01,
         "Визначено компоненти системи яким необхідно здійснювати профілактичне обслуговування",
         [type: :string, default: nil]},
        {:ma_6_1_odp_02,
         "Визначено часові інтервали з якими необхідно здійснювати профілактичне обслуговування визначеним компонентам системи",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ma-6-2") do
    %{
      id: :"id-spe-ma-6-2",
      description: "Здійснювати планове технічне обслуговування [Призначення: визначених організацією компонентів системи] у [Призначення: визначені організацією часові інтервали].",
      title: "СВОЄЧАСНЕ ОБСЛУГОВУВАННЯ - ПЛАНОВЕ ТЕХНІЧНЕ ОБСЛУГОВУВАННЯ (MA-6(2))",
      parameters: [
        {:ma_6_2_01,
         "Здійснюється планове технічне обслуговування компонентів системи у часові інтервали",
         [type: :integer, default: 30]},
        {:ma_6_2_odp_02,
         "Визначено часові інтервали з якими необхідно здійснювати планове технічне обслуговування",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ma-6-3") do
    %{
      id: :"id-spe-ma-6-3",
      description: "Використовувати автоматизовані механізми для передачі даних планового технічного обслуговування до комп’ютеризованої системи управління обслуговуванням [Призначення: автоматизовані засоби визначені організацією].",
      title: "СВОЄЧАСНЕ ОБСЛУГОВУВАННЯ - АВТОМАТИЗОВАНА ПІДТРИМКА ПЛАНОВОГО ТЕХНІЧНОГО ОБСЛУГОВУВАННЯ (MA-6(3))",
      parameters: [
        {:ma_6_3_01,
         "Використовуються автоматизовані механізми для передачі даних планового технічного обслуговування до комп'ютеризованої системи управління обслуговуванням",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ma_6_3_odp,
         "Визначено автоматизовані механізми для передачі даних планового технічного обслуговування до комп'ютеризованої системи управління обслуговуванням",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ma-7") do
    %{
      id: :"id-spe-ma-7",
      description: "",
      title: "ТЕХНІЧНЕ ОБСЛУГОВУВАННЯ В ПОЛЬОВИХ УМОВАХ (MA-7)",
      parameters: [
        {:ma_7_01,
         "Технічне обслуговування в польових умовах систем або компонентів системи обмежене або заборонене для довірених засобів технічного обслуговування",
         [type: :string, default: nil]},
        {:ma_7_odp_01,
         "Визначені системи або компоненти системи, на яких технічне обслуговування в польових умовах обмежене або заборонене",
         [type: :string, default: nil]},
        {:ma_7_odp_02,
         "Визначено довірені засоби технічного обслуговуваннятехнічного обслуговування",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-mp-1") do
    %{
      id: :"id-spe-mp-1",
      description: "a. Розробити, задокументувати та поширити серед [Призначення: визначеного організацією персоналу або посад]: 1. 2. політику захисту носіїв інформації, яка: (a) містить мету, сферу застосування, ролі, обов’язки, відповідальність керівництва, координацію між організаційними підрозділами та систему контролю відповідності (complaince); (b) відповідає чинному законодавству, виконавчим наказам, директивам, нормам, політикам, стандартам та керівним принципам; процедури, які сприяють здійсненню політики та заходів захисту носіїв інформації. b. Призначити [Призначення: визначену організацією посадову особу] для управління розробкою, документування, та розповсюдження політики та процедурами захисту носіїв інформації. c. Переглядати та оновлювати чинну систему захисту носіїв інформації: 1. поточну політику захисту носіїв інформації [Призначення: з визначеною організацією частотою]; 2. поточні процедури захисту носіїв інформації [Призначення: з визначеною організацією частотою].",
      title: "ПОЛІТИКА ТА ПРОЦЕДУРИ ЩОДО ЗАХИСТУ НОСІЇВ ІНФОРМАЦІЇ (MP-1)",
      parameters: [
        {:mp_1_a_01,
         "Розроблено та задокументовано політику захисту носіїв інформації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:mp_1_a_02,
         "Політика захисту носіїв інформації поширюється на персонал або ролі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:mp_1_a_03,
         "Розроблено та задокументовано процедури захисту носіїв інформації, що сприятимуть реалізації політики захисту носіїв інформації та заходів захисту носіїв інформації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:mp_1_b,
         "Посадова особа призначається для управління розробкою, документуванням та розповсюдженням політики та процедур захисту носіїв інформації. MP-01(c)[01][01] переглядається та оновлюється поточна політика захисту носіїв інформації частота; MP-01(c)[01][02] переглядається та оновлюється поточна політика захисту носіїв інформації після подій; MP-01(c)[02][01] переглядаються та оновлюються поточні процедури захисту носіїв інформації частота; MP-01(c)[02][02] переглядаються та оновлюються поточні процедури захисту носіїв інформації після подій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:mp_1_odp_01,
         "Визначено персонал або ролі, серед яких має бути поширена політика захисту носіїв інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:mp_1_odp_02,
         "Визначено персонал або ролі, серед яких мають бути поширені процедури захисту носіїв інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:mp_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнес-процесу; рівень системи}",
         [type: :string, default: nil]},
        {:mp_1_odp_04,
         "Визначено посадову особу, яка керуватиме політикою та процедурами захисту носіїв інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:mp_1_odp_05,
         "Визначено частоту, з якою переглядається та оновлюється поточна політика захисту носіїв інформації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:mp_1_odp_06,
         "Визначено події, які потребують перегляду та оновлення чинної політики захисту носіїв інформації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:mp_1_odp_07,
         "Визначено частоту, з якою переглядаються та оновлюються чинні процедури захисту носіїв інформації",
         [type: :integer, default: 30]},
        {:mp_1_odp_08,
         "Визначено події, які потребують перегляду та оновлення процедур захисту носіїв інформації",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-mp-2") do
    %{
      id: :"id-spe-mp-2",
      description: "Обмежити доступ до [Призначення: визначених організацією типів цифрових та/або нецифрових носіїв інформації] [Призначення: визначеним організацією персоналом або ролями].",
      title: "ДОСТУП ДО НОСІЇВ ІНФОРМАЦІЇ (MP-2)",
      parameters: [
        {:mp_2_01,
         "Доступ до типів цифрових носіїв інформації обмежено для персоналу або ролей",
         [type: :list, default: ["admin", "security_officer"]]},
        {:mp_2_02,
         "Доступ до типів нецифрових носіїв інформації обмежено для персоналу або ролей",
         [type: :list, default: ["admin", "security_officer"]]},
        {:mp_2_odp_01,
         "Визначено типи цифрових носіїв інформації, доступ до яких обмежено",
         [type: :string, default: nil]},
        {:mp_2_odp_02,
         "Визначено персонал або ролі, уповноважені на доступ до цифрових носіїв інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:mp_2_odp_03,
         "Визначено типи нецифрових носіїв інформації, доступ до яких обмежено",
         [type: :string, default: nil]},
        {:mp_2_odp_04,
         "Визначено персонал або ролі, уповноважені на доступ до нецифрових носіїв інформації",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-mp-2-1") do
    %{
      id: :"id-spe-mp-2-1",
      description: "",
      title: "ДОСТУП ДО НОСІЇВ ІНФОРМАЦІЇ - АВТОМАТИЗОВАНИЙ ОБМЕЖЕННИЙ ДОСТУП (MP-2(1))",
      parameters: [
        {:mp_2_1_01,
         "ДОСТУП ДО НОСІЇВ ІНФОРМАЦІЇ - АВТОМАТИЗОВАНИЙ ОБМЕЖЕННИЙ ДОСТУП [Вилучено: Включено до MP-04(02)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-2-2") do
    %{
      id: :"id-spe-mp-2-2",
      description: "",
      title: "ДОСТУП ДО НОСІЇВ ІНФОРМАЦІЇ - КРИПТОГРАФІЧНИЙ ЗАХИСТ (MP-2(2))",
      parameters: [
        {:mp_2_2_01,
         "ДОСТУП ДО НОСІЇВ ІНФОРМАЦІЇ - КРИПТОГРАФІЧНИЙ ЗАХИСТ [Вилучено: Включено до SC-28(01)]",
         [type: :string, default: "AES-256-GCM"]}
      ]
    }
  end

  def spec(:"id-spe-mp-3") do
    %{
      id: :"id-spe-mp-3",
      description: "a. Наносити на носії інформації маркування, що вказують на обмеження поширення, обробки, а також застереження та відповідні мітки безпеки (якщо такі є) інформації. b. Звільнити [Призначення: визначені організацією типи носіїв системи] від маркування, якщо носії залишаються в межах [Призначення: визначених організацією контрольованих зон].",
      title: "МАРКУВАННЯ НОСІЇВ ІНФОРМАЦІЇ (MP-3)",
      parameters: [
        {:mp_3_01,
         "МАРКУВАННЯ НОСІЇВ ІНФОРМАЦІЇ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:mp_3_a,
         "Носії інформації маркуються, щоб вказати на обмеження поширення, обробки, а також застереження та відповідні мітки безпеки (якщо такі є) інформації",
         [type: :string, default: nil]},
        {:mp_3_b,
         "Типи носіїв інформації залишаються в межах контрольованих зон",
         [type: :string, default: nil]},
        {:mp_3_odp_01,
         "Визначено типи носіїв інформації, які звільняються від маркування під час перебування на контрольованих зонах",
         [type: :integer, default: 30]},
        {:mp_3_odp_02,
         "Визначено контрольовані зони, де носії інформації звільняються від маркування",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-4") do
    %{
      id: :"id-spe-mp-4",
      description: "a. Фізично контролювати та безпечно зберігати [Призначення: визначені організацією типи цифрових та/або нецифрових носіїв інформації] в межах [Призначення: визначених організацією контрольованих зон]. b. Захищати системні носії, які визначені в МР-4 до того часу, як носії знищуються або очищаються, з використанням затвердженого обладнання, методів та процедур.",
      title: "ЗБЕРІГАННЯ НОСІЇВ ІНФОРМАЦІЇ (MP-4)",
      parameters: [
        {:mp_4_a_01,
         "Типи цифрових носіїв контролюються фізично",
         [type: :string, default: nil]},
        {:mp_4_a_02,
         "Типи нецифрових носіїв контролюються фізично",
         [type: :string, default: nil]},
        {:mp_4_a_03,
         "Типи цифрових носіїв безпечно зберігаються в контрольованих зонах",
         [type: :string, default: nil]},
        {:mp_4_a_04,
         "Типи нецифрових носіїв безпечно зберігаються в контрольованих зонах",
         [type: :string, default: nil]},
        {:mp_4_b,
         "Типи носіїв інформації (визначені в MP-04_ODP[01], MP04_ODP[02], MP-04_ODP[03], MP-04_ODP[04]) захищені доти, доки носії інформації не будуть знищені або очищені за допомогою визначеного обладнання, методик та процедур",
         [type: :string, default: nil]},
        {:mp_4_odp_01,
         "Визначено типи цифрових носіїв інформації, які підлягають фізичному контролю (якщо вибрано)",
         [type: :string, default: nil]},
        {:mp_4_odp_02,
         "Визначено типи нецифрових носіїв інформації, які підлягають фізичному контролю (якщо вибрано)",
         [type: :string, default: nil]},
        {:mp_4_odp_03,
         "Визначено типи цифрових носіїв інформації для безпечного зберігання (якщо вибрано)",
         [type: :string, default: nil]},
        {:mp_4_odp_04,
         "Визначено типи нецифрових носіїв інформації для безпечного зберігання (якщо вибрано)",
         [type: :string, default: nil]},
        {:mp_4_odp_05,
         "Визначено контрольовані зони, в яких можна безпечно зберігати цифрові носії інформації; MP-04_ODP[06] визначено контрольовані зони, в яких можна безпечно зберігати нецифрові носії інформації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-4-1") do
    %{
      id: :"id-spe-mp-4-1",
      description: "",
      title: "ЗБЕРІГАННЯ НОСІЇВ ІНФОРМАЦІЇ - КРИПТОГРАФІЧНИЙ ЗАХИСТ (MP-4(1))",
      parameters: [
        {:mp_4_1_01,
         "ЗБЕРІГАННЯ НОСІЇВ ІНФОРМАЦІЇ - КРИПТОГРАФІЧНИЙ ЗАХИСТ [Вилучено: Включено до SC-28(01)]",
         [type: :string, default: "AES-256-GCM"]}
      ]
    }
  end

  def spec(:"id-spe-mp-4-2") do
    %{
      id: :"id-spe-mp-4-2",
      description: "",
      title: "ЗБЕРІГАННЯ НОСІЇВ ІНФОРМАЦІЇ - АВТОМАТИЗОВАНИЙ ОБМЕЖЕНИЙ ДОСТУП (MP-4(2))",
      parameters: [
        {:mp_4_2_01,
         "Доступ до зон зберігання носіїв інформації обмежено за допомогою автоматизованих механізмів",
         [type: :string, default: nil]},
        {:mp_4_2_02,
         "Спроби доступу до зон зберігання носіїв інформації реєструються за допомогою автоматизованих механізмів",
         [type: :integer, default: 3]},
        {:mp_4_2_03,
         "Доступ, наданий до зон зберігання носіїв, реєструється за допомогою автоматизованих механізмів",
         [type: :string, default: nil]},
        {:mp_4_2_odp_01,
         "Визначено автоматизовані механізми обмеження доступу до зон зберігання носіїв інформації",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:mp_4_2_odp_02,
         "Визначено автоматизовані механізми реєстрації спроб доступу до зон зберігання носіїв інформації; MP-04(02)_ODP[03] визначено автоматизовані механізми реєстрації доступу, наданого до зон зберігання носіїв інформації",
         [type: :integer, default: 3]}
      ]
    }
  end

  def spec(:"id-spe-mp-5") do
    %{
      id: :"id-spe-mp-5",
      description: "a. Захищати та контролювати [Призначення: визначені організацією типи носіїв системи] під час транспортування за межами контрольованих зон, використовуючи [Призначення: визначені організацією заходи безпеки]. b. Вести облік носіїв системи інформації під час транспортування за межами контрольованих зон. c. Документувати дії, пов’язані з транспортуванням носіїв системи. d. Обмежити діяльність уповноваженого персоналу, пов’язану з транспортуванням носіїв системи.",
      title: "Транспортування носіїв інформації (MP-5)",
      parameters: [
        {:mp_5_a_01,
         "Типи носіїв інформації системи захищаються під час транспортування за межі контрольованих зон за допомогою заходів безпеки",
         [type: :integer, default: 30]},
        {:mp_5_a_02,
         "Типи носіїв інформації системи контролюються під час транспортування за межі контрольованих зон за допомогою заходів безпеки",
         [type: :integer, default: 30]},
        {:mp_5_b,
         "Під час транспортування за межі контрольованих зон ведеться облік носіїв інформації системи",
         [type: :integer, default: 30]},
        {:mp_5_c,
         "Діяльність, пов'язана з транспортуванням носіїв інформації системи, задокументована",
         [type: :string, default: nil]},
        {:mp_5_d_01,
         "Визначено персонал, уповноважений здійснювати діяльність з транспортування носіїв інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:mp_5_d_02,
         "Діяльність, пов'язана з транспортуванням носіїв інформації системи, обмежується визначеним уповноваженим персоналом",
         [type: :list, default: ["admin", "security_officer"]]},
        {:mp_5_odp_01,
         "Визначено типи носіїв інформації системи для захисту та контролю під час транспортування за межі контрольованих зон",
         [type: :integer, default: 30]},
        {:mp_5_odp_02,
         "Визначено заходи безпеки, що використовуються для захисту носіїв інформації системи поза контрольованими зонами",
         [type: :string, default: nil]},
        {:mp_5_odp_03,
         "Визначено заходи безпеки, що використовуються для контролю носіїв інформації системи за межами контрольованих зон",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-5-1") do
    %{
      id: :"id-spe-mp-5-1",
      description: "",
      title: "ТРАНСПОРТУВАННЯ НОСІЇВ ІНФОРМАЦІЇ - ЗАХИСТ ПОЗА КОНТРОЛЬОВАНИМИ ЗОНАМИ (MP-5(1))",
      parameters: [
        {:mp_5_1_01,
         "ТРАНСПОРТУВАННЯ НОСІЇВ ІНФОРМАЦІЇ - ЗАХИСТ ПОЗА КОНТРОЛЬОВАНИМИ ЗОНАМИ [Вилучено: Включено до MP-05]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-5-2") do
    %{
      id: :"id-spe-mp-5-2",
      description: "",
      title: "ТРАНСПОРТУВАННЯ НОСІЇВ ІНФОРМАЦІЇ - ДОКУМЕНТУВАННЯ ДІЙ (MP-5(2))",
      parameters: [
        {:mp_5_2_01,
         "ТРАНСПОРТУВАННЯ НОСІЇВ ІНФОРМАЦІЇ - ДОКУМЕНТУВАННЯ ДІЙ [Вилучено: Включено до MP-05]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-5-3") do
    %{
      id: :"id-spe-mp-5-3",
      description: "",
      title: "ТРАНСПОРТУВАННЯ НОСІЇВ ІНФОРМАЦІЇ - ЗБЕРІГАЧІ (MP-5(3))",
      parameters: [
        {:mp_5_3_01,
         "Визначено зберігачів інформації під час транспортування носіїв інформації системи за межі контрольованих зон",
         [type: :integer, default: 30]},
        {:mp_5_3_02,
         "Залучено визначених зберігачів інформації під час транспорту- вання носіїв інформації системи за межі контрольованих зон",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-mp-5-4") do
    %{
      id: :"id-spe-mp-5-4",
      description: "",
      title: "ТРАНСПОРТУВАННЯ НОСІЇВ ІНФОРМАЦІЇ - КРИПТОГРАФІЧНИЙ ЗАХИСТ (MP-5(4))",
      parameters: [
        {:mp_5_4_01,
         "ТРАНСПОРТУВАННЯ НОСІЇВ ІНФОРМАЦІЇ - КРИПТОГРАФІЧНИЙ ЗАХИСТ [Вилучено: Включено до SC-28(01)]",
         [type: :string, default: "AES-256-GCM"]}
      ]
    }
  end

  def spec(:"id-spe-mp-6") do
    %{
      id: :"id-spe-mp-6",
      description: "a. Очищувати [Призначення: визначені організацією системні носії] перед утилізацією, випуском за межі організаційного контролю, або перед повторним використанням [Призначення: методами та процедурами очищення, визначеними організацією]. b. Використовувати механізми очищення зі стійкістю та цілісністю, що відповідає категорії безпеки або рівню секретності інформації.",
      title: "ЗНИЩЕННЯ ІНФОРМАЦІЇ НА НОСІЯХ ІНФОРМАЦІЇ (MP-6)",
      parameters: [
        {:mp_6_a_01,
         "Носії інформації системи перед утилізацією піддаються очищенню за допомогою методів та процедур очищення",
         [type: :string, default: nil]},
        {:mp_6_a_02,
         "Носії інформації системи очищаються за допомогою методів та процедур очищення перед випуском за межі контрольованої зони",
         [type: :string, default: nil]},
        {:mp_6_a_03,
         "Носії інформації системи очищуються за допомогою методів і процедур очищення перед повторним використанням",
         [type: :string, default: nil]},
        {:mp_6_b,
         "Застосовуються механізми очищення, надійність і цілісність яких відповідає категорії безпеки або рівню секретності інформації",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:mp_6_odp_01,
         "Визначено носії інформації системи, які підлягають очищенню перед утилізацією",
         [type: :string, default: nil]},
        {:mp_6_odp_02,
         "Визначено носії інформації системи, які підлягають очищенню перед випуском за межі контрольованої зони",
         [type: :string, default: nil]},
        {:mp_6_odp_03,
         "Визначені носії інформації системи, що підлягають очищенню перед повторним використанням",
         [type: :string, default: nil]},
        {:mp_6_odp_04,
         "Визначено методи та процедури очищення, які слід використовувати для очищення перед утилізацією",
         [type: :string, default: nil]},
        {:mp_6_odp_05,
         "Визначено методи та процедури очищення, які слід використовувати для очищення перед випуском за межі контрольованої зони",
         [type: :string, default: nil]},
        {:mp_6_odp_06,
         "Визначено методи та процедури очищення, які слід використовувати для очищення перед повторним використанням",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-6-1") do
    %{
      id: :"id-spe-mp-6-1",
      description: "",
      title: "ЗНИЩЕННЯ ІНФОРМАЦІЇ НА НОСІЯХ ІНФОРМАЦІЇ - ПЕРЕГЛЯДАТИ, ЗАТВЕРДЖЕННЯ, ВІДСТЕЖЕННЯ, ДОКУМЕНТУВАННЯ ТА ПЕРЕВІРКА (MP-6(1))",
      parameters: [
        {:mp_6_1_01,
         "Переглядаються заходи з очищення та утилізації носіїв інформації",
         [type: :string, default: nil]},
        {:mp_6_1_02,
         "Затверджуються заходи з очищення та утилізації носіїв інформації",
         [type: :string, default: nil]},
        {:mp_6_1_03,
         "Відстежуються заходи з очищення та утилізації носіїв інформації",
         [type: :string, default: nil]},
        {:mp_6_1_04,
         "Документуються заходи з очищення та утилізації носіїв інформації",
         [type: :string, default: nil]},
        {:mp_6_1_05,
         "Перевіряються заходи з очищення та утилізації носіїв інформації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-6-2") do
    %{
      id: :"id-spe-mp-6-2",
      description: "",
      title: "ЗНИЩЕННЯ ІНФОРМАЦІЇ НА НОСІЯХ ІНФОРМАЦІЇ - ПЕРЕВІРКА ОБЛАДНАННЯ (MP-6(2))",
      parameters: [
        {:mp_6_2_01,
         "Обладнання для очищення тестується частота, щоб переконатися в досягненні запланованого очищення",
         [type: :string, default: "щорічно"]},
        {:mp_6_2_02,
         "Процедури санітарної обробки тестуються частота, щоб переконатися в досягненні запланованого очищення",
         [type: :string, default: "щорічно"]},
        {:mp_6_2_odp_01,
         "Визначена частота, з якою проводиться перевірка обладнання для очищення",
         [type: :string, default: "щорічно"]},
        {:mp_6_2_odp_02,
         "Визначено частоту, з якою потрібно перевіряти процедури очищення",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-mp-6-3") do
    %{
      id: :"id-spe-mp-6-3",
      description: "",
      title: "ЗНИЩЕННЯ ІНФОРМАЦІЇ НА НОСІЯХ ІНФОРМАЦІЇ - НЕРУЙНІВНІ МЕТОДИ (MP-6(3))",
      parameters: [
        {:mp_6_3_01,
         "Застосовуються методи неруйнівного очищення до зовнішніх носіїв інформації перед підключенням таких пристроїв до системи при умовах, що вимагають очищення зовнішніх носіїв інформації",
         [type: :string, default: nil]},
        {:mp_6_3_odp,
         "Визначено умови, які вимагають очищення зовнішніх носіїв інформації",
         [type: :list, default: []]}
      ]
    }
  end

  def spec(:"id-spe-mp-6-4") do
    %{
      id: :"id-spe-mp-6-4",
      description: "",
      title: "ЗНИЩЕННЯ ІНФОРМАЦІЇ НА НОСІЯХ ІНФОРМАЦІЇ - КЕРОВАНА НЕСЕКРЕТНА ІНФОРМАЦІЯ (MP-6(4))",
      parameters: [
        {:mp_6_4_01,
         "ЗНИЩЕННЯ ІНФОРМАЦІЇ НА НОСІЯХ ІНФОРМАЦІЇ - КЕРОВАНА НЕСЕКРЕТНА ІНФОРМАЦІЯ [Вилучено: Включено до MP-06]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-6-5") do
    %{
      id: :"id-spe-mp-6-5",
      description: "",
      title: "ЗНИЩЕННЯ ІНФОРМАЦІЇ НА НОСІЯХ ІНФОРМАЦІЇ - СЕКРЕТНА ІНФОРМАЦІЯ (MP-6(5))",
      parameters: [
        {:mp_6_5_01,
         "ЗНИЩЕННЯ ІНФОРМАЦІЇ НА НОСІЯХ ІНФОРМАЦІЇ - СЕКРЕТНА ІНФОРМАЦІЯ [Вилучено: Включено до MP-06]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-6-6") do
    %{
      id: :"id-spe-mp-6-6",
      description: "",
      title: "ЗНИЩЕННЯ ІНФОРМАЦІЇ НА НОСІЯХ ІНФОРМАЦІЇ - ЗНИЩЕННЯ НОСІЇВ ІНФОРМАЦІЇ (MP-6(6))",
      parameters: [
        {:mp_6_6_01,
         "ЗНИЩЕННЯ ІНФОРМАЦІЇ НА НОСІЯХ ІНФОРМАЦІЇ - ЗНИЩЕННЯ НОСІЇВ ІНФОРМАЦІЇ [Вилучено: Включено до MP-06]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-6-7") do
    %{
      id: :"id-spe-mp-6-7",
      description: "",
      title: "ЗНИЩЕННЯ ІНФОРМАЦІЇ НА НОСІЯХ ІНФОРМАЦІЇ - ПОДВІЙНА АВТОРИЗАЦІЯ (MP-6(7))",
      parameters: [
        {:mp_6_7_01,
         "Здійснюється подвійна авторизація для очищення носії інформації",
         [type: :string, default: nil]},
        {:mp_6_7_odp,
         "Визначено носії інформації для яких необхідно здійснювати подвійну авторизацію для очищення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-6-8") do
    %{
      id: :"id-spe-mp-6-8",
      description: "",
      title: "ЗНИЩЕННЯ ІНФОРМАЦІЇ НА НОСІЯХ ІНФОРМАЦІЇ - ВІДДАЛЕНЕ ОЧИЩЕННЯ АБО СТИРАННЯ ІНФОРМАЦІЇ (MP-6(8))",
      parameters: [
        {:mp_6_8_odp_01,
         "Визначено системи або компоненти системи для очищення або стирання інформації віддалено або за певних умов",
         [type: :string, default: nil]},
        {:mp_6_8_odp_02,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {віддалено; за умов }",
         [type: :string, default: nil]},
        {:mp_6_8_odp_03,
         "Визначаються умови, за яких інформація підлягає очищенню або стиранню (якщо вибрано)",
         [type: :list, default: []]}
      ]
    }
  end

  def spec(:"id-spe-mp-7") do
    %{
      id: :"id-spe-mp-7",
      description: "a. [Вибір: обмежити; заборонити] використання [Призначення: визначених організацією типів носіїв системи] на [Призначення: визначені організацією системи або компоненти системи], використовуючи [Призначення: визначені організацією заходи безпеки]. b. Заборонити використання портативних пристроїв зберігання даних в системах організації, якщо такі пристрої не мають визначеного власника.",
      title: "ВИКОРИСТАННЯ НОСІЇВ ІНФОРМАЦІЇ (MP-7)",
      parameters: [
        {:mp_7_01,
         "ВИКОРИСТАННЯ НОСІЇВ ІНФОРМАЦІЇ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:mp_7_b,
         "Використання зовнішніх носіїв інформації в системах організації заборонено, якщо такі пристрої не мають власника, якого можна ідентифікувати",
         [type: :string, default: nil]},
        {:mp_7_odp_01,
         "Визначено типи носіїв інформації, які мають бути обмежені або заборонені до використання в системі або компонентах системи",
         [type: :string, default: nil]},
        {:mp_7_odp_02,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРА: {обмежити; заборонити}",
         [type: :string, default: nil]},
        {:mp_7_odp_03,
         "Системи або компоненти системи, для яких визначено використання певних типів носіїв інформації, що підлягають обмеженню або забороні",
         [type: :string, default: nil]},
        {:mp_7_odp_04,
         "Визначено заходи безпеки для обмеження або заборони використання певних типів носіїв інформації в системах або компонентах системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-7-1") do
    %{
      id: :"id-spe-mp-7-1",
      description: "",
      title: "ВИКОРИСТАННЯ НОСІЇВ ІНФОРМАЦІЇ - ЗАБОРОНА ВИКОРИСТАННЯ БЕЗ ВИЗНАЧЕНОГО ВЛАСНИКА (MP-7(1))",
      parameters: [
        {:mp_7_1_01,
         "ВИКОРИСТАННЯ НОСІЇВ ІНФОРМАЦІЇ - ЗАБОРОНА ВИКОРИСТАННЯ БЕЗ ВИЗНАЧЕНОГО ВЛАСНИКА [Вилучено: Включено до MP-07]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-7-2") do
    %{
      id: :"id-spe-mp-7-2",
      description: "",
      title: "ВИКОРИСТАННЯ НОСІЇВ ІНФОРМАЦІЇ - ЗАБОРОНА ВИКОРИСТАННЯ (MP-7(2))",
      parameters: [
        {:mp_7_2_01,
         "Ідентифіковано стійкі до очищення носії інформації",
         [type: :string, default: nil]},
        {:mp_7_2_02,
         "Використання стійких до очищення носіїв інформації в системах організації заборонено",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-8") do
    %{
      id: :"id-spe-mp-8",
      description: "a. сплануйте розташування або ділянку об’єкта, де знаходиться система, враховуючи фізичні та екологічні ризики; b. для існуючих об’єктів врахуйте фізичні та екологічні ризики в організаційній стратегії управління ризиками.",
      title: "ЗНИЖЕННЯ КАТЕГОРІЇ БЕЗПЕКИ НОСІЇВ ІНФОРМАЦІЇ (MP-8)",
      parameters: [
        {:mp_8_a_01,
         "Встановлено безпеки носіїв інформаці; процес зниження категорії",
         [type: :string, default: nil]},
        {:mp_8_a_02,
         "Процес зниження категорії безпеки носіїв інформаці охоплює використання механізмів зниження грифа секретності носіїв інформації за стійкістю та цілісністю, що відповідає категорії безпеки або рівню секретності інформації",
         [type: :string, default: nil]},
        {:mp_8_b_01,
         "Здійснюється перевірка того, що процес зниження категорії безпеки носіїв інформації відповідає категорії безпеки та/або рівню секретності інформації, що підлягає видаленню",
         [type: :string, default: nil]},
        {:mp_8_b_02,
         "Здійснюється перевірка того, що процес зниження категорії безпеки носіїв інформації співмірний з правами доступу потенційних одержувачів пониженої інформації; MP-08(c) визначено носії інформації системи, що потребують пониження статусу",
         [type: :string, default: nil]},
        {:mp_8_d,
         "Визначений носій інформації понижено у категорії безпеки за допомогою процес зниження категорії безпеки носіїв інформації",
         [type: :string, default: nil]},
        {:mp_8_odp_01,
         "Визначено процес зниження категорії безпеки носіїв інформації",
         [type: :string, default: nil]},
        {:mp_8_odp_02,
         "Визначено носії інформації системи, що вимагають зниження категорії безпеки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-8-1") do
    %{
      id: :"id-spe-mp-8-1",
      description: "",
      title: "ЗНИЖЕННЯ КАТЕГОРІЇ БЕЗПЕКИ НОСІЇВ ІНФОРМАЦІЇ - ДОКУМЕНТУВАННЯ ПРОЦЕСУ (MP-8(1))",
      parameters: [
        {:mp_8_1_01,
         "Документуються дії зі зниження категорії безпеки носіїв інформації",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-mp-8-2") do
    %{
      id: :"id-spe-mp-8-2",
      description: "",
      title: "ЗНИЖЕННЯ КАТЕГОРІЇ БЕЗПЕКИ НОСІЇВ ІНФОРМАЦІЇ - ПЕРЕВІРКА ОБЛАДНАННЯ (MP-8(2))",
      parameters: [
        {:mp_8_2_01,
         "Обладнання для заниження категорії безпеки перевіряється частота, щоб переконатися в досягненні запланованих заходів щодо зниження",
         [type: :string, default: "щорічно"]},
        {:mp_8_2_02,
         "Процедури для заниження категорії безпеки перевіряється частота, щоб переконатися в досягненні запланованих заходів щодо зниження",
         [type: :string, default: "щорічно"]},
        {:mp_8_2_odp_02,
         "Визначено частоту, з якою потрібно перевіряти процедури для заниження категорії безпеки ",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-mp-8-3") do
    %{
      id: :"id-spe-mp-8-3",
      description: "",
      title: "ЗНИЖЕННЯ КАТЕГОРІЇ БЕЗПЕКИ НОСІЇВ ІНФОРМАЦІЇ - КРИТИЧНА ІНФОРМАЦІЯ (MP-8(3))",
      parameters: [
        {:mp_8_3_01,
         "Визначено критичну інформацію за наявності якої на носії інформації, знижують категорію безпеки до рівня публічного доступу",
         [type: :string, default: nil]},
        {:mp_8_3_02,
         "Знижується категорія безпеки носіїв інформації, що містять визначену критичну інформацію до рівня публічного доступу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-mp-8-4") do
    %{
      id: :"id-spe-mp-8-4",
      description: "",
      title: "ЗНИЖЕННЯ КАТЕГОРІЇ БЕЗПЕКИ НОСІЇВ ІНФОРМАЦІЇ - ТАЄМНА ІНФОРМАЦІЯ (MP-8(4))",
      parameters: [
        {:mp_8_4_01,
         "Ідентифіковано носії інформації, що містять інформацію з обмеженим доступом",
         [type: :string, default: nil]},
        {:mp_8_4_02,
         "Носії інформації, що містять інформацію з обмеженим доступом, знижуються в класі перед передачею особам, які не мають необхідних дозволів на доступ",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pe-1") do
    %{
      id: :"id-spe-pe-1",
      description: "",
      title: "РЕ-1 фізичного захисту та захисту робочого середовища Авторизація фізичного (PE-1)",
      parameters: [
        {:pe_1_a_01,
         "Розроблено та задокументовано політику фізичного захисту та захисту робочого середовища",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:pe_1_a_02,
         "Політика фізичного захисту та захисту робочого середовища розповсюджується серед персоналу або ролей",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pe_1_b,
         "Посадова особа призначається для управління розробкою, документуванням та розповсюдженням політики та процедур фізичного захисту та захисту робочого середовища; PE-01(c)[01][01] переглядається та оновлюється поточна політика фізичного захисту та захисту робочого середовища частота; PE-01(c)[01][02] поточна політика фізичного захисту та захисту робочого середовища переглядається та оновлюється після подій; PE-01(c)[02][01] переглядаються та оновлюються поточні процедури фізичного захисту та захисту робочого середовища частота; поточні процедури фізичного та екологічного захисту переглядаються та оновлюються після подій. PE-01(c)[02][02]",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pe_1_odp_01,
         "Визначено персонал або ролі, до яких має бути доведена політика фізичного захисту та захисту робочого середовища",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pe_1_odp_02,
         "Визначено персонал або ролі, на які поширюються процедури фізичного захисту та захисту робочого середовища",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pe_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнес-процесу; рівень системи}",
         [type: :string, default: nil]},
        {:pe_1_odp_04,
         "Визначено посадову особу, яка керуватиме політикою та процедурами фізичного захисту та захисту робочого середовища",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pe_1_odp_05,
         "Визначено частоту, з якою переглядається та оновлюється поточна політика фізичного захисту та захисту робочого середовища",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:pe_1_odp_06,
         "Визначено події, які потребують перегляду та оновлення поточної політики фізичного захисту та захисту робочого середовища",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:pe_1_odp_07,
         "Визначено частоту, з якою переглядаються та оновлюються поточні процедури фізичного захисту та захисту робочого середовища",
         [type: :integer, default: 30]},
        {:pe_1_odp_08,
         "Визначено події, які потребують перегляду та оновлення процедур фізичного захисту та захисту робочого середовища",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-pe-2") do
    %{
      id: :"id-spe-pe-2",
      description: "",
      title: "РЕ-2 доступу (PE-2)",
      parameters: [
        {:pe_2_a_01,
         "Розроблено перелік осіб, які мають право авторизованого доступу до об’єкта, де перебуває система",
         [type: :list, default: []]},
        {:pe_2_a_02,
         "Затверджено перелік осіб, які мають право авторизованого доступу до об’єкта, де перебуває система",
         [type: :list, default: []]},
        {:pe_2_a_03,
         "Ведеться перелік осіб, які мають право авторизованого доступу до об’єкта, де перебуває система",
         [type: :list, default: []]},
        {:pe_2_b,
         "Для доступу до об'єкта надаються повноваження",
         [type: :string, default: nil]},
        {:pe_2_c,
         "Переглядається список доступу, , у якому закріплений перелік персоналу або ролей, яким дозволений санкціонований доступ до об’єкта частота",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pe_2_d,
         "Особи видаляються зі списку доступу до об'єкта, коли доступ більше не потрібен",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pe_2_odp,
         "Визначено періодичність перегляду списку доступу, у якому закріплений перелік персоналу або ролей, яким дозволений санкціонований доступ до об’єкта",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pe-3-5") do
    %{
      id: :"id-spe-pe-3-5",
      description: "",
      title: "Керування фізичним доступом — Захист від злому (PE-3(5))",
      parameters: [
        {:pe_3_5_odp_01,
         "Визначено заходи захисту від фізичної підробки або підміни",
         [type: :string, default: nil]},
        {:pe_3_5_odp_02,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {виявлення; запобігання}",
         [type: :string, default: nil]},
        {:pe_3_5_odp_03,
         "Визначено апаратні компоненти, які мають захищені від фізичної підробки або підміни",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pe-4") do
    %{
      id: :"id-spe-pe-4",
      description: "",
      title: "РЕ-4 ліній електроживлення (PE-4)",
      parameters: [
        {:pe_4_01,
         "Фізичний доступ до систем розподілу та постачання живлення в межах об'єктів організації контролюється за допомогою заходів захисту",
         [type: :string, default: nil]},
        {:pe_4_odp_01,
         "Визначені системи розподілу та постачання живлення, які потребують фізичного контролю доступу",
         [type: :string, default: nil]},
        {:pe_4_odp_02,
         "Визначено заходи захисту, які необхідно впровадити для контролю фізичного доступу до систем розподілу та постачання живлення в межах об'єкту організації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pe-6-2") do
    %{
      id: :"id-spe-pe-6-2",
      description: "",
      title: "Моніторинг фізичного доступу — Автоматичні розпізнавання вторгнень і відповідна реакція (PE-6(2))",
      parameters: [
        {:pe_6_2_01,
         "Розпізнаються класи або типи вторгнень",
         [type: :string, default: nil]},
        {:pe_6_2_02,
         "Реакції ініціюються за допомогою автоматизованих механізмів",
         [type: :string, default: nil]},
        {:pe_6_2_odp_01,
         "Визначено класи або типи вторгнень, які мають розпізнаватися автоматизованими механізмами",
         [type: :string, default: nil]},
        {:pe_6_2_odp_02,
         "Визначено реакції, які мають ініціюватися автоматизованими механізмами при розпізнаванні визначених організацією класів або типів вторгнень",
         [type: :string, default: nil]},
        {:pe_6_2_odp_03,
         "Визначено автоматизовані механізми, що використовуються для розпізнавання класів або типів вторгнень та ініціювання дій реагування (визначені в PE06(02)_ODP)",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-pe-8-3") do
    %{
      id: :"id-spe-pe-8-3",
      description: "",
      title: "РЕЄСТРИ ДОСТУПУ ВІДВІДУВАЧІВ — ОБМЕЖЕННЯ ІНФОРМАЦІЇ, ЩО ІДЕНТИФІКУЄ ОСОБУ (PE-8(3))",
      parameters: [
        {:pe_8_3_01,
         "Інформація, що ідентифікує особу, яка міститься в реєстрах доступу відвідувачів, обмежується елементи, визначеними в оцінці ризиків для конфіденційності",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pe_8_3_odp,
         "В оцінці ризиків для конфіденційності визначено елементи, що обмежуються в реєстрі відвідувачів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pe-12") do
    %{
      id: :"id-spe-pe-12",
      description: "",
      title: "АВАРІЙНЕ ОСВІТЛЕННЯ (PE-12)",
      parameters: [
        {:pe_12_01,
         "Автоматичне аварійне освітлення, яке вмикається в разі відключення або збою в електропостачанні",
         [type: :string, default: nil]},
        {:pe_12_02,
         "Підтримується автоматичне аварійне освітлення, яке вмикається в разі відключення або збою в електропостачанні",
         [type: :string, default: nil]},
        {:pe_12_03,
         "Автоматичне аварійне освітлення системи освітлює евакуаційні виходи в межах об'єкта",
         [type: :string, default: nil]},
        {:pe_12_04,
         "Автоматичне аварійне освітлення системи освітлює шляхи евакуації в межах об'єкта",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pe-17") do
    %{
      id: :"id-spe-pe-17",
      description: "",
      title: "АЛЬТЕРНАТИВНЕ РОБОЧЕ МІСЦЕ (PE-17)",
      parameters: [
        {:pe_17_odp_01,
         "Визначені альтернативні робочі місця, дозволені для використання працівниками",
         [type: :string, default: nil]},
        {:pe_17_odp_02,
         "Визначаються заходи захисту, які будуть застосовуватися на альтернативних робочих місцях; РЕ-17(a) альтернативні робочі місця визначені та задокументовані; РЕ-17(b) заходи захисту впроваджені на альтернативних робочих місцях; РЕ-17(c) оцінюється ефективність заходів захисту на альтернативних робочих місцях; РЕ-17(d) працівникам надаються засоби комунікації з персоналом служби інформаційної безпеки на випадок інцидентів",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pe-18") do
    %{
      id: :"id-spe-pe-18",
      description: "",
      title: "РОЗТАШУВАННЯ КОМПОНЕНТІВ СИСТЕМИ (PE-18)",
      parameters: [
        {:pe_18_01,
         "Компоненти системи розміщені в межах об'єкта так, щоб мінімізувати потенційну шкоду від фізичні та екологічні небезпеки і звести до мінімуму можливість несанкціонованого доступу",
         [type: :string, default: nil]},
        {:pe_18_odp,
         "Визначено фізичні та екологічні небезпеки, які можуть призвести до потенційного пошкодження компонентів системи на об'єкті",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pe-20") do
    %{
      id: :"id-spe-pe-20",
      description: "",
      title: "МОНІТОРИНГ І ВІДСТЕЖЕННЯ АКТИВІВ (PE-20)",
      parameters: [
        {:pe_20_01,
         "Технології використовуються для відстеження та моніторингу місцезнаходження і переміщення <PE- 20_ODP[02] активів> в межах контрольованої зони",
         [type: :string, default: nil]},
        {:pe_20_odp_01,
         "Визначено технології, які будуть використовуватися для відстеження та моніторингу місцезнаходження та переміщення активів",
         [type: :string, default: nil]},
        {:pe_20_odp_02,
         "Визначено активи, місцезнаходження та переміщення яких необхідно відстежувати та моніторити",
         [type: :string, default: nil]},
        {:pe_20_odp_03,
         "Визначено контрольовані зони, в межах яких місцезнаходження та переміщення активів підлягають відстеженню та моніторингу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pe-21") do
    %{
      id: :"id-spe-pe-21",
      description: "",
      title: "ЗАХИСТ ВІД ЕЛЕКТРОМАГНІТНОГО ІМПУЛЬСУ (PE-21)",
      parameters: [
        {:pe_21_01,
         "Заходи захисту застосовуються проти пошкодження електромагнітними імпульсами для системи та компонентів системи",
         [type: :string, default: nil]},
        {:pe_21_odp_01,
         "Визначено заходи захисту від пошкодження електромагнітними імпульсами",
         [type: :string, default: nil]},
        {:pe_21_odp_02,
         "Визначено систему та компоненти системи, що потребують захисту від пошкодження електромагнітними імпульсами",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pe-22") do
    %{
      id: :"id-spe-pe-22",
      description: "",
      title: "МАРКУВАННЯ КОМПОНЕНТІВ (PE-22)",
      parameters: [
        {:pe_22_01,
         "Апаратні компоненти системи позначаються із зазначенням рівня впливу або класифікації інформації, яку дозволено обробляти, зберігати або передавати за допомогою апаратного компонента",
         [type: :string, default: nil]},
        {:pe_22_odp,
         "Визначено апаратні компоненти системи, які підлягають маркуванню із зазначенням рівня впливу або класифікації інформації, яку дозволено обробляти, зберігати або передавати за допомогою апаратного компонента",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pl-1") do
    %{
      id: :"id-spe-pl-1",
      description: "a. Розробити, задокументувати та поширити серед [Призначення: визначеного організацією персоналу або ролей]: 1. 2. [вибір (один або декілька): рівень організації; рівень місії/бізнес процесу; рівень системи] політику планування, яка: (a) містить мету, сферу застосування, ролі, обов’язки, відповідальність керівництва, координацію між організаційними підрозділами та системою контролю (complaince); (b) відповідає чинному законодавству, виконавчим наказам, директивам, нормам, політикам, стандартам та керівним принципам; процедури, що полегшують здійснення планування політики безпеки та приватності й пов’язані з ними заходи. b. Призначити [Призначення: визначену організацією посадову особу] для управління політикою та процедурами планування політики безпеки та приватності. c. Переглядати та оновлювати поточне планування: 1. політики планування безпеки та приватності [Призначення:з визначеною організацією частотою] та наступні [Призначення: визначені організацією події]; 2. поточні процедури планування політики [Призначення: з визначеною організацією [Призначення: визначені організацією події]. безпеки та приватності частотою] та наступні",
      title: "ПОЛІТИКИ ТА ПРОЦЕДУРИ ПЛАНУВАННЯ БЕЗПЕКИ (PL-1)",
      parameters: [
        {:pl_1_odp_01,
         "Визначено персонал або ролі, до яких має бути доведена політика планування безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pl_1_odp_02,
         "Визначено персонал або ролі, на які поширюватимуться процедури планування безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pl_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнеспроцесу; рівень системи}",
         [type: :string, default: nil]},
        {:pl_1_odp_04,
         "Визначено посадову особу, яка керуватиме політикою та процедурами планування безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pl_1_odp_05,
         "Визначено періодичність перегляду та оновлення поточної політики планування безпеки",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:pl_1_odp_06,
         "Є події, які потребують перегляду та оновлення поточної політики планування безпеки",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:pl_1_odp_07,
         "Визначена частота, з якою переглядаються та оновлюються поточні процедури планування безпеки",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-pl-2") do
    %{
      id: :"id-spe-pl-2",
      description: "a. Розробити план захисту інформації та персональних даних для інформаційної системи, який: 1. узгоджується з архітектурою підприємства організації; 2. чітко визначає складові компоненти системи; 3. описує оперативний контекст інформаційної системи з точки зору завдань та процесів; 4. визначає осіб, які виконують системні ролі та обов’язки; 5. визначає тип інформації, яка обробляється, зберігається та передається системою; 6. надає огляд вимог безпеки та приватності інформаційної системи; 7. описує будь які конкретні загрози системи, які викликають стурбованість організації; 8. надає результати оцінки ризику конфіденційності для систем, в яких обробляються персональні дані; 9. описує робоче середовище інформаційної системи та будь які залежності від систем або компонентів систем або підключень до таких систем та їх компонентів; 10. надає огляд вимог безпеки та конфіденційності системи; 11. визначає будь які відповідні контрольні базові рівні або накладання, якщо вони застосовуються; 12. описує чинні або заплановані заходи щодо забезпечення безпеки та приватності, включно з обґрунтуванням рішень щодо налаштування 13. включає виявлення ризиків для архітектури безпеки і приватності, а також проєктних рішень; 14. включає дії, пов’язані з безпекою та конфіденційністю, які впливають на систему, виконання яких вимагає планування та координацію з [Призначення: визначені організацією окремі особи або групи]; 15. розглядається та затверджується уповноваженою посадовою особою або призначеним представником до початку реалізації плану. b. Поширити копії планів захисту інформації та персональних даних і повідомляти про подальші зміни планів серед [Призначення:визначеного організацією персоналу або ролей]. c. Переглядати плани захисту інформації та персональних даних [Призначення: з визначеною організацією частотою]. d. Оновлювати плани захисту інформації та персональних даних для врахування змін в інформаційній системі й робочому середовищі або проблем, виявлених у ході реалізації або оцінювання заходів безпеки та приватності. e. забезпечити захист планів захисту інформації та персональних даних від несанкціонованого розголошення та змін.",
      title: "ПЛАНИ ЗАХИСТУ ІНФОРМАЦІЇ ТА ПЕРСОНАЛЬНИХ ДАНИХ (PL-2)",
      parameters: [
        {:pl_2_odp_01,
         "Призначені особи або групи, з якими пов'язана діяльність з безпекою та конфіденційністю, що впливає на систему, яка потребує планування та координації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pl_2_odp_02,
         "Призначено персонал або ролі для отримання розповсюджуваних копій планів захисту інформації та конфіденційності системи",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pl_2_odp_03,
         "Визначено періодичність перегляду інформації та конфіденційності системи; планів захисту PL-02a.01[01] розроблено план захисту інформації, архітектурі підприємства організації; який відповідає PL-02a.01[02] розроблено план конфіденційності для системи, відповідає архітектурі підприємства організації; який PL-02a.02[01] розроблено план захисту інформації, який чітко визначає складові компоненти системи; PL-02a.02[02] розроблено для системи план забезпечення конфіденційності, який чітко визначає складові компоненти системи; PL-02a.03[01] розроблено план захисту інформації системи, який описує операційний контекст системи з точки зору місії та бізнеспроцесів; PL-02a.03[02] розроблено для системи план забезпечення конфіденційності, який описує операційний контекст системи з точки зору місії та бізнес-процесів; PL-02a.04[01] розроблено план захисту інформації, який визначає осіб, що виконують системні ролі та обов'язки; PL-02a.04[02] розроблено для системи план забезпечення конфіденційності, який визначає осіб, що виконують ролі та обов'язки в системі; PL-02a.05[01] розроблено план захисту інформації, який визначає типи інформації, що обробляється, зберігається та передається системою; PL-02a.05[02] розроблено план конфіденційності для системи, який визначає типи інформації, що обробляється, зберігається та передається системою; PL-02a.06[01] розроблено план захисту інформації, який передбачає категоризацію безпеки системи, включаючи відповідне обґрунтування; PL-02a.06[02] розроблено для системи план забезпечення конфіденційності, який передбачає категоризацію системи за рівнем безпеки, включаючи обґрунтування; PL-02a.07[01] розроблено план захисту інформації, який описує будь-які конкретні загрози для системи, що викликають потенційні ризики для рганізації; PL-02a.07[02] розроблено план конфіденційності для системи, який описує будь-які конкретні загрози для системи, що викликають потенційні ризики для організації; PL-02a.08[01] розроблено план захисту інформації, який містить результати оцінки ризиків конфіденційності для систем, що обробляють інформацію, яка ідентифікує особу; PL-02a.08[02] розроблено для системи план забезпечення конфіденційності, який містить результати оцінки ризиків конфіденційності для систем, що обробляють інформацію, яка ідентифікує особу; PL-02a.09[01] розроблено план захисту інформації, який описує операційне середовище системи та будь-які залежності або зв'язки з іншими системами чи компонентами системи; PL-02a.09[02] розроблено для системи план забезпечення конфіденційності, який описує робоче середовище системи та будь-які залежності або зв'язки з іншими системами чи компонентами системи; PL-02a.10[01] розроблено план захисту інформації, який містить огляд вимог до безпеки системи; PL-02a.10[02] розроблено для системи план забезпечення конфіденційності, який містить огляд вимог до конфіденційності системи; PL-02a.11[01] розроблено план захисту інформації, який визначає будь-які відповідні базові рівні контролю або обмеження, якщо такі є; PL-02a.11[02] розроблено для системи план забезпечення конфіденційності, який визначає будь-які відповідні базові рівні контролю або обмеження, якщо такі є; PL-02a.12[01] розроблено план захисту інформації, який описує наявні або заплановані засоби контролю для виконання вимог безпеки, включаючи обґрунтування будь-яких рішень щодо адаптації; PL-02a.12[02] розроблено для системи план забезпечення конфіденційності, який описує наявні або заплановані засоби контролю для виконання вимог щодо конфіденційності, включаючи обґрунтування будь-яких рішень, пов'язаних з адаптацією; PL-02a.13[01] розроблено план захисту інформації, який включає визначення ризиків для архітектури безпеки та проектних рішень; PL-02a.13[02] розроблено план забезпечення конфіденційності для системи, який включає визначення ризиків для архітектури конфіденційності та проектних рішень; PL-02a.14[01] розроблено захисту інформації, який включає діяльність, пов'язану з безпекою, що впливає на систему і потребує планування та координації з окремими особами або групами; PL-02a.14[02] розроблено для системи план забезпечення конфіденційності, який включає діяльність, пов'язану з конфіденційністю, що впливає на систему і потребує планування та координації з окремими особами або групами; PL-02a.15[01] розроблено план захисту інформації, який розглядається та затверджується уповноваженою посадовою особою або призначеним представником до початку реалізації плану; PL-02a.15[02] розроблено план забезпечення конфіденційності для системи, який перевіряється та затверджується уповноваженою посадовою особою або призначеним представником перед впровадженням плану. PL-02b.[01] розповсюджуються копії персонал або ролі>; PL-02b.[02] повідомляються наступні зміни до планів персонал або ролі; PL-02c. переглядаються плани частота; планів серед <PL-02_ODP[02] PL-02d.[01] оновлюються плани відповідно до змін у системі та середовищі діяльності; PL-02d.[02] оновлюються плани для вирішення проблем, виявлених під час реалізації плану; PL-02d.[03] оновлюються плани для вирішення проблем, виявлених під час контрольних оцінок; PL-02e.[01] захищені плани від несанкціонованого розголошення; PL-02e.[02] захищені плани від несанкціонованої модифікації",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pl-2-1") do
    %{
      id: :"id-spe-pl-2-1",
      description: "",
      title: "КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ДИВЕРСИФІКАЦІЯ ПОСТАЧАЛЬНИКІВ (PL-2(1))",
      parameters: [
        {:pl_2_1_01,
         "КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ДИВЕРСИФІКАЦІЯ ПОСТАЧАЛЬНИКІВ [Вилучено: включено до PL-7]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pl-2-2") do
    %{
      id: :"id-spe-pl-2-2",
      description: "",
      title: "ПЛАНИ ЗАХИСТУ ІНФОРМАЦІЇ ФУНКЦІОНАЛЬНА АРХІТЕКТУРА (PL-2(2))",
      parameters: [
        {:pl_2_2_01,
         "ПЛАНИ ЗАХИСТУ ІНФОРМАЦІЇ ФУНКЦІОНАЛЬНА АРХІТЕКТУРА [Вилучено: включено до PL-8]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pl-3") do
    %{
      id: :"id-spe-pl-3",
      description: "",
      title: "ОНОВЛЕННЯ ПЛАНІВ ЗАХИСТУ ІНФОРМАЦІЇ ТА ПЕРСОНАЛЬНИХ ДАНИХ (PL-3)",
      parameters: [
        {:pl_3_01,
         "ОНОВЛЕННЯ ПЛАНІВ ЗАХИСТУ ІНФОРМАЦІЇ ТА ПЕРСОНАЛЬНИХ ДАНИХ [Вилучено: включено до PL-2]",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pl-4") do
    %{
      id: :"id-spe-pl-4",
      description: "a. Створити та надати особам, що потребують доступу до інформаційної системи, правила, які описують їхні обов’язки й очікувану поведінку щодо інформації та використання інформаційної системи, безпеки та приватності. b. Отримати документальне підтвердження від таких осіб про те, що вони прочитали, зрозуміли та погодилися дотримуватися правил поведінки, перш ніж дозволяти доступ до інформації та інформаційної системи. c. Переглядати й оновлювати правила поведінки [Призначення: з визначеною організацією частотою]. d. Вимагати від осіб, які підписали попередню версію правил поведінки, перечитати та повторно підписати правила [Вибір (один або декілька): [Призначення: з визначеною організацією частотою]; коли правила переглядаються чи оновлюються].",
      title: "ПРАВИЛА ПОВЕДІНКИ (PL-4)",
      parameters: [
        {:pl_4_odp_01,
         "Визначено періодичність перегляду та оновлення правил поведінки",
         [type: :string, default: "щорічно"]},
        {:pl_4_odp_02,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРА:{частота; коли правила переглядаються або оновлюються}",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:pl_4_odp_03,
         "Визначена періодичність перегляду та повторного підтвердження правил поведінки (якщо вибрано); PL-04a.[01] встановлені правила, які описують обов'язки та очікувану поведінку щодо використання інформації та системи, безпеки та конфіденційності для осіб, яким потрібен доступ до системи; PL-04a.[02] надаються правила, які описують обов'язки та очікувану поведінку щодо використання інформації та системи, безпеки та конфіденційності, особам, які отримують доступ до системи; PL-04b. отримано перед наданням доступу до інформації та системи задокументоване підтвердження від таких осіб про те, що вони прочитали, зрозуміли та згодні дотримуватися правил поведінки; PL-04c. переглядаються та оновлюються правила поведінки частота; PL-04d. потрібно особам, які визнали попередню версію правил поведінки, прочитати та повторно визнати ЗНАЧЕННЯ ВИБРАНОГО ПАРАМЕТРА(ів)",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pl-4-1") do
    %{
      id: :"id-spe-pl-4-1",
      description: "",
      title: "ПРАВИЛА ПОВЕДІНКИ - ОБМЕЖЕННЯ НА СОЦІАЛЬНІ МЕДІА ТА МЕРЕЖУ (PL-4(1))",
      parameters: [
        {:pl_4_1_a,
         "Включають правила поведінки обмеження на використання соціальних медіа, соціальних мереж та зовнішніх сайтів/додатків",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:pl_4_1_b,
         "Включають правила поведінки обмеження на розміщення інформації про організацію на публічних веб-сайтах",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:pl_4_1_c,
         "Включають правила поведінки обмеження на використання наданих організацією ідентифікаторів (наприклад, адрес електронної пошти) та секретів автентифікації (наприклад, паролів) для створення облікових записів на зовнішніх сайтах/додатках. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pl-5") do
    %{
      id: :"id-spe-pl-5",
      description: "",
      title: "ОЦІНКА ВПЛИВУ НА ПРИВАТНІСТЬ (PL-5)",
      parameters: [
        {:pl_5_01,
         "ОЦІНКА ВПЛИВУ НА ПРИВАТНІСТЬ [Вилучено: включено до RА-8]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pl-6") do
    %{
      id: :"id-spe-pl-6",
      description: "",
      title: "ПЛАНУВАННЯ ДІЯЛЬНОСТІ, ПОВ'ЯЗАНОЇ З БЕЗПЕКОЮ (PL-6)",
      parameters: [
        {:pl_6_01,
         "ПЛАНУВАННЯ ДІЯЛЬНОСТІ, ПОВ'ЯЗАНОЇ З БЕЗПЕКОЮ [Вилучено: включено до PL-2]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pl-7") do
    %{
      id: :"id-spe-pl-7",
      description: "a. Розробити концепцію експлуатації інформаційної системи, яка описує, як організація має намір керувати системою з погляду забезпечення безпеки та приватності інформації. b. Переглядати й оновлювати концепцію експлуатації [Призначення: з визначеною організацією частотою].",
      title: "КОНЦЕПЦІЯ ЕКСПЛУАТАЦІЇ (PL-7)",
      parameters: [
        {:pl_7_odp,
         "Визначена періодичність перегляду концепцію експлуатації системи; та оновлення PL-07a. розроблено концепцію експлуатації системи, що описує, як організація має намір експлуатувати систему з точки зору інформаційної безпеки та конфіденційності; PL-07b. переглядається та оновлюється концепція експлуатації системи частота",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-pl-8") do
    %{
      id: :"id-spe-pl-8",
      description: "a. b. Розробити архітектуру безпеки та приватності для інформаційної системи, яка: 1. характеризує методологію, вимоги та підходи, які слід вживати для забезпечення конфіденційності, цілісності та доступності інформації, що циркулює в системі; 2. характеризує методологію, вимоги та підхід до обробки персональних даних для мінімізації ризику їх втрати; 3. характеризує, як архітектури безпеки та приватності інтегруються в архітектуру підприємства; 4. характеризує будь-які припущення, що пов’язані з безпекою та приватністю, щодо зовнішніх служб і залежності від них. Переглядати й оновлювати архітектуру безпеки та приватності [Призначення:з визначеною організацією частотою], щоб відображати оновлення в архітектурі підприємства. c. Відображати заплановані зміни архітектури плану безпеки та приватності, концепції експлуатації інформаційної системи, аналізу критичності, організаційних заходах, постачань та закупівель.",
      title: "АРХІТЕКТУРА БЕЗПЕКИ ТА ПРИВАТНОСТІ (PL-8)",
      parameters: [
        {:pl_8_01,
         "АРХІТЕКТУРА БЕЗПЕКИ ТА ПРИВАТНОСТІ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:pl_8_odp,
         "Потрібно переглядати та оновлювати частоту, відображати зміни в архітектурі підприємства; PL-08a.01 описує архітектура безпеки системи вимоги та підходи до захисту конфіденційності, цілісності та доступності організаційної інформації; PL-08a.02 описує архітектура конфіденційності вимоги та підходи до обробки персональних даних з метою мінімізації ризиків для приватного життя людей; PL-08a.03[01] описує архітектура безпеки системи те, як вона інтегрована в архітектуру підприємства та підтримує її; PL-08a.03[02] описує архітектура конфіденційності системи те, як вона інтегрована в архітектуру підприємства та підтримує її; PL-08a.04[01] описує архітектура безпеки системи будь-які припущення та залежності від зовнішніх систем та сервісів; PL-08a.04[02] описує архітектура конфіденційності системи будь-які припущення та залежності від зовнішніх систем і сервісів; PL-08b. переглядаються та оновлюються зміни в архітектурі підприємства частота для відображення змін в архітектурі підприємства; PL-08c.[01] заплановані зміни в архітектурі відображені в плані безпеки; PL-08c.[02] відображені заплановані конфіденційності; PL-08c.[03] заплановані зміни архітектури відображені діяльності концепції експлуатації системи; PL-08c.[04] заплановані зміни критичності; PL-08c.[05] відображені заплановані зміни архітектури в організаційних процедурах; PL-08c.[06] заплановані зміни в архітектурі відображаються на закупівлях та придбанні. в зміни архітектурі в архітектурі в щоб плані в Концепції відображені в аналізі",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pl-8-1") do
    %{
      id: :"id-spe-pl-8-1",
      description: "",
      title: "АРХІТЕКТУРА БЕЗПЕКИ ТА ПРИВАТНОСТІ - «ГЛИБОКА ОБОРОНА» (PL-8(1))",
      parameters: [
        {:pl_8_1_a_01,
         "Архітектура безпеки системи розроблена з використанням підходу «глибокої оборони», який розподіляє елементи керування за місцями та архітектурними рівнями",
         [type: :string, default: nil]},
        {:pl_8_1_a_02,
         "Архітектура конфіденційності системи розроблена з використанням підходу глибокого захисту, який розподіляє елементи керування за місцями та архітектурними рівнями",
         [type: :string, default: nil]},
        {:pl_8_1_b_01,
         "Архітектура безпеки системи розроблена з використанням підходу «глибокої оборони», який гарантує, що виділені засоби контролю працюють скоординовано і взаємно підсилюють один одного",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:pl_8_1_b_02,
         "Архітектура конфіденційності системи розроблена з використанням підходу «глибокої оборони», який гарантує, що виділені засоби контролю працюють скоординовано і взаємно підкріплюють один одного",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-pl-8-2") do
    %{
      id: :"id-spe-pl-8-2",
      description: "",
      title: "АРХІТЕКТУРА БЕЗПЕКИ ТА ПРИВАТНОСТІ - РІЗНОМАНІТНІСТЬ ПОСТАЧАЛЬНИКІВ (PL-8(2))",
      parameters: [
        {:pl_8_2_01,
         "Потрібно отримувати елементи керування, призначені для локацій та архітектурних рівнів, від різних постачальників",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pl-9") do
    %{
      id: :"id-spe-pl-9",
      description: "Централізовано управляти [Призначення: визначеними організацією організаційними заходами захисту та пов’язаними з ними процесами].",
      title: "ЦЕНТРАЛІЗОВАНЕ УПРАВЛІННЯ (PL-9)",
      parameters: [
        {:pl_9_01,
         "Здійснюється централізоване управління контролями та пов'язаними з ними процесами",
         [type: :string, default: nil]},
        {:pl_9_odp,
         "Визначені засоби контролю безпеки та конфіденційності і пов'язані з ними процеси, якими слід централізовано керувати",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-pl-10") do
    %{
      id: :"id-spe-pl-10",
      description: "Вибрати базовий профіль безпеки для інформаційної системи.",
      title: "ВИБІР БАЗОВОГО ПРОФІЛЮ БЕЗПЕКИ (PL-10)",
      parameters: [
        {:pl_10_01,
         "Вибрано базовий профіль безпеки для системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pl-11") do
    %{
      id: :"id-spe-pl-11",
      description: "a. Розробити та поширити на організаційному рівні план програми (концепцію) з інформаційної безпеки, яка: 1. містить огляд вимог до програми (концепції) безпеки й описує заходи управління програмою інформаційної безпеки та загальних заходів безпеки, які використовуються або плануються для виконання цих вимог; 2. містить визначення та розподіл ролей, обов’язків, відповідальності керівництва, заходи з координації діяльності організації і забезпечення відповідності вимогам законодавства та іншим нормативним документам; 3. відображає координацію між організаційними елементами, що відповідають за інформаційну безпеку; 4. затверджена вищою посадовою особою, що відповідає та підзвітна за управління ризиками, пов’язаними з організаційними операціями (включно з завданнями (місією), функціями, іміджем і репутацією організації), організаційні активи, фізичних осіб, інші організації та державу. b. Переглядати та оновлювати загальноорганізаційний план програми (концепцію) інформаційної безпеки [Призначення: з визначеною організацією частотою] та у випадку [Призначення: визначені організацією випадки]. c. Забезпечити захист плану програми (концепції) інформаційної безпеки від несанкціонованого розкриття та зміни.",
      title: "НАЛАШТУВАННЯ БАЗОВОГО ПРОФІЛЮ БЕЗПЕКИ (PL-11)",
      parameters: [
        {:pl_11_01,
         "Налаштуватовано вибраний базовий профіль застосовуючи вказані дії для налаштування. безпеки,",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-pm-2") do
    %{
      id: :"id-spe-pm-2",
      description: "Призначити старшу посадову особу служби інформаційної безпеки, яка наділена відповідними завданнями та ресурсами для здійснення координації, розробки, впровадження та підтримки програми (концепції) інформаційної безпеки.",
      title: "Ролі програми інформаційної безпеки (PM-2)",
      parameters: [
        {:pm_2_01,
         "Призначено старшу посадову особу з питань інформаційної безпеки в установі",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_2_02,
         "Надано посадовій особі з інформаційної безпеки відомства повноваження та ресурси для координації загальноорганізаційної програми (концепції) з інформаційної безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_2_03,
         "Має старша посадова особа з питань інформаційної безпеки відомства місію та ресурси для розробки загальноорганізаційної програми інформаційної безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_2_04,
         "Забезпечено старшу посадову особу з інформаційної безпеки відомства необхідним та ресурсами для впровадження загальноорганізаційної програми інформаційної безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_2_05,
         "Забезпечено старшу посадову особу з інформаційної безпеки відомства необхідним та ресурсами для підтримки загальноорганізаційної програми (концепції) з інформаційної безпеки",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pm-3") do
    %{
      id: :"id-spe-pm-3",
      description: "a. b. Запровадити процес для забезпечення того, щоб плани дій та етапи програм безпеки та приватності, програм управління ризиками ланцюга постачання і пов’язаних систем організації: 1. розроблялися та підтримувалися; 2. задокументовані корегувальні заходи захисту адекватно реагували на ризики для операцій організацї і активів, фізичних осіб, інших організацій та держави; 3. оприлюднювалися відповідно до встановлених вимог до звітності. Переглядати плани дій та етапи для узгодженості з організаційною стратегією управління ризиками й організаційними пріоритетами щодо дій з реагування на ризики.",
      title: "Ресурси забезпечення інформаційної безпеки та приватності (PM-3)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-pm-5") do
    %{
      id: :"id-spe-pm-5",
      description: "Розробити, відстежувати та звітувати про результати вимірювань показників продуктивності забезпечення безпеки інформації та приватності.",
      title: "Інвентаризація системи (PM-5)",
      parameters: [
        {:pm_5_01,
         "Розроблено перелік систем організацї",
         [type: :list, default: []]},
        {:pm_5_02,
         "Оновлюється frequency>. перелік оновлення систем переліку організації систем <PM-05_ODP",
         [type: :list, default: []]},
        {:pm_5_odp,
         "Визначена періодичність організацї",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-pm-7") do
    %{
      id: :"id-spe-pm-7",
      description: "Визначити завдання інформаційної безпеки та приватності при розробці документуванні та оновленні плану захисту критичної інфраструктури та ключових ресурсів.",
      title: "Архітектура підприємства (PM-7)",
      parameters: [
        {:pm_7_01,
         "Розроблена архітектура інформаційної безпеки; підприємства з урахуванням",
         [type: :string, default: nil]},
        {:pm_7_02,
         "Підтримується архітектура інформаційної безпеки; підприємства з урахуванням",
         [type: :string, default: nil]},
        {:pm_7_03,
         "Розроблена архітектура конфіденційності; підприємства з урахуванням",
         [type: :string, default: nil]},
        {:pm_7_04,
         "Підтримується архітектура конфіденційності; підприємства з урахуванням",
         [type: :string, default: nil]},
        {:pm_7_05,
         "Розроблена архітектура підприємства з урахуванням ризиків для діяльності та активів організації, окремих осіб, інших організацій та держави в цілому",
         [type: :string, default: nil]},
        {:pm_7_06,
         "Підтримується архітектура підприємства з урахуванням ризиків, що виникають в результаті цього для операцій та активів організації, окремих осіб, інших організацій та держави.,",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pm-7-1") do
    %{
      id: :"id-spe-pm-7-1",
      description: "",
      title: "АРХІТЕКТУРА ПІДПРИЄМСТВА - РОЗВАНТАЖЕННЯ (PM-7(1))",
      parameters: [
        {:pm_7_1_01,
         "Несуттєві функції або послуги вивантажуються на інші системи, компоненти системи або зовнішнього постачальника",
         [type: :string, default: nil]},
        {:pm_7_1_odp,
         "Визначені несуттєві функції або послуги, які потрібно розвантажити",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pm-8") do
    %{
      id: :"id-spe-pm-8",
      description: "",
      title: "ПЛАН ЗАХИСТУ КРИТИЧНОЇ ІНФРАСТРУКТУРИ (PM-8)",
      parameters: [
        {:pm_8_01,
         "Враховані питання інформаційної безпеки при розробці плану захисту критичної інфраструктури та ключових ресурсів; PM-08[02] розглядаються питання інформаційної безпеки в документації плану захисту критичної інфраструктури та ключових ресурсів",
         [type: :string, default: nil]},
        {:pm_8_03,
         "Враховані питання інформаційної безпеки в оновленому плані захисту критичної інфраструктури та ключових ресурсів",
         [type: :string, default: nil]},
        {:pm_8_04,
         "Враховані питання конфіденційності при розробці плану захисту критичної інфраструктури та ключових ресурсів",
         [type: :string, default: nil]},
        {:pm_8_05,
         "Розглядаються питання конфіденційності в документації плану захисту критичної інфраструктури та ключових ресурсів",
         [type: :string, default: nil]},
        {:pm_8_06,
         "Враховані питання конфіденційності в оновленому плані захисту критичної інфраструктури та ключових ресурсів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pm-9") do
    %{
      id: :"id-spe-pm-9",
      description: "a. Розробити комплексну стратегію управління: 1. ризиками безпеки для операцій та активів організації, фізичних осіб, інших організацій і держави, пов’язаних з експлуатацією та використанням систем організації; 2. ризиками приватності для фізичних осіб, які можуть виникати внаслідок збирання, обміну, зберігання, передачі, використання та розпорядження персональними даними; b. Реалізувати стратегію управління ризиками в масштабах організації. c. Переглядати й оновлювати стратегію управління ризиками [Призначення: з визначеною організацією частотою] або, якщо потрібно, у разі змін в організації.",
      title: "СТРАТЕГІЯ УПРАВЛІННЯ РИЗИКАМИ (PM-9)",
      parameters: [
        {:pm_9_odp,
         "Визначено періодичність перегляду та оновлення стратегії управління ризиками; PM-09a.01 розроблена комплексна стратегія управління ризиками безпеки для операцій та активів організації, окремих осіб, інших організацій та держави, пов'язаних з експлуатацією та використанням організаційних систем; PM-09a.02 розроблена комплексна стратегія управління ризиками для приватності осіб, що виникають внаслідок санкціонованої обробки інформації, що ідентифікує особу; PM-09b. стратегія управління ризиками послідовно впроваджується в організації; PM-09c. переглядається та оновлюється стратегія управління ризиками частота або в міру необхідності у зв'язку з організаційними змінами",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pm-10") do
    %{
      id: :"id-spe-pm-10",
      description: "a. Управляти станом безпеки та приватності інформаційних систем організації та середовищ, у яких ці інформаційні системи експлуатуються через процедури авторизації b. Призначити окремих осіб для виконання певних ролей і обов’язків у рамках організаційного процесу управління ризиками. c. Інтегрувати процеси авторизації в загальноорганізаційну програму управління ризиками.",
      title: "ПРОЦЕС АВТОРИЗАЦІЇ (PM-10)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-pm-11") do
    %{
      id: :"id-spe-pm-11",
      description: "Створити програму розвитку та вдосконалення спеціалістів з питань безпеки та приватності.",
      title: "ВИЗНАЧЕННЯ ЗАВДАНЬ ТА ПРОЦЕСІВ (PM-11)",
      parameters: [
        {:pm_11_odp,
         "Визначено періодичність перегляду завдань та бізнеспроцесів; PM-11a.[01] завдання та бізнес-процеси організації визначені з урахуванням інформаційної безпеки; PM-11a.[02] завдання та бізнес-процеси організації визначені з урахуванням права на приватність; PM-11a.[03] завдання та бізнес-процеси організації визначені з урахуванням ризиків для діяльності організації, її активів, окремих осіб, інших організацій та держави в цілому; PM-11b.[01] визначені потреби в захисті інформації, що випливають з визначених завдань та бізнес-процесів; PM-11b.[02] визначені потреби в обробці персональних випливають з визначеної місії та бізнес-процесів; PM-11c. переглядаються завдання та бізнес-процеси частота. даних, що",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pm-12") do
    %{
      id: :"id-spe-pm-12",
      description: "",
      title: "ПРОГРАМА ІНСАЙДЕРСЬКОЇ ЗАГРОЗИ (PM-12)",
      parameters: [
        {:pm_12_01,
         "Впроваджено програму інсайдерської (внутрішньої) загрози, яка передбачає наявність команди з обробки інцидентів, пов’язаних з внутрішньою дисципліною",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pm-13") do
    %{
      id: :"id-spe-pm-13",
      description: "",
      title: "БЕЗПЕКА ТА ПРИВАТНІСТЬ ПРАЦІВНИКІВ (PM-13)",
      parameters: [
        {:pm_13_01,
         "Існує програма розвитку та вдосконалення спеціалістів з питань безпеки",
         [type: :string, default: nil]},
        {:pm_13_02,
         "Створена програма розвитку та вдосконалення спеціалістів з питань приватності",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pm-14") do
    %{
      id: :"id-spe-pm-14",
      description: "Запровадити програму інформування про загрози, яка містить можливості спільного обміну інформацією між організаціями для аналізу загроз.",
      title: "ТЕСТУВАННЯ, НАВЧАННЯ ТА МОНІТОРИНГ (PM-14)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-pm-15") do
    %{
      id: :"id-spe-pm-15",
      description: "",
      title: "КОНТАКТИ З ГРУПАМИ ТА АСОЦІАЦІЯМИ З ПИТАНЬ БЕЗПЕКИ ІНФОРМАЦІЇ ТА ПРИВАТНОСТІ (PM-15)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-pm-16") do
    %{
      id: :"id-spe-pm-16",
      description: "",
      title: "ПРОГРАМА ІНФОРМУВАННЯ ПРО ЗАГРОЗИ (PM-16)",
      parameters: [
        {:pm_16_01,
         "Впроваджена програма інформування про загрози, яка передбачає можливість обміну інформацією між організаціями для розвідки загроз",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pm-16-1") do
    %{
      id: :"id-spe-pm-16-1",
      description: "",
      title: "automated mechanisms are employed to maximize the effectiveness of sharing threat intelligence information. (PM-16(1))",
      parameters: [
        {:pm_16_1_01,
         "Automated mechanisms are employed to maximize the effectiveness of sharing threat intelligence information",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pm-17") do
    %{
      id: :"id-spe-pm-17",
      description: "a. Розробити політику та процедури для забезпечення того, щоб вимоги до захисту публічної (некласифікованої) інформації, яка обробляється, зберігається або передається у зовнішніх системах, здійснювалися відповідно до чинного законодавства. b. Оновлювати політику та процедури [Призначення: з визначеною організацією частотою].",
      title: "ЗАХИСТ ПУБЛІЧНОЇ ІНФОРМАЦІЇ У ЗОВНІШНІХ СИСТЕМАХ (PM-17)",
      parameters: [
        {:pm_17_odp_01,
         "Визначена періодичність перегляду та оновлення політики",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:pm_17_odp_02,
         "Визначено періодичність перегляду та оновлення процедур; PM-17a.[01] розроблено політику, яка гарантує, що вимоги щодо захисту публічної (некласифікованої) інформації, яка обробляється, зберігається або передається в зовнішніх системах, виконуються відповідно до чинних законів, виконавчих наказів, директив, політик, нормативних актів та стандартів; PM-17a.[02] встановлені процедури для забезпечення виконання вимог щодо захисту публічної (некласифікованої) інформації, яка обробляється, зберігається або передається в зовнішніх системах, відповідно до чинних законів, наказів, директив, політик, нормативно-правових актів та стандартів; PM-17b.[01] переглядається та оновлюється політика частота; PM-17b.[02] переглядаються та оновлюються процедури частота",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-pm-18") do
    %{
      id: :"id-spe-pm-18",
      description: "a. b. Розробити та поширити загальноорганізаційну програму (концепцію) забезпечення приватності, яка: 1. містить опис структури програми забезпечення приватності та ресурсів, призначених для її реалізації; 2. містить огляд вимог до забезпечення приватності й опис засобів управління програмою забезпечення приватності та загальних заходів захисту, встановлених або запланованих для задоволення цих вимог; 3. визначає обов’язки посадової особи щодо приватності, а також визначає обов’язки інших посадових осіб і персоналу з питань забезпечення приватності; 4. описує зобов’язання керівництва, стратегічні цілі та завдання програми забезпечення приватності; 5. відображає координацію між організаційними структурами, відповідальними за різні аспекти приватності; 6. затверджена високопосадовцем, який є відповідальним (та підзвітним) за: управління ризиками приватності, що виникають при здійсненні операцій організації (включно із завданнями, функціями, іміджем і репутацією); організаційними активами, фізичними особами, іншими організаціями та країнами. Оновлювати програму [Призначення: за визначеною організацією частотою], а також в разі змін законодавства, змін в організації і виявлення проблем в ході реалізації програми або оцінювання заходів приватності.",
      title: "ПРОГРАМА (КОНЦЕПЦІЯ) ЗАБЕЗПЕЧЕННЯ ПРИВАТНОСТІ (PM-18)",
      parameters: [
        {:pm_18_odp,
         "Визначена періодичність (концепції) приватності; оновлення плану програми PM-18a.[01] розроблено загальноорганізаційний план програми (концепції) приватності, який містить огляд програми приватності організації; PM-18a.01[01] план програми (концепції) приватності містить опис структури програми конфіденційності; PM-18a.01[02] план програми (концепції) приватності містить опис ресурсів, призначених для реалізації програми конфіденційності; PM-18a.02[01] план програми (концепції) приватності містить огляд вимог до програми конфіденційності; PM-18a.02[02] план програми (концепції) приватності містить опис наявних або запланованих засобів контролю для управління програмою (концепцією) приватності для виконання вимог програми; PM-18a.02[03] план програми (концепції) приватності містить опис загальних засобів контролю, що діють або заплановані для виконання вимог програми конфіденційності; PM-18a.03[01] в плані програми (концепції) приватності передбачена роль старшої посадової особи організації з питань приватності; PM-18a.03[02] план програми (концепції) приватності включає визначення та призначення ролей інших посадових осіб і співробітників, відповідальних за забезпечення приватності, та їхні обов'язки; PM-18a.04[01] план програми (концепції) приватності описує зобов'язання керівництва; PM-18a.04[02] в плані програми (концепції) приватності описано дотримання вимог; PM-18a.04[03] план програми (концепція) приватності описує стратегічні цілі та завдання програми приватності; PM-18a.05 план програми (концепція) приватності відображає координацію між підрозділами організації, відповідальними за різні аспекти приватності; PM-18a.06 затверджено план програми (концепцію) приватності вищою посадовою особою, яка несе відповідальність і підзвітність за ризики для приватності, яких зазнають операції організації (включно з місією, функціями, іміджем і репутацією), активи організації, окремі особи, інші організації та держава; PM-18a.[02] поширюється план програми (концепція) приватності; PM-18b.[01] оновлено план програми (концепцію) приватності частота; PM-18b.[02] оновлюється план програми (концепція) приватності відповідно до змін у державному законодавстві та політиці щодо приватності; PM-18b.[03] оновлюється план програми відповідно до змін в організації; PM-18b.[04] оновлюється план програми (концепція) приватності забезпечення приватності для вирішення проблем, виявлених під час реалізації плану або оцінок контролю за дотриманням приватності. (концепція) приватності",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pm-19") do
    %{
      id: :"id-spe-pm-19",
      description: "Призначити старшу посадову особу з питань забезпечення приватності з повноваженнями, завданням, підзвітністю і ресурсами для координації, розробки та реалізації відповідних вимог забезпечення приватності й управління ризиками приватності в рамках програми забезпечення приватності всієї організації.",
      title: "КЕРІВНІ РОЛІ ПРОГРАМИ ПРИВАТНОСТІ (PM-19)",
      parameters: [
        {:pm_19_01,
         "Визначена періодичність приватності; оновлення плану програми",
         [type: :string, default: "щорічно"]},
        {:pm_19_02,
         "Розроблено загальноорганізаційний план програми приватності, який містить огляд програми приватності для організації",
         [type: :string, default: nil]},
        {:pm_19_03,
         "Містить план програми приватності опис структури програми приватності",
         [type: :string, default: nil]},
        {:pm_19_04,
         "Містить план програми приватності опис ресурсів, призначених для реалізації програми приватності",
         [type: :string, default: nil]},
        {:pm_19_05,
         "Містить план програми приватності огляд вимог до програми приватності",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pm-20") do
    %{
      id: :"id-spe-pm-20",
      description: "підтримувати центральну вебсторінку ресурсу на головному загальнодоступному вебсайті організації, яка слугує центральним джерелом інформації про програму приватності організації та яка: a. забезпечує доступ громадськості до інформації про діяльність щодо забезпечення приватності в організації та можливість комунікації з уповноваженою посадовою особою з питань забезпечення приватності; b. оприлюднює організаційну політику забезпечення приватності на вебсайті організації або іншим чином; c. використовує публічні адреси електронної пошти та/або телефонні лінії, щоб дати можливість громадськості надавати відгуки та/або направляти запитання щодо програми приватності в організації.",
      title: "СИСТЕМА ЗАПИСІВ ПРОГРАМИ ПРИВАТНОСТІ (PM-20)",
      parameters: [
        {:pm_20_01,
         "Ведеться центральна вебсторінка загальнодоступному вебсайті організації; на головному",
         [type: :string, default: nil]},
        {:pm_20_02,
         "Слугує вебсторінка основним джерелом програму приватності організації; інформації про PM-20a.[01] забезпечує вебсторінка доступ громадськості до інформації про діяльність організації, пов'язану із захистом приватності; PM-20a.[02] забезпечує вебсторінка можливість громадськості спілкуватися з вищим посадовцем організації з питань приватності; PM-20b.[01] забезпечує вебсторінка публічний доступ до інформації організації щодо приватності; PM-20b.[02] забезпечує вебсторінка публічний доступ до звітів про приватність організації; PM-20c. є на веб-сторінці загальнодоступні адреси електронної пошти та/або номери телефонів, щоб громадськість могла надавати зворотній зв'язок та/або направляти запитання до відділів з питань приватності",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pm-21") do
    %{
      id: :"id-spe-pm-21",
      description: "a. Забезпечити доступ громадськості до інформації із забезпечення приватності в організації та можливість комунікації з уповноваженою посадовою особою з питань забезпечення приватності щодо: 1. дати, характеру та мети кожного розкриття запису; 2. імені та адреси особи або організації, щодо яких було зроблено розкриття даних. b. Обліковувати та зберігати випадки розкриття персональних даних протягом терміну дії запису або п’яти років після розкриття інформації. c. Здійснювати облік випадків розкриття персональних даних, доступних особі, зазначеній у записі за запитом.",
      title: "ОБЛІК РОЗКРИТТЯ ПЕРСОНАЛЬНИХ ДАНИХ (PM-21)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-pm-22") do
    %{
      id: :"id-spe-pm-22",
      description: "Розробити та задокументувати загальноорганізаційну політику та процедури, які довзолять: a. Проводити огляд точності, актуальності, своєчасності та повноти персональних даних протягом їх життєвого циклу; b. Коригувати або видаляти неточну або застарілу інформацію; c. Інформувати осіб або інші відповідні організації про внесення змін або видалення персональної інформації; d. Оскаржувати відмови на запити щодо коригування чи видалення.",
      title: "УПРАВЛІННЯ ЯКІСТЮ ПЕРСОНАЛЬНИХ ДАНИХ (PM-22)",
      parameters: [
        {:pm_22_01,
         "Розроблені та задокументовані загальноорганізаційні політики управління якістю персональних даних",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_22_02,
         "Розроблені та задокументовані загальноорганізаційні процедури управління якістю персональних даних; PM-22a.[01] передбачено в політиці перевірку точності інформації, що ідентифікує особу, протягом усього життєвого циклу інформації; PM-22a.[02] передбачено в політиці перегляд актуальності інформації, що ідентифікує особу, протягом життєвого циклу інформації; PM-22a.[03] передбачено в політиці перевірку своєчасності інформації, що ідентифікує особу, протягом усього життєвого циклу інформації; PM-22a.[04] передбачено в політиці перевірку повноти інформації, що ідентифікує особу, протягом життєвого циклу інформації; PM-22a.[05] передбачено в процедурах перевірку точності інформації, що ідентифікує особу, протягом усього життєвого циклу інформації; PM-22a.[06] передбачено в процедурах перегляд актуальності інформації, що ідентифікує особу, протягом усього життєвого циклу інформації; PM-22a.[07] процедури передбачають перевірку своєчасності інформації, що ідентифікує особу, протягом усього життєвого циклу інформації; PM-22a.[08] передбачено в процедурах перевірку повноти інформації, що ідентифікує особу, протягом життєвого циклу інформації; PM-22b.[01] передбачено в політиці виправлення або видалення неточної або застарілої персональної інформації, що ідентифікує особу; PM-22b.[02] передбачено в процедурах виправлення або видалення неточної або застарілої персональної інформації; PM-22c.[01] передбачено в політиці розсилання повідомлень про виправлену або видалену персональну інформацію фізичним особам або іншим відповідним суб'єктам; PM-22c.[02] передбачено в процедурах повідомлення про виправлення або видалення персональних даних фізичним особам або іншим відповідним суб'єктам; PM-22d.[01] передбачено в політиці оскарження негативних рішень щодо запитів на виправлення або видалення; PM-22d.[02] передбачені процедури оскарження негативних рішень щодо запитів на виправлення або видалення",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pm-23") do
    %{
      id: :"id-spe-pm-23",
      description: "створити орган управління персональними даними, на якого покладено [Призначення: визначені організацією функції] та виконання [Призначення: визначені організацією обов’язки].",
      title: "ОРГАН УПРАВЛІННЯ ПЕРСОНАЛЬНИМИ ДАНИМИ (PM-23)",
      parameters: [
        {:pm_23_01,
         "Створено орган управління даними, що складається з ролей з обов'язками",
         [type: :string, default: nil]},
        {:pm_23_odp_01,
         "Визначені ролі органу управління персональними даними",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_23_odp_02,
         "Визначені обов'язки органу управління персональними даними",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pm-24") do
    %{
      id: :"id-spe-pm-24",
      description: "Створити орган з питань цілісності даних для здійснення: a. Розгляду пропозицій щодо проведення відповідної програми або участі у ній. b. Проведення огляду усіх поточних програм, в яких бере участь організація.",
      title: "ОРГАН З ПИТАНЬ ЦІЛІСНОСТІ ДАНИХ (PM-24)",
      parameters: [
        {:pm_24_01,
         "Створено орган з питань цілісності даних; PM-24a. розглядає орган з питань цілісності даних пропозиції щодо проведення або участі у відповідній програмі; PM-24b. проводить орган з питань цілісності даних щорічну перевірку всіх програм співставлення, в яких агентство брало участь",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-pm-25") do
    %{
      id: :"id-spe-pm-25",
      description: "a. Розробити та впровадити політики та процедури, спрямовані на врегулювання питань використання персональних даних для внутрішнього тестування, навчання та досліджень. b. Вжити заходи щодо обмеження або зведення до мінімуму кількості персональних даних, які використовуються для внутрішнього тестування, навчання та досліджень. c. Надавати дозвіл на використання персональних даних, коли така інформація вимагається для внутрішнього тестування, навчання і досліджень. d. Здійснювати огляд та оновлення політик та процедур, спрямованих на врегулювання питань використання персональних даних для внутрішнього тестування, навчання та досліджень [Призначення: з визначеною організацією частотою].",
      title: "МІНІМІЗАЦІЯ КІЛЬКОСТІ ПЕРСОНАЛЬНИХ ДАНИХ, ЩО ВИКОРИСТОВУЮТЬСЯ ПІД ЧАС ТЕСТУВАННЯ, НАВЧАННЯ ТА ДОСЛІДЖЕНЬ (PM-25)",
      parameters: [
        {:pm_25_odp_01,
         "Визначено періодичність перегляду політик, які стосуються використання персональних даних для внутрішнього тестування, навчання та досліджень",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_25_odp_02,
         "Визначено періодичність оновлення політик, які стосуються використання персональних даних для внутрішнього тестування, навчання та досліджень",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_25_odp_03,
         "Визначено періодичність перегляду процедур, які стосуються використання персональних даних для внутрішнього тестування, навчання та досліджень",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_25_odp_04,
         "Визначено періодичність оновлення процедур, які стосуються використання персональних даних для внутрішнього тестування, навчання та досліджень; PM-25a.[01] розроблені та задокументовані політики, які регулюють використання персональних даних для внутрішнього тестування; PM-25a.[02] розроблені та задокументовані політики, які стосуються використання персональних даних для внутрішнього навчання PM-25a.[03] розроблені та задокументовані політики, які регулюють використання персональних даних для внутрішніх досліджень; PM-25a.[04] розроблені та задокументовані процедури, які стосуються використання персональних даних для внутрішнього тестування; PM-25a.[05] розроблені та задокументовані процедури, які стосуються використання персональних даних для внутрішнього навчання; PM-25a.[06] розроблені та задокументовані процедури, які стосуються використання персональних даних для внутрішніх досліджень; PM-25a.[07] впроваджено політику, яка регулює використання персональних даних для внутрішнього тестування; PM-25a.[08] впроваджуються політики, які стосуються використання персональних даних для навчання; PM-25a.[09] впроваджуються політики, які стосуються використання персональної інформації для досліджень; PM-25a.[10] впроваджені процедури, які стосуються використання персональних даних для внутрішнього тестування; PM-25a.[11] впроваджені процедури, які стосуються використання персональної інформації для навчання; PM-25a.[12] впроваджені процедури, які стосуються використання особистої інформації для досліджень; PM-25b.[01] обмежено або зведено до мінімуму кількість персональних даних, що використовуються для цілей внутрішнього тестування; PM-25b.[02] обмежено або зведено до мінімуму обсяг інформації, що ідентифікує особу, яка використовується для внутрішніх навчальних цілей; PM-25b.[03] обмежено або зведено до мінімуму обсяг персональних даних, що використовуються для внутрішніх досліджень; PM-25c.[01] дозволено використання внутрішнього тестування; персональних даних для PM-25c.[02] дозволено використання внутрішнього навчання; персональних даних для PM-25c.[03] дозволено необхідне використання персональних даних для внутрішніх досліджень; PM-25d.[01] переглядаються політики частота; PM-25d.[02] оновлюються політики частота; PM-25d.[03] переглядаються процедури частота; PM-25d.[04] оновлюються процедури частота",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pm-26") do
    %{
      id: :"id-spe-pm-26",
      description: "Впровадити процес отримання та реагування на скарги, проблеми чи запитання від фізичних осіб щодо організаційної практики забезпечення приватності, який охоплює: a. механізми, які легко використовувати та які є легкодоступними для громадськості; b. усю інформацію, необхідну для успішного подання скарг; c. механізми відстеження, що забезпечують отримання всіх скарг та їх вчасний і належний розгляд протягом [Призначення: визначений організацією період часу]; d. підтвердження отримання скарг, заявлених проблем чи запитань від фізичних осіб протягом [Призначення: визначений організацією період часу]; e. надання відповідей на отримані скарги, заявлені проблеми чи запитання від фізичних осіб протягом [Призначення: визначений організацією період часу].",
      title: "УПРАВЛІННЯ СКАРГАМИ (PM-26)",
      parameters: [
        {:pm_26_01,
         "Впроваджено процес отримання скарг, занепокоєнь або запитань від фізичних осіб про безпеку та конфіденційність в організації",
         [type: :string, default: nil]},
        {:pm_26_02,
         "Впроваджено процес реагування на скарги, занепокоєння або запитання від фізичних осіб про безпеку та конфіденційність в організації; PM-26a.[01] включає процес управління скаргами механізми, які є простими у використанні для громадськості; PM-26c.[02] включає процес управління скаргами механізми, які є легкодоступними для громадськості; PM-26b. містить процес управління скаргами всю інформацію, необхідну для успішного подання скарг; PM-26c.[01] включає процес управління скаргами механізми відстеження, які гарантують, що всі скарги будуть розглянуті протягом періоду часу; період для підтвердження PM-26c.[02] включає процес управління скаргами механізми відстеження, щоб гарантувати, що всі скарги розглядаються протягом часового періоду; PM-26d. передбачає процес управління скаргами підтвердження отримання скарг, занепокоєнь або запитань від фізичних осіб протягом часового періоду; PM-26e. включає процес управління скаргами реагування на скарги, занепокоєння або питання від фізичних осіб протягом часового періоду",
         [type: :integer, default: 30]},
        {:pm_26_odp_01,
         "Визначено період часу, протягом якого мають бути розглянуті скарги (в тому числі звернення або питання) від фізичних осіб",
         [type: :integer, default: 30]},
        {:pm_26_odp_02,
         "Визначено період часу, протягом якого мають бути оброблені скарги (в тому числі звернення або питання) від фізичних осіб",
         [type: :integer, default: 30]},
        {:pm_26_odp_03,
         "Визначено часовий отримання скарг",
         [type: :integer, default: 30]},
        {:pm_26_odp_04,
         "Визначено термін для відповіді на скарги",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pm-27") do
    %{
      id: :"id-spe-pm-27",
      description: "a. Визначити та задокументувати: 1. припущення, що впливають на оцінку ризиків, реагування на ризики та моніторинг ризиків; 2. обмеження, що впливають на оцінку ризиків, реагування на ризики та моніторинг ризиків; 3. пріоритети та компроміси, які розглядаються організацією для здійснення управління ризиками; 4. стійкість організації до ризиків. b. Поінформувати [Призначення: визначений організацією персонал] про результати визначення ризиків. c. Переглядати та оновлювати підходи щодо визначення ризиків [Призначення: з визначеною організацією частотою].",
      title: "ЗВІТНІСТЬ З ПИТАНЬ ЗАБЕЗПЕЧЕННЯ ПРИВАТНОСТІ (PM-27)",
      parameters: [
        {:pm_27_odp_01,
         "Визначені звіти з питань забезпечення приватності",
         [type: :string, default: nil]},
        {:pm_27_odp_02,
         "Визначені органи нагляду за дотриманням приватності",
         [type: :string, default: nil]},
        {:pm_27_odp_03,
         "Визначені посадові особи, відповідальні за контроль і дотриманням програми приватності",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_27_odp_04,
         "Визначена періодичність перегляду та оновлення звітів про приватність; PM-27a. розроблено приватності; PM-27a.01 передаються звіти з питань забезпечення приватності до наглядових органів, щоб продемонструвати підзвітність законодавчим, регуляторним та політичним мандатам щодо приватності; звіти з питань PM-27a.02[01] поширюються звіти про конфіденційність серед посадових осіб; PM-27a.02[02] поширюються звіти з питань забезпечення приватності серед іншого персоналу, відповідального за контроль за дотриманням програми конфіденційності; PM-27b. переглядаються та оновлюються звіти з питань забезпечення приватності частота",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pm-28") do
    %{
      id: :"id-spe-pm-28",
      description: "",
      title: "ОЦІНКА РИЗИКІВ (PM-28)",
      parameters: [
        {:pm_28_odp_01,
         "Визначено персонал, який отримуватиме результати визначення ризиків",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_28_odp_02,
         "Визначено періодичність перегляду та міркувань щодо структуризації ризиків; PM-28a.01[01] визначені та задокументовані припущення, що впливають на оцінку ризиків; PM-28a.01[02] визначені та задокументовані припущення, що впливають на реагування ризиків; PM-28a.01[03] визначені та задокументовані припущення, що впливають на моніторинг ризиків; PM-28a.02[01] визначені та задокументовані обмеження, що впливають на оцінку ризиків; PM-28a.02[02] визначені та задокументовані обмеження, що впливають на реагування на ризики; PM-28a.02[03] визначені та задокументовані обмеження, що впливають на моніторинг ризиків; оновлення PM-28a.03[01] визначені та задокументовані пріоритети, розглядаються організацією для управління ризиками; які PM-28a.03[02] визначені та задокументовані компроміси, розглядаються організацією для управління ризиками; які PM-28a.04 визначена та задокументована організаційна толерантність до ризиків; PM-28b. поширюються результати діяльності з фреймворкінгу ризиків серед персоналу ; PM-28c. переглядаються та оновлюються міркування фреймінгу ризиків частота. щодо",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pm-29") do
    %{
      id: :"id-spe-pm-29",
      description: "a. Розробити план управління ризиками ланцюга постачання, пов’язаного з розробкою, придбанням, обслуговуванням та утилізацією систем, компонентів системи та послуг для системи. b. Реалізувати план управління ризиками ланцюга постачання послідовно та наскрізно по всій організації. c. Переглядати й оновлювати план управління ризиками ланцюга постачання [Призначення: з визначеною організацією частотою] або, якщо потрібно, у разі змін в організації.",
      title: "РОЛІ КЕРІВНИКІВ ПРОГРАМИ УПРАВЛІННЯ РИЗИКАМИ (PM-29)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-pm-30") do
    %{
      id: :"id-spe-pm-30",
      description: "",
      title: "ПЛАН УПРАВЛІННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ (PM-30)",
      parameters: [
        {:pm_30_odp,
         "Призначено старшу посадову особу, відповідальну за управління ризиками ланцюга постачання; PM-30a.[01] узгоджує старша посадова особа, відповідальна за управління ризиками ланцюга постачання, процеси управління інформаційною безпекою та конфіденційністю з процесами стратегічного, операційного та бюджетного планування; PM-30a.[02] створена посада (функція) ризик-менеджер; PM-30a.[03] розглядає та аналізує керівник з управління ризиками (функція) ризики з точки зору всієї організації; PM-30a.[04] забезпечує керівник (функція) з управління ризиками узгоджене управління ризиками в межах всієї організації. PM-30a.[05] стратегія управління ризиками ланцюга постачання враховує ризики, пов'язані з придбанням систем; PM-30a.[06] стратегія управління ризиками ланцюга поставок враховує ризики, пов'язані з придбанням компонентів системи; PM-30a.[07] стратегія управління ризиками ланцюга поставок враховує ризики, пов'язані з придбанням системних послуг; PM-30a.[08] тратегія управління ризиками ланцюга поставок враховує ризики, пов'язані з обслуговуванням систем; PM-30a.[09] стратегія управління ризиками ланцюга поставок враховує ризики, пов'язані з обслуговуванням компонентів системи; PM-30a.[10] стратегія управління ризиками ланцюга поставок враховує ризики, пов'язані з обслуговуванням системних послуг; PM-30a.[11] враховує стратегія управління ризиками ланцюга постачання ризики, пов'язані з утилізацією систем; PM-30a.[12] враховує стратегія управління ризиками ланцюга постачання ризики, пов'язані з утилізацією компонентів системи; PM-30a.[13] стратегія управління ризиками ланцюга поставок враховує ризики, пов'язані з утилізацією системних послуг; PM-30b. стратегія управління ризиками ланцюга послідовно впроваджується в організації; PM-30c. переглядається та оновлюється стратегія управління ризиками ланцюга постачання частота або в міру необхідності у зв'язку з організаційними змінами поставок",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pm-31") do
    %{
      id: :"id-spe-pm-31",
      description: "Розробити план безперервного моніторингу в масштабах всієї організації та впровадити програми безперервного моніторингу, які включають: a. Встановити відповідні показників для моніторингу в масштабах всієї організації [Призначення: визначені організацією показники]; b. Встановити [Призначення: частота, визначеної організацією] для здійснення моніторингу та [Призначення: періодичність, визначена організацією] проведення оцінки ефективності контролю; c. Постійний моніторинг визначених організацією показників відповідно до стратегії безперервного моніторингу; d. Співставлення та аналіз інформації, отриманої в результаті здійснення моніторингу, та контрольних оцінок; e. Заходи реагування на результати аналізу оцінок контролю та моніторингових даних; f. Звітування про стан безпеки та приватності систем організації перед [Призначення: визначеним організацією персоналом чи посадовою особою] [Призначення: з визначеною організацією періодичністю].",
      title: "ПЛАН БЕЗПЕРЕРВНОГО МОНІТОРИНГУ (PM-31)",
      parameters: [
        {:pm_31_01,
         "Розроблена загальноорганізаційна стратегія безперервного моніторингу; PM-31a. впроваджуються програми безперервного моніторингу, які включають встановлення параметрів, що підлягають моніторингу; PM-31b.[01] впроваджено програми безперервного моніторингу, які встановлюють частоту для моніторингу; PM-31b.[02] впроваджуються програми безперервного моніторингу, які встановлюють частоту для оцінки ефективності контролю; про стан PM-31c. впроваджуються програми безперервного моніторингу, які включають моніторинг параметрів на постійній основі відповідно до стратегії безперервного моніторингу; PM-31d.[01] впроваджуються програми безперервного моніторингу, які включають співставлення інформації, отриманої в результаті контрольних оцінок та моніторингу; PM-31d.[02] впроваджуються програми постійного моніторингу, які включають аналіз інформації, отриманої в результаті контрольних оцінок та моніторингу; PM-31e.[01] впроваджуються програми безперервного моніторингу, які передбачають заходи реагування на аналіз інформації, отриманої в результаті оцінки результатів контролю; PM-31e.[02] впроваджуються програми безперервного моніторингу, які передбачають заходи реагування на результати аналізу інформації, отриманої під час моніторингу; PM-31f.[01] впроваджено програми безперервного моніторингу, які передбачають звітування про стан безпеки систем організації перед персонал або ролі частота; PM-31f.[02] впроваджені програми безперервного моніторингу, які передбачають звітування про стан конфіденційності організаційних систем перед персонал або ролі частота",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_31_odp_01,
         "Визначені параметри для безперервного моніторингу в масштабах всієї організації",
         [type: :string, default: nil]},
        {:pm_31_odp_02,
         "Визначено періодичність моніторингу",
         [type: :string, default: "щорічно"]},
        {:pm_31_odp_03,
         "Визначена періодичність оцінки ефективності контролю",
         [type: :string, default: "щорічно"]},
        {:pm_31_odp_04,
         "Визначено персонал або ролі для звітування про стан безпеки систем організації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_31_odp_05,
         "Визначено персонал або ролі для звітування про стан конфіденційності систем організації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pm_31_odp_06,
         "Визначено періодичність звітування про стан безпеки систем організації",
         [type: :string, default: "щорічно"]},
        {:pm_31_odp_07,
         "Визначено періодичність звітування конфіденційності систем організації",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-pm-32") do
    %{
      id: :"id-spe-pm-32",
      description: "Включіть ролі й обов’язки з безпеки та приватності в опис посади в організації.",
      title: "ПРИЗНАЧЕННЯ (PM-32)",
      parameters: [
        {:pm_32_01,
         "Аналізуються допоміжні послуги або функції, необхідні для виконання місії, для забезпечення того, щоб інформаційні ресурси використовувалися відповідно до їхнього призначення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ps-1") do
    %{
      id: :"id-spe-ps-1",
      description: "",
      title: "Політика та процедури кадрової безпеки (PS-1)",
      parameters: [
        {:ps_1_odp_01,
         "Визначено персонал або ролі, на які поширюється політика кадрової безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ps_1_odp_02,
         "Визначено персонал або ролі, на які поширюються процедури кадрової безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ps_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнеспроцесу; рівень системи}",
         [type: :string, default: nil]},
        {:ps_1_odp_04,
         "Визначено посадову особу, яка керуватиме політикою та процедурами кадрової безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ps_1_odp_05,
         "Визначена періодичність перегляду та оновлення поточної політики кадрової безпеки",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ps_1_odp_06,
         "Є події, які вимагають перегляду та оновлення поточної політики кадрової безпеки",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ps_1_odp_07,
         "Визначено періодичність перегляду та оновлення поточних процедур кадрової безпеки",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-ps-2") do
    %{
      id: :"id-spe-ps-2",
      description: "",
      title: "Визначення посадового ризику (PS-2)",
      parameters: [
        {:ps_2_odp,
         "Визначено періодичність перегляду ідентифікаторів посадових ризиків; та оновлення PS-02a. всім посадам в організації присвоєно ідентифікатор ризику; PS-02b. вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнес-процесу; рівень системи}; PS-02c. встановлені критерії відбору для осіб, які обіймають посади в організації",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ps-3") do
    %{
      id: :"id-spe-ps-3",
      description: "",
      title: "Перевірка персоналу (PS-3)",
      parameters: [
        {:ps_3_odp_01,
         "Визначені умови, що вимагають повторної перевірки осіб",
         [type: :list, default: []]},
        {:ps_3_odp_02,
         "Визначена частота повторної перевірки осіб, для яких це показано; PS-03a. проходять особи перевірку перед тим, як надати їм доступ до системи; PS-03b.[01] проходять особи повторну перевірку відповідно до умови, що вимагають повторної перевірки; PS-03b.[02] проводиться повторна перевірка у випадках, коли це зазначено, частота",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ps-4") do
    %{
      id: :"id-spe-ps-4",
      description: "",
      title: "Звільнення персоналу (PS-4)",
      parameters: [
        {:ps_4_odp_01,
         "Визначено період часу, протягом якого забороняється доступ до системи",
         [type: :integer, default: 30]},
        {:ps_4_odp_02,
         "Визначені теми інформаційної безпеки для обговорення під час проведення співбесід; PS-04a. при звільненні працівника доступ до системи вимикається протягом часового періоду; PS-04b. припиняють дію або анулюють будь-які автентифікатори та облікові дані після припинення трудових відносин з окремими особами; PS-04c. проводяться при звільненні окремих працівників співбесіди, які включають обговорення питань інформаційної безпеки; PS-04d. отримується після звільнення особи все майно, пов'язане з безпекою організаційної системи; PS-04e. зберігається доступ до організаційної інформації та систем, які раніше перебували під контролем особи, що звільняється, після припинення нею трудових відносин",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ps-5") do
    %{
      id: :"id-spe-ps-5",
      description: "",
      title: "Переведення персоналу (PS-5)",
      parameters: [
        {:ps_5_odp_01,
         "Визначені дії, які мають бути ініційовані після переведення або перепризначення",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ps_5_odp_02,
         "Визначено період часу, протягом якого мають бути здійснені дії з переведення або перепризначення після переведення або перепризначення",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ps_5_odp_03,
         "Визначено персонал або ролі, про які необхідно повідомляти, коли осіб призначають на інші посади або переводять на інші посади в організації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ps_5_odp_04,
         "Визначено період часу, протягом якого необхідно повідомляти визначений організацією персонал або ролі, коли осіб перепризначають або переводять на інші посади в межах організації; PS-05a. переглядаються та підтверджуються поточні потреби в логічних та фізичних дозволах на доступ до систем та об'єктів при перепризначенні або переведенні осіб на інші посади в організації; PS-05b. були ініційовані дії з переведення або перепризначення протягом періоду часу після формальної дії з переведення; PS-05c. змінюється авторизація доступу за необхідності, щоб відповідати будь-яким змінам в оперативних потребах у зв'язку з перепризначенням або переведенням; PS-05d. було повідомлено персонал або ролі протягом часового періоду",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ps-6") do
    %{
      id: :"id-spe-ps-6",
      description: "",
      title: "Угоди про доступ (PS-6)",
      parameters: [
        {:ps_6_odp_01,
         "Визначено періодичність перегляду та оновлення угод про доступ",
         [type: :string, default: "щорічно"]},
        {:ps_6_odp_02,
         "Визначена періодичність перепідписання угод про доступ для збереження доступу до інформації організації; PS-06a. розроблені та задокументовані угоди про доступ до систем організації; PS-06b. переглядаються та оновлюються угоди про доступ частота; PS-06c.01 підписують особи, яким потрібен доступ до інформації та систем організації, відповідні угоди про доступ до того, як їм буде надано доступ; PS-06c.02 перепідписують особи, яким потрібен доступ до інформації та систем організації, угоди про доступ для збереження доступу до систем організації, коли угоди про доступ були оновлені чи як частота",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ps-6-1") do
    %{
      id: :"id-spe-ps-6-1",
      description: "",
      title: "УГОДИ ПРО ДОСТУП - ІНФОРМАЦІЯ, ЩО ВИМАГАЄ СПЕЦІАЛЬНОГО ЗАХИСТУ (PS-6(1))",
      parameters: [
        {:ps_6_1_01,
         "УГОДИ ПРО ДОСТУП - ІНФОРМАЦІЯ, ЩО ВИМАГАЄ СПЕЦІАЛЬНОГО ЗАХИСТУ [Вилучено: включено до PS-3] РS-6(2) УГОДИ ПРО ДОСТУП - ІНФОРМАЦІЯ З ОБМЕЖЕНИМ ДОСТУПОМ, ЩО ВИМАГАЄ СПЕЦІАЛЬНОГО ЗАХИСТУ",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ps-7") do
    %{
      id: :"id-spe-ps-7",
      description: "",
      title: "Безпека зовнішнього персоналу (PS-7)",
      parameters: [
        {:ps_7_odp_01,
         "Визначено персонал або ролі, які мають бути повідомлені про будь-які кадрові переведення або звільнення зовнішнього персоналу, який володіє організаційними повноваженнями та/або бейджами, або має системні привілеї",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ps_7_odp_02,
         "Визначено період часу, протягом якого сторонні провайдери повинні повідомляти визначений організацією персонал або ролі про будь-які кадрові переведення або звільнення зовнішнього персоналу, який володіє організаційними повноваженнями та/або бейджами або має системні привілеї; PS-07a. встановлені вимоги до безпеки персоналу, включаючи ролі та обов'язки зовнішніх постачальників послуг у сфері безпеки; PS-07b. зобов'язані зовнішні провайдери дотримуватися політики та процедур кадрової безпеки, встановлених організацією; PS-07c. задокументовані вимоги до безпеки персоналу; PS-07d. зобов'язані зовнішні провайдери повідомляти персонал або ролі про будь-які кадрові переведення або звільнення зовнішнього персоналу, який володіє організаційними повноваженнями та/або бейджами або має системні привілеї протягом часового періоду; PS-07e. контролюється дотримання провайдером вимог щодо безпеки персоналу",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ps-8") do
    %{
      id: :"id-spe-ps-8",
      description: "",
      title: "Кадрові санкції (PS-8)",
      parameters: [
        {:ps_8_odp_01,
         "Визначено персонал або ролі, про які необхідно повідомляти, коли ініціюється офіційний процес санкцій щодо працівників",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ps-9") do
    %{
      id: :"id-spe-ps-9",
      description: "",
      title: "ОПИС ПОЗИЦІЙ (PS-9)",
      parameters: [
        {:ps_9_02,
         "Включені функції та обов'язки з безпеки в описи посадових осіб в організації; включені ролі та обов'язки щодо конфіденційності в описи посадових осіб в організації",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-1") do
    %{
      id: :"id-spe-pt-1",
      description: "a. Розробіть, задокументуйте та поширте [Призначення: персонал або ролі, визначені організацією]: 1. [Вибір (один або декілька): Рівень організації; Рівень місії/бізнес-процесу; рівень системи], обробки персональних даних та політики прозорості, який: a) розглядає мету, сферу діяльності, ролі, відповідальність, зобов’язання керівництва, координацію між організаційними підрозділами та відповідність; b) відповідає чинним законам, розпорядженням, директивам, положенням, політикам, стандартам і рекомендаціям. 2. Процедури для реалізації політики обробки та прозорості персональних даних, а також пов’язані засоби контролю; b. Призначте [Призначення: посадову особу, визначену організацією] для керування розробкою, документуванням і розповсюдженням політики й процедур щодо обробки персональних даних та прозорості; c. Перегляньте та оновіть поточні процедури обробки та прозорість персональних даних: 1. Політика [Призначення: частота, визначена організацією] і наступні [Призначення: події, визначені організацією]; 2. Процедури [Призначення: частота, визначена організацією] та наступні [Призначення: подія, визначена організацією].",
      title: "PT (PT-1)",
      parameters: [
        {:pt_1_odp_01,
         "Визначено персонал або ролі, на які поширюється політика обробки персональних даних та забезпечення прозорості",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_1_odp_02,
         "Визначено персонал або ролі, на які поширюються процедури обробки персональних даних та політики прозорості",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнеспроцесу; рівень системи}",
         [type: :string, default: nil]},
        {:pt_1_odp_04,
         "Визначено посадову особу, яка керуватиме політикою та процедурами обробки персональних даних, а також політикою та процедурами прозорості",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_1_odp_05,
         "Визначена періодичність перегляду та оновлення поточної політики обробки та прозорості інформації, що ідентифікує особу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_1_odp_06,
         "Є події, які вимагають перегляду та оновлення поточної політики обробки персональних даних та прозорості",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_1_odp_07,
         "Визначена частота, з якою переглядаються та оновлюються поточні процедури обробки персональних даних та забезпечення прозорості",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-2") do
    %{
      id: :"id-spe-pt-2",
      description: "a. визначити та задокументувати [Призначення: повноваження, визначені організацією], які дозволяють [Призначення: обробку, визначену організацією] персональної інформації; b. обмежити [Призначення: обробку, визначену організацією] персональної інформації лише таким чином, яким дозволено (тільки до того, що дозволено)",
      title: "ПОВНОВАЖЕННЯ НА ОБРОБКУ ПЕРСОНАЛЬНИХ ДАНИХ (PT-2)",
      parameters: [
        {:pt_2_odp_01,
         "Визначені повноваження щодо надання дозволу на обробку (визначені в PT-02_ODP[02]) персональних даних",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_2_odp_02,
         "Визначено тип обробки персональних даних",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_2_odp_03,
         "Визначено тип обробки підлягають обмеженню; PT-02a. визначено та задокументовано орган, який дозволяє обробку персональних даних; PT-02b. обробка персональних обмежується лише таким чином, яким дозволено. персональних даних, що даних,",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-2-1") do
    %{
      id: :"id-spe-pt-2-1",
      description: "",
      title: "ПОВНОВАЖЕННЯ НА ТЕГУВАННЯ ДАНИХ (PT-2(1))",
      parameters: [
        {:pt_2_1_01,
         "Теги даних, що містять <PT-02(01) _ODP[01] санкціонована обробка>, прикріплені до <PT-02(01) _ODP[02] елементів інформації, що іденти0фікує особу>",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-2-2") do
    %{
      id: :"id-spe-pt-2-2",
      description: "",
      title: "ПОВНОВАЖЕННЯ АВТОМАТИЗАЦІЯ (PT-2(2))",
      parameters: [
        {:pt_2_2_01,
         "Управління дотриманням санкціонованої обробки персональних даних здійснюється за допомогою <PТ02(02)_ODP автоматизовані механізми обробки персональних даних>",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_2_2_odp,
         "Визначені автоматизовані механізми, які використовуються для управління дотриманням санкціонованої обробки інформації, що ідентифікує особу",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-3") do
    %{
      id: :"id-spe-pt-3",
      description: "a. визначити та задокументувати [Призначення: цілі, визначені організацією] для обробки персональних даних; b. описати мету (цілі) у публічних повідомленнях про конфіденційність і політиках організації; c. обмежити [Призначення: обробку, визначену організацією] персональних даних лише тією, яка сумісна з визначеною ціллю(ями); d. відстежувати зміни в обробці персональних даних та впроваджувати [Завдання: визначені організацією механізми], щоб гарантувати, що будь-які зміни вносяться відповідно до [Завдання: визначені організацією вимоги].",
      title: "ЦІЛІ ОБРОБКИ ПЕРСОНАЛЬНИХ ДАНИХ (PT-3)",
      parameters: [
        {:pt_3_odp_01,
         "Визначено мету (цілі) обробки персональних даних",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_3_odp_02,
         "Визначена обробка персональних даних, яка підлягає обмеженню",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_3_odp_03,
         "Визначені механізми, які мають бути впроваджені для забезпечення того, щоб будь-які зміни в персональних данних, вносилися відповідно до вимог",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_3_odp_04,
         "Визначені вимоги до зміни обробкиперсональних даних; PT-03a. визначено та задокументовано мету (цілі) обробки персональних даних; PT-03b.[01] описана мета (цілі) в публічних конфіденційність організації; PT-03b.[02] описана мета (цілі) в політиці організації; PT-03c обробка персональних даних, обмежується лише тим, що є сумісним з визначеною метою (цілями); PT-03d.[01] здійснюється моніторинг змін в обробці персональних даних; PT-03d.[02] впроваджено механізми для забезпечення того, щоб будь-які зміни вносилися відповідно до вимог. повідомленнях про",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-3-1") do
    %{
      id: :"id-spe-pt-3-1",
      description: "",
      title: "ЦІЛІ ОБРОБКИ ПЕРСОНАЛЬНИХ ДАНИХ - ТЕГУВАННЯ ДАНИХ (PT-3(1))",
      parameters: [
        {:pt_3_1_01,
         "Теги даних, що містять <PT-03(01) _ODP[01] цілі обробки>, приєднані до <PT-03(01) _ODP[02] елементів інформації, що ідентифікує особу>",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-3-2") do
    %{
      id: :"id-spe-pt-3-2",
      description: "",
      title: "ЦІЛІ ОБРОБКИ ПЕРСОНАЛЬНИХ ДАНИХ - АВТОМАТИЗАЦІЯ (PT-3(2))",
      parameters: [
        {:pt_3_2_01,
         "Відстежуються цілі обробки персональних даних за допомогою автоматизованих механізмів",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_3_2_odp,
         "Визначені автоматизовані механізми відстеження цілей обробки персональних даних",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-4") do
    %{
      id: :"id-spe-pt-4",
      description: "Впроваджувати [Призначення: інструменти або механізми, визначені організацією], щоб окремі особи давали згоду на обробку їх персональних даних до її збору, що полегшить прийняття обґрунтованих рішень особами.",
      title: "Згода на обробку персональних даних (PT-4)",
      parameters: [
        {:pt_4_01,
         "Впроваджено інструменти або механізми для надання фізичними особами згоди на обробку їхніх персональних даних до її збору, які сприяють прийняттю фізичними особами поінформованих рішень",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_4_odp,
         "Визначені інструменти або механізми, які мають бути застосовані для надання особами згоди на обробку їхніх персональних даних",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-4-1") do
    %{
      id: :"id-spe-pt-4-1",
      description: "",
      title: "ЗГОДА НА ОБРОБКУ ПЕРСОНАЛЬНИХ ДАНИХ - ІНДИВІДУАЛЬНА ЗГОДА НА ОБРОБКУ ПЕРСОНАЛЬНИХ ДАНИХ (PT-4(1))",
      parameters: [
        {:pt_4_1_odp,
         "Визначені механізми адаптації для обробки окремих елементів дозволів персональних даних; PT-04(01) передбачені механізми, які дозволяють особам пристосовувати дозволи на обробку до вибраних елементів персональних даних",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-4-2") do
    %{
      id: :"id-spe-pt-4-2",
      description: "",
      title: "ЗГОДА НА ОБРОБКУ ПЕРСОНАЛЬНИХ ДАНИХ - СВОЄЧАСНА ЗГОДА НА ОБРОБКУ ПЕРСОНАЛЬНИХ ДАНИХ (PT-4(2))",
      parameters: [
        {:pt_4_2_01,
         "Надаються механізми згоди особам частота та в поєднанні з обробкою персональних даних",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-4-3") do
    %{
      id: :"id-spe-pt-4-3",
      description: "",
      title: "ЗГОДА НА ОБРОБКУ ПЕРСОНАЛЬНИХ ДАНИХ - ВІДКЛИКАННЯ (PT-4(3))",
      parameters: [
        {:pt_4_3_01,
         "Впроваджено інструменти або механізми, які дозволяють фізичним особам відкликати згоду на обробку їхніх персональних даних",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_4_3_odp,
         "Визначені інструменти або механізми для відкликання згоди на обробку персональних даних",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-5") do
    %{
      id: :"id-spe-pt-5",
      description: "Впровадити повідомлення про конфіденційність особам, чиї персональні дані обробляються в системі, які: a. доступні окремим особам під час першої взаємодії з організацією, та згодом [Призначення: частота, визначена організацією]; b. виражені простою мовою; c. визначають орган, який надає дозвіл на обробку персональних даних; d. визначають цілі, для яких мають оброблятися персональні дані; e. включають [Призначення: інформація, визначена організацією].",
      title: "ПОВІДОМЛЕННЯ ПРО КОНФІДЕНЦІЙНІСТЬ (PT-5)",
      parameters: [
        {:pt_5_odp_01,
         "Визначена частота, з якою повідомлення надається особам на рівні первинної взаємодії з організацією",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_5_odp_02,
         "Визначена інформація, яка повинна бути включена до повідомлення про обробку персональних даних; PT-05a.[01] направляється особам повідомлення про обробку персональних даних таким чином, щоб вони могли ознайомитися з ним при першій взаємодії з організацією; PT-05a.[02] направляється повідомлення фізичним особам про обробку пермональних даних, таким чином, щоб це повідомлення було згодом доступне фізичним особам частота; PT-05b. направляється фізичним особам повідомлення про обробку персональних даних, яке є чітким, легким для розуміння та містить інформацію про обробку персональних даних простою мовою; PT-05c. направляється фізичним особам повідомлення про обробку персональних даних, яке визначає орган, що надає дозвіл на обробку персональних даних; PT-05d. направляється повідомлення фізичним особам про обробку персональних даних, в якому вказується мета, з якою буде оброблятися персональна інформація; PT-05e. направляється повідомлення фізичним особам про обробку персональних даних, які включають інформацію",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-5-1") do
    %{
      id: :"id-spe-pt-5-1",
      description: "",
      title: "ПОВІДОМЛЕННЯ ПРО КОНФІДЕНЦІЙНІСТЬ ПОВІДОМЛЕННЯ ПРО КОНФІДЕНЦІЙНІСТЬ (PT-5(1))",
      parameters: [
        {:pt_5_1_01,
         "Надається повідомлення про обробку персональних даних особам у той час і в тому місці, де особа надає персональні дані, у зв'язку з якою здійснюється дія з даними, або періодичність обробки даних частота",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_5_1_odp,
         "Визначена періодичність подання обробку персональних даних; повідомлення про",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-5-2") do
    %{
      id: :"id-spe-pt-5-2",
      description: "",
      title: "ПОВІДОМЛЕННЯ ПРО КОНФІДЕНЦІЙНІСТЬ (PT-5(2))",
      parameters: [
        {:pt_5_2_01,
         "Включаються повідомлення про конфіденційність у форми, які збирають інформацію, що буде зберігатися в системі записів Закону про конфіденційність, або ж заяви про конфіденційність надаються на окремих формах, які можуть зберігатися у приватних осіб",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pt-6") do
    %{
      id: :"id-spe-pt-6",
      description: "для систем, які обробляють інформацію, яка зберігатиметься в системі записів Закону про конфіденційність: a. розробити проект системи повідомлень про записи відповідно до вказівок OMB і подати нову та суттєво змінену систему повідомлень про записи до OMB та відповідних комітетів Конгресу для попереднього розгляду; b. опублікувати систему записів повідомлень у Державному реєстрі; c. зберігайте повідомлення системи записів точними, оновленими та в обсязі відповідно до впровадженої політики.",
      title: "СИСТЕМА ЗАПИСІВ ПОВІДОМЛЕНЬ ПРО КОНФІДЕНЦІЙНІСТЬ (PT-6)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-pt-6-1") do
    %{
      id: :"id-spe-pt-6-1",
      description: "",
      title: "СИСТЕМА ЗАПИСІВ ПОВІДОМЛЕНЬ ПРО КОНФІДЕНЦІЙНІСТЬ ЗВИЧАЙНЕ ВИКОРИСТАННЯ (PT-6(1))",
      parameters: [
        {:pt_6_1_01,
         "Переглядаються всі звичайні види використання, опубліковані в повідомленні системи записів періодичність, для забезпечення постійної точності, а також для забезпечення того, щоб звичайні види використання і надалі були сумісними з метою, для якої була зібрана інформація",
         [type: :string, default: "щорічно"]},
        {:pt_6_1_odp,
         "Визначено періодичність перегляду всіх звичайних видів використання, опублікованих у системі обліку повідомлень",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-pt-6-2") do
    %{
      id: :"id-spe-pt-6-2",
      description: "",
      title: "СИСТЕМА ЗАПИСІВ ПОВІДОМЛЕНЬ ПРО КОНФІДЕНЦІЙНІСТЬ - (PT-6(2))",
      parameters: [
        {:pt_6_2_01,
         "Всі винятки із Закону про конфіденційність, заявлені для системи записів, переглядаються частота, щоб переконатися, що вони залишаються доречними та необхідними відповідно до закону",
         [type: :string, default: "щорічно"]},
        {:pt_6_2_02,
         "Всі винятки із Закону про конфіденційність, заявлені для системи записів, переглядаються частота, щоб переконатися, що вони були оприлюднені як нормативні акти",
         [type: :string, default: "щорічно"]},
        {:pt_6_2_03,
         "Всі винятки із Закону про конфіденційність, заявлені для системи записів, переглядаються частота, щоб переконатися, що вони точно описані в повідомленні про систему записів",
         [type: :string, default: "щорічно"]},
        {:pt_6_2_odp,
         "Визначено періодичність перегляду всіх винятків із Закону про конфіденційність, заявлених для системи записів",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-pt-7") do
    %{
      id: :"id-spe-pt-7",
      description: "Застосувати [Призначення: умови обробки, визначені організацією] для певних категорій персональних даних.",
      title: "СПЕЦІАЛЬНІ КАТЕГОРІЇ ПЕРСОНАЛЬНИХ ДАНИХ (PT-7)",
      parameters: [
        {:pt_7_01,
         "Застосовуються умови обробки до певних категорій персональних даних",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_7_odp,
         "Визначені умови обробки, що застосовуються до певних категорій персональних даних",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-7-1") do
    %{
      id: :"id-spe-pt-7-1",
      description: "",
      title: "СПЕЦІАЛЬНІ КАТЕГОРІЇ ПЕРСОНАЛЬНИХ СОЦІАЛЬНОГО СТРАХУВАННЯ (PT-7(1))",
      parameters: [
        {:pt_7_1_a_01,
         "При обробці системою номерів соціального страхування усувається непотрібний збір, зберігання та використання номерів соціального страхування",
         [type: :string, default: nil]},
        {:pt_7_1_a_02,
         "Вивчаються альтернативи використанню номерів соціального страхування в якості персонального ідентифікатора, коли система обробляє їх",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_7_1_b,
         "Не відмовляється система при обробці номерів соціального страхування в індивідуальних правах, пільгах або привілеях, передбачених законом, через відмову особи розкрити свій номер соціального страхування",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_7_1_c_01,
         "При обробці системою номерів соціального страхування кожну особу, яку просять розкрити свій номер соціального страхування, інформують про те, чи є таке розкриття обов'язковим чи добровільним, яким законодавчим чи іншим органом запитується такий номер, і як він буде використовуватися",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_7_1_c_02,
         "При обробці системою номерів соціального страхування кожну особу, яку просять розкрити свій номер соціального страхування, інформують про те, яким законодавчим чи іншим органом запитується цей номер",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pt_7_1_c_03,
         "При обробці системою номерів соціального страхування кожну особу, яку просять розкрити свій номер соціального страхування, інформують про те, як він буде використовуватися",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-7-2") do
    %{
      id: :"id-spe-pt-7-2",
      description: "",
      title: "СПЕЦІАЛЬНІ КАТЕГОРІЇ ПЕРСОНАЛЬНИХ ДАНИХ - ІНФОРМАЦІЯ ПРО ПЕРШУ ПОПРАВКУ (PT-7(2))",
      parameters: [
        {:pt_7_2_01,
         "Заборонена обробка інформації, що описує, як будь-яка особа реалізує права, гарантовані Першою поправкою, за винятком випадків, коли це прямо дозволено законом або особою, або якщо вона не стосується та входить до сфери санкціонованої діяльності правоохоронних органів",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pt-8") do
    %{
      id: :"id-spe-pt-8",
      description: "Коли система чи організація обробляє інформацію з метою проведення програми відповідності необхідно: a. отримати схвалення Ради з цілісності даних для проведення програми відповідності; b. розробити та укласти договір комп’ютерної відповідності; c. незалежним чином перевіряти інформацію, надану програмою відповідності, перш ніж вживати негативних заходів проти особи; d. повідомляти осіб і надати їм можливість оскаржити висновки, перш ніж вживати проти них негативних заходів.",
      title: "ВИМОГИ ДО ВІДПОВІДНОСТІ (PT-8)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ra-1") do
    %{
      id: :"id-spe-ra-1",
      description: "a. Розробити, задокументувати та поширити серед [Призначення: визначеного організацією персоналу або посадових осіб]: 1. 2. Політику оцінювання ризику, яка: (a) містить мету, сферу застосування, ролі, обов’язки, відповідальність керівництва, координацію між організаційними підрозділами та систему контролю відповідності (complaince); (b) відповідає чинному законодавству, виконавчим наказам, директивам, нормам, політикам, стандартам і керівним принципам. Процедури, що сприяють здійсненню політики оцінювання ризику та пов’язаних з ними заходів оцінювання ризику. b. Призначити [Призначення: визначена організацією посадову особу] для управління політикою та процедурами оцінювання ризику. c. Переглядати й оновлювати: 1. Поточну політику оцінювання організацією частотою]. ризику [Призначення: з визначеною 2. Поточні процедури оцінювання ризику [Призначення: з визначеною організацією частотою].",
      title: "ПОЛІТИКА ТА ПРОЦЕДУРИ ОЦІНЮВАННЯ РИЗИКУ (RA-1)",
      parameters: [
        {:ra_1_odp_01,
         "Визначено персонал або ролі, на які поширюється політика оцінювання ризику",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ra_1_odp_02,
         "Визначено персонал або ролі, на які поширюються процедури, що сприяють здійсненню політики оцінювання ризику",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ra_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнеспроцесу; рівень системи}",
         [type: :string, default: nil]},
        {:ra_1_odp_04,
         "Визначена посадова особа, відповідальна за управління політикою та процедурами оцінювання ризику",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ra_1_odp_05,
         "Визначена періодичність перегляду та оновлення поточної політики оцінювання ризику",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ra_1_odp_06,
         "Є події, які вимагають перегляду та оновлення поточної політики оцінювання ризику",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:ra_1_odp_07,
         "Визначено періодичність перегляду поточних процедур оцінювання ризику",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-ra-2") do
    %{
      id: :"id-spe-ra-2",
      description: "a. b. Проводити оцінювання ризику, включно з вірогідністю й величиною шкоди від: 1. несанкціонованого доступу, використання, розголошення, руйнування, модифікації або знищення інформаційної системи, інформації, яку вона обробляє, зберігає та передає; а також будь-якої пов’язаної інформації; 2. проблем, пов’язаних з приватністю фізичних осіб, що виникають у результаті обробки персональних даних. Інтегрувати результати оцінювання ризику та рішення з управління ризиками на рівні організації та завдань/процесів з оцінюванням ризиків на рівні інформаційної системи. c. Задокументувати результати оцінювання ризику до [Вибір: планів безпеки та приватності; звіту про оцінювання ризику; [Призначення: визначеного організацією документа]]. d. Переглядати результати оцінювання ризиків [Призначення: з визначеною організацією частотою]. e. Поширити результати оцінювання ризику серед [Призначення: визначеного організацією персоналу або посадових осіб]. f. Оновлювати оцінювання ризику [Призначення: з визначеною організацією частотою] або коли є суттєві зміни в інформаційній системі, її робочому середовищі чи інших умовах, які можуть вплинути на стан безпеки або приватність інформаційної системи.",
      title: "КАТЕГОРІЮВАННЯ БЕЗПЕКИ (RA-2)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ra-2-1") do
    %{
      id: :"id-spe-ra-2-1",
      description: "",
      title: "КАТЕГОРІЮВАННЯ БЕЗПЕКИ - КАТЕГОРІЮВАННЯ ДРУГОГО РІВНЯ (RA-2(1))",
      parameters: [
        {:ra_2_1_01,
         "Проводиться категоріювання другого рівня для інформаційних систем організації з метою отримання додаткової деталізації рівнів критичності системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ra-3") do
    %{
      id: :"id-spe-ra-3",
      description: "",
      title: "ОЦІНЮВАННЯ РИЗИКУ (RA-3)",
      parameters: [
        {:ra_3_odp_01,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {плани безпеки та приватності; звіт про оцінювання ризику; документ}",
         [type: :string, default: nil]},
        {:ra_3_odp_02,
         "Визначено документ, в якому мають бути задокументовані результати оцінювання ризику (якщо вони не задокументовані в планах безпеки та приватності або в звіті про оцінювання ризику) (якщо вибрано)",
         [type: :string, default: nil]},
        {:ra_3_odp_03,
         "Визначено періодичність оцінювання ризику",
         [type: :string, default: "щорічно"]},
        {:ra_3_odp_04,
         "Визначено персонал або ролі, до яких мають бути доведені результати оцінювання ризику",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ra_3_odp_05,
         "Визначена періодичність оновлення оцінювання ризику; перегляду результатів RA-03a.01 проводиться оцінювання ризику для виявлення загроз і вразливостей у системі; RA-03a.02 проводиться оцінювання ризику для визначення ймовірності та розміру шкоди від несанкціонованого доступу, використання, розкриття, порушення, модифікації або знищення системи; інформації, яку вона обробляє, зберігає або передає; а також будь-якої пов'язаної з нею інформації; RA-03a.03 проводиться оцінювання ризику для визначення ймовірності та впливу несприятливих наслідків для фізичних осіб, що виникають у зв'язку з обробкою інформації, яка ідентифікує особу; RA-03b. інтегровані результати оцінювання ризику та рішення з управління ризиками з точки зору організації та місії або бізнес-процесів з оцінкою ризиків на системному рівні; RA-03c. результати оцінювання ризику задокументовані в ЗНАЧЕННЯ ВИБРАНОГО ПАРАМЕТРА; RA-03d. переглядаються результати 03_ODP[03] частота>; RA-03e. поширюються результати оцінювання ризику серед персоналу або ролей; RA-03f. оновлюється оцінювання ризику частота або коли відбуваються значні зміни в системі, середовищі її функціонування або інших умовах, які можуть вплинути на стан безпеки або приватності системи оцінювання ризику <RA-",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ra-3-1") do
    %{
      id: :"id-spe-ra-3-1",
      description: "",
      title: "ОЦІНЮВАННЯ ПОСТАЧАННЯ (RA-3(1))",
      parameters: [
        {:ra_3_1_a,
         "Оцінювання ризику ланцюга постачання, пов'язані з системами, системними компонентами та системними послугами",
         [type: :string, default: nil]},
        {:ra_3_1_b,
         "Потрібно оновлювати оцінювання ризику ланцюга постачання, коли відбуваються значні зміни у відповідному ланцюгу постачання, або коли зміни в системі, середовищі функціонування чи інших умовах можуть вимагати змін у ланцюгу постачання",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ra-3-2") do
    %{
      id: :"id-spe-ra-3-2",
      description: "",
      title: "ОЦІНЮВАННЯ РИЗИКУ - ВИКОРИСТАННЯ ІНФОРМАЦІЇ З УСІХ ДОСТУПНИХ ДЖЕРЕЛ (RA-3(2))",
      parameters: [
        {:ra_3_2_01,
         "Використовується інформація з усіх доступних джерел для аналізу ризиків",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ra-3-3") do
    %{
      id: :"id-spe-ra-3-3",
      description: "",
      title: "ОЦІНЮВАННЯ РИЗИКУ - УСВІДОМЛЕННЯ ДИНАМІЧНИХ ЗАГРОЗ (RA-3(3))",
      parameters: [
        {:ra_3_3_01,
         "Визначається поточне середовище кіберзагроз на постійній основі за допомогою засоби",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ra_3_3_odp,
         "Є засоби для постійного визначення поточного стану кіберзагроз",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ra-3-4") do
    %{
      id: :"id-spe-ra-3-4",
      description: "",
      title: "ОЦІНЮВАННЯ РИЗИКУ - ПРОГНОСТИЧНА КІБЕРАНАЛІТИКА (RA-3(4))",
      parameters: [
        {:ra_3_4_01,
         "Використовуються розширені можливості автоматизації для прогнозування та виявлення ризику для систем або компонентів системи",
         [type: :string, default: nil]},
        {:ra_3_4_02,
         "Застосовуються розширені аналітичні можливості для прогнозування та виявлення ризику для систем або компонентів системи. аналітики",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ra-4") do
    %{
      id: :"id-spe-ra-4",
      description: "",
      title: "ОНОВЛЕННЯ ОЦІНЮВАННЯ РИЗИКУ (RA-4)",
      parameters: [
        {:ra_4_01,
         "ОНОВЛЕННЯ ОЦІНЮВАННЯ РИЗИКУ [Вилучено: включено до RA-3]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ra-5") do
    %{
      id: :"id-spe-ra-5",
      description: "Використовувати заходи ПДТР за [Призначення: визначені організацією місця] [Вибір (один або кілька): [Призначення: з визначеною організацією частотою]; [Призначення: за визначеними організацією подіями або показниками]].",
      title: "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ (RA-5)",
      parameters: [
        {:ra_5_odp_01,
         "Визначена необхідність моніторингу систем та розміщених застосунків на наявність вразливостей",
         [type: :string, default: nil]},
        {:ra_5_odp_02,
         "Визначена періодичність перевірки систем та розміщених на них застосунків на наявність вразливостей",
         [type: :string, default: "щорічно"]},
        {:ra_5_odp_03,
         "Визначено час реагування на усунення законних вразливостей відповідно до організаційної оцінення ризику",
         [type: :integer, default: 30]},
        {:ra_5_odp_04,
         "Потрібно ділитися інформацією, отриманою в процесі сканування вразливостей та оцінок контролю, з персоналом або ролями, з якими потрібно ділитися; RA-05a.[01] здійснюється моніторинг систем та розміщених застосунків на наявність вразливостей частота та/або випадковість відповідно до визначеного організацією процесу, а також коли виявляються та повідомляються нові вразливості, що потенційно можуть вплинути на систему; RA-05a.[02] перевіряються системи та розміщені застосунки на наявність вразливостей частота та/або випадковим чином відповідно до визначеного організацією процесу, а також коли виявляються та повідомляються нові вразливості, що потенційно можуть вплинути на систему; RA-05b. застосовуються інструменти та методи моніторингу вразливостей для забезпечення сумісності між інструментами; RA-05b.01 застосовуються інструменти та методи моніторингу вразливостей для автоматизації частини процесу управління вразливостями, використовуючи стандарти для переліку платформ, недоліків програмного забезпечення та неправильних конфігурацій; RA-05b.02 застосовуються інструменти та методи моніторингу вразливостей для полегшення взаємодії між інструментами та автоматизації частини процесу управління вразливостями шляхом використання стандартів для формування контрольних списків та процедур тестування; RA-05b.03 застосовуються інструменти та методи моніторингу вразливостей для полегшення взаємодії між інструментами та автоматизації частин процесу управління вразливостями шляхом використання стандартів для вимірювання впливу вразливостей; RA-05c. аналізуються звіти про сканування вразливостей та результати моніторингу вразливостей; RA-05d. усуваються легітимні вразливості час реагування відповідно до організаційної оцінки ризиків; RA-05e. надається інформація, отримана в процесі моніторингу вразливостей та оцінки контролю, персонал або ролі, щоб допомогти усунути подібні вразливості в інших системах; RA-05f. використовуються інструменти моніторингу вразливостей, які передбачають можливість швидкого оновлення вразливостей, що підлягають скануванню",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-ra-5-1") do
    %{
      id: :"id-spe-ra-5-1",
      description: "",
      title: "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ ІНСТРУМЕНТІВ (RA-5(1))",
      parameters: [
        {:ra_5_1_01,
         "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ ІНСТРУМЕНТІВ [Вилучено: включено до RA-5]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ra-5-2") do
    %{
      id: :"id-spe-ra-5-2",
      description: "",
      title: "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ - ОНОВЛЕННЯ ЗА ЧАСТОТОЮ, ПЕРЕД НОВИМ СКАНУВАННЯМ АБО ПРИ ІДЕНТИФІКАЦІЇ (RA-5(2))",
      parameters: [
        {:ra_5_2_01,
         "Визначено час реагування на усунення законних вразливостей відповідно до організаційної оцінення ризику",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ra-5-3") do
    %{
      id: :"id-spe-ra-5-3",
      description: "",
      title: "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ - ШИРОТА ТА ГЛИБИНА ПОКРИТТЯ (RA-5(3))",
      parameters: [
        {:ra_5_3_01,
         "Визначено ширину вразливостей. та глибину охоплення сканування",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ra-5-4") do
    %{
      id: :"id-spe-ra-5-4",
      description: "",
      title: "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ - ВИЯВНА ІНФОРМАЦІЯ (RA-5(4))",
      parameters: [
        {:ra_5_4_01,
         "Є інформація про систему відкритою; RA-05(04)[02] вживаються коригувальні дії, коли інформація про систему підтверджується як така, що може бути виявлена",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ra_5_4_odp,
         "Визначені коригувальні дії, які необхідно вжити, якщо інформація про систему буде виявлена",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ra-5-5") do
    %{
      id: :"id-spe-ra-5-5",
      description: "",
      title: "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ - ПРИВІЛЕЙОВАНИЙ ДОСТУП (RA-5(5))",
      parameters: [
        {:ra_5_5_01,
         "Реалізовано авторизацію привілейованого доступу до компоненти системи для діяльность зі сканування вразливостей",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ra-5-6") do
    %{
      id: :"id-spe-ra-5-6",
      description: "",
      title: "СКАНУВАННЯ ТЕНДЕНЦІЙ (RA-5(6))",
      parameters: [
        {:ra_5_6_01,
         "Порівнюються результати багаторазового сканування вразливостей за допомогою автоматизовані механізми",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:ra_5_6_odp,
         "Визначені автоматизовані механізми для порівняння результатів багаторазового сканування вразливостей",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-ra-5-7") do
    %{
      id: :"id-spe-ra-5-7",
      description: "",
      title: "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ - АВТОМАТИЗОВАНЕ ВИЯВЛЕННЯ ТА СПОВІЩЕННЯ ПРО НЕАВТОРИЗОВАНІ КОМПОНЕНТИ (RA-5(7))",
      parameters: [
        {:ra_5_7_01,
         "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ - АВТОМАТИЗОВАНЕ ВИЯВЛЕННЯ ТА СПОВІЩЕННЯ ПРО НЕАВТОРИЗОВАНІ КОМПОНЕНТИ [Вилучено: включено до CM-8]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ra-5-8") do
    %{
      id: :"id-spe-ra-5-8",
      description: "",
      title: "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ - ОГЛЯД ЖУРНАЛІВ АУДИТУ ЗА МИНУЛІ ПЕРІОДИ (RA-5(8))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ra-5-9") do
    %{
      id: :"id-spe-ra-5-9",
      description: "",
      title: "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ ПРОНИКНЕННЯ (RA-5(9))",
      parameters: [
        {:ra_5_9_01,
         "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ ПРОНИКНЕННЯ [Вилучено: включено до CA-8] RA5(10) СКАНУВАННЯ ВРАЗЛИВОСТЕЙ - ЗІСТАВЛЕННЯ ІНФОРМАЦІЇ ПРО СКАНУВАННЯ - ТЕСТУВАННЯ ТА АНАЛІЗ",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ra-6") do
    %{
      id: :"id-spe-ra-6",
      description: "",
      title: "ЗАХОДИ ПРОТИДІЇ ТЕХНІЧНІЙ РОЗВІДЦІ (RA-6)",
      parameters: [
        {:ra_6_odp_01,
         "Визначені місця для використання заходів ПДТР",
         [type: :string, default: nil]},
        {:ra_6_odp_02,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {частота; коли події або показники}",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ra_6_odp_03,
         "Визначено частоту, з якою слід проводити заходи ПДТР (якщо обрано)",
         [type: :integer, default: 30]},
        {:ra_6_odp_04,
         "Визначені події або показники, які, у разі їх виникнення, спричиняють проведення заходів ПДТР (якщо вони були обрані)",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-ra-7") do
    %{
      id: :"id-spe-ra-7",
      description: "Реагувати на результати оцінювання, моніторингу й аудиту безпеки та приватності.",
      title: "РЕАГУВАННЯ НА РИЗИК (RA-7)",
      parameters: [
        {:ra_7_01,
         "Вживаються заходи реагування на результати оцінок безпеки відповідно до організаційної толерантності до ризиків",
         [type: :string, default: nil]},
        {:ra_7_02,
         "Вживаються заходи реагування на результати оцінювання приватності відповідно до організаційної толерантності до ризиків",
         [type: :string, default: nil]},
        {:ra_7_03,
         "Вживаються заходи реагування на результати моніторингу відповідно до організаційної толерантності до ризиків",
         [type: :string, default: nil]},
        {:ra_7_04,
         "Вживаються заходи реагування на висновки аудиту відповідно до організаційної толерантності до ризиків",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ra-8") do
    %{
      id: :"id-spe-ra-8",
      description: "Проводити оцінювання впливу на приватність інформаційних систем, програм або інших заходів, які становлять ризик приватності перед тим, як: a. розробити або закупити інформаційні технології, які збирають, підтримують чи поширюють критичну інформацію; b. ініціювати створення нових архівів інформації, яка: 1. буде зібрана, збережена чи розповсюджена за допомогою інформаційних технологій; 2. містить персональні дані, які дозволяють встановити фізичне або онлайнз’єднання з конкретною особою.",
      title: "ОЦІНКА ВПЛИВУ НА ПРИВАТНІСТЬ (RA-8)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-ra-9") do
    %{
      id: :"id-spe-ra-9",
      description: "Визначити критичні компоненти інформаційної системи та функції, виконавши аналіз критичності для [Призначення: визначених організацією систем, компонентів системи або послуг для системи] в [Призначення: визначенні організацією точки ухвалення рішень у життєвому циклі розробки системи].",
      title: "АНАЛІЗ КРИТИЧНОСТІ (RA-9)",
      parameters: [
        {:ra_9_01,
         "Визначені критичні компоненти та функції системи шляхом проведення аналізу критичності для систем, системних компонентів або системних служб в точках прийняття рішень в життєвому циклі розробки системи",
         [type: :string, default: nil]},
        {:ra_9_odp_01,
         "Визначені системи, компоненти системи або системні сервіси, що підлягають аналізу на предмет критичності",
         [type: :string, default: nil]},
        {:ra_9_odp_02,
         "Визначені точки прийняття рішень в життєвому циклі розробки системи, коли необхідно проводити аналіз критичності",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ra-10") do
    %{
      id: :"id-spe-ra-10",
      description: "a. Створити та підтримувати можливості активного пошуку кіберзагроз: 1. пошук індикаторів компроментації в системах організації; 2. виявлення, відстеження та знищення загроз, які можуть обходити існуючі засоби контролю безпеки. b. використовуйте можливості активного пошуку загроз [Призначення: частота, визначена організацією].",
      title: "АКТИВНИЙ ПОШУК ЗАГРОЗ (RA-10)",
      parameters: [
        {:ra_10_odp,
         "Визначена частота, з якою можливість виявлення загроз; слід використовувати RA-10a.01 створена та підтримується спроможність протидії кіберзагрозам для пошуку індикаторів компрометації в організаційних системах; RA-10a.02 створена та підтримується спроможність виявляти, відслідковувати та знешкоджувати кіберзагрози, які не піддаються існуючому контролю; RA-10b. використовується функція відстеження загроз частота",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-sa-1") do
    %{
      id: :"id-spe-sa-1",
      description: "a. Розробити, задокументувати та поширити серед [Призначення: визначеного організацією персоналу або ролей]: 1. 2. b. [Вибір (один або декілька): рівень організації; рівень місії/бізнес-процесу; рівень системи] політики придбання систем і послуг, яка: (a) містить мету, сферу застосування, ролі, обов’язки, відповідальність керівництва, координацію між організаційними підрозділами та систему контролю (complaince); (b) відповідає чинному законодавству, виконавчим наказам, директивам, нормам, політикам, стандартам і рекомендаціям. Процедури, що полегшують впровадження політики та заходів придбання систем і послуг. Призначити [Призначення: визначену організацією посадову особу] для управління політикою та процедурами придбання системи та послуг. c. Переглядати й оновлювати поточні політику та процедури придбання систем та послуг: 1. Поточну політику придбання системи та послуг [Призначення: з визначеною організацією частотою]. 2. Поточні процедури придбання системи та послуг [Призначення: з визначеною організацією частотою] та наступні [Призначення: події, визначені організацією].",
      title: "ПОЛІТИКИ ТА ПРОЦЕДУРИ ПРИДБАННЯ СИСТЕМ ТА ПОСЛУГ (SA-1)",
      parameters: [
        {:sa_1_odp_01,
         "Визначено персонал або ролі, на які поширюватиметься політика придбання систем і послуг",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sa_1_odp_02,
         "Визначено персонал або ролі, на які поширюються процедури придбання систем і послуг",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sa_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнеспроцесу; рівень системи}",
         [type: :string, default: nil]},
        {:sa_1_odp_04,
         "Визначено посадову особу, яка керуватиме політикою та процедурами придбання систем і послуг",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sa_1_odp_05,
         "Визначено періодичність перегляду та оновлення поточної політики придбання систем і послуг",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sa_1_odp_06,
         "Є події, які вимагають перегляду та оновлення поточної політики придбання систем і послуг",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sa_1_odp_07,
         "Визначено частоту, з якою переглядаються та оновлюються поточні процедури придбання систем і послуг",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-sa-2") do
    %{
      id: :"id-spe-sa-2",
      description: "a. Визначити вимоги щодо інформаційної безпеки та приватності для систем або послуг для системи при плануванні завдань та процесів. b. Визначити, задокументувати та розподілити ресурси, які необхідні для захисту систем або послуг для системи у рамках процесу фінансового планування в організації та управління інвестиціями. c. Створити окрему позицію бюджету для фінансування заходів із забезпечення інформаційної безпеки та приватності.",
      title: "РОЗПОДІЛ РЕСУРСІВ (SA-2)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sa-3") do
    %{
      id: :"id-spe-sa-3",
      description: "a. Придбати, розробити та керувати системою, використовуючи [Призначення: визначений організацією життєвий цикл розробки], який охоплює питання захисту інформації та приватності. b. Визначити та задокументувати роль і обов’язки із забезпечення безпеки та приватності інформації протягом усього життєвого циклу розробки системи. c. Визначити осіб, які мають повноваження та обов’язки в області інформаційної безпеки та приватності. d. Інтегрувати процес управління інформаційною безпекою та приватністю в процеси життєвого циклу розробки системи.",
      title: "ЖИТТЄВИЙ ЦИКЛ РОЗРОБКИ СИСТЕМИ (SA-3)",
      parameters: [
        {:sa_3_odp,
         "Визначено життєвий цикл розробки системи; SA-03a.[01] система придбана, розроблена та керується з використанням життєвого циклу життєвий цикл розробки системи , який охоплює інформаційну безпеку; SA-03a.[02] система придбана, розроблена та керується з використанням життєвий цикл розробки системи , який охоплює приватність; SA-03b.[01] визначені та задокументовані ролі та обов'язки з інформаційної безпеки протягом усього життєвого циклу розробки системи; SA-03b.[02] визначені та задокументовані ролі та обов'язки щодо приватності протягом усього життєвого циклу розробки системи; SA-03c.[01] визначені особи, які виконують функції та обов'язки з інформаційної безпеки; SA-03c.[02] визначені особи з функціями та обов'язками, пов'язаними з приватністю; SA-03d.[01] інтегровані процеси управління інформаційною безпекою організації в діяльність життєвого циклу розробки системи; SA-03d.[02] інтегровані процеси управління приватністю в життєвого циклу розробки системи",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-sa-3-1") do
    %{
      id: :"id-spe-sa-3-1",
      description: "",
      title: "ЖИТТЄВИЙ ЦИКЛ РОЗРОБКИ СЕРЕДОВИЩЕМ РОЗРОБКИ (SA-3(1))",
      parameters: [
        {:sa_3_1_01,
         "Захищене середовище розробки системи, відповідно до ризиків протягом усього життєвого циклу розробки системи для системи, компонентів системи або служб.",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-3-2") do
    %{
      id: :"id-spe-sa-3-2",
      description: "",
      title: "ЖИТТЄВИЙ ЦИКЛ РЕАЛЬНИХ ДАНИХ (SA-3(2))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sa-3-3") do
    %{
      id: :"id-spe-sa-3-3",
      description: "",
      title: "ЖИТТЄВИЙ ЦИКЛ ТЕХНОЛОГІЙ (SA-3(3))",
      parameters: [
        {:sa_3_3_01,
         "Планується оновлення технологій для підтримки системи протягом усього життєвого циклу розробки системи",
         [type: :string, default: nil]},
        {:sa_3_3_02,
         "Впроваджено графік оновлення технологій для підтримки системи протягом усього життєвого циклу розробки системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-4") do
    %{
      id: :"id-spe-sa-4",
      description: "Включіть такі вимоги, описи та критерії, явно або за допомогою посилання, використовуючи [Вибір (один або більше): стандартні пункти контракту; [Призначення: пункти контракту, визначені організацією]] в контракті про придбання системи, системного компонента або системної послуги: a. функціональні вимоги безпеки та приватності; b. вимоги до стійкості механізму; c. вимоги до забезпечення безпеки та приватності; d. заходи захисту для забезпечення вимог безпеки та приватності; e. вимоги до захисту документації з безпеки та приватності; f. опис середовища розробки системи та середовища, у якому система призначена для роботи; g. розподіл відповідальності або визначення сторін, відповідальних за управління інформаційною безпекою, приватністю та управлінням ланцюгами постачання; h. критерії прийнятності.",
      title: "ПРОЦЕС ЗАКУПІВЕЛЬ (SA-4)",
      parameters: [
        {:sa_4_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРА: { стандартні пункти контракту; пункт контракту}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-4-1") do
    %{
      id: :"id-spe-sa-4-1",
      description: "",
      title: "ПРОЦЕС ЗАКУПІВЕЛЬ - ФУНКЦІОНАЛЬНІ ВЛАСТИВОСТІ ЗАХОДІВ (SA-4(1))",
      parameters: [
        {:sa_4_1_01,
         "Планується оновлення технологій для системи протягом життєвого циклу розробки системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-4-2") do
    %{
      id: :"id-spe-sa-4-2",
      description: "",
      title: "ПРОЦЕС ЗАКУПІВЕЛЬ - РОЗРОБКА ТА ВПРОВАДЖЕННЯ ІНФОРМАЦІЇ ДЛЯ ЗАХОДІВ (SA-4(2))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sa-4-3") do
    %{
      id: :"id-spe-sa-4-3",
      description: "",
      title: "ПРОЦЕС ЗАКУПІВЕЛЬ РОЗРОБКИ (SA-4(3))",
      parameters: [
        {:sa_4_3_a,
         "Повинен розробник системи, системного компонента або системної послуги демонструвати використання процесу життєвого циклу розробки системи, який включає методи системної інженерії",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-4-4") do
    %{
      id: :"id-spe-sa-4-4",
      description: "",
      title: "ПРОЦЕС ЗАКУПІВЕЛЬ - ВІДНЕСЕННЯ КОМПОНЕНТІВ ДО СИСТЕМ (SA-4(4))",
      parameters: [
        {:sa_4_4_01,
         "ПРОЦЕС ЗАКУПІВЕЛЬ - ВІДНЕСЕННЯ КОМПОНЕНТІВ ДО СИСТЕМ [Вилучено: включено до CM-8(9)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-4-5") do
    %{
      id: :"id-spe-sa-4-5",
      description: "",
      title: "ПРОЦЕС ЗАКУПІВЕЛЬ - КОНФІГУРАЦІЇ СИСТЕМИ, КОМПОНЕНТА ТА СИСТЕМНОЇ СЛУЖБИ (SA-4(5))",
      parameters: [
        {:sa_4_5_a,
         "Повинен розробник системи, компонента системи або системної служби постачати систему, компонент або службу із впровадженими конфігураціями безпеки",
         [type: :string, default: nil]},
        {:sa_4_5_b,
         "Будуть конфігурації використовуватися за замовчуванням для будь-якої наступної переінсталяції або оновлення системи, компонента чи служби",
         [type: :string, default: nil]},
        {:sa_4_5_odp,
         "Визначено конфігурації безпеки для системи, компонента або служби",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-4-6") do
    %{
      id: :"id-spe-sa-4-6",
      description: "",
      title: "ПРОЦЕС ЗАКУПІВЕЛЬ ІНФОРМАЦІЇ (SA-4(6))",
      parameters: [
        {:sa_4_6_a,
         "Використовуються лише засоби захисту інформації, які пройшли державну експертизу або сертифікацію, створені для технічного та криптографічного захисту інформації",
         [type: :string, default: "AES-256-GCM"]},
        {:sa_4_6_b,
         "Були ці засоби захисту мають позитивний експертний висновок або сертифікат відповідності, а також відповідні дозволи для використання для захисту критичної інформації",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sa-4-7") do
    %{
      id: :"id-spe-sa-4-7",
      description: "",
      title: "ПРОЦЕС ЗАКУПІВЕЛЬ - ЗАТВЕРДЖЕНІ ПРОФІЛІ ЗАХИЩЕНОСТІ (SA-4(7))",
      parameters: [
        {:sa_4_7_a,
         "Обмежується використання комерційної готової до використання технічної продукції, створеної для захисту інформації та з функцією підтримки забезпечення безпеки інформації, до тих продуктів, які були успішно оцінені відповідно до профілю захищеності для конкретного типу технології, затвердженого уповноваженим державним органом, якщо такий профіль наявний",
         [type: :string, default: nil]},
        {:sa_4_7_b,
         "Якщо немає профілю захищеності для певного типу технологій, затвердженого уповноваженим органом, але забезпечення політики безпеки продукту, що надається на комерційній основі, залежить від криптографічних функцій, — вимагати, щоб криптографічний модуль пройшов державну експертизу, мав позитивний експертний висновок і був рекомендований до використання уповноваженим органом",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-sa-4-8") do
    %{
      id: :"id-spe-sa-4-8",
      description: "",
      title: "ПРОЦЕС ЗАКУПІВЕЛЬ - ПЛАН БЕЗПЕРЕРВНОГО МОНІТОРИНГУ ЗАХОДІВ БЕЗПЕКИ (SA-4(8))",
      parameters: [
        {:sa_4_8_01,
         "Розробник системи, системного компонента або системної служби створив план безперервного моніторингу ефективності заходів безпеки та приватності, який узгоджується з відповідним планом постійного моніторингу організації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-4-9") do
    %{
      id: :"id-spe-sa-4-9",
      description: "",
      title: "ПРОЦЕС ЗАКУПІВЕЛЬ - ФУНКЦІЇ, ПОСЛУГИ, ЩО ВИКОРИСТОВУЮТЬСЯ (SA-4(9))",
      parameters: [
        {:sa_4_9_01,
         "Зобов'язаний розробник системи, системного компонента або системного сервісу визначити функції, призначені для використання в організації",
         [type: :string, default: nil]},
        {:sa_4_9_02,
         "Зобов'язаний розробник системи, системного компонента або системної служби визначити порти, призначені для використання в організації",
         [type: :string, default: nil]},
        {:sa_4_9_03,
         "Зобов'язаний розробник системи, системного компонента або системної служби визначити протоколи, призначені для використання в організації",
         [type: :string, default: "TLS 1.3"]},
        {:sa_4_9_04,
         "Зобов'язаний розробник системи, системного компонента або системної послуги визначити послуги, призначені для використання в організації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-5") do
    %{
      id: :"id-spe-sa-5",
      description: "a. b. Отримати або розробити документацію адміністратора для системи, системного компонента або системної служби, яка описує: 1. безпечне налаштування, установку та роботу системи, компонента або служби; 2. ефективне використання, підтримку функцій та механізмів безпеки та приватності; 3. відомі вразливості щодо конфігурації та використання адміністративних або привілейованих функцій. Отримати або розробити документацію користувача для системи, системного компонента або системної служби, яка описує: 1. функції та механізми безпеки та приватності та способи ефективного використання цих функцій і механізмів; 2. методи взаємодії з користувачем, що дозволяють окремим особам використовувати систему, компонент або службу безпечнішим чином та захищати індивідуальну приватність; 3. обов’язки користувача щодо забезпечення безпеки системи, компонента або служби та приватності окремих осіб. c. Документувати спроби отримати доступ до документації системи, системного компонента чи системної служби, коли така документація недоступна або ж відсутня, і вжити [Призначення: визначені організацією заходи] у відповідь. d. Поширити документацію серед [Призначення: визначеного організацією персоналу або посадових осіб].",
      title: "СИСТЕМНА ДОКУМЕНТАЦІЯ (SA-5)",
      parameters: [
        {:sa_5_odp_01,
         "Визначені дії, яких слід вжити, коли документація на систему, системний компонент або системне обслуговування недоступна або відсутня",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:sa_5_odp_02,
         "Визначено персонал або системної документації; SA-05a.01[01] отримана або розроблена документація для адміністратора системи, системного компонента або системної служби, яка описує безпечну конфігурацію системи, компонента або служби; SA-05a.01[02] була отримана або розроблена документація для адміністратора системи, системного компонента або системної служби, яка описує безпечне встановлення системи, компонента або служби; SA-05a.01[03] отримана або розроблена ролі для розповсюдження документація адміністратора системи, системного компонента або системної служби, яка описує безпечну роботу системи, компонента або служби; SA-05a.02[01] отримана або розроблена адміністраторська документація системи, системного компонента або системної служби, яка описує ефективне використання функцій та механізмів безпеки; SA-05a.02[02] була отримана або розроблена документація адміністратора системи, системного компонента або системної служби, яка описує безпечне встановлення системи, компонента або служби; SA-05a.02[03] отримана або розроблена документація для адміністратора системи, системного компонента або системної служби, яка описує ефективне використання функцій і механізмів забезпечення конфіденційності; SA-05a.02[04] отримана або розроблена документація для адміністратора системи, системного компонента або системної служби, яка описує ефективну підтримку функцій і механізмів забезпечення конфіденційності; SA-05a.03[01] була отримана або розроблена документація адміністратора системи, системного компонента або системної служби, яка описує відомі вразливості, що стосуються конфігурації адміністративних або привілейованих функцій; SA-05a.03[02] була отримана або розроблена документація адміністратора системи, системного компонента або системної служби, яка описує відомі вразливості, пов'язані з використанням адміністративних або привілейованих функцій; SA-05b.01[01] отримана або розроблена користувацька документація системи, системного компонента або системної служби, яка описує доступні користувачеві функції та механізми безпеки; SA-05b.01[02] отримана або розроблена користувацька документація системи, системного компоненту або системної служби, яка описує, як ефективно використовувати ці (доступні користувачеві) функції та механізми безпеки; SA-05b.01[03] отримана або розроблена користувацька документація системи, системного компонента або системної служби, яка описує доступні користувачеві функції та механізми забезпечення конфіденційності; SA-05b.01[04] отримана або розроблена користувацька документація системи, системного компонента або системної служби, яка описує, як ефективно використовувати ці (доступні користувачеві) функції та механізми захисту приватності; SA-05b.02[01] отримана або розроблена користувацька документація системи, системного компонента або системної послуги, яка описує методи взаємодії з користувачем, що дозволяють особам використовувати систему, компонент або послугу в більш безпечний спосіб; SA-05b.02[02] отримана або розроблена користувацька документація системи, системного компонента або системної служби, яка описує методи взаємодії з користувачем, що дозволяють особам використовувати систему, компонент або службу для захисту особистої приватності; SA-05b.03[01] отримана або розроблена користувацька документація системи, системного компоненту або системного сервісу, яка описує обов'язки користувача щодо підтримання безпеки системи, компоненту або сервісу; SA-05b.03[02] отримана або розроблена користувацька документація системи, системного компонента або системної служби, яка описує обов'язки користувачів щодо збереження приватності приватних осіб; SA-05c.[01] були задокументовані спроби отримати документацію на систему, системний компонент або системне обслуговування, коли така документація або недоступна, або взагалі не існує; SA-05c.[02] після спроб отримати документацію системи, системного компонента або системної служби, коли така документація недоступна або не існує, у відповідь виконуються дії; SA-05d. розповсюджується документація персоналу або ролей>. серед <SA-05_ODP[02]",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-sa-5-1") do
    %{
      id: :"id-spe-sa-5-1",
      description: "",
      title: "СИСТЕМНА ДОКУМЕНТАЦІЯ - ФУНКЦІОНАЛЬНІ ВЛАСТИВОСТІ ЗАХОДІВ БЕЗПЕКИ (SA-5(1))",
      parameters: [
        {:sa_5_1_01,
         "СИСТЕМНА ДОКУМЕНТАЦІЯ - ФУНКЦІОНАЛЬНІ ВЛАСТИВОСТІ ЗАХОДІВ БЕЗПЕКИ [Вилучено: включено до SA-4(1)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-5-2") do
    %{
      id: :"id-spe-sa-5-2",
      description: "",
      title: "СИСТЕМНА ДОКУМЕНТАЦІЯ - ЗОВНІШНІ СИСТЕМНІ ІНТЕРФЕЙСИ, (SA-5(2))",
      parameters: [
        {:sa_5_2_01,
         "СИСТЕМНА ДОКУМЕНТАЦІЯ - ЗОВНІШНІ СИСТЕМНІ ІНТЕРФЕЙСИ, ЩО СТОСУЮТЬСЯ БЕЗПЕКИ [Вилучено: включено до SA-4(2)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-5-3") do
    %{
      id: :"id-spe-sa-5-3",
      description: "",
      title: "СИСТЕМНА ДОКУМЕНТАЦІЯ - АРХІТЕКТУРА (ПРОЄКТ) ВИСОКОГО РІВНЯ (SA-5(3))",
      parameters: [
        {:sa_5_3_01,
         "СИСТЕМНА ДОКУМЕНТАЦІЯ - АРХІТЕКТУРА (ПРОЄКТ) ВИСОКОГО РІВНЯ [Вилучено: включено до SA-4(2)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-5-4") do
    %{
      id: :"id-spe-sa-5-4",
      description: "",
      title: "СИСТЕМНА ДОКУМЕНТАЦІЯ - АРХІТЕКТУРА (ПРОЄКТ) НИЗЬКОГО РІВНЯ (SA-5(4))",
      parameters: [
        {:sa_5_4_01,
         "СИСТЕМНА ДОКУМЕНТАЦІЯ - АРХІТЕКТУРА (ПРОЄКТ) НИЗЬКОГО РІВНЯ [Вилучено: включено до SA-4(2)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-5-5") do
    %{
      id: :"id-spe-sa-5-5",
      description: "",
      title: "СИСТЕМНА ДОКУМЕНТАЦІЯ - ВИХІДНИЙ КОД (SA-5(5))",
      parameters: [
        {:sa_5_5_01,
         "СИСТЕМНА ДОКУМЕНТАЦІЯ - ВИХІДНИЙ КОД [Вилучено: включено до SA-4(2)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-6") do
    %{
      id: :"id-spe-sa-6",
      description: "",
      title: "ОБМЕЖЕННЯ ЩОДО ВИКОРИСТАННЯ ЗАБЕЗПЕЧЕННЯ (SA-6)",
      parameters: [
        {:sa_6_01,
         "ОБМЕЖЕННЯ ЩОДО ВИКОРИСТАННЯ ЗАБЕЗПЕЧЕННЯ [Вилучено: включено до CM-10 та SI-7]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-7") do
    %{
      id: :"id-spe-sa-7",
      description: "",
      title: "ВСТАНОВЛЕНЕ КОРИСТУВАЧЕМ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ (SA-7)",
      parameters: [
        {:sa_7_01,
         "ВСТАНОВЛЕНЕ КОРИСТУВАЧЕМ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ [Вилучено: включено до CM-11 та SI-7]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8") do
    %{
      id: :"id-spe-sa-8",
      description: "Застосовувати [Призначення: визначені організацією принципи інжинірингу безпеки та конфіденційності системи] в специфікації, проєктуванні, розробці, впровадженні та зміні системи й компонентів системи.",
      title: "БЕЗПЕКА ТА ПРИВАТНІСТЬ ПРИНЦИПІВ ІНЖИНІРИНГУ (SA-8)",
      parameters: [
        {:sa_8_01,
         "Застосовуються принципи інжинірингу безпеки систем у специфікації системи та компонентів системи",
         [type: :string, default: nil]},
        {:sa_8_02,
         "Застосовуються принципи інжинірингу безпеки систем при розробці системи та її компонентів",
         [type: :string, default: nil]},
        {:sa_8_03,
         "Були застосовані принципи інжинірингу безпеки систем при розробці системи та компонентів систем",
         [type: :string, default: nil]},
        {:sa_8_04,
         "Застосовуються принципи інжинірингу безпеки систем при реалізації системи та компонентів систем",
         [type: :string, default: nil]},
        {:sa_8_05,
         "Застосовуються принципи інжинірингу безпеки систем при модифікації системи та компонентів систем",
         [type: :string, default: nil]},
        {:sa_8_06,
         "Застосовуються принципи інжинірингу конфіденційності у специфікації системи та компонентів систем; принципи інжинірингу конфіденційності SA-08[07] застосовуються принципи інжинірингу конфіденційності при розробці системи та компонентів систем",
         [type: :string, default: nil]},
        {:sa_8_08,
         "Застосовуються принципи інжинірингу конфіденційності при розробці системи та компонентів систем",
         [type: :string, default: nil]},
        {:sa_8_09,
         "Застосовуються принципи інжинірингу конфіденційності при реалізації системи та компонентів систем",
         [type: :string, default: nil]},
        {:sa_8_10,
         "Застосовуються принципи інжинірингу конфіденційності при модифікації системи та компонентів систем",
         [type: :string, default: nil]},
        {:sa_8_odp_01,
         "Визначені принципи інжинірингу безпеки систем",
         [type: :string, default: nil]},
        {:sa_8_odp_02,
         "Визначені системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-1") do
    %{
      id: :"id-spe-sa-8-1",
      description: "",
      title: "БЕЗПЕКА ТА ПРИВАТНІСТЬ ПРИНЦИПІВ ІНЖИНІРИНГУ - ЧІТКА АБСТРАКЦІЯ (SA-8(1))",
      parameters: [
        {:sa_8_1_01,
         "Реалізовано принцип проектування безпеки чітких абстракцій",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-2") do
    %{
      id: :"id-spe-sa-8-2",
      description: "",
      title: "БЕЗПЕКА ТА ПРИВАТНІСТЬ ПРИНЦИПІВ НАЙМЕНШ ПОШИРЕНИЙ МЕХАНІЗМ (SA-8(2))",
      parameters: [
        {:sa_8_2_01,
         "Реалізують системи або компоненти системи принцип побудови безпеки за принципом найменш поширеного механізму",
         [type: :string, default: nil]},
        {:sa_8_2_odp,
         "Реалізовано абстракцій. принцип проектування безпеки чітких",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-3") do
    %{
      id: :"id-spe-sa-8-3",
      description: "",
      title: "БЕЗПЕКА ТА ПРИВАТНІСТЬ ПРИНЦИПІВ МОДУЛЬНІСТЬ І БАГАТОРІВНЕВІСТЬ (SA-8(3))",
      parameters: [
        {:sa_8_3_01,
         "БЕЗПЕКА ТА ПРИВАТНІСТЬ ПРИНЦИПІВ МОДУЛЬНІСТЬ І БАГАТОРІВНЕВІСТЬ ІНЖИНІРИНГУ - МЕТА ОЦІНКИ: Визначити, чи: SA08(03)_ODP[01] визначені системи або компоненти системи, реалізують принцип модульності дизайну безпеки; які SA08(03)_ODP[02] визначені системи або компоненти реалізують принцип багаторівневого безпеки",
         [type: :string, default: nil]},
        {:sa_8_3_02,
         "Системи або компоненти системи реалізують принцип багаторівневого проектування безпеки. системи, які проектування",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-4") do
    %{
      id: :"id-spe-sa-8-4",
      description: "",
      title: "БЕЗПЕКА ТА ПРИВАТНІСТЬ ПРИНЦИПІВ ЧАСТКОВО ВПОРЯДКОВАНІ ЗАЛЕЖНОСТІ (SA-8(4))",
      parameters: [
        {:sa_8_4_01,
         "Системи або компоненти системи реалізують принцип проектування безпеки частково впорядкованих залежностей",
         [type: :integer, default: 30]},
        {:sa_8_4_odp,
         "Визначені системи або компоненти системи, які реалізують принцип проектування безпеки частково впорядкованих залежностей",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-5") do
    %{
      id: :"id-spe-sa-8-5",
      description: "",
      title: "БЕЗПЕКА ТА ПРИВАТНІСТЬ ПРИНЦИПІВ ЕФЕКТИВНИЙ ОПОСЕРЕДКОВАНИЙ ДОСТУП (SA-8(5))",
      parameters: [
        {:sa_8_5_01,
         "Системи або компоненти системи реалізують принцип проектування безпеки ефективного опосередкованого доступу",
         [type: :string, default: nil]},
        {:sa_8_5_odp,
         "Визначені системи або її компоненти, які реалізують принцип проектування безпеки ефективного опосередкованого доступу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-6") do
    %{
      id: :"id-spe-sa-8-6",
      description: "",
      title: "БЕЗПЕКА ТА ПРИВАТНІСТЬ МІНІМІЗОВАНИЙ ОБМІН (SA-8(6))",
      parameters: [
        {:sa_8_6_01,
         "Системи або компоненти системи реалізують принцип побудови безпеки за принципом мінімізації спільного використання",
         [type: :string, default: nil]},
        {:sa_8_6_odp,
         "Визначені системи або компоненти системи, які реалізують принцип проектування безпеки, що полягає в мінімізації спільного використання",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-7") do
    %{
      id: :"id-spe-sa-8-7",
      description: "",
      title: "БЕЗПЕКА ТА ПРИВАТНІСТЬ ПРИНЦИПІВ ІНЖИНІРИНГУ - ЗНИЖЕНА СКЛАДНІСТЬ (SA-8(7))",
      parameters: [
        {:sa_8_7_01,
         "Системи або компоненти системи реалізують принцип проектування безпеки за принципом зниженої складності. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: nil]},
        {:sa_8_7_odp,
         "Визначені системи або компоненти системи, які реалізують принцип проектування безпеки за принципом зниженої складності",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-8") do
    %{
      id: :"id-spe-sa-8-8",
      description: "",
      title: "БЕЗПЕКА ТА ПРИВАТНІСТЬ ПРИНЦИПІВ ЕВОЛЮЦІЯ БЕЗПЕКИ В СИСТЕМІ (SA-8(8))",
      parameters: [
        {:sa_8_8_01,
         "Системи або компоненти системи реалізують принцип безпечного проектування безпечної еволюційності",
         [type: :string, default: nil]},
        {:sa_8_8_odp,
         "Визначені системи або компоненти системи, які реалізують принцип безпечного проектування безпечної еволюційності",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-9") do
    %{
      id: :"id-spe-sa-8-9",
      description: "",
      title: "БЕЗПЕКА ТА ПРИВАТНІСТЬ ПРИНЦИПІВ ІНЖИНІРИНГУ - ДОВІРЕНІ КОМПОНЕНТИ СИСТЕМИ (SA-8(9))",
      parameters: [
        {:sa_8_9_01,
         "Системи або компоненти реалізують принцип побудови безпеки компонентів. системи довірених",
         [type: :string, default: nil]},
        {:sa_8_9_odp,
         "Визначені системи або компоненти системи, які реалізують принцип побудови безпеки довірених компонентів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-10") do
    %{
      id: :"id-spe-sa-8-10",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП ІЄРАРХІЧНОЇ ДОВІРИ В ДИЗАЙНІ БЕЗПЕКИ (SA-8(10))",
      parameters: [
        {:sa_8_10_01,
         "Системи або компоненти системи реалізують принцип ієрархічної довіри в дизайні безпеки. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: nil]},
        {:sa_8_10_odp,
         "Визначені системи або компоненти системи, які реалізують принцип ієрархічної довіри при проектуванні безпеки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-11") do
    %{
      id: :"id-spe-sa-8-11",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП ПРОЕКТУВАННЯ БЕЗПЕКИ ЗВОРОТНОГО ПОРОГУ МОДИФІКАЦІЇ (SA-8(11))",
      parameters: [
        {:sa_8_11_01,
         "Системи або компоненти системи реалізують принцип проектування безпеки зворотного порогу модифікації",
         [type: :string, default: nil]},
        {:sa_8_11_odp,
         "Визначені системи або компоненти системи, які реалізують принцип ієрархічної довіри при проектуванні безпеки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-12") do
    %{
      id: :"id-spe-sa-8-12",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП ПОБУДОВИ ІЄРАРХІЧНОГО ЗАХИСТУ (SA-8(12))",
      parameters: [
        {:sa_8_12_01,
         "Системи або компоненти системи реалізують принцип побудови ієрархічного захисту",
         [type: :string, default: nil]},
        {:sa_8_12_odp,
         "Визначені системи або компоненти системи, реалізують принцип ієрархічного дизайну безпеки; які",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-13") do
    %{
      id: :"id-spe-sa-8-13",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП ПРОЕКТУВАННЯ БЕЗПЕКИ З МІНІМІЗАЦІЄЮ ЕЛЕМЕНТІВ БЕЗПЕКИ (SA-8(13))",
      parameters: [
        {:sa_8_13_01,
         "Системи або компоненти системи реалізують принцип проектування безпеки з мінімізацією елементів безпеки. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: nil]},
        {:sa_8_13_odp,
         "Визначено системи або компоненти системи, які реалізують принцип проектування безпеки за принципом мінімізації елементів безпеки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-14") do
    %{
      id: :"id-spe-sa-8-14",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП ПОБУДОВИ БЕЗПЕКИ ЗА ПРИНЦИПОМ НАЙМЕНШИХ ПРИВІЛЕЇВ (SA-8(14))",
      parameters: [
        {:sa_8_14_01,
         "Системи або компоненти системи реалізують принцип побудови безпеки за принципом найменших привілеїв",
         [type: :string, default: nil]},
        {:sa_8_14_odp,
         "Визначено системи або компоненти системи, які реалізують принцип побудови безпеки за принципом найменших привілеїв",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-15") do
    %{
      id: :"id-spe-sa-8-15",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП ПРОЕКТУВАННЯ БЕЗПЕКИ ПОПЕРЕДНЬОГО ДОЗВОЛУ (SA-8(15))",
      parameters: [
        {:sa_8_15_01,
         "Системи або компоненти системи реалізують принцип проектування безпеки попереднього дозволу",
         [type: :string, default: nil]},
        {:sa_8_15_odp,
         "Визначено системи або компоненти системи, які реалізують принцип проектування безпеки попереднього дозволу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-16") do
    %{
      id: :"id-spe-sa-8-16",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП ПРОЕКТУВАННЯ БЕЗПЕКИ САМОДОСТАТНЬОЇ НАДІЙНОСТІ (SA-8(16))",
      parameters: [
        {:sa_8_16_01,
         "Системи або компоненти системи реалізують принцип проектування безпеки самодостатньої надійності. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: nil]},
        {:sa_8_16_odp,
         "Визначено системи або компоненти реалізують принцип проектування ґрунтується на самодостатній надійності; системи, безпеки, які що",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-17") do
    %{
      id: :"id-spe-sa-8-17",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП ПРОЕКТУВАННЯ БЕЗПЕКИ ЗАХИЩЕНОГО РОЗПОДІЛЕНОГО ВМІСТУ (SA-8(17))",
      parameters: [
        {:sa_8_17_01,
         "Системи або компоненти системи реалізують принцип проектування безпеки захищеного розподіленого вмісту",
         [type: :string, default: nil]},
        {:sa_8_17_odp,
         "Визначено системи або компоненти системи, які реалізують принцип безпечного проектування захищеного розподіленого вмісту",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-18") do
    %{
      id: :"id-spe-sa-8-18",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП ПОБУДОВИ БЕЗПЕКИ ДОВІРЕНИХ КАНАЛІВ ЗВ'ЯЗКУ (SA-8(18))",
      parameters: [
        {:sa_8_18_01,
         "Системи або компоненти системи реалізують принцип побудови безпеки довірених каналів зв'язку",
         [type: :string, default: nil]},
        {:sa_8_18_odp,
         "Визначено системи або компоненти системи, які реалізують принцип побудови безпеки довірених каналів зв'язку",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-19") do
    %{
      id: :"id-spe-sa-8-19",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП ПРОЕКТУВАННЯ БЕЗПЕКИ ДОВГОТРИВАЛОГО (SA-8(19))",
      parameters: [
        {:sa_8_19_01,
         "Системи або компоненти системи реалізують принцип проектування безпеки довготривалого захисту",
         [type: :string, default: nil]},
        {:sa_8_19_odp,
         "Визначено системи або компоненти системи, які втілюють принцип проектування безпеки довготривалого захисту",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-20") do
    %{
      id: :"id-spe-sa-8-20",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП БЕЗПЕЧНОГО УПРАВЛІННЯ МЕТАДАНИМИ (SA-8(20))",
      parameters: [
        {:sa_8_20_01,
         "Системи або компоненти системи реалізують принцип безпечного управління метаданими",
         [type: :string, default: nil]},
        {:sa_8_20_odp,
         "Визначено системи або компоненти системи, які реалізують принцип безпечного управління метаданими",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-21") do
    %{
      id: :"id-spe-sa-8-21",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП ПРОЕКТУВАННЯ БЕЗПЕКИ НА ОСНОВІ САМОАНАЛІЗУ (SA-8(21))",
      parameters: [
        {:sa_8_21_01,
         "Системи або компоненти системи реалізують принцип проектування безпеки на основі самоаналізу",
         [type: :string, default: nil]},
        {:sa_8_21_odp,
         "Визначено системи або компоненти системи, які реалізують принцип самоаналізу при проектуванні безпеки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-23") do
    %{
      id: :"id-spe-sa-8-23",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП ПРОЕКТУВАННЯ БЕЗПЕЧНИХ НАЛАШТУВАНЬ ЗА ЗАМОВЧУВАННЯМ (SA-8(23))",
      parameters: [
        {:sa_8_23_odp,
         "Визначено системи або компоненти системи, реалізують принцип безпечних налаштувань замовчуванням; які за SA-08(23) системи або компоненти системи реалізують принцип проектування безпечних налаштувань за замовчуванням",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-25") do
    %{
      id: :"id-spe-sa-8-25",
      description: "",
      title: "<SA-08(25)_ODP системи або компоненти реалізують принцип безпеки економіки. (SA-8(25))",
      parameters: [
        {:sa_8_25_01,
         "Системи або компоненти реалізують принцип безпеки економіки. які системи",
         [type: :string, default: nil]},
        {:sa_8_25_odp,
         "Визначено системи або компоненти реалізують принцип безпеки економіки; системи,",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-26") do
    %{
      id: :"id-spe-sa-8-26",
      description: "",
      title: "<SA-08(26)_ODP системи або компоненти реалізують принцип безпеки продуктивності. (SA-8(26))",
      parameters: [
        {:sa_8_26_01,
         "Системи або компоненти реалізують принцип безпеки продуктивності. які системи",
         [type: :string, default: nil]},
        {:sa_8_26_odp,
         "Визначено системи або компоненти системи, реалізують принцип безпеки продуктивності",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-27") do
    %{
      id: :"id-spe-sa-8-27",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП БЕЗПЕКИ З УРАХУВАННЯМ ЛЮДСЬКОГО ФАКТОРУ (SA-8(27))",
      parameters: [
        {:sa_8_27_01,
         "Системи або компоненти системи реалізують принцип безпеки з урахуванням людського фактору",
         [type: :string, default: nil]},
        {:sa_8_27_odp,
         "Визначено системи або компоненти системи, які реалізують принцип безпеки з урахуванням людського фактору",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-28") do
    %{
      id: :"id-spe-sa-8-28",
      description: "",
      title: "<SA-08(28)_ODP системи або компоненти реалізують принцип прийнятного рівня безпеки. (SA-8(28))",
      parameters: [
        {:sa_8_28_01,
         "Системи або компоненти системи реалізують принцип повторюваних та задокументованих процедур",
         [type: :string, default: nil]},
        {:sa_8_28_odp,
         "Визначено системи або компоненти системи, реалізують принцип прийнятного рівня безпеки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-31") do
    %{
      id: :"id-spe-sa-8-31",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП БЕЗПЕЧНОЇ МОДИФІКАЦІЇ СИСТЕМ (SA-8(31))",
      parameters: [
        {:sa_8_31_01,
         "Системи або компоненти системи реалізують принцип безпечної модифікації систем",
         [type: :string, default: nil]},
        {:sa_8_31_odp,
         "Визначено системи або компоненти системи, реалізують принцип безпечної модифікації систем; які",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-32") do
    %{
      id: :"id-spe-sa-8-32",
      description: "",
      title: "РЕАЛІЗУЮТЬ ПРИНЦИП ДОСТАТНЬОЇ ДОПУСКНОЇ ДОКУМЕНТАЦІЇ (SA-8(32))",
      parameters: [
        {:sa_8_32_01,
         "Системи або компоненти системи реалізують принцип достатньої допускної документації",
         [type: :string, default: nil]},
        {:sa_8_32_odp,
         "Визначено системи або компоненти системи, які реалізують принцип достатньої допускної документації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-8-33") do
    %{
      id: :"id-spe-sa-8-33",
      description: "",
      title: "<SA-08(33)_ODP системи або компоненти реалізують принцип мінімізації конфіденційності. (SA-8(33))",
      parameters: [
        {:sa_8_33_odp,
         "Визначено системи або компоненти системи, реалізують принцип мінімізації конфіденційності; які SA-08(33) системи або компоненти реалізують принцип мінімізації конфіденційності. системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-9") do
    %{
      id: :"id-spe-sa-9",
      description: "a. Вимагати, щоб постачальники зовнішніх послуг для системи відповідали вимогам безпеки та приватності в організації та застосовували такі заходи захисту [Призначення: встановлені організацією заходи безпеки та приватності]. b. Визначити та задокументувати нагляд організаціїповноваження та обов’язки користувачів щодо зовнішніх послуг для системи. c. Використовувати наступні процеси, методи та техніки для постійного моніторингу дотримання контролю зовнішніми постачальниками послуг: [Призначення: визначені організацією процеси, методи та техніки].",
      title: "ЗОВНІШНІ ПОСЛУГИ ДЛЯ СИСТЕМИ (SA-9)",
      parameters: [
        {:sa_9_odp_01,
         "Визначені засоби контролю, які будуть застосовуватися зовнішніми постачальниками системних послуг",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sa_9_odp_02,
         "Визначені процеси, методи та техніки, що застосовуються для моніторингу дотримання вимог контролю зовнішніми постачальниками послуг; SA-09a.[01] дотримуються постачальники зовнішніх системних послуг вимог організаційної безпеки; SA-09a.[02] дотримуються постачальники зовнішніх системних послуг вимог приватності організації; SA-09a.[03] використовують постачальники зовнішніх системних послуг елементи керування; SA-09b.[01] визначено та задокументовано організаційний нагляд за зовнішніми системними послугами; SA-09b.[02] визначені та задокументовані ролі та обов'язки користувачів щодо зовнішніх системних сервісів; SA-09c. визначені та задокументовані ролі та обов'язки користувачів щодо зовнішніх системних послуг",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-sa-9-1") do
    %{
      id: :"id-spe-sa-9-1",
      description: "(a) Проводити організаційне оцінювання ризиків перед придбанням або переданням послуг інформаційної безпеки служб інформаційної безпеки. (b) Переконатися, що придбання або передача спеціалізованих служб інформаційної безпеки погоджені [Призначення: визначеним організацією персоналом або посадовими особами].",
      title: "ЗОВНІШНІ ПОСЛУГИ ДЛЯ СИСТЕМИ- ОЦІНЮВАННЯ РИЗИКІВ ТА ОРГАНІЗАЦІЙНІ ПОГОДЖЕННЯ (SA-9(1))",
      parameters: [
        {:sa_9_1_a,
         "Проводиться організаційна оцінка ризиків перед придбанням або передачею послуг з інформаційної безпеки",
         [type: :string, default: nil]},
        {:sa_9_1_b,
         "Схвалюють персонал або ролі придбання або передачу спеціальних послуг з інформаційної безпеки",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sa_9_1_odp,
         "Визначено персонал або ролі, які схвалюють придбання або передачу спеціальних послуг з інформаційної безпеки",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-sa-9-2") do
    %{
      id: :"id-spe-sa-9-2",
      description: "Вимагати від постачальників наведених нижче зовнішніх послуг для системи [Призначення: визначених організацією зовнішніх послуг для системи] визначити функції, порти, протоколи та інші служби, необхідні для використання таких служб.",
      title: "ЗОВНІШНІ ПОСЛУГИ ДЛЯ СИСТЕМИ- ВИЗНАЧЕННЯ ФУНКЦІЙ, ПОРТІВ, ПРОТОКОЛІВ ТА СЛУЖБ (SA-9(2))",
      parameters: [
        {:sa_9_2_01,
         "Необхідно постачальникам зовнішніх системних послуг ідентифікувати функції, порти, протоколи та інші послуги, необхідні для використання таких послуг",
         [type: :string, default: "TLS 1.3"]},
        {:sa_9_2_odp,
         "Визначені зовнішні системні сервіси, які потребують ідентифікації функцій, портів, протоколів та інших сервісів",
         [type: :string, default: "TLS 1.3"]}
      ]
    }
  end

  def spec(:"id-spe-sa-9-3") do
    %{
      id: :"id-spe-sa-9-3",
      description: "Створити, задокументувати та підтримувати довірчі відносини із зовнішніми постачальниками послуг на основі таких вимог, властивостей, факторів або умов: [Призначення: визначених організацією вимог, властивостей, факторів або умов щодо безпеки та приватності, що визначають прийнятні довірчі відносини].",
      title: "ЗОВНІШНІ ПОСЛУГИ ДЛЯ СИСТЕМИ - СТВОРЕННЯ ТА ПІДТРИМКА ДОВІРЧИХ ВІДНОСИН З ПОСТАЧАЛЬНИКАМИ (SA-9(3))",
      parameters: [
        {:sa_9_3_01,
         "Встановлені та задокументовані довірчі відносини з зовнішніми постачальниками послуг на основі вимог, властивостей, факторів або умов безпеки",
         [type: :string, default: nil]},
        {:sa_9_3_02,
         "Підтримуються довірчі відносини з зовнішніми постачальниками послуг на основі вимог, властивостей, факторів або умов безпеки",
         [type: :string, default: nil]},
        {:sa_9_3_03,
         "Встановлені та задокументовані довірчі відносини із зовнішніми постачальниками послуг на основі вимог, властивостей, факторів або умов конфіденційності",
         [type: :string, default: nil]},
        {:sa_9_3_04,
         "Підтримуються довірчі відносини із зовнішніми постачальниками послуг на основі вимог, властивостей, факторів або умов конфіденційності",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-9-4") do
    %{
      id: :"id-spe-sa-9-4",
      description: "Виконайте такі дії, щоб переконатися, що інтереси [Призначення: визначених організацією зовнішніх постачальників послуг] узгоджуються з інтересами організації та відображають їх: [Призначення: дії, визначені організацією].",
      title: "ЗОВНІШНІ СИСТЕМНІ СЛУЖБИ СПОЖИВАЧІВ І ПОСТАЧАЛЬНИКІВ (SA-9(4))",
      parameters: [
        {:sa_9_4_01,
         "Вживаються дії для перевірки того, що інтереси зовнішніх постачальників послуг узгоджуються з інтересами організації та відображають їх",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-sa-9-5") do
    %{
      id: :"id-spe-sa-9-5",
      description: "Обмежити розташування [Вибір (один або більше): обробка інформації; інформація або дані; системні служби] до [Призначення: визначені організацією місця] на основі [Призначення: визначених організацією вимог або умов].",
      title: "ЗОВНІШНІ ПОСЛУГИ ДЛЯ СИСТЕМИ- МІСЦЕ ОБРОБКИ, ЗБЕРІГАННЯ ТА ОБСЛУГОВУВАННЯ (SA-9(5))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sa-9-6") do
    %{
      id: :"id-spe-sa-9-6",
      description: "Зберігати контроль над криптографічними ключами для зашифрованої інформації, яка зберігається або передається через зовнішню систему.",
      title: "ЗОВНІШНІ ПОСЛУГИ ДЛЯ СИСТЕМИ- КРИПТОГРАФІЧНІ КЛЮЧІ, КЕРОВАНІ ОРГАНІЗАЦІЄЮ (SA-9(6))",
      parameters: [
        {:sa_9_6_01,
         "Зберігається ексклюзивний контроль над криптографічними ключами для зашифрованих матеріалів, що зберігаються або передаються через зовнішню систему",
         [type: :string, default: "AES-256-GCM"]}
      ]
    }
  end

  def spec(:"id-spe-sa-9-7") do
    %{
      id: :"id-spe-sa-9-7",
      description: "Забезпечити можливість перевірки цілісності інформації в організації під час її перебування в зовнішній системі.",
      title: "ЗОВНІШНІ ПОСЛУГИ ДЛЯ СИСТЕМИ- ПЕРЕВІРКА ЦІЛІСНОСТІ, ЩО КОНТРОЛЮЄТЬСЯ ОРГАНІЗАЦІЄЮ (SA-9(7))",
      parameters: [
        {:sa_9_7_01,
         "Передбачена можливість перевірки цілісності інформації під час її перебування у зовнішній системі",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-sa-9-8") do
    %{
      id: :"id-spe-sa-9-8",
      description: "Обмежити географічне розміщення обробки та зберігання даних об’єктами, розташованими в межах юридичної юрисдикції України.",
      title: "ЗОВНІШНІ ПОСЛУГИ ДЛЯ СИСТЕМИЗБЕРІГАННЯ – ЮРИСДИКЦІЯ УКРАЇНИ (SA-9(8))",
      parameters: [
        {:sa_9_8_01,
         "Обмежується географічне розміщення обробки інформації та зберігання даних об'єктами, розташованими в межах юридичної юрисдикції України",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-10") do
    %{
      id: :"id-spe-sa-10",
      description: "Вимагати від розробника системи, системного компонента або системної служби: a. виконання управління конфігурацією під час [Вибір (один або кілька): проєктування; розробки; реалізації; експлуатації; видалення] системи, компонента або служби; b. документувати, керувати та контролювати цілісність змін у [Призначення: визначених організацією елементах конфігурації при управлінні конфігурацією]; c. впроваджувати тільки схвалені організацією зміни в системі, компоненті або службі; d. документувати зміни в системі, компоненті або службі та можливі наслідки таких змін для безпеки та приватності; e. відстежувати недоліки безпеки та усунення дефектів у системі, компоненті або службі та повідомляти про результати [Призначення: визначений організацією персонал].",
      title: "УПРАВЛІННЯ КОНФІГУРАЦІЄЮ РОЗРОБНИКА (SA-10)",
      parameters: [
        {:sa_10_odp_02,
         "Визначено елементи конфігурації під керуванням",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-10-1") do
    %{
      id: :"id-spe-sa-10-1",
      description: "",
      title: "Управління конфігурацією розробника — Перевірка цілісності програмного забезпечення та мікропрограм (SA-10(1))",
      parameters: [
        {:sa_10_1_01,
         "Зобов'язаний розробник системи, системного компонента або системного служби забезпечити перевірку цілісності програмного забезпечення та компонентів програмного забезпечення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-10-6") do
    %{
      id: :"id-spe-sa-10-6",
      description: "",
      title: "Управління конфігурацією розробника — Довірене постачання (SA-10(6))",
      parameters: [
        {:sa_10_6_01,
         "Повинен розробник системи, системного компонента або системної служби виконувати процедури для забезпечення того, щоб апаратні засоби, програмне забезпечення й оновлення прошивки, що стосуються безпеки й оновлюються в організації, точно відповідали оригінальним копіям",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sa-11") do
    %{
      id: :"id-spe-sa-11",
      description: "Вимагати від розробника системи, системного компонента або системної служби на всіх етапах проєктування та життєвого циклу розробки системи: a. створити та впровадити план з оцінювання безпеки та приватності; b. виконати [Вибір (один або кілька): одиниця; інтеграція; система; регресія] тестування/оцінювання [Призначення: з визначеною організацією частотою] з [Призначення: визначена організацією глибиною та охопленням]; c. надати докази (свідчення) виконання плану оцінювання та результати тестування й оцінювань; d. впровадити перевірку процесу виправлення недоліків; e. виправити дефекти, виявлені під час тестування та оцінювання.",
      title: "УПРАВЛІННЯ КОНФІГУРАЦІЄЮ РОЗРОБНИКА - ПРЕДСТАВНИКИ БЕЗПЕКИ ТА ПРИВАТНОСТІ (SA-11)",
      parameters: [
        {:sa_11_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {одиниця; інтеграція; система; регресія}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-11-2") do
    %{
      id: :"id-spe-sa-11-2",
      description: "",
      title: "Тестування та оцінювання розробника — Моделювання загроз і аналіз вразливостей (SA-11(2))",
      parameters: [
        {:sa_11_2_a_01,
         "Повинен розробник системи, компонента системи або системного сервісу виконувати моделювання загроз під час розробки системи, компонента або сервісу, що використовує <SA-11(02)_ODP[01]_інформацію>",
         [type: :integer, default: 30]},
        {:sa_11_2_a_02,
         "Повинен розробник системи, системного компонента або системної служби виконувати аналіз вразливостей під час розробки системи, компонента або служби, які використовують <SA-11(02)_ODP[01]_інформацію>",
         [type: :integer, default: 30]},
        {:sa_11_2_a_03,
         "Повинен розробник системи, компонента системи або системного сервісу виконувати моделювання загроз під час подальшого тестування та оцінювання системи, компонента або сервісу, що використовує <SA- 11(02)_ODP[01]_інформацію>",
         [type: :integer, default: 30]},
        {:sa_11_2_a_04,
         "Повинен розробник системи, системного компонента або системного сервісу виконувати аналіз вразливостей під час подальшого тестування та оцінювання системи, компонента або сервісу, що використовує <SA11(02)_ODP[01]_інформацію>",
         [type: :integer, default: 30]},
        {:sa_11_2_b_01,
         "Повинен розробник системи, компонента системи або системного сервісу виконувати моделювання загроз під час розробки системи, компонента або сервісу, що використовує засоби та методи",
         [type: :integer, default: 30]},
        {:sa_11_2_b_02,
         "Повинен розробник системи, компонента системи або системного сервісу виконувати моделювання загроз під час подальшого тестування та оцінювання системи, компонента або сервісу, що використовує інструменти та методи",
         [type: :integer, default: 30]},
        {:sa_11_2_b_03,
         "Повинен розробник системи, компонента системи або системної служби виконувати аналіз вразливостей під час розробки системи, компонента або служби, яка використовує інструменти та методи",
         [type: :integer, default: 30]},
        {:sa_11_2_b_04,
         "Повинен розробник системи, системного компонента або системного сервісу виконувати аналіз вразливостей під час подальшого тестування та оцінювання системи, компонента або сервісу, що використовує інструменти та методи",
         [type: :integer, default: 30]},
        {:sa_11_2_c_01,
         "Повинен розробник системи, системного компонента або системної служби виконувати моделювання загроз на широті та глибині під час розробки системи, компонента або сервісу",
         [type: :integer, default: 30]},
        {:sa_11_2_c_02,
         "Зобов'язаний розробник системи, компонента системи або системної служби виконувати аналіз вразливостей під час подальшого тестування та оцінювання системи, компонента або сервісу, який проводить моделювання та аналіз на ширину та глибину",
         [type: :integer, default: 30]},
        {:sa_11_2_d_01,
         "Повинен розробник системи, компонента системи або системної служби виконувати моделювання загроз під час розробки системи, компонента або сервісу, що дає змогу отримати докази, які відповідають критеріям прийнятності",
         [type: :integer, default: 30]},
        {:sa_11_2_d_02,
         "Повинен розробник системи, компонента системи або системної служби виконувати моделювання загроз під час подальшого тестування та оцінювання системи, компонента або сервісу, що дає змогу отримати докази, які відповідають критеріям прийнятності ",
         [type: :integer, default: 30]},
        {:sa_11_2_d_03,
         "Повинен розробник системи, системного компонента або системної служби виконувати аналіз вразливостей під час розробки системи, компонента або служби, який надає докази, що відповідають прийнятності>",
         [type: :integer, default: 30]},
        {:sa_11_2_d_04,
         "Критеріям повинен розробник системи, системного компонента або системної служби виконувати аналіз вразливостей під час подальшого тестування та оцінювання системи, компонента або сервісу, який надає докази, що відповідають <SA11(02)_ODP[06] критеріям прийнятності",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-sa-11-3") do
    %{
      id: :"id-spe-sa-11-3",
      description: "",
      title: "ATE_IND.2 EAL2 Незалежне тестування EAL3 Незалежне тестування — EAL4 EAL5 EAL6 зразок (SA-11(3))",
      parameters: [
        {:sa_11_3_a_01,
         "Потрібен незалежний агент, який відповідатиме критеріям незалежності для перевірки правильності виконання плану оцінки безпеки розробника та доказів, отриманих під час тестування та оцінки",
         [type: :integer, default: 30]},
        {:sa_11_3_a_02,
         "Потрібен незалежний агент, який відповідатиме критеріям незалежності для перевірки правильності виконання плану оцінювання конфіденційності розробника та доказів, отриманих під час тестування та оцінювання",
         [type: :integer, default: 30]},
        {:sa_11_3_b,
         "Надано незалежному агенту достатньо інформації для завершення процесу перевірки, чи надано йому повноваження для отримання такої інформації",
         [type: :string, default: nil]},
        {:sa_11_3_odp,
         "Визначені критерії незалежності, відповідати незалежний агент; яким повинен",
         [type: :list, default: []]}
      ]
    }
  end

  def spec(:"id-spe-sa-11-5") do
    %{
      id: :"id-spe-sa-11-5",
      description: "",
      title: "Тестування та оцінювання розробника — Тестування на проникнення (SA-11(5))",
      parameters: [
        {:sa_11_5_a_01,
         "Зобов'язаний розробник системи, системного компонента або системної служби виконувати тестування на проникнення на наступному рівні суворості: ширина",
         [type: :string, default: nil]},
        {:sa_11_5_a_02,
         "Зобов'язаний розробник системи, системного компонента або системної служби виконувати тестування на проникнення на наступному рівні суворості: глибина",
         [type: :string, default: nil]},
        {:sa_11_5_b,
         "Зобов'язаний розробник системи, системного компонента або системної служби проводити тестування на проникнення в умовах <SA-11(05)_ODP[03]_обмежень>",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-11-7") do
    %{
      id: :"id-spe-sa-11-7",
      description: "",
      title: "Покриття Аналіз покриття (SA-11(7))",
      parameters: [
        {:sa_11_7_01,
         "Повинен розробник системи, системного компонента або системної служби перевіряти, що обсяг тестування та оцінювання забезпечує повне покриття необхідних засобів контролю на ширину",
         [type: :string, default: nil]},
        {:sa_11_7_02,
         "Повинен розробник системи, системного компонента або системної служби перевіряти, що обсяг тестування та оцінювання забезпечує повне покриття необхідних засобів контролю на глибину",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-11-8") do
    %{
      id: :"id-spe-sa-11-8",
      description: "",
      title: "ТЕСТУВАННЯ ТА ОЦІНЮВАННЯ РОЗРОБНИКА - ДИНАМІЧНИЙ АНАЛІЗ КОДУ (SA-11(8))",
      parameters: [
        {:sa_11_8_01,
         "Повинен розробник системи, системного компонента або системної служби використовувати інструменти динамічного аналізу коду для виявлення недоліків помилок",
         [type: :string, default: nil]},
        {:sa_11_8_02,
         "Зобов'язаний розробник системи, системного компонента або системної служби документувати результати аналізу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-12") do
    %{
      id: :"id-spe-sa-12",
      description: "",
      title: "КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ (SA-12)",
      parameters: [
        {:sa_12_01,
         "КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ [Вилучено: включено до SR]. SA12(1) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ - СТРАТЕГІЇ, ІНСТРУМЕНТИ ТА МЕТОДИ ЗАКУПІВЕЛЬ [Вилучено: включено до SR-5]. SA12(2) КЕРУВАННЯ РИЗИКАМИ ПОСТАЧАЛЬНИКІВ [Вилучено: включено до SR-6]. SA12(3) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ - НАДІЙНЕ ПЕРЕВЕЗЕННЯ ТА ЗБЕРІГАННЯ [Вилучено: включено до SR-3]. SA12(4) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ДИВЕРСИФІКАЦІЯ ПОСТАЧАЛЬНИКІВ [Вилучено: включено до SR-3 (1)]. SA12(5) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ - ОБМЕЖЕННЯ ШКОДИ [Вилучено: включено до SR-3 (2)]. SA12(6) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ - МІНІМІЗАЦІЯ ЧАСУ ЗАКУПІВЕЛЬ [Вилучено: включено до SR-5 (1)]. SA12(7) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ - ОЦІНЮВАННЯ ПЕРЕД ВИБОРОМ, ПРИЙНЯТТЯМ ТА ОНОВЛЕННЯМ [Вилучено: включено до SR-5 (2)]. SA12(8) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ ВИКОРИСТАННЯ ВСЕБІЧНОЇ РОЗВІДУВАЛЬНОЇ ІНФОРМАЦІЇ [Вилучено: включено до SR-3 (2)]. ЛАНЦЮГА ПОСТАЧАННЯ - АНАЛІЗ ПОСТАЧАННЯ - - SA12(9) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ - ОПЕРАЦІЙНА БЕЗПЕКА [Вилучено: включено до SR-7]. SA12(10) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ - ПЕРЕВІРКА НА СПРАВЖНІСТЬ І НЕЗМІНЕНІСТЬ [Вилучено: включено до SR-4 (3)]. SA12(11) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ - ПЕРЕВІРКА НА СПРАВЖНІСТЬ І НЕЗМІНЕНІСТЬ [Вилучено: включено до SR-6 (1)]. SA12(12) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ - УГОДИ ПРО ПОВІДОМЛЕННЯ [Вилучено: включено до SR-8]. SA12(13) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ - КОМПОНЕНТИ КРИТИЧНИХ СИСТЕМ [Вилучено: включено до MA-6 та RA-9]. SA12(14) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ - ІДЕНТИЧНІСТЬ ТА ПРОСТЕЖУВАНІСТЬ [Вилучено: включено до SR-4 (1) та SR-4(2)]. SA12(15) КЕРУВАННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ - ПРОЦЕСИ ДЛЯ УСУНЕННЯ НЕДОЛІКІВ АБО ДЕФЕКТІВ [Вилучено: включено до SR-3]",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-sa-13") do
    %{
      id: :"id-spe-sa-13",
      description: "",
      title: "ДОВІРЧІСТЬ (SA-13)",
      parameters: [
        {:sa_13_01,
         "ДОВІРЧІСТЬ [Вилучено: включено до SA-8]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-14") do
    %{
      id: :"id-spe-sa-14",
      description: "",
      title: "АНАЛІЗ КРИТИЧНОСТІ (SA-14)",
      parameters: [
        {:sa_14_01,
         "АНАЛІЗ КРИТИЧНОСТІ [Вилучено: включено до RA-9]. SA14(1) КРИТИЧНІ КОМПОНЕНТИ БЕЗ ЖИТТЄЗДАТНИХ АЛЬТЕРНАТИВНИХ ДЖЕРЕЛ [Вилучено: включено до SA-20]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-15") do
    %{
      id: :"id-spe-sa-15",
      description: "a. b. Вимагати від розробника системи, системного компонента або системної служби слідувати документованому процесу розробки, який: 1. явно відповідає вимогам безпеки та приватності; 2. визначає стандарти й інструменти, які використовуються в процесі розробки; 3. документує конкретні параметри та конфігурації інструментарію, що використовуються в процесі розробки; 4. документує, управляє та забезпечує цілісність змін у процесі та/або інструментах, які використовуються в процесі розробки. Ознайомитися з процесом розробки, стандартами, інструментами, параметрами інструментарію і конфігураціями інструментів [Призначення: визначена організацією частота], щоб визначити, чи можуть вибрані й використовувані процеси, стандарти, інструменти, параметри та конфігурації інструментів задовольнити [Призначення: визначені організацією вимоги до безпеки та приватності].",
      title: "ПРОЦЕСИ, СТАНДАРТИ ТА ІНСТРУМЕНТИ РОЗРОБКИ (SA-15)",
      parameters: [
        {:sa_15_odp_01,
         "Визначено періодичність перегляду процесу розробки, стандартів, інструментів, опцій інструментів та конфігурацій інструментів",
         [type: :string, default: "щорічно"]},
        {:sa_15_odp_02,
         "Визначені вимоги до безпеки, яким має відповідати процес, стандарти, інструменти, опції інструментів та конфігурації інструментів",
         [type: :string, default: nil]},
        {:sa_15_odp_03,
         "Визначені вимоги до конфіденційності, яким має відповідати процес, стандарти, інструменти, опції інструментів та конфігурації інструментів; SA-15a.01[01] зобов'язаний розробник системи, системного компонента або системної служби дотримуватися задокументованого процесу розробки, який явно враховує вимоги безпеки; SA-15a.01[02] зобов'язаний розробник системи, системного компонента або системної служби дотримуватися задокументованого процесу розробки, який чітко враховує вимоги щодо конфіденційності; SA-15a.02[01] повинен розробник системи, системного компонента або системної служби дотримуватися задокументованого процесу розробки, який визначає стандарти, що використовуються в процесі розробки; SA-15a.02[02] повинен розробник системи, системного компонента або системного служби дотримуватися задокументованого процесу розробки, який визначає інструменти, що використовуються в процесі розробки; SA-15a.03[01] овинен розробник системи, системного компонента або системної служби дотримуватися задокументованого процесу розробки, який документує конкретний інструмент, що використовується в процесі розробки; SA-15a.03[02] повинен розробник системи, системного компонента або системної служби дотримуватися задокументованого процесу розробки, який документує конкретні конфігурації інструментів, що використовуються в процесі розробки; SA-15a.04 повинен розробник системи, системного компонента або системної служби дотримуватися задокументованого процесу розробки, який документує, управляє та забезпечує цілісність змін у процесі та/або інструментах, що використовуються під час розробки; SA-15b.[01] повинен розробник системи, системного компонента або системної служби дотримуватися задокументованого процесу розробки, в якому процес розробки, стандарти, інструменти, опції інструментів та конфігурації інструментів переглядаються з частотою, щоб визначити, що процес, стандарти, інструменти, опції інструментів та конфігурації інструментів, вибрані та застосовані, задовольняють вимоги безпеки; SA-15b.[02] повинен розробник системи, системного компонента або системної служби дотримуватися задокументованого процесу розробки, в якому процес розробки, стандарти, інструменти, опції інструментів та конфігурації інструментів переглядаються з частотою, щоб визначити, що процес, стандарти, інструменти, опції інструментів та конфігурації інструментів, обрані та застосовані, задовольняють вимоги щодо конфіденційності",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-sa-15-5") do
    %{
      id: :"id-spe-sa-15-5",
      description: "",
      title: "ПРОЦЕС, СТАНДАРТИ ТА ІНСТРУМЕНТИ РОЗРОБКИ - ЗМЕНШЕННЯ ПОВЕРХНІ АТАКИ (SA-15(5))",
      parameters: [
        {:sa_15_5_01,
         "Зобов'язаний розробник системи, системного компонента або системної служби зменшити поверхню атаки до межі",
         [type: :string, default: nil]},
        {:sa_15_5_odp,
         "Визначені порогові значення, до яких необхідно зменшити поверхню атаки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-15-6") do
    %{
      id: :"id-spe-sa-15-6",
      description: "",
      title: "ПРОЦЕС, СТАНДАРТИ ТА ІНСТРУМЕНТИ РОЗРОБКИ - ПОСТІЙНЕ ВДОСКОНАЛЕННЯ (SA-15(6))",
      parameters: [
        {:sa_15_6_01,
         "Зобов'язаний розробник системи, системного компонента або системної служби впроваджувати чіткий процес постійного вдосконалення процесу розробки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-15-7") do
    %{
      id: :"id-spe-sa-15-7",
      description: "",
      title: "Співбесіда: [ВИБІР: Персонал організації, який відповідає за придбання систем та послуг; персонал організації, який відповідає за інформаційну ПРОЦЕС, СТАНДАРТИ ТА ІНСТРУМЕНТИ РОЗРОБКИ безпеку; розробник системи]. АНАЛІЗ ВРАЗЛИВОСТЕЙ АВТОМАТИЗОВАНИЙ (SA-15(7))",
      parameters: [
        {:sa_15_7_a,
         "Зобов'язаний розробник системи, системного компонента або системного сервісу виконувати автоматизований аналіз вразливостей частота з використанням інструментарію",
         [type: :string, default: "щорічно"]},
        {:sa_15_7_b,
         "Зобов'язаний розробник системи, системного компоненту або системної служби визначати потенціал використання виявлених вразливостей частота",
         [type: :string, default: "щорічно"]},
        {:sa_15_7_c,
         "Повинен розробник системи, системного компоненту або системної служби визначати потенційні заходи зменшення ризику частота для наданих вразливостей",
         [type: :string, default: "щорічно"]},
        {:sa_15_7_d,
         "Повинен розробник системи, системного компонента або системної послуги надавати вихідні дані інструментів і результати аналізу частота персоналу або ролям",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-sa-15-8") do
    %{
      id: :"id-spe-sa-15-8",
      description: "",
      title: "ПРОЦЕС, СТАНДАРТИ ТА ІНСТРУМЕНТИ РОЗРОБКИ - ПОВТОРНЕ ВИКОРИСТАННЯ ІНФОРМАЦІЇ ПРО ЗАГРОЗИ ТА ВРАЗЛИВОСТІ (SA-15(8))",
      parameters: [
        {:sa_15_8_01,
         "Повинен розробниксистеми, системного компонента або системної служби використовувати моделювання загроз з подібних систем, компонентів або служб для інформування про поточний процес розробки",
         [type: :string, default: nil]},
        {:sa_15_8_02,
         "Повинен розробник системи, системного компонента або системних служб використовувати аналіз вразливостей аналогічних систем, компонентів або служб для інформування поточного процесу розробки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-15-9") do
    %{
      id: :"id-spe-sa-15-9",
      description: "",
      title: "ПРОЦЕС, СТАНДАРТИ ТА ІНСТРУМЕНТИ ВИКОРИСТАННЯ РЕАЛЬНИХ ДАНИХ (SA-15(9))",
      parameters: [
        {:sa_15_9_01,
         "ПРОЦЕС, СТАНДАРТИ ТА ІНСТРУМЕНТИ ВИКОРИСТАННЯ РЕАЛЬНИХ ДАНИХ [Вилучено: включено до SA-3(2)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-16") do
    %{
      id: :"id-spe-sa-16",
      description: "Вимагати від розробника системи, системного компонента або системної служби забезпечити наступне навчання щодо правильного використання та функціонування реалізованих функцій, заходів і механізмів безпеки та приватності [Призначення: визначене організацією навчання].",
      title: "НАВЧАННЯ, ЩО НАДАЄТЬСЯ РОЗРОБНИКАМИ (SA-16)",
      parameters: [
        {:sa_16_01,
         "Повинен розробник системи, системного компонента або системної служби проводити навчання щодо правильного використання та експлуатації впроваджених функцій, засобів управління та/або механізмів безпеки та приватності",
         [type: :string, default: nil]},
        {:sa_16_odp,
         "Визначено навчання щодо правильного використання та експлуатації впроваджених функцій безпеки та приватності, засобів контролю та/або механізмів, що надаються розробником системи, системного компонента або системної служби",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-17") do
    %{
      id: :"id-spe-sa-17",
      description: "Вимагати від розробника системи, системного компонента або системної служби створення специфікації проєкту та архітектури безпеки та приватності, яка: a. узгоджується з архітектурою безпеки та приватності організації яка є невід’ємною частиною корпоративної архітектури організації; b. точно та повністю описує необхідні функції безпеки та приватності, а також розподіл заходів захисту між фізичними та логічними компонентами; c. пояснює, як разом працюють окремі функції, механізми та служби безпеки для забезпечення необхідних можливостей безпеки та єдиного підходу до захисту.",
      title: "ПРОЄКТ ТА АРХІТЕКТУРА РОЗРОБНИКА (SA-17)",
      parameters: [
        {:sa_17_a_01,
         "Повинен розробник системи, системного компонента або системної служби створювати специфікації проєкту та архітектури безпеки, які відповідають архітектурі безпеки організації, що є невід'ємною частиною архітектури підприємства організації",
         [type: :integer, default: 30]},
        {:sa_17_a_02,
         "Повинен розробник системи, системного компонента або системної служби створювати проєкту та архітектури безпеки поиватності, які відповідають архітектурі приватності організації, що є невід'ємною частиною корпоративної архітектури організації",
         [type: :integer, default: 30]},
        {:sa_17_b_01,
         "Зобов'язаний розробник системи, системного компонента або системної служби підготувати специфікацію проєкту та архітектуру безпеки, які точно і повно описують необхідну функціональність безпеки та розподіл засобів контролю між фізичними та логічними компонентами",
         [type: :string, default: nil]},
        {:sa_17_b_02,
         "Зобов'язаний розробник системи, системного компонента або системної служби підготувати специфікацію проєкту та архітектуру приватності, які точно і повно описують необхідну функціональність приватності та розподіл засобів контролю між фізичними та логічними компонентами",
         [type: :string, default: nil]},
        {:sa_17_c_01,
         "Повинен розробник системи, системного компонента або системного сервісу створювати проектну специфікацію та архітектуру безпеки, які описують, як окремі функції, механізми та сервіси безпеки працюють разом для забезпечення необхідних можливостей безпеки та єдиного підходу до захисту",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sa_17_c_02,
         "Повинен розробник системи, системного компонента або системної служби створювати специфікацію проєкту та архітектуру приватності, які описують, як окремі функції, механізми та служби конфіденційності працюють разом для забезпечення необхідних можливостей приватності та єдиного підходу до захисту",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sa-17-1") do
    %{
      id: :"id-spe-sa-17-1",
      description: "",
      title: "Проєкт і архітектура безпеки розробника — Формальна модель політики (SA-17(1))",
      parameters: [
        {:sa_17_1_a_02,
         "Повинен розробник системи, системного компонента або системної служби, як невід'ємну частину процесу розробки, створювати формальну модель політики, що описує організаційну політику конфіденційності, яка підлягає виконанню",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sa_17_1_b_01,
         "Повинен розробник системи, системного компонента або системної служби доводити, що формальна модель політики є внутрішньо узгодженою і достатньою для забезпечення дотримання визначених елементів політики безпеки організації при її впровадженні",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sa_17_1_b_02,
         "Повинен розробник системи, системного компонента або системної служби доводити, що формальна модель політики є внутрішньо узгодженою і достатньою для забезпечення дотримання визначених елементів організаційної політики приватності при її впровадженні",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-sa-17-2") do
    %{
      id: :"id-spe-sa-17-2",
      description: "",
      title: "Проєкт і архітектура безпеки розробника — Компоненти, що необхідні для забезпечення безпеки (SA-17(2))",
      parameters: [
        {:sa_17_2_a_01,
         "Зобов'язаний розробник системи, системного компонента або системної служби визначати апаратне забезпечення, що має відношення до безпеки",
         [type: :string, default: nil]},
        {:sa_17_2_a_02,
         "Зобов'язаний розробник системи, системного компонента або системної служби визначати програмне забезпечення, що має відношення до безпеки; SA-17(02)(a)[03] зобов'язаний розробник системи, системного компонента або системної служби визначати мікропрограмне забезпечення, що мають відношення до безпеки",
         [type: :string, default: nil]},
        {:sa_17_2_b,
         "Повинен розробник системи, системного компонента або системної служби надавати обґрунтування того, що визначення обладнання, програмного забезпечення та мікропрограмного забезпечення, що мають відношення до безпеки, є повним",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-17-3") do
    %{
      id: :"id-spe-sa-17-3",
      description: "",
      title: "Проєкт і архітектура безпеки розробника — Формальна відповідність (SA-17(3))",
      parameters: [
        {:sa_17_3_a_01,
         "Зобов'язаний розробник системи, системного компонента або системної служби визначати апаратне забезпечення, що має відношення до безпеки",
         [type: :string, default: nil]},
        {:sa_17_3_a_02,
         "Зобов'язаний розробник системи, системного компонента або системної служби визначати програмне забезпечення, що має відношення до безпеки",
         [type: :string, default: nil]},
        {:sa_17_3_a_03,
         "Зобов'язаний розробник системи, системного компонента або системної служби визначати мікропрограми, що мають відношення до безпеки",
         [type: :string, default: nil]},
        {:sa_17_3_b,
         "Повинен розробник системи, системного компонента або системної служби надавати обґрунтування того, що визначення обладнання, програмного забезпечення та мікропрограмного забезпечення, що мають відношення до безпеки, є повним",
         [type: :string, default: nil]},
        {:sa_17_3_c,
         "Повинен розробник системи, системного компонента або системної служби демонструвати за допомогою неформальної демонстрації, що формальна специфікація верхнього рівня повністю охоплює інтерфейси до обладнання, програмного забезпечення та мікропрограмного забезпечення, що мають відношення до безпеки",
         [type: :string, default: nil]},
        {:sa_17_3_d,
         "Повинен розробник системи, системного компонента або системної служби доводити, що формальна специфікація верхнього рівня є точним описом впровадженого обладнання, програмного забезпечення та мікропрограмного забезпечення, що мають відношення до безпеки",
         [type: :string, default: nil]},
        {:sa_17_3_e,
         "Повинен розробник системи, системного компонента або системної служби описувати релевантні для безпеки апаратні, програмні та мікропрограмні механізми, які не розглядаються у формальній специфікації верхнього рівня, але є суто внутрішніми для релевантних для безпеки апаратних, програмних та мікропрограмних засобів",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sa-17-4") do
    %{
      id: :"id-spe-sa-17-4",
      description: "",
      title: "Проєкт і архітектура безпеки розробника — Неформальна відповідність (SA-17(4))",
      parameters: [
        {:sa_17_4_a_01,
         "Повинен розробник системи, системного компонента або системної служби, як невід'ємну частину процесу розробки, створювати неформальну описову специфікацію верхнього рівня, яка визначає інтерфейси до релевантного для безпеки апаратного, програмного та мікропрограмного забезпечення з точки зору винятків",
         [type: :integer, default: 30]},
        {:sa_17_4_a_02,
         "Повинен розробник системи, системного компонента або системної служби, як невід'ємну частину процесу розробки, створювати неформальну описову специфікацію верхнього рівня, яка визначає інтерфейси до релевантного для безпеки апаратного, програмного та мікропрограмного забезпечення в термінах повідомлень про помилки",
         [type: :integer, default: 30]},
        {:sa_17_4_a_03,
         "Повинен розробник системи, системного компоненту або системної служби, як невід'ємну частину процесу розробки, створювати неформальну описову специфікацію верхнього рівня, яка визначає інтерфейси до релевантного для безпеки обладнання, програмного забезпечення та мікропрограмного забезпечення з точки зору наслідків",
         [type: :integer, default: 30]},
        {:sa_17_4_c,
         "Повинен розробник системи, системного компонента або системної служби демонструвати за допомогою неформальної демонстрації, що описова специфікація верхнього рівня повністю охоплює інтерфейси до апаратного, програмного та мікропрограмного забезпечення, що мають відношення до безпеки",
         [type: :string, default: nil]},
        {:sa_17_4_d,
         "Повинен розробник системи, системного компонента або системної служби показувати, що описова специфікація верхнього рівня є точним описом інтерфейсів до релевантного для безпеки апаратного, програмного та мікропрограмного забезпечення",
         [type: :string, default: nil]},
        {:sa_17_4_e,
         "Повинен розробник системи, системного компонента або системної служби описувати релевантні для безпеки апаратні, програмні та мікропрограмні механізми, які не розглядаються в описовій специфікації верхнього рівня, але є суто внутрішніми для релевантних для безпеки апаратних, програмних та мікропрограмних засобів",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sa_17_4_odp,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРА: {неформальна описова специфікація, переконливий аргумент за допомогою формальних методів як можлива}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-18") do
    %{
      id: :"id-spe-sa-18",
      description: "",
      title: "ЗАХИСТ ТА ВИЯВЛЕННЯ ПІДРОБКИ (SA-18)",
      parameters: [
        {:sa_18_01,
         "ЗАХИСТ ТА ВИЯВЛЕННЯ ПІДРОБКИ [Вилучено: включено до SR-9]. SA18(1) ЗАХИСТ ТА ВИЯВЛЕННЯ ПІДРОБКИ - ЕТАПИ ЖИТТЄВОГО ЦИКЛУ РОЗРОБКИ СИСТЕМИ [Вилучено: включено до SR-9 (1)]. SA18(2) ЗАХИСТ ТА ВИЯВЛЕННЯ ПІДРОБКИ - ПЕРЕВІРКА СИСТЕМ АБО КОМПОНЕНТІВ [Вилучено: включено до SR-10]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-19") do
    %{
      id: :"id-spe-sa-19",
      description: "",
      title: "СПРАВЖНІСТЬ КОМПОНЕНТА (SA-19)",
      parameters: [
        {:sa_19_01,
         "СПРАВЖНІСТЬ КОМПОНЕНТА [Вилучено: включено до SR-11]. SA19(1) СПРАВЖНІСТЬ КОМПОНЕНТА ПІДРОБЛЕННЯМ [Вилучено: включено до SR-11 (1)]. SA19(2) СПРАВЖНІСТЬ КОМПОНЕНТА - УПРАВЛІННЯ КОНФІГУРАЦІЄЮ ДЛЯ ОБСЛУГОВУВАННЯ ТА РЕМОНТУ КОМПОНЕНТІВ [Вилучено: включено до SR-11 (2)]. SA19(3) СПРАВЖНІСТЬ КОМПОНЕНТА - УТИЛІЗАЦІЯ КОМПОНЕНТІВ - НАВЧАННЯ БОРОТЬБІ З [Вилучено: включено до SR-12]. SA19(4) СПРАВЖНІСТЬ КОМПОНЕНТА - СКАНУВАННЯ НА ПІДРОБКУ [Вилучено: включено до SR-11 (3)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-20") do
    %{
      id: :"id-spe-sa-20",
      description: "Повторно реалізувати або налаштувати [Призначення: визначені організацією критичні компоненти системи].",
      title: "ІНДИВІДУАЛЬНА РОЗРОБКА КРИТИЧНИХ КОМПОНЕНТІВ (SA-20)",
      parameters: [
        {:sa_20_01,
         "Критична система повторно реалізувати або налаштувати на замовлення",
         [type: :string, default: nil]},
        {:sa_20_odp,
         "Потрібно повторно реалізувати або налаштувати на замовлення критичні компоненти системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-21") do
    %{
      id: :"id-spe-sa-21",
      description: "Вимагати, щоб розробник [Призначення: визначених організацією системи, компонент системи або послуги]: a. мав відповідні дозволи доступу, як визначено призначеним [Призначення: визначеним організацією уповноваженим органом]; b. відповідає таким додатковим критеріям перевірки персоналу: [Призначення: визначені організацією додаткові критерії перевірки персоналу].",
      title: "ПЕРЕВІРКА РОЗРОБНИКА (SA-21)",
      parameters: [
        {:sa_21_odp_01,
         "Визначена система, компонент системи або системна служба, до яких має доступ розробник",
         [type: :string, default: nil]},
        {:sa_21_odp_02,
         "Визначені офіційні обов'язки, покладені на розробника",
         [type: :string, default: nil]},
        {:sa_21_odp_03,
         "Визначені додаткові розробників; SA-21a. повинен розробник системи, системного компонента або системної служби мати відповідні повноваження доступу, як визначено призначеними уповноваженим органом організації; SA-21b. повинен розробник системи, системного компонента або системної служби відповідати додатковим критеріям перевірки персоналу. критерії перевірки персоналу",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-sa-22") do
    %{
      id: :"id-spe-sa-22",
      description: "a. Замінювати компоненти системи, якщо підтримка компонентів більше не доступна розробнику, постачальнику або виробнику. b. Надавати такі варіанти альтернативних джерел для подальшої підтримки непідтримуваних компонентів [Вибір (один або більше): внутрішня підтримка; [Призначення: підтримка, визначена організацією від зовнішніх постачальників]].",
      title: "КОМПОНЕНТИ СИСТЕМИ, ЩО НЕ ПІДТРИМУЮТЬСЯ (SA-22)",
      parameters: [
        {:sa_22_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {внутрішня підтримка; підтримка від зовнішніх постачальників}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sa-23") do
    %{
      id: :"id-spe-sa-23",
      description: "Покращення [Вибір (один або кілька): проектування; модифікація; збільшення; реконфігурація] на [Призначення: системи або системні компоненти, визначені організацією], які підтримують важливі служби або функції для підвищення надійності цих систем або компонентів.",
      title: "СПЕЦІАЛІЗАЦІЯ (SA-23)",
      parameters: [
        {:sa_23_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {модифікація дизайну; доповнення; реконфігурація}",
         [type: :string, default: nil]},
        {:sa_23_odp_02,
         "Визначені системи або компоненти системи, підтримують важливі для місії послуги або функції",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-1") do
    %{
      id: :"id-spe-sc-1",
      description: "a. Розробити, задокументувати та поширити серед [Призначення: визначеного організацією персоналу або посадових осіб]: 1. 2. Політику захисту системи та комунікацій, яка: (a) містить мету, сферу застосування, ролі, обов’язки, відповідальність керівництва, координацію між організаційними підрозділами та систему контролю відповідності (complaince); (b) відповідає чинному законодавству, виконавчим наказам, директивам, нормам, політикам, стандартам та керівним принципам. Процедури для сприяння впровадженню політики в області захисту систем і комунікацій, а також пов’язаних з ними систем і засобів захисту зв’язку. b. Призначити [Призначення: визначена організацією посадову особу] для управління політикою та процедурами захисту системи та комунікацій. c. Переглядати та оновлювати: 1. поточну політику захисту системи та комунікацій [Призначення: визначена організацією частота]; 2. поточні процедури захисту системи та комунікацій [Призначення: визначена організацією частота].",
      title: "ПОЛІТИКА ТА ПРОЦЕДУРИ ЗАХИСТУ СИСТЕМИ ТА КОМУНІКАЦІЙ (SC-1)",
      parameters: [
        {:sc_1_odp_01,
         "Визначено персонал або ролі, до яких має бути доведена політика захисту системи та комунікацій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sc_1_odp_02,
         "Визначено персонал або ролі, на які поширюються процедури захисту системи та комунікацій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sc_1_odp_03,
         "Вибрано жодне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнеспроцесу; рівень системи}",
         [type: :string, default: nil]},
        {:sc_1_odp_04,
         "Визначено посадову особу, яка керуватиме політикою та процедурами захисту системи та комунікацій",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sc_1_odp_05,
         "Визначена періодичність перегляду та оновлення поточної політики захисту системи та комунікацій",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sc_1_odp_06,
         "Є події, які вимагають перегляду та оновлення поточної політики захисту системи та комунікацій",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sc_1_odp_07,
         "Визначена періодичність перегляду та оновлення поточних процедур захисту системи та засобів зв'язку",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-sc-2") do
    %{
      id: :"id-spe-sc-2",
      description: "Розділяти функціональність користувача, включно зі службами, що призначені для користувача інтерфейсу, від функціональності системного управління.",
      title: "РОЗДІЛЕННЯ ФУНКЦІЙ (SC-2)",
      parameters: [
        {:sc_2_01,
         "Розділена функціональність користувача, включаючи сервіси користувацького інтерфейсу, від функціональності управління системою. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-2-1") do
    %{
      id: :"id-spe-sc-2-1",
      description: "",
      title: "РОЗДІЛЕННЯ ФУНКЦІЙ - ІНТЕРФЕЙСИ ДЛЯ НЕПРИВІЛЕЙОВАНИХ КОРИСТУВАЧІВ (SC-2(1))",
      parameters: [
        {:sc_2_1_01,
         "Запобігається представлення функціональності управління системою в інтерфейсі непривілейованим користувачам",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-2-2") do
    %{
      id: :"id-spe-sc-2-2",
      description: "",
      title: "РОЗДІЛЕННЯ ФУНКЦІЙ - ВІДОКРЕМЛЕННЯ (SC-2(2))",
      parameters: [
        {:sc_2_2_01,
         "Зберігається інформація окремо від додатків та програмного забезпечення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-3") do
    %{
      id: :"id-spe-sc-3",
      description: "Ізолювати функції безпеки від інших функцій.",
      title: "ІЗОЛЯЦІЯ ФУНКЦІЙ БЕЗПЕКИ (SC-3)",
      parameters: [
        {:sc_3_01,
         "Ізольовані функції безпеки від інших функцій",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-3-1") do
    %{
      id: :"id-spe-sc-3-1",
      description: "",
      title: "ІЗОЛЯЦІЯ ФУНКЦІЙ ЗАБЕЗПЕЧЕННЯ (SC-3(1))",
      parameters: [
        {:sc_3_1_01,
         "Застосовуються механізми розділення апаратних засобів для реалізації ізоляції функцій безпеки",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sc-3-2") do
    %{
      id: :"id-spe-sc-3-2",
      description: "",
      title: "ІЗОЛЯЦІЯ ФУНКЦІЙ БЕЗПЕКИ - ФУНКЦІЇ УПРАВЛІННЯ ДОСТУПОМ ТА ПОТОКОМ (SC-3(2))",
      parameters: [
        {:sc_3_2_01,
         "Ізольовані функції безпеки, що забезпечують управління доступом, які не пов'язані з безпекою",
         [type: :string, default: nil]},
        {:sc_3_2_02,
         "Ізольовані функції безпеки, що забезпечують контроль доступу, від інших функцій безпеки",
         [type: :string, default: nil]},
        {:sc_3_2_03,
         "Ізольовані функції безпеки, які не пов'язані з безпекою забезпечують контроль інформаційних потоків",
         [type: :string, default: nil]},
        {:sc_3_2_04,
         "Ізольовані функції безпеки, що забезпечують контроль інформаційних потоків, від інших функцій безпеки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-3-3") do
    %{
      id: :"id-spe-sc-3-3",
      description: "",
      title: "ІЗОЛЯЦІЯ ФУНКЦІЙ БЕЗПЕКИ - МІНІМІЗАЦІЯ ФУНКЦІОНАЛЬНОСТІ (SC-3(3))",
      parameters: [
        {:sc_3_3_01,
         "Мінімізовано кількість функцій, не пов'язаних з безпекою, що входять до сфери ізоляції, яка містить функції безпеки",
         [type: :integer, default: 3]}
      ]
    }
  end

  def spec(:"id-spe-sc-3-4") do
    %{
      id: :"id-spe-sc-3-4",
      description: "",
      title: "ІЗОЛЯЦІЯ ФУНКЦІЙ ЗВ’ЯЗНІСТЬ (SC-3(4))",
      parameters: [
        {:sc_3_4_02,
         "Реалізовані функції безпеки як значною мірою незалежні модулі, які мінімізують зв'язок між модулями",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-3-5") do
    %{
      id: :"id-spe-sc-3-5",
      description: "",
      title: "ІЗОЛЯЦІЯ ФУНКЦІЙ БЕЗПЕКИ - БАГАТОРІВНЕВА СТРУКТУРА (SC-3(5))",
      parameters: [
        {:sc_3_5_01,
         "Реалізовані функції безпеки як багаторівнева структура, що мінімізує взаємодію між шарами дизайну та уникає будь-якої залежності нижчих шарів від функціональності або коректності вищих шарів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-4") do
    %{
      id: :"id-spe-sc-4",
      description: "Запобігати несанкціонованій та ненавмисній передачі інформації через спільні системні ресурси.",
      title: "ІНФОРМАЦІЯ В ЗАГАЛЬНИХ СИСТЕМНИХ РЕСУРСАХ (SC-4)",
      parameters: [
        {:sc_4_01,
         "Запобігається несанкціонована передача інформації через спільні системні ресурси",
         [type: :string, default: nil]},
        {:sc_4_02,
         "Запобігається ненавмисна передача інформації через спільні системні ресурси. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-4-1") do
    %{
      id: :"id-spe-sc-4-1",
      description: "",
      title: "ІНФОРМАЦІЯ В ЗАГАЛЬНИХ СИСТЕМНИХ РЕСУРСАХ - РІВНІ БЕЗПЕКИ (SC-4(1))",
      parameters: [
        {:sc_4_1_01,
         "ІНФОРМАЦІЯ В ЗАГАЛЬНИХ СИСТЕМНИХ РЕСУРСАХ - РІВНІ БЕЗПЕКИ [Вилучено: включено до SC-4]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-4-2") do
    %{
      id: :"id-spe-sc-4-2",
      description: "",
      title: "ІНФОРМАЦІЯ В ЗАГАЛЬНИХ СИСТЕМНИХ БАГАТОРІВНЕВА АБО ПЕРІОДИЧНА ОБРОБКА (SC-4(2))",
      parameters: [
        {:sc_4_2_01,
         "Запобігається несанкціонована передача інформації через спільні ресурси відповідно до процедур, коли системна обробка явно перемикається між різними рівнями класифікації інформації або категоріями безпеки",
         [type: :string, default: nil]},
        {:sc_4_2_odp,
         "Визначені процедури для запобігання несанкціонованій передачі інформації через спільні ресурси",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-5") do
    %{
      id: :"id-spe-sc-5",
      description: "a. [Призначення: захистити від; Обмежити] наслідки наступних типів подій відмови в обслуговуванні (DoS): [Призначення: визначені організацією типи подій відмови в обслуговуванні]; b. Застосувати наступні заходи захисту для досягнення мети відмови обслуговування [Призначення: заходи захисту визначені організацією, за типом події відмови в обслуговуванні].",
      title: "ЗАХИСТ ВІД АТАК «ВІДМОВА В ОБСЛУГОВУВАННІ» (SC-5)",
      parameters: [
        {:sc_5_odp_01,
         "Визначені типи подій відмов в обслуговуванні, від яких потрібно захищати або обмежувати; SC-05_ODP[02] вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {захистити від; обмежити}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-5-1") do
    %{
      id: :"id-spe-sc-5-1",
      description: "",
      title: "ЗАХИСТ ВІД АТАК «ВІДМОВА В ОБСЛУГОВУВАННІ» - ОБМЕЖЕННЯ ВНУТРІШНІХ КОРИСТУВАЧІВ (SC-5(1))",
      parameters: [
        {:sc_5_1_01,
         "Обмежена можливість окремих осіб здійснювати атаки на відмову в обслуговуванні проти інших систем",
         [type: :string, default: nil]},
        {:sc_5_1_odp,
         "Визначені атаки на відмову в обслуговуванні, для яких необхідно обмежити можливість їх запуску окремими особами",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-sc-5-2") do
    %{
      id: :"id-spe-sc-5-2",
      description: "",
      title: "ЗАХИСТ ВІД АТАК «ВІДМОВА В ОБСЛУГОВУВАННІ» ПРОДУКТИВНІСТЬ, ПРОПУСКНА ЗДАТНІСТЬ ТА НАДМІРНІСТЬ (SC-5(2))",
      parameters: [
        {:sc_5_2_01,
         "Здійснюється управління ємністю, пропускною здатністю або іншими надлишковими ресурсами для обмеження наслідків інформаційних атак на відмову в обслуговуванні",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-5-3") do
    %{
      id: :"id-spe-sc-5-3",
      description: "",
      title: "ЗАХИСТ ВІД АТАК «ВІДМОВА В ОБСЛУГОВУВАННІ» - ВИЯВЛЕННЯ ТА МОНІТОРИНГ (SC-5(3))",
      parameters: [
        {:sc_5_3_a,
         "Використовуються засоби моніторингу для виявлення ознак атак на відмову в обслуговуванні, спрямованих на систему або запущених з неї",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sc_5_3_b,
         "Здійснюється моніторинг системних ресурсів для визначення наявності достатніх ресурсів для запобігання ефективним атакам на відмову в обслуговуванні",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-6") do
    %{
      id: :"id-spe-sc-6",
      description: "Забезпечити захист доступності ресурсів, виділивши [Призначення: визначені організацією ресурси], по [Вибір (один або кілька); пріоритет; квоти; [Призначення: визначені організацією заходи з безпеки]].",
      title: "ДОСТУПНІСТЬ РЕСУРСІВ (SC-6)",
      parameters: [
        {:sc_6_01,
         "Захищено доступність ресурсів шляхом розподілу ресурсів за ВИБІРКОВИМ ЗНАЧЕННЯМ ПАРАМЕТРА(ів)",
         [type: :string, default: nil]},
        {:sc_6_odp_01,
         "Визначені ресурси, які необхідно виділити для захисту доступності ресурсів",
         [type: :string, default: nil]},
        {:sc_6_odp_02,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {priority; quota; controls}",
         [type: :string, default: nil]},
        {:sc_6_odp_03,
         "Визначені засоби контролю для захисту доступності ресурсів (якщо вибрано)",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sc-7") do
    %{
      id: :"id-spe-sc-7",
      description: "a. Контролювати та управляти зв’язком на зовнішньому периметрі системи та на ключових внутрішніх периметрах всередині системи. b. Реалізувати підмережі для загальнодоступних компонентів системи, які є [Вибір: фізично; логічно] відділені від внутрішніх мереж організації. c. Підключатися до зовнішніх мереж або систем тільки через керовані інтерфейси, що складаються з пристроїв захисту периметру, і розташованих відповідно до архітектури безпеки та приватності організації.",
      title: "ДОСТУПНІСТЬ РЕСУРСІВ (SC-7)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sc-7-1") do
    %{
      id: :"id-spe-sc-7-1",
      description: "",
      title: "ЗАХИСТ ПЕРИМЕТРА - ФІЗИЧНО ВІДДІЛЕНІ ПІДМЕРЕЖІ (SC-7(1))",
      parameters: [
        {:sc_7_1_01,
         "ЗАХИСТ ПЕРИМЕТРА - ФІЗИЧНО ВІДДІЛЕНІ ПІДМЕРЕЖІ [Вилучено: включено до SC-7]]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-7-2") do
    %{
      id: :"id-spe-sc-7-2",
      description: "",
      title: "ЗАХИСТ ПЕРИМЕТРА - ПУБЛІЧНИЙ ДОСТУП (SC-7(2))",
      parameters: [
        {:sc_7_2_01,
         "ЗАХИСТ ПЕРИМЕТРА - ПУБЛІЧНИЙ ДОСТУП [Вилучено: включено до SC-7]]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-7-3") do
    %{
      id: :"id-spe-sc-7-3",
      description: "",
      title: "ЗАХИСТ ПЕРИМЕТРА - ТОЧКИ ДОСТУПУ (SC-7(3))",
      parameters: [
        {:sc_7_3_01,
         "Обмежена кількість зовнішніх мережевих підключень до системи",
         [type: :integer, default: 3]}
      ]
    }
  end

  def spec(:"id-spe-sc-7-4") do
    %{
      id: :"id-spe-sc-7-4",
      description: "",
      title: "ЗАХИСТ ПЕРИМЕТРА - ЗОВНІШНІ КОМУНІКАЦІЙНІ СЛУЖБИ (SC-7(4))",
      parameters: [
        {:sc_7_4_a,
         "Реалізовано керований інтерфейс для кожної зовнішньої телекомунікаційної послуги",
         [type: :string, default: nil]},
        {:sc_7_4_b,
         "Встановлена політика потоку трафіку для кожного керованого інтерфейсу",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sc_7_4_c_01,
         "Захищена конфіденційність інформації, що передається через кожен інтерфейс",
         [type: :string, default: nil]},
        {:sc_7_4_c_02,
         "Захищена цілісність інформації, що передається через кожен інтерфейс",
         [type: :string, default: nil]},
        {:sc_7_4_d,
         "Задокументовано кожен виняток з політики управління трафіком з обґрунтуванням місії або бізнес-потреби, а також тривалості такої потреби",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sc_7_4_e_01,
         "Переглядаються винятки з політики потоку трафіку частота",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sc_7_4_e_02,
         "Потрібно видалити винятки з політики потоку трафіку, які більше не підтримуються чітко визначеною місією або бізнеспотребою",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sc_7_4_f,
         "Запобігається несанкціонований обмін управління із зовнішніми мережами",
         [type: :string, default: nil]},
        {:sc_7_4_g,
         "Публікується інформація, яка дозволяє віддаленим мережам виявляти несанкціонований трафік площини керування з внутрішніх мереж",
         [type: :string, default: nil]},
        {:sc_7_4_h,
         "Фільтрується несанкціонований трафік з зовнішніх мереж. трафіком плану",
         [type: :string, default: nil]},
        {:sc_7_4_odp,
         "Визначено періодичність перегляду винятків з політики управління інформаційними потоками",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-sc-7-5") do
    %{
      id: :"id-spe-sc-7-5",
      description: "",
      title: "ЗАХИСТ ПЕРИМЕТРА - ВІДМОВА ЗА ЗАМОВЧУВАННЯМ - ДОЗВІЛ ЗА ВИНЯТКОМ (SC-7(5))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sc-7-6") do
    %{
      id: :"id-spe-sc-7-6",
      description: "",
      title: "ЗАХИСТ ПЕРИМЕТРА - ВІДПОВІДЬ НА РОЗПІЗНАНІ ПОМИЛКИ (SC-7(6))",
      parameters: [
        {:sc_7_6_01,
         "ЗАХИСТ ПЕРИМЕТРА - ВІДПОВІДЬ НА РОЗПІЗНАНІ ПОМИЛКИ [Вилучено: включено до SC-7(18)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-7-7") do
    %{
      id: :"id-spe-sc-7-7",
      description: "",
      title: "ЗАХИСТ ПЕРИМЕТРА - ЗАПОБІГАННЯ ПОДІЛУ ТУНЕЛЮВАННЯ ДЛЯ ВІДДАЛЕНИХ ПРИСТРОЇВ (SC-7(7))",
      parameters: [
        {:sc_7_7_01,
         "Запобігається розділеному тунелюванню для віддалених пристроїв, що підключаються до систем організації, якщо розділене тунелюванню не захищено за допомогою засоби захисту",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sc_7_7_odp,
         "Визначені гарантії безпечного прокладання розділеному тунелюванню",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-7-8") do
    %{
      id: :"id-spe-sc-7-8",
      description: "",
      title: "ЗАХИСТ ПЕРИМЕТРА -МАРШРУТИЗАЦІЯ АВТЕНТИФІКОВАНИХ ПРОКСІ-СЕРВЕРІВ (SC-7(8))",
      parameters: [
        {:sc_7_8_01,
         "SC-07(08) _ODP[01] внутрішній комунікаційний трафік> спрямовується до <SC-07(08) _ODP[02] зовнішніх мереж> через автентифіковані проксі-сервери на керованих інтерфейсах",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-7-9") do
    %{
      id: :"id-spe-sc-7-9",
      description: "",
      title: "ЗАХИСТ (SC-7(9))",
      parameters: [
        {:sc_7_9_a_01,
         "Виявлено вихідний комунікаційний трафік, що становить загрозу для зовнішніх систем",
         [type: :string, default: nil]},
        {:sc_7_9_a_02,
         "Заборонено вихідний комунікаційний трафік, що становить загрозу для зовнішніх систем",
         [type: :string, default: nil]},
        {:sc_7_9_b,
         "Перевіряється ідентичність внутрішніх пов'язаних з відмовою у зв’язку. користувачів,",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-7-13") do
    %{
      id: :"id-spe-sc-7-13",
      description: "",
      title: "ІЗОЛЬОВАНІ ВІД ІНШИХ ВНУТРІШНІХ КОМПОНЕНТІВ СИСТЕМИ ШЛЯХОМ ВПРОВАДЖЕННЯ ФІЗИЧНО ВІДОКРЕМЛЕНИХ ПІДМЕРЕЖ З КЕРОВАНИМИ ІНТЕРФЕЙСАМИ ДО ІНШИХ КОМПОНЕНТІВ СИСТЕМИ (SC-7(13))",
      parameters: [
        {:sc_7_13_01,
         "Ізольовані засоби, механізми та компоненти підтримки інформаційної безпеки від інших внутрішніх компонентів системи шляхом впровадження фізично відокремлених підмереж з керованими інтерфейсами до інших компонентів системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sc_7_13_odp,
         "Визначені інструменти, механізми та компоненти підтримки інформаційної безпеки, які мають бути ізольовані від інших внутрішніх компонентів системи",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sc-8") do
    %{
      id: :"id-spe-sc-8",
      description: "Забезпечити [Вибір (один або кілька): конфіденційність; цілісність] інформації, що передається.",
      title: "КОНФІДЕНЦІЙНІСТЬ ТА ЦІЛІСНІСТЬ ПЕРЕДАЧІ (SC-8)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sc-8-1") do
    %{
      id: :"id-spe-sc-8-1",
      description: "",
      title: "КОНФІДЕНЦІЙНІСТЬ ТА КРИПТОГРАФІЧНИЙ ЗАХИСТ (SC-8(1))",
      parameters: [
        {:sc_8_1_odp,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {запобігти несанкціонованому розголошенню інформації; виявити зміни в інформації}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-8-2") do
    %{
      id: :"id-spe-sc-8-2",
      description: "",
      title: "КОНФІДЕНЦІЙНІСТЬ ТА ЦІЛІСНІСТЬ ПЕРЕДАЧІ - ПОПЕРЕДНЯ І ПОСТОБРОБКА (SC-8(2))",
      parameters: [
        {:sc_8_2_01,
         "КОНФІДЕНЦІЙНІСТЬ ТА ЦІЛІСНІСТЬ ПЕРЕДАЧІ - ПОПЕРЕДНЯ І ПОСТОБРОБКА МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: nil]},
        {:sc_8_2_odp,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {конфіденційність; цілісність}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-8-3") do
    %{
      id: :"id-spe-sc-8-3",
      description: "",
      title: "КОНФІДЕНЦІЙНІСТЬ ТА ЦІЛІСНІСТЬ КРИПТОГРАФІЧНИЙ ЗАХИСТ ПОВІДОМЛЕНЬ (SC-8(3))",
      parameters: [
        {:sc_8_3_01,
         "Впроваджено криптографічні механізми для захисту зовнішніх повідомлень, якщо інше не захищено альтернативні фізичні засоби контролю",
         [type: :string, default: "AES-256-GCM"]},
        {:sc_8_3_odp,
         "Визначено альтернативні фізичні засоби контролю для захисту зовнішніх повідомлень",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sc-8-4") do
    %{
      id: :"id-spe-sc-8-4",
      description: "",
      title: "КОНФІДЕНЦІЙНІСТЬ ТА ЦІЛІСНІСТЬ ПЕРЕДАЧІ - ПРИХОВУВАННЯ АБО РАНДОМІЗАЦІЯ КОМУНІКАЦІЇ (SC-8(4))",
      parameters: [
        {:sc_8_4_01,
         "Застосовуються криптографічні механізми для приховування або рандомізації шаблонів комунікації, якщо інше не захищено альтернативні фізичні засоби контролю",
         [type: :string, default: "AES-256-GCM"]},
        {:sc_8_4_odp,
         "Визначені альтернативні фізичні засоби контролю для захисту від несанкціонованого розкриття шаблонів комунікації",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sc-8-5") do
    %{
      id: :"id-spe-sc-8-5",
      description: "",
      title: "КОНФІДЕНЦІЙНІСТЬ ТА СИСТЕМА РОЗПОДІЛУ (SC-8(5))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sc-9") do
    %{
      id: :"id-spe-sc-9",
      description: "",
      title: "КОНФІДЕНЦІЙНІСТЬ ПЕРЕДАЧІ (SC-9)",
      parameters: [
        {:sc_9_01,
         "КОНФІДЕНЦІЙНІСТЬ ПЕРЕДАЧІ [Вилучено: включено до SC-8]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-10") do
    %{
      id: :"id-spe-sc-10",
      description: "Завершити з’єднання з мережею, яке пов’язане із сеансом зв’язку в кінці сеансу або після [Призначення: визначений організацією період часу] бездіяльності.",
      title: "ВІДКЛЮЧЕННЯ МЕРЕЖІ (SC-10)",
      parameters: [
        {:sc_10_odp,
         "Визначено період бездіяльності, після якого система розриває мережеве з'єднання, пов'язане з сеансом зв'язку; SC08(05)_ODP[02] мережеве з'єднання, пов'язане з сеансом зв'язку, розірвано в кінці сеансу або після період часу бездіяльності",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-sc-11") do
    %{
      id: :"id-spe-sc-11",
      description: "a. Надати [Вибір: фізично; логічно] ізольований надійний канал зв’язку для зв’язку між користувачем і довіреними компонентами системи. b. Дозволити користувачам запросити довірений канал зв’язку для обміну даними між користувачем і наступними функціями безпеки системи, включно з, як мінімум, автентифікацією та повторною автентифікацією: [Призначення: визначені організацією функції безпеки].",
      title: "ДОВІРЕНИЙ КАНАЛ ЗВ’ЯЗКУ (SC-11)",
      parameters: [
        {:sc_11_odp_01,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {фізично; логічно}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-12") do
    %{
      id: :"id-spe-sc-12",
      description: "Встановити та управляти криптографічними ключами для криптографічних засобів, які використовуються в системі відповідно до [Призначення: визначені організацією вимоги до генерації, поширення, зберігання, доступу та знищення ключів].",
      title: "ВСТАНОВЛЕННЯ КЛЮЧАМИ (SC-12)",
      parameters: [
        {:sc_12_01,
         "Встановлюються криптографічні ключі, коли в системі використовується криптографія відповідно до < SC-12_ODP вимог >",
         [type: :string, default: "AES-256-GCM"]},
        {:sc_12_02,
         "Здійснюється управління криптографічними ключами, коли в системі використовується криптографія, відповідно до вимог ",
         [type: :string, default: "AES-256-GCM"]},
        {:sc_12_odp,
         "Визначені вимоги до генерації, розповсюдження, зберігання, доступу та знищення ключів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-13") do
    %{
      id: :"id-spe-sc-13",
      description: "a. Визначити [Призначення: використання криптографічних засобів, визначених організацією]; b. Впровадити [Завдання: визначені організацією види криптографії для кожного визначеного криптографічного використання].",
      title: "КРИПТОГРАФІЧНИЙ ЗАХИСТ (SC-13)",
      parameters: [
        {:sc_13_01,
         "КРИПТОГРАФІЧНИЙ ЗАХИСТ МЕТА ОЦІНКИ: Визначити, чи:",
         [type: :string, default: "AES-256-GCM"]},
        {:sc_13_odp_01,
         "Визначено використання криптографічних засобів",
         [type: :string, default: "AES-256-GCM"]},
        {:sc_13_odp_02,
         "Визначено типи криптографії для кожного вказаного криптографічного використання; SC-13a. ідентифіковано використання>; SC-13b. реалізовано типи криптографії для кожного вказаного криптографічного використання (визначеного в SC-13_ODP[01]). криптографічне <SC-13_ODP[01]",
         [type: :string, default: "AES-256-GCM"]}
      ]
    }
  end

  def spec(:"id-spe-sc-14") do
    %{
      id: :"id-spe-sc-14",
      description: "",
      title: "ЗАХИСТ ГРОМАДСЬКОГО ДОСТУПУ (SC-14)",
      parameters: [
        {:sc_14_01,
         "ЗАХИСТ ГРОМАДСЬКОГО ДОСТУПУ [Вилучено: включено до AC-2, AC-3, AC-5, AC-6, SI-3, SI-4, SI-5, SI-7, SI-10]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-15") do
    %{
      id: :"id-spe-sc-15",
      description: "a. Заборонити віддалену активацію спільних обчислювальних пристроїв (хмар) та застосунків з такими виключеннями: [Призначення: визначені організацією виключення, у яких дозволена віддалена активація]. b. Надати явну вказівку щодо використання користувачами фізично присутніми пристроями.",
      title: "СПІЛЬНІ ОБЧИСЛЮВАЛЬНІ ПРИСТРОЇ ТА ЗАСТОСУНКИ (SC-15)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sc-16") do
    %{
      id: :"id-spe-sc-16",
      description: "Пов’язувати [Призначення: визначені організацією атрибути безпеки та приватності] з інформацією, яка передається між системами та компонентами системи.",
      title: "ПЕРЕДАЧА АТРИБУТІВ БЕЗПЕКИ ТА ПРИВАТНОСТІ (SC-16)",
      parameters: [
        {:sc_16_01,
         "Пов'язані атрибути інформацією, якою обмінюються системи; безпеки з",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sc_16_02,
         "Пов'язані атрибути безпеки інформацією, якою обмінюються компоненти системи; з",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sc_16_03,
         "Пов'язані атрибути приватності інформацією, якою обмінюються системи; з",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sc_16_04,
         "Пов'язані атрибути приватності інформацією, якою обмінюються компоненти системи. з",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sc_16_odp_01,
         "Визначені атрибути безпеки, які будуть пов'язані з інформацією, що обмінюється",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sc_16_odp_02,
         "Визначені атрибути приватності, які будуть пов'язані з інформацією, що обмінюється",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-sc-17") do
    %{
      id: :"id-spe-sc-17",
      description: "a. Випускати сертифікати відкритого ключа відповідно до [Призначення: визначеної організацією політики сертифікації]; b. Отримувати сертифікати відкритого ключа від затвердженого постачальника послуг.",
      title: "СЕРТИФІКАТИ ІНФРАСТРУКТУРИ ВІДКРИТИХ КЛЮЧІВ (SC-17)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sc-18") do
    %{
      id: :"id-spe-sc-18",
      description: "a. Визначати прийнятні та неприйнятні мобільні коди та технології мобільних кодів. b. Проводити авторизацію, відстежувати та контролювати використання мобільного коду всередині системи.",
      title: "МОБІЛЬНИЙ КОД (SC-18)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sc-19") do
    %{
      id: :"id-spe-sc-19",
      description: "",
      title: "ІНТЕРНЕТ-ПРОТОКОЛ ГОЛОСОВОГО ЗВ’ЯЗКУ (SC-19)",
      parameters: [
        {:sc_19_01,
         "ІНТЕРНЕТ-ПРОТОКОЛ ГОЛОСОВОГО ЗВ’ЯЗКУ [Вилучено: залежить від технології; розглядається як будь-яка інша технологія або протокол]",
         [type: :string, default: "TLS 1.3"]}
      ]
    }
  end

  def spec(:"id-spe-sc-20") do
    %{
      id: :"id-spe-sc-20",
      description: "a. Надати додаткові дані автентифікації та перевірки цілісності джерела даних разом з офіційними даними розпізнавання імен, які система повертає у відповідь на запити дозволу імен/адрес. b. Надати засоби для вказання статусу безпеки дочірніх зон і (якщо дочірня зона підтримує служби безпечного дозволу) забезпечити перевірку ланцюга довіри між батьківськими та дочірніми доменами при роботі в складі розподіленого ієрархічного простору імен.",
      title: "БЕЗПЕЧНА СЛУЖБА ІМЕН, АДРЕС (УПОВНОВАЖЕНЕ ДЖЕРЕЛО) (SC-20)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sc-21") do
    %{
      id: :"id-spe-sc-21",
      description: "Зробити запит та виконати перевірку автентичності джерела даних і перевірку цілісності даних у відповідях на дозвіл імен/адрес, які система отримує від уповноважених джерел.",
      title: "БЕЗПЕЧНА СЛУЖБА ІМЕН, АДРЕС (УПОВНОВАЖЕНЕ ДЖЕРЕЛО) ДЖЕРЕЛО ДАНИХ ТА ЦІЛІСНІСТЬ (SC-21)",
      parameters: [
        {:sc_21_01,
         "Реалізується запит перевірки автентичності джерела даних для відповідей на запит дозволу імен/адрес, які система отримує від авторитетних джерел",
         [type: :string, default: nil]},
        {:sc_21_02,
         "Реалізується запит автентифікація походження даних на основі відповідей з дозволу імен/адрес, які система отримує від авторитетних джерел",
         [type: :string, default: nil]},
        {:sc_21_03,
         "Реалізується запит перевірки цілісності даних для відповідей на запит дозволу імен/адрес, які система отримує від авторитетних джерел",
         [type: :string, default: nil]},
        {:sc_21_04,
         "Виконується перевірка цілісності даних для відповідей на запит про дозвіл імен/адрес, які система отримує від авторитетних джерел",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-22") do
    %{
      id: :"id-spe-sc-22",
      description: "Переконатися, що системи, які спільно надають послуги розпізнавання імен/адрес для організації, є відмовостійкими та забезпечують поділ внутрішніх і зовнішніх ролей.",
      title: "(РЕКУРСИВНИЙ АБО ДЖЕРЕЛО ДАНИХ ТА (SC-22)",
      parameters: [
        {:sc_22_01,
         "Є системи, які спільно надають послуги з визначення імен/адрес для організації, відмовостійкими",
         [type: :string, default: nil]},
        {:sc_22_02,
         "Реалізовано в системах, які спільно надають послуги з вирішення імен/адрес для організації, внутрішній розподіл ролей",
         [type: :string, default: nil]},
        {:sc_22_03,
         "Реалізовано в системах, які спільно надають послуги з вирішення імен/адрес для організації, зовнішній розподіл ролей",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-23") do
    %{
      id: :"id-spe-sc-23",
      description: "Забезпечити автентифікацію сеансів зв’язку.",
      title: "АВТЕНТИФІКАЦІЯ СЕСІЇ (SC-23)",
      parameters: [
        {:sc_23_01,
         "Захищено автентифікацію сеансів зв'язку",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-24") do
    %{
      id: :"id-spe-sc-24",
      description: "Увести систему в [Призначення: визначений організацією відомий стан системи] у разі [Призначення: визначені організацією типи збоїв системи] зі збереженням [Призначення: визначена організацією інформація про стан системи] при збої.",
      title: "УВЕДЕННЯ У ВІДОМИЙ СТАН (SC-24)",
      parameters: [
        {:sc_24_01,
         "Типи системних збоїв на компонентах системи призводять до відомого стану системи, зберігаючи при цьому інформацію про стан системи у збої",
         [type: :string, default: nil]},
        {:sc_24_odp_01,
         "Визначені типи відмов системи, за яких компоненти системи переходять до відомого стану",
         [type: :string, default: nil]},
        {:sc_24_odp_02,
         "Відомий стан системи, до якого переходять компоненти системи у випадку її відмови",
         [type: :string, default: nil]},
        {:sc_24_odp_03,
         "Потрібно зберігати інформацію про стан системи у випадку її збою",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-25") do
    %{
      id: :"id-spe-sc-25",
      description: "Використовувати [Призначення: визначені організацією системні компоненти] з мінімальною функціональністю та зберіганням інформації.",
      title: "ТОНКІ ВУЗЛИ (SC-25)",
      parameters: [
        {:sc_25_01,
         "Використовується мінімальна функціональність для компонентів системи",
         [type: :string, default: nil]},
        {:sc_25_02,
         "Виділено мінімальне сховище інформації на компоненти системи",
         [type: :string, default: nil]},
        {:sc_25_odp,
         "Потрібно використовувати компоненти системи з мінімальною функціональністю та обсягом зберігання інформації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-26") do
    %{
      id: :"id-spe-sc-26",
      description: "Вносити в систему компоненти, які спеціально призначені як об’єкти атак, з метою виявлення, відбиття й аналізу таких атак.",
      title: "ПРИМАНКА ДЛЯ ЗЛОВМИСНИКІВ (DECOYS) (SC-26)",
      parameters: [
        {:sc_26_01,
         "Є в системах організації компоненти, спеціально розроблені для того, щоб стати мішенню зловмисних атак, і чи є в них засоби для виявлення таких атак",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sc_26_02,
         "Є в організаційних компонентах системи, спеціально розроблені для того, щоб стати мішенню зловмисних атак, і чи є в них засоби для відбиття таких атак",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sc_26_03,
         "Включені в організаційні компоненти системи, спеціально розроблені для того, щоб бути мішенню зловмисних атак, для аналізу таких атак",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-27") do
    %{
      id: :"id-spe-sc-27",
      description: "Внести до системи: [Призначення: визначені організацією незалежні від платформи застосунки].",
      title: "НЕЗАЛЕЖНІ ВІД ПЛАТФОРМИ ЗАСТОСУНКИ (SC-27)",
      parameters: [
        {:sc_27_01,
         "Включені незалежні від платформи додатки в системи організації",
         [type: :string, default: nil]},
        {:sc_27_odp,
         "Визначені незалежні від платформи додатки, які мають бути включені в системи організації",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-28") do
    %{
      id: :"id-spe-sc-28",
      description: "Забезпечити [Вибір (один або кілька): конфіденційність; цілісність] [Призначення: визначена організацією інформація] в стані спокою.",
      title: "ЗАХИСТ ІНФОРМАЦІЇ В СТАНІ СПОКОЮ (SC-28)",
      parameters: [
        {:sc_28_odp,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {конфіденційність; цілісність}",
         [type: :string, default: nil]},
        {:sc_28_odp_02,
         "Є інформація в стані спокою, яка потребує захисту",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-29") do
    %{
      id: :"id-spe-sc-29",
      description: "Використовувати різноманітний набір інформаційних технологій для [Призначення: визначені організацією системні компоненти] при впровадженні системи.",
      title: "ГЕТЕРОГЕННІСТЬ (SC-29)",
      parameters: [
        {:sc_29_01,
         "Використовується різноманітний набір інформаційних технологій для компоненти системни при впровадженні системи",
         [type: :string, default: nil]},
        {:sc_29_odp,
         "Визначені компоненти системи, які потребують різноманітного набору інформаційних технологій, що мають бути використані при впровадженні системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-30") do
    %{
      id: :"id-spe-sc-30",
      description: "Використовувати [Призначення: визначені організацією методи маскування та хибного напряму] для [Призначення: визначені організацією системи] у [Призначення: визначений організацією період часу], щоб заплутати та ввести в оману зловмисників.",
      title: "МАСКУВАННЯ ТА ХИБНИЙ НАПРЯМ (SC-30)",
      parameters: [
        {:sc_30_01,
         "Застосовуються методи маскування та хибного напряму для систем протягом періодів часу, щоб заплутати та ввести супротивника в оману. застосування методів",
         [type: :integer, default: 30]},
        {:sc_30_odp_01,
         "Визначені методи маскування та хибного напряму, які будуть застосовані для того, щоб заплутати і ввести в оману супротивників, які потенційно можуть націлитися на системи",
         [type: :string, default: nil]},
        {:sc_30_odp_02,
         "Визначені системи, для яких повинні застосовуватися методи маскування та хибного напряму",
         [type: :string, default: nil]},
        {:sc_30_odp_03,
         "Визначені часові періоди для маскування та хибного напряму",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-sc-31") do
    %{
      id: :"id-spe-sc-31",
      description: "a. Проводити аналіз прихованого каналу, щоб визначити ті аспекти комунікацій у системі, які володіють потенційними можливостями для реалізації прихованих каналів [Вибір (один або кілька): зберігання; синхронізації]. b. Оцінювати максимальну пропускну здатність цих каналів.",
      title: "АНАЛІЗ ПРИХОВАНОГО КАНАЛУ (SC-31)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sc-32") do
    %{
      id: :"id-spe-sc-32",
      description: "Розділити систему на [Призначення: визначені організацією системні компоненти], що розміщені в окремих фізичних доменах або середовищах на основі [Призначення: визначені організацією умови для фізичного поділу компонентів].",
      title: "ПОДІЛ СИСТЕМИ НА ЧАСТИНИ (SC-32)",
      parameters: [
        {:sc_32_01,
         "Розділена система на компоненти системи, що знаходяться в окремих ЗНАЧЕННЯ ВИБРАНОГО ПАРАМЕТРА доменах або середовищах на основі обставин для фізичного або логічного поділу компонентів. фізичного або логічного",
         [type: :string, default: nil]},
        {:sc_32_odp_01,
         "Повинні компоненти системи перебувати в окремих фізичних або логічних доменах або середовищах, виходячи з обставин фізичного або логічного поділу компонентів",
         [type: :string, default: nil]},
        {:sc_32_odp_02,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРА: {фізичний; логічний}",
         [type: :string, default: nil]},
        {:sc_32_odp_03,
         "Визначені обставини для розділення компонентів",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-33") do
    %{
      id: :"id-spe-sc-33",
      description: "",
      title: "ПІДГОТОВКА ЦІЛІСНОСТІ ПЕРЕДАЧІ (SC-33)",
      parameters: [
        {:sc_33_01,
         "ПІДГОТОВКА ЦІЛІСНОСТІ ПЕРЕДАЧІ [Вилучено: включено до SC-8]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-34") do
    %{
      id: :"id-spe-sc-34",
      description: "У [Призначення: визначені організацією системні компоненти]: a. Завантажити та виконати операційне середовище з апаратного носія, що працює в режимі лише для зчитування. b. Завантажити та виконати [Призначення: визначені організацією застосунки] з апаратного носія, що працює в режимі лише для зчитування.",
      title: "НЕЗМІНЮВАНІ ВИКОНАВЧІ ПРОГРАМИ (SC-34)",
      parameters: [
        {:sc_34_odp_01,
         "Визначені компоненти системи, для яких операційне середовище та додатки мають завантажуватися та виконуватися з апаратних носіїв, призначених лише для читання",
         [type: :string, default: nil]},
        {:sc_34_odp_02,
         "Визначено додатки, які мають завантажуватися та виконуватися з апаратних носіїв, призначених лише для читання; SC-34a. завантажується та виконується операційне середовище для системних компонентів з апаратного носія, доступного лише для читання; SC-34b. додатки для компонентів системи завантажуються та виконуються з апаратного носія, доступного лише для читання. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-35") do
    %{
      id: :"id-spe-sc-35",
      description: "Ввімкнути системні компоненти, які активно намагаються ідентифікувати мережевий шкідливий код та шкідливі вебсайти.",
      title: "РОЗПІЗНАВАННЯ ПРИМАНОК ДЛЯ ЗЛОВМИСНИКІВ (HONEYCLIENT) (SC-35)",
      parameters: [
        {:sc_35_01,
         "Ввімкнуті компоненти системи, які активно намагаються ідентифікувати мережевий шкідливий код та шкідливі вебсайти",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-36") do
    %{
      id: :"id-spe-sc-36",
      description: "Розподіліть наведені нижче компоненти обробки та зберігання в кількох [Вибір: фізичні локації; логічні домени]: [Призначення: компоненти обробки та зберігання, визначені організацією].",
      title: "РОЗПОДІЛЕНА ОБРОБКА ТА ЗБЕРІГАННЯ (SC-36)",
      parameters: [
        {:sc_36_odp_01,
         "Потрібно розподіляти компоненти обробки між кількома локаціями/доменами",
         [type: :string, default: nil]},
        {:sc_36_odp_02,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {фізичні локації; логічні домени}",
         [type: :string, default: nil]},
        {:sc_36_odp_03,
         "Потрібно розподіляти компоненти сховища між кількома локаціями/доменами",
         [type: :string, default: nil]},
        {:sc_36_odp_04,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {фізичні локації; логічні домени}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-37") do
    %{
      id: :"id-spe-sc-37",
      description: "Використовувати [Призначення: визначені організацією позасмугові канали] для фізичного доставлення або електронної передачі [Призначення: визначена організацією інформація, системні компоненти або пристрої] до [Призначення: визначені організацією особи або системи].",
      title: "ПОЗАСМУГОВІ КАНАЛИ (SC-37)",
      parameters: [
        {:sc_37_01,
         "Використовуються позасмугові канали для фізичної доставки або електронної передачі інформації, системних компонентів або пристроїв до осіб або систем",
         [type: :string, default: nil]},
        {:sc_37_odp_02,
         "Визначено інформацію, компоненти системи або пристрої для використання позасмугових каналів для фізичної доставки або електронної передачі",
         [type: :string, default: nil]},
        {:sc_37_odp_03,
         "Визначені особи або системи, до яких фізична доставка або електронна передача інформації, системних компонентів або пристроїв має бути досягнута за допомогою використання позасмугових каналів",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-sc-38") do
    %{
      id: :"id-spe-sc-38",
      description: "Впровадити [Призначення: визначені організацією заходи з безпеки операцій] для захисту ключової організаційної інформації протягом усього життєвого циклу розробки системи.",
      title: "БЕЗПЕКА ОПЕРАЦІЙ (SC-38)",
      parameters: [
        {:sc_38_01,
         "Застосовуються засоби контролю заходів з безпеки операцій для захисту ключової інформації організації протягом життєвого циклу розробки системи",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sc_38_odp,
         "Визначені засоби контролю заходів з безпеки операцій, які будуть застосовуватися для захисту ключової інформації організації протягом усього життєвого циклу розробки системи",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sc-39") do
    %{
      id: :"id-spe-sc-39",
      description: "Підтримувати окремий домен виконання для кожного процесу, що виконується в системі.",
      title: "ІЗОЛЯЦІЯ ПРОЦЕСУ (SC-39)",
      parameters: [
        {:sc_39_01,
         "Підтримується окремий домен виконання для кожного процесу, що виконується в системі",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-40") do
    %{
      id: :"id-spe-sc-40",
      description: "Забезпечити захист зовнішніх і внутрішніх [Призначення: визначені організацією бездротові з’єднання] від [Призначення: визначені організацією типи атак з параметрами сигналів або посилання на джерела для таких атак].",
      title: "ЗАХИСТ БЕЗДРОТОВОГО З'ЄДНАННЯ (SC-40)",
      parameters: [
        {:sc_40_01,
         "Захищені зовнішні бездротові з’єднання від типів атак на параметри сигналу або посилання на джерела таких атак. SC-40[02] захищені внутрішні бездротові з’єднання від типів атак на параметри сигналу або посилання на джерела для таких атак",
         [type: :string, default: nil]},
        {:sc_40_odp_01,
         "Потрібно захищати зовнішні бездротові з’єднання від певних типів атак на параметри сигналу",
         [type: :string, default: nil]},
        {:sc_40_odp_02,
         "Визначено типи атак на параметри сигналу або посилання на джерела таких атак, від яких потрібно захищати зовнішні бездротові з’єднання",
         [type: :string, default: nil]},
        {:sc_40_odp_03,
         "Потрібно захищати внутрішні бездротові з’єднання від певних типів атак на параметри сигналу",
         [type: :string, default: nil]},
        {:sc_40_odp_04,
         "Визначені типи атак на параметри сигналу або посилання на джерела таких атак, від яких потрібно захищати внутрішні бездротові з’єднання",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-41") do
    %{
      id: :"id-spe-sc-41",
      description: "[Вибір: фізично або логічно] відключити або видалити [Призначення: визначені організацією, порти підключення або пристрої введення/виводу] у [Призначення: визначені організацією системи або системні компоненти].",
      title: "ДОСТУП ДО ПОРТІВ ТА ПРИСТРОЇВ ВВЕДЕННЯ, ВИВЕДЕННЯ (SC-41)",
      parameters: [
        {:sc_41_odp_01,
         "Визначено порти підключення або пристрої вводу/виводу, які потрібно відключити або видалити",
         [type: :string, default: nil]},
        {:sc_41_odp_02,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {фізично; логічно}",
         [type: :string, default: nil]},
        {:sc_41_odp_03,
         "Визначені системи або компоненти системи з портами підключення або пристроями вводу/виводу, які потрібно відключити або видалити",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-42") do
    %{
      id: :"id-spe-sc-42",
      description: "a. Заборонити дистанційну активацію можливостей зондування навколишнього середовища в системах організації або компонентах системи за такими виключеннями: [Призначення: визначені організацією виключення, в яких допускається дистанційна активація датчиків]. b. Забезпечити явну вказівку використання датчика для [Призначення: визначений організацією клас користувачів].",
      title: "Захист бездротового з’єднання Доступ до портів і пристроїв введення/виведення Можливості датчика та дані (SC-42)",
      parameters: [
        {:sc_42_01,
         "Механізми, що перешкоджають МОЖЛИВОСТІ ДАТЧИКА ТА ДАНІ",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sc_42_odp_01,
         "Вибрано одне або більше з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {використання пристроїв, що мають <SC- 42_ODP[02] можливості зондування довкілля> на об'єктах, територіях або системах}; дистанційна активація можливостей зондування довкілля на організаційних системах або системних компонентах з наступними винятками: <SC-42_ODP[04] винятки, де дозволяється дистанційна активація датчиків}",
         [type: :string, default: nil]},
        {:sc_42_odp_02,
         "Визначені можливості зондування навколишнього середовища в пристроях (якщо вибрано)",
         [type: :string, default: nil]},
        {:sc_42_odp_03,
         "Визначені об'єкти, зони або системи, на яких заборонено використання пристроїв, що мають можливості зондування навколишнього середовища (якщо вони були обрані)",
         [type: :string, default: nil]},
        {:sc_42_odp_04,
         "Визначено винятки, коли дозволено віддалену активацію датчиків (якщо вибрано)",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-43") do
    %{
      id: :"id-spe-sc-43",
      description: "a. Встановити обмеження на використання та рекомендації щодо впровадження для [Призначення: визначених організацією компонентів системи]. b. Проводити авторизацію, спостереження та контроль використання таких компонентів у системі.",
      title: "ОБМЕЖЕННЯ ВИКОРИСТАННЯ (SC-43)",
      parameters: [
        {:sc_43_odp,
         "Визначені компоненти, для яких мають бути встановлені обмеження на використання та настанови щодо впровадження; SC-43a. встановлені обмеження на використання та настанови щодо впровадження для компонентів; SC-43b.[01] дозволено системі; SC-43b.[02] здійснюється моніторинг компонентів> в системі; SC-43b.[03] контролюється використання компонентів в системі. використання компонентів використання у <SC-43_ODP",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-44") do
    %{
      id: :"id-spe-sc-44",
      description: "Впровадити екрановані камери в [Призначення: визначену організацією систему, компонент системи або місце розташування].",
      title: "ЕКРАНОВАНІ КАМЕРИ (SC-44)",
      parameters: [
        {:sc_44_01,
         "Використовується в системі <SC-44_ODP, компоненті або місці розташування> застосування екранованої камери системному можливість",
         [type: :string, default: nil]},
        {:sc_44_odp,
         "Визначена система, компонент системи або місце, де має бути застосований потенціал екранованої камери",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-45") do
    %{
      id: :"id-spe-sc-45",
      description: "Синхронізація системного годинника в системі та компонентах системи і між ними.",
      title: "СИНХРОНІЗАЦІЯ СИСТЕМИ З ЧАСОМ (SC-45)",
      parameters: [
        {:sc_45_01,
         "Синхронізовані системні годинники всередині системи та між системами і системними компонентами",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-sc-46") do
    %{
      id: :"id-spe-sc-46",
      description: "Впровадити механізм примусового виконання політики [Вибір: фізично; логічно] між фізичними та/або мережевими інтерфейсами для підключених доменів безпеки.",
      title: "ЗАБЕЗПЕЧЕННЯ ВИКОНАННЯ МІЖДОМЕННОЇ ПОЛІТИКИ (SC-46)",
      parameters: [
        {:sc_46_odp,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {фізично; логічно}",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-47") do
    %{
      id: :"id-spe-sc-47",
      description: "Встановіть [Призначення: альтернативні шляхи зв’язку, визначені організацією] для організаційного управління та контролю операцій системи.",
      title: "АЛЬТЕРНАТИВНИЙ ШЛЯХ ЗВʼЯЗКУ (SC-47)",
      parameters: [
        {:sc_47_01,
         "Встановлені альтернативні шляхи зв'язку для системних операцій та контролю операцій системи",
         [type: :string, default: nil]},
        {:sc_47_odp,
         "Визначені альтернативні шляхи зв'язку для системних операцій та контролю операцій системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sc-48") do
    %{
      id: :"id-spe-sc-48",
      description: "Перенесіть [Призначення: датчики та можливості моніторингу, визначені організацією] до [Призначення: місця, визначені організацією] за таких умов або обставин: [Призначення: умови або обставини, визначені організацією].",
      title: "ПЕРЕМІЩЕННЯ ДАТЧИКА (SC-48)",
      parameters: [
        {:sc_48_01,
         "Переміщуються датчики і засоби моніторингу до місць розташування за умов або обставин",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sc_48_odp_01,
         "Визначені датчики та можливості необхідно перемістити; моніторингу, які",
         [type: :string, default: nil]},
        {:sc_48_odp_02,
         "Визначені місця, куди будуть переміщені датчики та засоби моніторингу",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sc_48_odp_03,
         "Визначені умови або обставини для переміщення датчиків і можливостей моніторингу",
         [type: :list, default: []]}
      ]
    }
  end

  def spec(:"id-spe-sc-48-1") do
    %{
      id: :"id-spe-sc-48-1",
      description: "",
      title: "ДИНАМІЧНО ПЕРЕМІЩУЮТЬСЯ ДО ЗА (SC-48(1))",
      parameters: [
        {:sc_48_1_01,
         "Датчики та засоби моніторингу динамічно переміщуються до місць розташування за умов або обставин. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sc-49") do
    %{
      id: :"id-spe-sc-49",
      description: "Впровадити механізми апаратного поділу та застосування політики між [Призначення: домени безпеки, визначені організацією].",
      title: "ПРИМУСОВЕ АПАРАТНЕ ЗАБЕЗПЕЧЕННЯ ВИКОНАННЯ (SC-49)",
      parameters: [
        {:sc_49_01,
         "Впроваджено механізми апаратного розділення та застосування політик між доменами безпеки",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sc_49_odp,
         "Визначені домени безпеки, які потребують апаратного розділення та механізмів забезпечення дотримання політики",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-sc-50") do
    %{
      id: :"id-spe-sc-50",
      description: "Впровадити програмне розділення та механізми застосування політики між [Призначення: домени безпеки, визначені організацією].",
      title: "ПРИМУСОВЕ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ ВИКОНАННЯ (SC-50)",
      parameters: [
        {:sc_50_01,
         "Впроваджено програмне розділення та механізми застосування політик між доменами безпеки. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sc_50_odp,
         "Визначені домени безпеки, які потребують програмного розділення та механізмів забезпечення дотримання політик",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-sc-51") do
    %{
      id: :"id-spe-sc-51",
      description: "a. Перевіряти правильність роботи [Призначення: визначені організацією функції безпеки та приватності]. b. Виконувати перевірку [Вибір (один або кілька): [Призначення: визначені організацією системні перехідні стани]; за командою користувача з відповідними повноваженнями; [Призначення: визначена організацією частота]]. c. Повідомляти [Призначення: визначені організацією персонал або посадові особи] про невдалі перевірки безпеки та приватності. d. [Вибір (один або кілька): Вимкнути систему; Перезапустити систему; [Призначення: визначені організацією альтернативні дії]], коли виявляються аномалії.",
      title: "АПАРАТНИЙ ЗАХИСТ (SC-51)",
      parameters: [
        {:sc_51_odp_01,
         "Визначено компоненти системної прошивки, потребують апаратного захисту від запису; які",
         [type: :string, default: nil]},
        {:sc_51_odp_02,
         "Визначені уповноважені особи, які повинні виконувати процедури вимкнення та повторного ввімкнення апаратного захисту від запису; SC-51a. використовується апаратний захист від запису для компонентів мікропрограми системи; SC-51b.[01] впроваджено спеціальні процедури для уповноважених осіб для ручного вимкнення апаратного захисту від запису для модифікацій мікропрограми; SC-51b.[02] реалізовано спеціальні процедури для уповноважених осіб для повторного увімкнення захисту від запису перед поверненням до робочого режиму",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-1") do
    %{
      id: :"id-spe-si-1",
      description: "",
      title: "ПОЛІТИКА І ПРОЦЕДУРИ ЦІЛІСНОСТІ ІНФОРМАЦІЇ (SI-1)",
      parameters: [
        {:si_1_odp_01,
         "Визначено персонал або ролі, до яких має бути доведена політика цілісності системи та інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_1_odp_02,
         "Визначено персонал або ролі, на які поширюються процедури цілісності системи та інформації ",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень місії/бізнеспроцесу; рівень системи}",
         [type: :string, default: nil]},
        {:si_1_odp_04,
         "Визначено посадову особу, відповідальну за управління системою та політикою і процедурами цілісності інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_1_odp_05,
         "Визначено періодичність перегляду та оновлення поточної політики цілісності системи та інформації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:si_1_odp_06,
         "Є події, які вимагають перегляду та оновлення поточної політики цілісності системи та інформації",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:si_1_odp_07,
         "Визначено частоту, з якою переглядаються та оновлюються поточні цілісності системи та інформації",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-2") do
    %{
      id: :"id-spe-si-2",
      description: "",
      title: "ВИПРАВЛЕННЯ ДЕФЕКТІВ (SI-2)",
      parameters: [
        {:si_2_odp,
         "Визначено період часу, протягом якого необхідно встановити оновлення програмного забезпечення, пов'язані з безпекою, після виходу оновлень; SI-02a.[01] виявлено недоліки системи; SI-02a.[02] повідомляється про недоліки системи; SI-02a.[03] виправлені недоліки системи; SI-02b.[01] перевіряються оновлення програмного забезпечення, пов'язані з усуненням недоліків, на ефективність перед встановленням; SI-02b.[02] перевіряються оновлення програмного забезпечення, пов'язані з виправленням дефектів, на наявність потенційних побічних ефектів перед встановленням; SI-02b.[03] перевіряються оновлення прошивки, пов'язані з усуненням недоліків, на ефективність перед встановленням; SI-02b.[04] перевіряються оновлення прошивки, пов'язані з усуненням недоліків, на наявність потенційних побічних ефектів перед встановленням; SI-02c.[01] встановлено оновлення програмного забезпечення, що стосуються безпеки, протягом часовий проміжок з моменту випуску оновлень; SI-02c.[02] встановлено оновлення мікропрограми, що стосуються безпеки, протягом часового періоду з моменту випуску оновлень; SI-02d. включено відновлення порушених прав у процес управління організаційною конфігурацією",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-2-1") do
    %{
      id: :"id-spe-si-2-1",
      description: "",
      title: "ВИПРАВЛЕННЯ ДЕФЕКТІВ - ЦЕНТРАЛІЗОВАНЕ УПРАВЛІННЯ (SI-2(1))",
      parameters: [
        {:si_2_1_01,
         "ВИПРАВЛЕННЯ ДЕФЕКТІВ - ЦЕНТРАЛІЗОВАНЕ УПРАВЛІННЯ [Вилучено: перенесено до PL-09]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-2-2") do
    %{
      id: :"id-spe-si-2-2",
      description: "",
      title: "ВИПРАВЛЕННЯ ДЕФЕКТІВ - АВТОМАТИЗОВАНЕ ВИПРАВЛЕННЯ ДЕФЕКТІВ (SI-2(2))",
      parameters: [
        {:si_2_2_01,
         "Встановлені на компонентах системи відповідні оновлення програмного забезпечення та мікропрограми, що стосуються безпеки, з частотою за допомогою автоматизованих механізмів",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-2-3") do
    %{
      id: :"id-spe-si-2-3",
      description: "",
      title: "ВИПРАВЛЕННЯ ДЕФЕКТІВ - ЧАС ДЛЯ УСУНЕННЯ ДЕФЕКТІВ ТА ОРІЄНТИРИ ДЛЯ КОРИГУВАЛЬНИХ ДІЙ (SI-2(3))",
      parameters: [
        {:si_2_3_a,
         "Вимірюється час між виявленням дефекту та його усуненням; SI-02(03)(b) були встановлені орієнтири для вжиття коригувальних дій",
         [type: :integer, default: 30]},
        {:si_2_3_odp,
         "Визначені контрольні коригувальних заходів; показники для вжиття",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-2-4") do
    %{
      id: :"id-spe-si-2-4",
      description: "",
      title: "ВИПРАВЛЕННЯ ДЕФЕКТІВ - АВТОМАТИЧНІ ЗАСОБИ УПРАВЛІННЯ ВИПРАВЛЕННЯМИ (SI-2(4))",
      parameters: [
        {:si_2_4_odp,
         "Визначені компоненти системи, які потребують автоматизованих інструментів управління виправленнями для полегшення усунення дефектів; SI-02(04)] застосовуються автоматизовані засоби управління виправленнями для полегшення виправлення недоліків у компонентах",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-si-2-5") do
    %{
      id: :"id-spe-si-2-5",
      description: "",
      title: "ВИПРАВЛЕННЯ ДЕФЕКТІВ АВТОМАТИЧНЕ ОНОВЛЕННЯ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ (SI-2(5))",
      parameters: [
        {:si_2_5_01,
         "SI-02(05) _ODP[01] оновлення програмного забезпечення та мікропрограми, що стосуються безпеки>, встановлено автоматично до <SI-02(05) _ODP[02] компонентів системи>",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-2-6") do
    %{
      id: :"id-spe-si-2-6",
      description: "",
      title: "ВИПРАВЛЕННЯ ДЕФЕКТІВ - ВИДАЛЕННЯ ПОПЕРЕДНІХ ВЕРСІЙ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ (SI-2(6))",
      parameters: [
        {:si_2_6_01,
         "Видаляються попередні версії програмне забезпечення та компоненти мікропрограми після встановлення оновлених версій",
         [type: :string, default: nil]},
        {:si_2_6_odp,
         "Потрібно видаляти компоненти програмного забезпечення та мікропрограми після встановлення оновлених версій",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-3") do
    %{
      id: :"id-spe-si-3",
      description: "",
      title: "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ (SI-3)",
      parameters: [
        {:si_3_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {підписаний; непідписаний}",
         [type: :string, default: nil]},
        {:si_3_odp_02,
         "Визначено частоту, з якою механізми шкідливого коду виконують сканування",
         [type: :integer, default: 30]},
        {:si_3_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {кінцева точка; точки входу та виходу з мережі}",
         [type: :string, default: nil]},
        {:si_3_odp_04,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {block malicious code; quarantitne malicious code; take action}",
         [type: :string, default: nil]},
        {:si_3_odp_05,
         "Визначено дії, яких слід вжити у відповідь на виявлення шкідливого коду (якщо вибрано)",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-si-3-1") do
    %{
      id: :"id-spe-si-3-1",
      description: "",
      title: "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ - ЦЕНТРАЛІЗОВАНЕ УПРАВЛІННЯ (SI-3(1))",
      parameters: [
        {:si_3_1_01,
         "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ - ЦЕНТРАЛІЗОВАНЕ УПРАВЛІННЯ [Вилучено: включено до PL-9]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-3-2") do
    %{
      id: :"id-spe-si-3-2",
      description: "",
      title: "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ - АВТОМАТИЧНІ ОНОВЛЕННЯ (SI-3(2))",
      parameters: [
        {:si_3_2_01,
         "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ - АВТОМАТИЧНІ ОНОВЛЕННЯ [Вилучено: включено до SI-03]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-3-3") do
    %{
      id: :"id-spe-si-3-3",
      description: "",
      title: "ЗАХИСТ ВІД ШКІДЛИВОГО КОРИСТУВАЧІ (SI-3(3))",
      parameters: [
        {:si_3_3_01,
         "ЗАХИСТ ВІД ШКІДЛИВОГО КОРИСТУВАЧІ [Вилучено: включено до AC-6(10)]. КОДУ - НЕПРИВІЛЕЙОВАНІ SI-3(4) ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ ПРИВІЛЕЙОВАНИМИ КОРИСТУВАЧАМИ ОНОВЛЕННЯ ТІЛЬКИ",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-3-4") do
    %{
      id: :"id-spe-si-3-4",
      description: "",
      title: "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ ПРИВІЛЕЙОВАНИМИ КОРИСТУВАЧАМИ (SI-3(4))",
      parameters: [
        {:si_3_4_01,
         "Оновлюються механізми захисту від шкідливого коду лише за вказівкою привілейованого користувача",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-si-3-5") do
    %{
      id: :"id-spe-si-3-5",
      description: "",
      title: "ЗАХИСТ ВІД ШКІДЛИВОГО ЗБЕРІГАННЯ ДАНИХ (SI-3(5))",
      parameters: [
        {:si_3_5_01,
         "ЗАХИСТ ВІД ШКІДЛИВОГО ЗБЕРІГАННЯ ДАНИХ [Вилучено: включено до MP-7]. КОДУ",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-3-6") do
    %{
      id: :"id-spe-si-3-6",
      description: "",
      title: "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ - ТЕСТУВАННЯ ТА ВЕРИФІКАЦІЯ (SI-3(6))",
      parameters: [
        {:si_3_6_a,
         "Перевіряються механізми захисту від шкідливого коду частота шляхом введення в систему відомого доброякісного коду",
         [type: :string, default: "щорічно"]},
        {:si_3_6_b_01,
         "Відбувається виявлення (доброякісний тест) коду",
         [type: :string, default: nil]},
        {:si_3_6_b_02,
         "Відбувається відповідне звітування про інцидент",
         [type: :string, default: nil]},
        {:si_3_6_odp,
         "Визначено періодичність тестування механізмів захисту від зловмисного коду",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-si-3-7") do
    %{
      id: :"id-spe-si-3-7",
      description: "",
      title: "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ - ВИЯВЛЕННЯ БЕЗ ПІДПИСУ (SI-3(7))",
      parameters: [
        {:si_3_7_01,
         "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ - ВИЯВЛЕННЯ БЕЗ ПІДПИСУ [Вилучено: включено до SI-3]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-3-8") do
    %{
      id: :"id-spe-si-3-8",
      description: "",
      title: "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ - ВИЯВЛЕННЯ НЕАВТОРИЗОВАНИХ КОМАНД (SI-3(8))",
      parameters: [
        {:si_3_8_a,
         "Виявлено <SI-03(08) _ODP[01] неавторизовані команди операційної системи> через інтерфейс прикладного програмування ядра на <SI-03(08) _ODP[02] апаратних компонентах системи>",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-3-9") do
    %{
      id: :"id-spe-si-3-9",
      description: "",
      title: "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ - АВТЕНТИФІКАЦІЯ ВІДДАЛЕНИХ КОМАНД (SI-3(9))",
      parameters: [
        {:si_3_9_01,
         "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ - АВТЕНТИФІКАЦІЯ ВІДДАЛЕНИХ КОМАНД [Вилучено: включено до AC-17(10)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-3-10") do
    %{
      id: :"id-spe-si-3-10",
      description: "",
      title: "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ - АНАЛІЗ ШКІДЛИВОГО КОДУ (SI-3(10))",
      parameters: [
        {:si_3_10_a,
         "Використовуються інструменти та методи для аналізу характеристик та поведінки шкідливого коду",
         [type: :string, default: nil]},
        {:si_3_10_b_01,
         "Включені результати аналізу шкідливого коду в організаційні процеси реагування на інциденти",
         [type: :string, default: nil]},
        {:si_3_10_b_02,
         "Включені результати аналізу шкідливого коду в організаційні процеси виправлення недоліків",
         [type: :string, default: nil]},
        {:si_3_10_odp,
         "Визначені інструменти та методи, які будуть використовуватися для аналізу характеристик та поведінки шкідливого коду",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4") do
    %{
      id: :"id-spe-si-4",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ (SI-4)",
      parameters: [
        {:si_4_odp_02,
         "Визначені методи та способи, що використовуються для виявлення несанкціонованого використання системи",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_4_odp_03,
         "Визначена інформація про моніторинг системи, яка повинна надаватися персоналу або ролям",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_4_odp_04,
         "Визначено персонал або ролі, яким має надаватися інформація про моніторинг системи",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_4_odp_05,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {за потребою; частота}",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-si-4-1") do
    %{
      id: :"id-spe-si-4-1",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ ВИЯВЛЕННЯ ВТОРГНЕНЬ (IDS) (SI-4(1))",
      parameters: [
        {:si_4_1_01,
         "Підключені окремі засоби виявлення вторгнень загальносистемної системи виявлення вторгнень; до",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:si_4_1_02,
         "Об'єднані окремі інструменти виявлення вторгнень загальносистемну систему виявлення вторгнень. у",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4-2") do
    %{
      id: :"id-spe-si-4-2",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - АВТОМАТИЗОВАНІ МЕХАНІЗМИ АНАЛІЗУ В РЕАЛЬНОМУ ЧАСІ (SI-4(2))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-si-4-3") do
    %{
      id: :"id-spe-si-4-3",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ МЕХАНІЗМИ ІНТЕГРАЦІЇ (SI-4(3))",
      parameters: [
        {:si_4_3_01,
         "Використовуються автоматизовані інструменти та механізми для інтеграції інструментів та механізмів виявлення вторгнень у механізми контролю доступу",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:si_4_3_02,
         "Використовуються автоматизовані інструменти та механізми для інтеграції інструментів та механізмів виявлення вторгнень у механізми контролю потоків",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-si-4-4") do
    %{
      id: :"id-spe-si-4-4",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ КОМУНІКАЦІЙ (SI-4(4))",
      parameters: [
        {:si_4_4_a_01,
         "Визначені критерії незвичної або несанкціонованої діяльності або умови для вхідного трафіку зв'язку",
         [type: :list, default: []]},
        {:si_4_4_a_02,
         "Визначені критерії незвичайної або несанкціонованої діяльності або умови для вихідного трафіку зв'язку",
         [type: :list, default: []]},
        {:si_4_4_b_01,
         "Здійснюється моніторинг вхідного комунікаційного трафіку частота на предмет незвичних або несанкціонованих дій або умов",
         [type: :string, default: "щорічно"]},
        {:si_4_4_b_02,
         "Контролюється вихідний трафік зв'язку частота на предмет незвичних або несанкціонованих дій або умов. вихідного виявлення",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-si-4-5") do
    %{
      id: :"id-spe-si-4-5",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - СИСТЕМНІ СПОВІЩЕННЯ (SI-4(5))",
      parameters: [
        {:si_4_5_01,
         "Відбувається оповіщення <SI-04(05) _ODP[01] персоналу або ролей> при виникненні згенерованих системою <SI-04(05) _ODP[02] індикаторів компрометації>",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-4-6") do
    %{
      id: :"id-spe-si-4-6",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - ЗАБОРОНА ДЛЯ НЕПРИВІЛЕЙОВАНИХ КОРИСТУВАЧІВ (SI-4(6))",
      parameters: [
        {:si_4_6_01,
         "МОНІТОРИНГ СИСТЕМИ - ЗАБОРОНА ДЛЯ НЕПРИВІЛЕЙОВАНИХ КОРИСТУВАЧІВ [Вилучено: включено до AC-6(10)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4-7") do
    %{
      id: :"id-spe-si-4-7",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ ПІДОЗРІЛІ ПОДІЇ (SI-4(7))",
      parameters: [
        {:si_4_7_a,
         "Повідомляється персонал з реагування на інциденти про виявлені підозрілі події",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_4_7_b,
         "Вживаються найменш руйнівні дії при виявленні підозрілих подій",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-si-4-8") do
    %{
      id: :"id-spe-si-4-8",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - ЗАХИСТ ІНФОРМАЦІЇ МОНІТОРИНГУ (SI-4(8))",
      parameters: [
        {:si_4_8_01,
         "МОНІТОРИНГ СИСТЕМИ - ЗАХИСТ ІНФОРМАЦІЇ МОНІТОРИНГУ [Вилучено: включено до SI-4]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4-9") do
    %{
      id: :"id-spe-si-4-9",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - ТЕСТУВАННЯ ЗАСОБІВ І МЕХАНІЗМІВ МОНІТОРИНГУ (SI-4(9))",
      parameters: [
        {:si_4_9_01,
         "Тестуються інструменти та механізми моніторингу вторгнень <SI-04(09)_ ODP періодичність>",
         [type: :string, default: "щорічно"]},
        {:si_4_9_odp,
         "Визначена періодичність тестування механізмів моніторингу вторгнень; інструментів і",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-si-4-10") do
    %{
      id: :"id-spe-si-4-10",
      description: "",
      title: "МОНІТОРИНГ КОМУНІКАЦІЙ (SI-4(10))",
      parameters: [
        {:si_4_10_01,
         "Передбачено, щоб <SI-04(10) _ODP[01] зашифрований трафік зв’язку> був видимим для <SI-04(10) _ODP[02] засобів та механізмів моніторингу системи>",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4-11") do
    %{
      id: :"id-spe-si-4-11",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ КОМУНІКАЦІЙ (SI-4(11))",
      parameters: [
        {:si_4_11_01,
         "Аналізується вихідний комунікаційний трафік на зовнішніх інтерфейсах системи для виявлення аномалій",
         [type: :string, default: nil]},
        {:si_4_11_02,
         "Аналізується вихідний трафік зв'язку в внутрішніх точках для виявлення аномалій",
         [type: :string, default: nil]},
        {:si_4_11_odp,
         "Визначені внутрішні точки в системі, в яких необхідно аналізувати комунікаційний трафік",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4-12") do
    %{
      id: :"id-spe-si-4-12",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ АВТОМАТИЗОВАНІ СПОВІЩЕННЯ (SI-4(12))",
      parameters: [
        {:si_4_12_01,
         "Оповіщається <SI-04(12) _ODP[01] персонал або ролі> за допомогою <SI-04(12) _ODP[02] автоматизованих механізмів>, коли <SI-04(12) _ODP[03] дії, що викликають оповіщення> вказують на невідповідну або незвичну викликають оповіщення персоналу, або діяльність, що має вплив на безпеку або приватне життя",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-4-13") do
    %{
      id: :"id-spe-si-4-13",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - АНАЛІЗ ТРАФІКУ ТА ШАБЛОНІВ ПОДІЙ (SI-4(13))",
      parameters: [
        {:si_4_13_a_01,
         "Аналізується трафік для системи",
         [type: :string, default: nil]},
        {:si_4_13_a_02,
         "Проаналізовано патерни подій для системи",
         [type: :string, default: nil]},
        {:si_4_13_b_01,
         "Розроблені профілі, що представляють загальний трафік",
         [type: :string, default: nil]},
        {:si_4_13_b_02,
         "Розроблені профілі, що представляють патерни подій",
         [type: :string, default: nil]},
        {:si_4_13_c_01,
         "Використовуються профілі трафіку пристроїв системного моніторингу",
         [type: :string, default: nil]},
        {:si_4_13_c_02,
         "Використовуються профілі подій при налаштуванні пристроїв системного моніторингу при налаштуванні",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4-14") do
    %{
      id: :"id-spe-si-4-14",
      description: "",
      title: "МОНІТОРИНГ ВТОРГНЕННЯ (SI-4(14))",
      parameters: [
        {:si_4_14_01,
         "Використовується система виявлення бездротових вторгнень для виявлення несанкціонованих бездротових пристроїв",
         [type: :string, default: nil]},
        {:si_4_14_02,
         "Використовується бездротова система виявлення вторгнень для виявлення спроб атак на систему",
         [type: :integer, default: 3]},
        {:si_4_14_03,
         "Використовується бездротова система виявлення вторгнень для виявлення потенційних компрометації або порушень в системі",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4-15") do
    %{
      id: :"id-spe-si-4-15",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - ПЕРЕХІД ВІД БЕЗДРОТОВОГО ЗВ’ЯЗКУ ДО ПРОВІДНИХ МЕРЕЖ (SI-4(15))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-si-4-16") do
    %{
      id: :"id-spe-si-4-16",
      description: "",
      title: "МОНІТОРИНГ МОНІТОРИНГУ (SI-4(16))",
      parameters: [
        {:si_4_16_01,
         "Співвідноситься інформація з інструментів моніторингу та механізмів, що застосовуються в системі",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4-17") do
    %{
      id: :"id-spe-si-4-17",
      description: "",
      title: "МОНІТОРИНГ ОБІЗНАНІСТЬ (SI-4(17))",
      parameters: [
        {:si_4_17_01,
         "Співвідноситься інформація, отримана в результаті моніторингу фізичної, кібернетичної діяльності та діяльності ланцюга поставок, з метою досягнення інтегрованої, загальноорганізаційної ситуаційної обізнаності",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4-18") do
    %{
      id: :"id-spe-si-4-18",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - АНАЛІЗ ТРАФІКУ ТА ПРИХОВАНОЇ ЕКСФІЛЬТРАЦІЇ (SI-4(18))",
      parameters: [
        {:si_4_18_01,
         "Аналізується вихідний комунікаційний трафік на зовнішніх по відношенню до системи інтерфейсах для виявлення прихованого витоку інформації",
         [type: :string, default: nil]},
        {:si_4_18_02,
         "Аналізується вихідний трафік зв'язку в внутрішніх точках для виявлення прихованого витоку інформації",
         [type: :string, default: nil]},
        {:si_4_18_odp,
         "Визначені внутрішні точки в системі, в яких необхідно аналізувати комунікаційний трафік",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4-19") do
    %{
      id: :"id-spe-si-4-19",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - ОСОБИ, ЯКІ ПРЕДСТАВЛЯЮТЬ БІЛЬШИЙ РИЗИК (SI-4(19))",
      parameters: [
        {:si_4_19_01,
         "Здійснюється <SI-04(19) _ODP[01] додатковий моніторинг> щодо осіб, які були ідентифіковані джерелами <SI-04(19) _ODP[02] як такі, що становлять підвищений рівень ризику>",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4-20") do
    %{
      id: :"id-spe-si-4-20",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - ПРИВІЛЕЙОВАНІ КОРИСТУВАЧІ (SI-4(20))",
      parameters: [
        {:si_4_20_01,
         "Реалізовано привілейованих користувачів. привілейованих додатковий моніторинг",
         [type: :string, default: nil]},
        {:si_4_20_odp,
         "Визначено додатковий користувачів; моніторинг",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4-21") do
    %{
      id: :"id-spe-si-4-21",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - ВИПРОБУВАЛЬНІ ТЕРМІНИ (SI-4(21))",
      parameters: [
        {:si_4_21_01,
         "Здійснюється <SI-04(21) _ODP[01] додатковий моніторинг> осіб під час <SI-04(21) _ODP[02] випробувального терміну>",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-4-22") do
    %{
      id: :"id-spe-si-4-22",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - НЕСАНКЦІОНОВАНІ ПОСЛУГИ МЕРЕЖІ (SI-4(22))",
      parameters: [
        {:si_4_22_a,
         "Виявлено послуги мережі, які не було авторизовано або схвалено відповідно до процесів авторизації або схвалення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-4-23") do
    %{
      id: :"id-spe-si-4-23",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - ПРИСТРОЇ НА ОСНОВІ ХОСТА (SI-4(23))",
      parameters: [
        {:si_4_23_01,
         "Реалізовано <SI-04(23) _ODP[01] механізми моніторингу на основі хостів> на <SI-04(23) _ODP[02] компоненти системи>",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-si-4-24") do
    %{
      id: :"id-spe-si-4-24",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - ІНДИКАТОРИ КОМПРОМЕТАЦІЇ (SI-4(24))",
      parameters: [
        {:si_4_24_01,
         "Виявлено індикатори компрометації, 04(24)_ODP[01] джерелами>",
         [type: :string, default: nil]},
        {:si_4_24_02,
         "Збираються індикатори компрометації, що надаються джерелами",
         [type: :string, default: nil]},
        {:si_4_24_03,
         "Індикатори компрометації, надані <SI-04(24) джерелами>, поширюються на <SI-04(24) персонал або ролі>. надані <SI- _ODP[01] _ODP[02]",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-4-25") do
    %{
      id: :"id-spe-si-4-25",
      description: "",
      title: "МОНІТОРИНГ СИСТЕМИ - АНАЛІЗ МЕРЕЖЕВОГО ТРАФІКУ (SI-4(25))",
      parameters: [
        {:si_4_25_01,
         "Забезпечується видимість мережевого трафіку на зовнішніх системних інтерфейсах для оптимізації ефективності пристроїв моніторингу",
         [type: :string, default: nil]},
        {:si_4_25_02,
         "Забезпечено видимість мережевого трафіку на ключових внутрішніх інтерфейсах системи для оптимізації ефективності пристроїв моніторингу",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-5") do
    %{
      id: :"id-spe-si-5",
      description: "",
      title: "ПОПЕРЕДЖЕННЯ, РЕКОМЕНДАЦІЇ ТА ДИРЕКТИВИ З БЕЗПЕКИ (SI-5)",
      parameters: [
        {:si_5_odp_01,
         "Визначені зовнішні організації, від яких необхідно постійно отримувати оповіщення, поради та директиви щодо безпеки системи",
         [type: :string, default: nil]},
        {:si_5_odp_02,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {персонал або ролі; елементи; зовнішні організації}",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_5_odp_03,
         "Визначено персонал або ролі, до яких мають бути доведені попередження, поради та директиви з безпеки (якщо визначено)",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_5_odp_04,
         "Визначені елементи в організації, до яких мають надсилатися оповіщення, поради та директиви з безпеки (якщо вони були обрані)",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-5-1") do
    %{
      id: :"id-spe-si-5-1",
      description: "",
      title: "ПОПЕРЕДЖЕННЯ, РЕКОМЕНДАЦІЇ ТА ДИРЕКТИВИ З БЕЗПЕКИ АВТОМАТИЧНІ ПОПЕРЕДЖЕННЯ ТА РЕКОМЕНДАЦІЇ (SI-5(1))",
      parameters: [
        {:si_5_1_01,
         "Використовуються автоматизовані механізми для трансляції попередження та рекомендації інформації з питань безпеки по всій організації",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:si_5_1_odp,
         "Визначені автоматизовані механізми, які використовуються для трансляції попередження та рекомендації інформації про безпеку в організації",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-si-6") do
    %{
      id: :"id-spe-si-6",
      description: "",
      title: "ПЕРЕВІРКА ФУНКЦІЙ БЕЗПЕКИ ТА ПРИВАТНОСТІ (SI-6)",
      parameters: [
        {:si_6_odp_01,
         "Визначені функції безпеки, які необхідно перевірити на коректність роботи",
         [type: :string, default: nil]},
        {:si_6_odp_02,
         "Визначені функції приватності, які потрібно перевіряти на коректність роботи",
         [type: :string, default: nil]},
        {:si_6_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {перехідні стани системи; за командою користувача з відповідним привілеєм; частота}",
         [type: :string, default: "щорічно"]},
        {:si_6_odp_04,
         "Визначені перехідні стани системи, що вимагають перевірки функцій безпеки та конфіденційності; (якщо вибрано)",
         [type: :string, default: nil]},
        {:si_6_odp_05,
         "Визначена періодичність перевірки правильності роботи функцій безпеки та приватності; (якщо вибрано)",
         [type: :string, default: "щорічно"]},
        {:si_6_odp_06,
         "Визначено персонал або ролі, які мають бути сповіщені про невдалу перевірку безпеки та приватності",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_6_odp_07,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {вимкнути систему; перезапустити систему; альтернативна дія (дії)}",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-si-6-1") do
    %{
      id: :"id-spe-si-6-1",
      description: "",
      title: "ПЕРЕВІРКА БЕЗПЕКИ ТА ФУНКЦІЙ ПРИВАТНОСТІ - СПОВІЩЕННЯ ПРО НЕУСПІШНЕ ПРОХОДЖЕННЯ ТЕСТІВ З БЕЗПЕКИ (SI-6(1))",
      parameters: [
        {:si_6_1_01,
         "ПЕРЕВІРКА БЕЗПЕКИ ТА ФУНКЦІЙ ПРИВАТНОСТІ - СПОВІЩЕННЯ ПРО НЕУСПІШНЕ ПРОХОДЖЕННЯ ТЕСТІВ З БЕЗПЕКИ [Вилучено: включено до SI-6]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-6-2") do
    %{
      id: :"id-spe-si-6-2",
      description: "",
      title: "ПЕРЕВІРКА БЕЗПЕКИ ТА ФУНКЦІЙ ПРИВАТНОСТІ АВТОМАТИЗОВАНА ПІДТРИМКА РОЗПОДІЛЕНОГО ТЕСТУВАННЯ (SI-6(2))",
      parameters: [
        {:si_6_2_01,
         "Впроваджені автоматизовані механізми для розподіленого тестуванням функцій безпеки; підтримки",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:si_6_2_02,
         "Проваджені автоматизовані механізми для розподіленого тестуванням функцій приватності. підтримки",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-si-6-3") do
    %{
      id: :"id-spe-si-6-3",
      description: "",
      title: "ПЕРЕВІРКА БЕЗПЕКИ ТА ФУНКЦІЙ ПРИВАТНОСТІ ПОВІДОМЛЕННЯ ПРО РЕЗУЛЬТАТИ ПЕРЕВІРКИ (SI-6(3))",
      parameters: [
        {:si_6_3_01,
         "Повідомляються результати перевірки функцій безпеки персоналу або ролям",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_6_3_odp,
         "Визначено персонал або ролі, призначені для отримання результатів перевірки функцій безпеки та приватності",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-7") do
    %{
      id: :"id-spe-si-7",
      description: "a. Впровадити механізми захисту від спаму в точках входу та виходу системи, щоб виявляти та протидіяти небажаним повідомленням. b. Оновлювати механізми захисту від спаму, коли доступні нові механізми відповідно до організаційної політики та процедур управління конфігурацією.",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ (SI-7)",
      parameters: [
        {:si_7_odp_01,
         "Визначено програмне забезпечення, яке потребує застосування засобів перевірки цілісності для виявлення несанкціонованих змін",
         [type: :string, default: nil]},
        {:si_7_odp_02,
         "Визначено прошивку, яка потребує застосування інструментів перевірки цілісності для виявлення несанкціонованих змін",
         [type: :string, default: nil]},
        {:si_7_odp_03,
         "Визначена інформація, яка потребує застосування засобів перевірки цілісності для виявлення несанкціонованих змін",
         [type: :string, default: nil]},
        {:si_7_odp_04,
         "Визначені дії, яких слід вжити при виявленні несанкціонованих змін у програмному забезпеченні",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:si_7_odp_05,
         "Визначені дії, яких слід вжити несанкціонованих змін у прошивці; при виявленні SI-07_ODP[06] визначені дії, яких слід вжити несанкціонованих змін до інформації; при виявленні SI-07a.[01] використовуються засоби перевірки цілісності для виявлення несанкціонованих змін у програмному забезпеченні; SI-07a.[02] використовуються засоби перевірки цілісності для виявлення несанкціонованих змін у мікропрограмі; SI-07a.[03] використовуються засоби перевірки цілісності для виявлення несанкціонованих змін до інформації; SI-07b.[01] виконуються дії при виявленні несанкціонованих змін у програмному забезпеченні; SI-07b.[02] виконуються дії несанкціонованих змін у прошивці; при виявленні SI-07b.[03] виконуються дії несанкціонованих змін в інформації. при виявленні",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-si-7-1") do
    %{
      id: :"id-spe-si-7-1",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - ПЕРЕВІРКА ЦІЛІСНОСТІ (SI-7(1))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-si-7-2") do
    %{
      id: :"id-spe-si-7-2",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - АВТОМАТИЧНІ СПОВІЩЕННЯ ПРО ПОРУШЕННЯ ЦІЛІСНОСТІ (SI-7(2))",
      parameters: [
        {:si_7_2_01,
         "Застосовуються автоматизовані інструменти, які надають повідомлення персоналу або ролям при виявленні розбіжностей під час перевірки цілісності",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_7_2_odp,
         "Визначено персонал або ролі, яким необхідно повідомляти про виявлення розбіжностей під час перевірки цілісності",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-7-3") do
    %{
      id: :"id-spe-si-7-3",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - ІНСТРУМЕНТИ ЦІЛІСНОСТІ З ЦЕНТРАЛІЗОВАНИМ УПРАВЛІННЯМ (SI-7(3))",
      parameters: [
        {:si_7_3_01,
         "Застосовуються інструменти цілісності з централізованим управлінням",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-7-4") do
    %{
      id: :"id-spe-si-7-4",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ – ПАКУВАННЯ З ІНДИКАЦІЄЮ ОЗНАК ЇЇ НЕСАНКЦІОНОВАНОГО РОЗКРИТТЯ (SI-7(4))",
      parameters: [
        {:si_7_4_01,
         "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ – ПАКУВАННЯ З ІНДИКАЦІЄЮ ОЗНАК ЇЇ НЕСАНКЦІОНОВАНОГО РОЗКРИТТЯ [Вилучено: включено до SA-12]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-7-5") do
    %{
      id: :"id-spe-si-7-5",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - АВТОМАТИЧНІ ВІДПОВІДІ ПРО ПОРУШЕННЯ ЦІЛІСНОСТІ (SI-7(5))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-si-7-6") do
    %{
      id: :"id-spe-si-7-6",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ КРИПТОГРАФІЧНИЙ ЗАХИСТ (SI-7(6))",
      parameters: [
        {:si_7_6_01,
         "Впроваджені криптографічні механізми для виявлення несанкціонованих змін у програмному забезпеченні",
         [type: :string, default: "AES-256-GCM"]},
        {:si_7_6_02,
         "Реалізовані криптографічні механізми несанкціонованих змін у прошивці; для виявлення",
         [type: :string, default: "AES-256-GCM"]},
        {:si_7_6_03,
         "Впроваджені криптографічні механізми несанкціонованих змін інформації. для виявлення",
         [type: :string, default: "AES-256-GCM"]}
      ]
    }
  end

  def spec(:"id-spe-si-7-7") do
    %{
      id: :"id-spe-si-7-7",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - ІНТЕГРАЦІЯ ВИЯВЛЕННЯ І РЕАГУВАННЯ (SI-7(7))",
      parameters: [
        {:si_7_7_01,
         "Виявлення змін включено до можливості організації реагування на інциденти",
         [type: :string, default: nil]},
        {:si_7_7_odp,
         "Визначені зміни в системі, що мають відношення до безпеки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-7-8") do
    %{
      id: :"id-spe-si-7-8",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - АУДИТ ВАЖЛИВИХ ПОДІЙ (SI-7(8))",
      parameters: [
        {:si_7_8_01,
         "Передбачена можливість аудиту потенційного порушення цілісності",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-7-9") do
    %{
      id: :"id-spe-si-7-9",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - ПЕРЕВІРКА ПРОЦЕСУ ЗАВАНТАЖЕННЯ (SI-7(9))",
      parameters: [
        {:si_7_9_01,
         "Перевіряється цілісність процесу завантаження 07(09)_ODP системних компонентів>. <SI-",
         [type: :string, default: nil]},
        {:si_7_9_odp,
         "Визначено компоненти системи, які потребують перевірки цілісності процесу завантаження",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-7-10") do
    %{
      id: :"id-spe-si-7-10",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - ЗАХИСТ ЗАВАНТАЖУВАЛЬНОГО ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ (SI-7(10))",
      parameters: [
        {:si_7_10_01,
         "Реалізовано <SI-07(10) _ODP[01] механізми> для захисту цілісності завантажувальної прошивки у <SI-07(10) _ODP[02] системних компонентах>. компоненти системи, захисту цілісності які потребують завантажувальної",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-si-7-11") do
    %{
      id: :"id-spe-si-7-11",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - ОБМЕЖЕНЕ СЕРЕДОВИЩЕ З ОБМЕЖЕНИМИ ПРИВІЛЕЯМИ (SI-7(11))",
      parameters: [
        {:si_7_11_01,
         "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - ОБМЕЖЕНЕ СЕРЕДОВИЩЕ З ОБМЕЖЕНИМИ ПРИВІЛЕЯМИ [Вилучено: включено до CM-7(6)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-7-12") do
    %{
      id: :"id-spe-si-7-12",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - ПЕРЕВІРКА ЦІЛІСНОСТІ (SI-7(12))",
      parameters: [
        {:si_7_12_01,
         "Перевіряється забезпечення, виконанням. цілісність програмне встановлене користувачем перед",
         [type: :string, default: nil]},
        {:si_7_12_odp,
         "Визначено програмне забезпечення, встановлене користувачем, яке потребує перевірки цілісності перед виконанням",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-7-13") do
    %{
      id: :"id-spe-si-7-13",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - ВИКОНАННЯ КОДУ В ЗАХИЩЕНИХ СЕРЕДОВИЩАХ (SI-7(13))",
      parameters: [
        {:si_7_13_01,
         "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - ВИКОНАННЯ КОДУ В ЗАХИЩЕНИХ СЕРЕДОВИЩАХ [Вилучено: включено до CM-7(7)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-7-14") do
    %{
      id: :"id-spe-si-7-14",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - ДВІЙКОВИЙ АБО МАШИННО-ВИКОНУВАНИЙ КОД (SI-7(14))",
      parameters: [
        {:si_7_14_01,
         "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - ДВІЙКОВИЙ АБО МАШИННО-ВИКОНУВАНИЙ КОД [Вилучено: включено до CM-7(8)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-7-15") do
    %{
      id: :"id-spe-si-7-15",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ АВТЕНТИФІКАЦІЯ КОДУ (SI-7(15))",
      parameters: [
        {:si_7_15_01,
         "Реалізовано криптографічні механізми для автентифікації програмного забезпечення або компонентів мікропрограми перед інсталяцією",
         [type: :string, default: "AES-256-GCM"]},
        {:si_7_15_odp,
         "Визначено компоненти програмного забезпечення або мікропрограми, які мають бути автентифіковані за допомогою криптографічних механізмів перед встановленням",
         [type: :string, default: "AES-256-GCM"]}
      ]
    }
  end

  def spec(:"id-spe-si-7-16") do
    %{
      id: :"id-spe-si-7-16",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ - ТЕРМІН ВИКОНАННЯ ПРОЦЕСУ БЕЗ НАГЛЯДУ (SI-7(16))",
      parameters: [
        {:si_7_16_01,
         "Заборонено процесам виконуватися без нагляду довше, ніж часовий період",
         [type: :integer, default: 30]},
        {:si_7_16_odp,
         "Визначено максимальний період часу, протягом якого процеси можуть виконуватися без нагляду",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-7-17") do
    %{
      id: :"id-spe-si-7-17",
      description: "",
      title: "ЦІЛІСНІСТЬ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ, ВБУДОВАНОГО ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ ТА ІНФОРМАЦІЇ – САМОЗАХИСТ ПРОГРАМ ВІД САМОВІЛЬНОГО ВИКОНАННЯ (SI-7(17))",
      parameters: [
        {:si_7_17_odp,
         "Визначено елементи керування, які потрібно реалізувати для самозахисту програми під час виконання",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-8") do
    %{
      id: :"id-spe-si-8",
      description: "",
      title: "ЗАХИСТ ВІД СПАМУ (SI-8)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-si-8-1") do
    %{
      id: :"id-spe-si-8-1",
      description: "",
      title: "ЗАХИСТ ВІД СПАМУ - ЦЕНТРАЛІЗОВАНЕ УПРАВЛІННЯ (SI-8(1))",
      parameters: [
        {:si_8_1_01,
         "ЗАХИСТ ВІД СПАМУ - ЦЕНТРАЛІЗОВАНЕ УПРАВЛІННЯ [Вилучено: включено до PL-9]. SI-8(2) ЗАХИСТ ВІД СПАМУ - АВТОМАТИЧНІ ОНОВЛЕННЯ",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-8-2") do
    %{
      id: :"id-spe-si-8-2",
      description: "",
      title: "ЗАХИСТ ВІД СПАМУ - АВТОМАТИЧНІ ОНОВЛЕННЯ (SI-8(2))",
      parameters: [
        {:si_8_2_01,
         "Автоматично оновлюються механізми захисту від спаму частота",
         [type: :string, default: "щорічно"]},
        {:si_8_2_odp,
         "Визначено періодичність автоматичного механізмів захисту від спаму; оновлення",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-si-8-3") do
    %{
      id: :"id-spe-si-8-3",
      description: "",
      title: "ЗАХИСТ ВІД СПАМУ - БЕЗПЕРЕРВНЕ НАВЧАННЯ (SI-8(3))",
      parameters: [
        {:si_8_3_01,
         "Впроваджені механізми захисту від спаму з можливістю навчання для більш ефективного визначення законого комунікаційного трафіку",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-si-9") do
    %{
      id: :"id-spe-si-9",
      description: "",
      title: "ОБМЕЖЕННЯ НА ВВЕДЕННЯ ІНФОРМАЦІЇ (SI-9)",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-si-10") do
    %{
      id: :"id-spe-si-10",
      description: "Перевіряти дійсність [Призначення: визначена організацією введена інформація].",
      title: "ПЕРЕВІРКА ВВОДУ ІНФОРМАЦІЇ (SI-10)",
      parameters: [
        {:si_10_01,
         "Перевіряється дійсність синтаксису вхідної інформації",
         [type: :string, default: nil]},
        {:si_10_odp,
         "Визначено вхідні дані до системи, які перевірки достовірності; потребують",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-10-1") do
    %{
      id: :"id-spe-si-10-1",
      description: "",
      title: "ПЕРЕВІРКА ВВОДУ ПЕРЕВИЗНАЧЕННЯ (SI-10(1))",
      parameters: [
        {:si_10_1_a,
         "Передбачена можливість ручного перевизначення валідації інформаційних входів",
         [type: :string, default: nil]},
        {:si_10_1_b,
         "Використання можливості ручного перевизначення обмежено лише уповноваженими особами",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_10_1_c,
         "Проводиться аудит перевизначення. використання можливості для ручного",
         [type: :string, default: nil]},
        {:si_10_1_odp,
         "Визначено авторизованих осіб, які можуть користуватися можливістю ручного перевизначення",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-10-2") do
    %{
      id: :"id-spe-si-10-2",
      description: "",
      title: "ПЕРЕВІРКА ВВОДУ ІНФОРМАЦІЇ ПОМИЛОК (SI-10(2))",
      parameters: [
        {:si_10_2_01,
         "Переглядаються помилки валідації вхідних даних протягом часового періоду",
         [type: :integer, default: 30]},
        {:si_10_2_02,
         "Помилки валідації вводу вирішуються 10(02)_ODP[02] часового проміжку>. протягом <SI-",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-10-3") do
    %{
      id: :"id-spe-si-10-3",
      description: "",
      title: "ПЕРЕВІРКА ВВОДУ ІНФОРМАЦІЇ - ПЕРЕДБАЧУВАНА ПОВЕДІНКА (SI-10(3))",
      parameters: [
        {:si_10_3_02,
         "Система поводиться задокументованим чином при отриманні недійсних вхідних даних",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-10-4") do
    %{
      id: :"id-spe-si-10-4",
      description: "",
      title: "ПЕРЕВІРКА ВВОДУ ІНФОРМАЦІЇ - ЧАСОВІ ВЗАЄМОДІЇ (SI-10(4))",
      parameters: [
        {:si_10_4_01,
         "Враховується часова взаємодія між компонентами системи при визначенні відповідної реакції на невірні вхідні дані",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-10-5") do
    %{
      id: :"id-spe-si-10-5",
      description: "",
      title: "ПЕРЕВІРКА ВВОДУ ІНФОРМАЦІЇ - ОБМЕЖЕННЯ ВХІДНИХ ДАНИХ ДОВІРЕНИМИ ДЖЕРЕЛАМИ І ЗАТВЕРДЖЕНИМИ ФОРМАТАМИ (SI-10(5))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-si-10-6") do
    %{
      id: :"id-spe-si-10-6",
      description: "",
      title: "ПЕРЕВІРКА ВВОДУ ІНФОРМАЦІЇ - ПРОФІЛАКТИКА ВВОДУ ДАНИХ (SI-10(6))",
      parameters: [
        {:si_10_6_01,
         "Визначено елементи керування, які потрібно реалізувати для самозахисту програми під час виконання",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-11") do
    %{
      id: :"id-spe-si-11",
      description: "a. Створити повідомлення про помилки, які надають інформацію, необхідну для реалізації виправних дій, без виявлення інформації, що може бути використана. b. Показувати повідомлення про помилки лише [Призначення: визначений організацією персонал або посадові особи].",
      title: "ОБРОБКА ПОМИЛОК (SI-11)",
      parameters: [
        {:si_11_odp,
         "Визначено персонал або ролі, яким слід повідомляти про повідомлення про помилки; SI-11a. генеруються повідомлення про помилки, які надають інформацію, необхідну для коригувальних дій, без розкриття інформації, яка може бути використана; SI-11b. показувати повідомлення про помилки лише для персонал або ролі",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-12") do
    %{
      id: :"id-spe-si-12",
      description: "Управляти та зберігати інформацію всередині системи та виводити інформацію із системи відповідно до чинного законодавства, виконавчих наказів, директив, правил, політик, стандартів, керівних принципів та експлуатаційних вимог.",
      title: "УПРАВЛІННЯ ТА ЗБЕРЕЖЕННЯ ІНФОРМАЦІЇ (SI-12)",
      parameters: [
        {:si_12_01,
         "Здійснюється управління інформацією в системі відповідно до чинних законів, наказів, директив, положень, політик, стандартів, інструкцій та експлуатаційних вимог",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:si_12_02,
         "Зберігається інформація в системі відповідно до чинних законів, указів Президента, директив, положень, політик, стандартів, інструкцій та експлуатаційних вимог",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:si_12_03,
         "Управління інформацією, що виводиться з системи, здійснюється відповідно до чинних законів, указів Президента, директив, положень, політик, стандартів, інструкцій та операційних вимог",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:si_12_04,
         "Зберігається інформація, що виводиться з системи, відповідно до чинних законів, наказів, директив, положень, політик, стандартів, інструкцій та експлуатаційних вимог",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]}
      ]
    }
  end

  def spec(:"id-spe-si-12-1") do
    %{
      id: :"id-spe-si-12-1",
      description: "",
      title: "УПРАВЛІННЯ ТА ЗБЕРЕЖЕННЯ ІНФОРМАЦІЇ ЕЛЕМЕНТІВ ПЕРСОНАЛЬНИХ ДАНИХ (SI-12(1))",
      parameters: [
        {:si_12_1_01,
         "Обмежується обробка персональних даних у життєвому циклі інформації в життєвому циклі інформації, елементами інформації, що ідентифікує особу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_12_1_odp,
         "Визначені елементи персональних даних у життєвому циклі інформації",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-12-2") do
    %{
      id: :"id-spe-si-12-2",
      description: "",
      title: "УПРАВЛІННЯ ТА ЗБЕРЕЖЕННЯ ІНФОРМАЦІЇ - МІНІМІЗАЦІЯ ВИКОРИСТАННЯ ПЕРСОНАЛЬНИХ ДАНИХ ПІД ЧАС ТЕСТУВАННЯ, НАВЧАННЯ ТА ДОСЛІДЖЕННІ (SI-12(2))",
      parameters: [
        {:si_12_2_01,
         "Використовуються методи для мінімізації використання персональних даних для досліджень; SI-12(02)[02] використовуються методи для мінімізації використання персональних даних для тестування",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_12_2_03,
         "Застосовуються методи для мінімізації використання персональних даних для навчання",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-12-3") do
    %{
      id: :"id-spe-si-12-3",
      description: "",
      title: "УПРАВЛІННЯ ІНФОРМАЦІЇ (SI-12(3))",
      parameters: [
        {:si_12_3_01,
         "Використовуються методи для знищення інформації після закінчення терміну зберігання",
         [type: :string, default: nil]},
        {:si_12_3_02,
         "Використовуються методи для знищення інформації після закінчення терміну зберігання",
         [type: :string, default: nil]},
        {:si_12_3_03,
         "Використовуються методи для стирання інформації після закінчення періоду зберігання",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-13") do
    %{
      id: :"id-spe-si-13",
      description: "a. Визначити середній час до збою (MTTF) для [Призначення: визначені організацією компоненти системи] в певних середовищах роботи. b. Надати замінні компоненти системи та засоби для заміни активних компонентів резервними компонентами відповідно до [Призначення: визначені організацією критерії заміни].",
      title: "ПЕРЕДБАЧУВАНЕ ЗАПОБІГАННЯ ЗБОЇВ (SI-13)",
      parameters: [
        {:si_13_odp_01,
         "Визначені компоненти системи, для яких необхідно визначити середній час до збою (MTTF)",
         [type: :integer, default: 30]},
        {:si_13_odp_02,
         "Визначені критерії заміни за середнім часом напрацювання до збою (MTTF), які будуть використовуватися для заміни активних і резервних компонентів; SI-13a. визначено середній час напрацювання до збою (MTTF) для системних компонентів у конкретних умовах експлуатації; SI-13b. передбачені замінні компоненти системи та засоби заміни активних і резервних компонентів відповідно до критеріїв заміни середнього часу напрацювання на відмову (MTTF) ",
         [type: :list, default: []]}
      ]
    }
  end

  def spec(:"id-spe-si-13-1") do
    %{
      id: :"id-spe-si-13-1",
      description: "",
      title: "ЗАПОБІГАННЯ ПЕРЕДБАЧУВАНИХ ЗБОЇВ - ВІДПОВІДАЛЬНІСТЬ ЗА ПЕРЕДАЧУ ФУНКЦІЙ КОМПОНЕНТІВ (SI-13(1))",
      parameters: [
        {:si_13_1_01,
         "Виводяться компоненти системи з експлуатації шляхом передачі обов'язків компонентів на запасні компоненти не пізніше, ніж частка або відсоток середнього напрацювання на відмову",
         [type: :integer, default: 30]},
        {:si_13_1_odp,
         "Визначено частку або напрацювання до збою, відсоток середнього часу в межах якого обов'язки компонента системи можуть бути передані компоненту, що замінює його",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-13-2") do
    %{
      id: :"id-spe-si-13-2",
      description: "",
      title: "ЗАПОБІГАННЯ ПЕРЕДБАЧУВАНИХ ЗБОЇВ - ТЕРМІН ВИКОНАННЯ ПРОЦЕСУ БЕЗ НАГЛЯДУ (SI-13(2))",
      parameters: [
        {:si_13_2_01,
         "ЗАПОБІГАННЯ ПЕРЕДБАЧУВАНИХ ЗБОЇВ - ТЕРМІН ВИКОНАННЯ ПРОЦЕСУ БЕЗ НАГЛЯДУ [Вилучено: включено до SI-7 (16)]",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-13-3") do
    %{
      id: :"id-spe-si-13-3",
      description: "",
      title: "ЗАПОБІГАННЯ ПЕРЕДБАЧУВАНИХ ФУНКЦІЙ КОМПОНЕНТІВ (SI-13(3))",
      parameters: [
        {:si_13_3_01,
         "Ініціюються вручну передачі між активним та резервним компонентами системи, коли використання активного компонента досягає відсоток від середнього часу напрацювання до збою",
         [type: :integer, default: 30]},
        {:si_13_3_odp,
         "Визначено відсоток середнього часу напрацювання на відмову для передач, які потрібно ініціювати вручну",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-13-4") do
    %{
      id: :"id-spe-si-13-4",
      description: "",
      title: "ЗАПОБІГАННЯ ПЕРЕДБАЧУВАНИХ ЗБОЇВ РЕЗЕРВНИХ КОМПОНЕНТІВ ТА ОПОВІЩЕННЯ (SI-13(4))",
      parameters: [
        {:si_13_4_a,
         "Успішно і прозоро встановлюються резервні компоненти протягом часу, якщо виявлено збої у роботі системних компонентів",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-13-5") do
    %{
      id: :"id-spe-si-13-5",
      description: "",
      title: "ЗАПОБІГАННЯ ПЕРЕДБАЧУВАНИХ АВАРІЙНОГО ПЕРЕМИКАННЯ (SI-13(5))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-si-14") do
    %{
      id: :"id-spe-si-14",
      description: "Реалізувати нестійкі [Призначення: визначені організацією компоненти системи та служби], які ініціюються у відомих станах і завершуються [Вибір (один або кілька): після закінчення сеансу використання; періодично з [Призначення: визначена організацією частота]].",
      title: "НЕСТІЙКІСТЬ (SI-14)",
      parameters: [
        {:si_14_01,
         "Реалізовано непостійні компоненти системи та сервіси, які ініціюються у відомому стані",
         [type: :string, default: nil]},
        {:si_14_odp_01,
         "Визначені непостійні компоненти системи та сервіси, які необхідно застосовувати",
         [type: :string, default: nil]},
        {:si_14_odp_02,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {по закінченні сеансу використання; частота}",
         [type: :string, default: "щорічно"]},
        {:si_14_odp_03,
         "Визначено частоту завершення роботи непостійних компонентів і сервісів, які ініціюються у відомому стані (якщо вибрано)",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-14-1") do
    %{
      id: :"id-spe-si-14-1",
      description: "",
      title: "НЕСТІЙКІСТЬ - ОНОВЛЕННЯ З НАДІЙНИХ ДЖЕРЕЛ (SI-14(1))",
      parameters: [
        {:si_14_1_01,
         "Програмне забезпечення та дані, що використовуються під час оновлення системних компонентів та служб, отримані з довірених джерел",
         [type: :integer, default: 30]},
        {:si_14_1_odp,
         "Визначені надійні джерела для отримання програмного забезпечення та даних для оновлення системних компонентів і служб",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-14-2") do
    %{
      id: :"id-spe-si-14-2",
      description: "",
      title: "НЕСТІЙКІСТЬ - НЕСТІЙКА ІНФОРМАЦІЯ (SI-14(2))",
      parameters: [
        {:si_14_2_b,
         "Видаляється інформація, коли вона більше не потрібна",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-14-3") do
    %{
      id: :"id-spe-si-14-3",
      description: "",
      title: "НЕСТІЙКІСТЬ - НЕСТІЙКІ ПІДКЛЮЧЕННЯ (SI-14(3))",
      parameters: [
        {:si_14_3_01,
         "Встановлюються з'єднання з системою на вимогу",
         [type: :string, default: nil]},
        {:si_14_3_odp,
         "Вибрано одне з наступних ЗНАЧЕНЬ ПАРАМЕТРА: {завершення запиту; період невикористання}",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-15") do
    %{
      id: :"id-spe-si-15",
      description: "Перевіряти інформацію, що виходить з [Призначення: визначені організацією програмні продукти та/або застосунки], щоб переконатися, що інформація відповідає очікуваному змісту.",
      title: "ФІЛЬТРАЦІЯ ВИХІДНИХ ДАНИХ (SI-15)",
      parameters: [
        {:si_15_01,
         "Перевіряється інформація, що виводиться з програмне забезпечення та/або додатки, щоб переконатися, що інформація відповідає очікуваному змісту",
         [type: :string, default: nil]},
        {:si_15_odp,
         "Визначені програми та/або додатки, виведення інформації з яких потребує перевірки",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-16") do
    %{
      id: :"id-spe-si-16",
      description: "Виконати [Призначення: визначені організацією заходи безпеки] для захисту системної пам’яті від несанкціонованого коду, що виконується.",
      title: "ЗАХИСТ ПАМ'ЯТІ (SI-16)",
      parameters: [
        {:si_16_01,
         "Реалізовано контроль для захисту системної пам'яті від несанкціонованого виконання коду",
         [type: :string, default: nil]},
        {:si_16_odp,
         "Визначено засоби контролю для захисту системної пам'яті від несанкціонованого виконання коду",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-si-17") do
    %{
      id: :"id-spe-si-17",
      description: "Виконати [Призначення: визначені організацією відмовостійкі процедури], коли настають [Призначення: визначені організацією умови виявлення несправностей].",
      title: "ВІДМОВОСТІЙКІ ПРОЦЕДУРИ (SI-17)",
      parameters: [
        {:si_17_01,
         "Реалізовано процедури захисту від збоїв при виникненні перелік умов збою. відмови, що вимагають",
         [type: :list, default: []]},
        {:si_17_odp_01,
         "Визначені відмовостійкі процедури, пов'язані з умовами відмови",
         [type: :string, default: nil]},
        {:si_17_odp_02,
         "Визначено перелік умов відмовостійких процедур",
         [type: :list, default: []]}
      ]
    }
  end

  def spec(:"id-spe-si-18") do
    %{
      id: :"id-spe-si-18",
      description: "a. Перевіряти точність, актуальність, своєчасність і повноту персональної інформації протягом її життєвого циклу [Завдання: частота, визначена організацією]; b. Виправляти або видаляти неточну або застарілу персональну інформацію.",
      title: "ОПЕРАЦІЇ ЗАБЕЗПЕЧЕННЯ ЯКОСТІ ДАНИХ (SI-18)",
      parameters: [
        {:si_18_odp_01,
         "Визначено періодичність перевірки точності персональну інформацію протягом життєвого циклу інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_18_odp_02,
         "Визначено періодичність перевірки актуальності персональної інформації протягом життєвого циклу інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_18_odp_03,
         "Визначено періодичність перевірки актуальності персональної інформації протягом життєвого циклу інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_18_odp_04,
         "Визначено періодичність перевірки повноти персональної інформації протягом життєвого циклу інформації; SI-18a.[01] перевіряється точність персональної інформації протягом життєвого циклу інформації частота; SI-18a.[02] перевіряється актуальність персональної інформації протягом життєвого циклу інформації < SI-18_ODP[02] частота>; SI-18a.[03] перевіряється своєчасність персональної інформації протягом життєвого циклу інформації <частота SI-18_ODP[03]>; SI-18a.[04] перевіряється повнота персональної інформації протягом життєвого циклу інформації частота; SI-18b. потрібно виправити або видалити неточну або застарілу персональну інформацію",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-18-1") do
    %{
      id: :"id-spe-si-18-1",
      description: "",
      title: "ОПЕРАЦІЇ ЗАБЕЗПЕЧЕННЯ ПІДТРИМКА (SI-18(1))",
      parameters: [
        {:si_18_1_01,
         "Використовуються автоматизовані механізми для виправлення або видалення персональної інформації яка є неточною, застарілою, неправильно визначеною щодо впливу або неправильно деідентифікованою",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_18_1_odp,
         "Визначені автоматизовані механізми, які використовуються для виправлення або видалення персональної інформації яка є неточною, застарілою, неправильно визначеною щодо впливу або неправильно деідентифікованою",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-18-2") do
    %{
      id: :"id-spe-si-18-2",
      description: "",
      title: "ОПЕРАЦІЇ ЗАБЕЗПЕЧЕННЯ ЯКОСТІ ДАНИХ - ТЕГУВАННЯ ДАНИХ (SI-18(2))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-si-18-3") do
    %{
      id: :"id-spe-si-18-3",
      description: "",
      title: "ОПЕРАЦІЇ ЗАБЕЗПЕЧЕННЯ ЯКОСТІ ДАНИХ - ЗБИРАННЯ (SI-18(3))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-si-18-4") do
    %{
      id: :"id-spe-si-18-4",
      description: "",
      title: "ОПЕРАЦІЇ ЗАПИТИ (SI-18(4))",
      parameters: [
        {:si_18_4_01,
         "Виправляється або видаляється персональну інформація на вимогу осіб або їхніх уповноважених представників. ПОТЕНЦІЙНІ МЕТОДИ ТА ОБ’ЄКТИ ОЦІНКИ:",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-18-5") do
    %{
      id: :"id-spe-si-18-5",
      description: "",
      title: "ОПЕРАЦІЇ ЗАБЕЗПЕЧЕННЯ ЯКОСТІ ДАНИХ - ПОВІДОМЛЕННЯ ПРО ВИПРАВЛЕННЯ ЧИ ВИДАЛЕННЯ (SI-18(5))",
      parameters: [
        {:si_18_5_01,
         "Одержувачі та фізичні особи повідомляються про виправлення або видалення персональної інформації",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_18_5_odp,
         "Визначені одержувачі персональних даних, які повинні бути повідомлені про виправлення або видалення персональних даних",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-19") do
    %{
      id: :"id-spe-si-19",
      description: "a. Видаліть такі елементи персональних даних з наборів даних: [Призначення: визначені організацією елементи персональних даних]; b. Оцініть [Призначення: деідентифікації. частота, визначена організацією] ефективність",
      title: "ДЕІДЕНТИФІКАЦІЯ (SI-19)",
      parameters: [
        {:si_19_odp_02,
         "Визначено частоту, з якою слід оцінювати ефективність деідентифікації; SI-19a. вилучено елементи з наборів даних; SI-19b. оцінюється ефективність деідентифікації частота",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-si-19-1") do
    %{
      id: :"id-spe-si-19-1",
      description: "",
      title: "ДЕІДЕНТИФІКАЦІЯ - ЗБІР (SI-19(1))",
      parameters: [
        {:si_19_1_01,
         "Деідентифікується набір даних після збору шляхом відмови від збору персональної інформації",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-19-2") do
    %{
      id: :"id-spe-si-19-2",
      description: "",
      title: "ДЕІДЕНТИФІКАЦІЯ - АРХІВАЦІЯ (SI-19(2))",
      parameters: [
        {:si_19_2_01,
         "Заборонено архівування елементів персональної інформації, якщо ці елементи в наборі даних не будуть потрібні після того, як набір даних буде заархівовано",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-19-3") do
    %{
      id: :"id-spe-si-19-3",
      description: "",
      title: "ДЕІДЕНТИФІКАЦІЯ - ВИДАЛЕННЯ (SI-19(3))",
      parameters: [
        {:si_19_3_01,
         "Видаляються елементи персональної інформаціїз набору даних перед його оприлюдненням, якщо ці елементи в наборі даних не повинні бути частиною оприлюднення даних",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-19-4") do
    %{
      id: :"id-spe-si-19-4",
      description: "",
      title: "ДЕІДЕНТИФІКАЦІЯ - ВИДАЛЕННЯ, МАСКУВАННЯ, ШИФРУВАННЯ, ХЕШУВАННЯ АБО ЗАМІНА ПРЯМИХ ІДЕНТИФІКАТОРІВ (SI-19(4))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-si-19-5") do
    %{
      id: :"id-spe-si-19-5",
      description: "",
      title: "ДЕІДЕНТИФІКАЦІЯ - КОНТРОЛЬ СТАТИСТИЧНОГО РОЗКРИТТЯ (SI-19(5))",
      parameters: [
        {:si_19_5_01,
         "Не маніпулюють числовими даними так, щоб у результатах аналізу не можна було ідентифікувати жодну особу чи організацію",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_19_5_02,
         "Не маніпулюють таблицями непередбачених обставин таким чином, щоб у результатах аналізу не можна було ідентифікувати жодну особу чи організацію",
         [type: :list, default: ["admin", "security_officer"]]},
        {:si_19_5_03,
         "Не маніпулюють статистичними даними так, щоб за результатами аналізу не можна було ідентифікувати жодну особу чи організацію",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-19-6") do
    %{
      id: :"id-spe-si-19-6",
      description: "",
      title: "ДЕІДЕНТИФІКАЦІЯ - ДИФЕРЕНЦІЙОВАНА КОНФІДЕНЦІЙНІСТЬ (SI-19(6))",
      parameters: [
        {:si_19_6_01,
         "Запобігає розголошенню персональної інформації, додавання недетермінованого шуму до результатів математичних операцій до того, як результати будуть повідомлені",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-si-19-7") do
    %{
      id: :"id-spe-si-19-7",
      description: "",
      title: "ДЕІДЕНТИФІКАЦІЯ - ПЕРЕВІРЕНЕ ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ (SI-19(7))",
      parameters: [
        {:si_19_7_01,
         "Виконується деідентифікація за допомогою перевірених алгоритмів",
         [type: :string, default: "AES-256-GCM"]},
        {:si_19_7_02,
         "Виконується деідентифікація за допомогою програмного забезпечення, яке пройшло валідацію для реалізації алгоритмів",
         [type: :string, default: "AES-256-GCM"]}
      ]
    }
  end

  def spec(:"id-spe-si-19-8") do
    %{
      id: :"id-spe-si-19-8",
      description: "",
      title: "ДЕІДЕНТИФІКАЦІЯ - МОТИВОВАНИЙ ПОРУШНИК (SI-19(8))",
      parameters: [
        {:si_19_8_01,
         "Виконується тест мотивованого зловмисника для деідентифікованого набору даних, щоб визначити, чи залишаються ідентифіковані дані або чи можна повторно ідентифікувати деідентифіковані дані",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-20") do
    %{
      id: :"id-spe-si-20",
      description: "Вбудуйте дані або можливості в такі системи або системні компоненти, щоб визначити, чи дані організації були викрадені або неналежним чином видалені з організації: [Призначення: визначені організацією системи або системні компоненти].",
      title: "ПСУВАННЯ (SI-20)",
      parameters: [
        {:si_20_01,
         "Вбудовані дані або можливості в системи або компоненти системи, щоб визначити, чи були дані організації викрадені або неналежним чином видалені з організації",
         [type: :string, default: nil]},
        {:si_20_odp,
         "Визначені системи або компоненти системи з даними або можливостями, що підлягають застосуванню",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-21") do
    %{
      id: :"id-spe-si-21",
      description: "Оновлюйте [Призначення: інформація, визначена організацією] з [Призначення: частота, визначена організацією] або згенеруйте інформацію за запитом і видаліть її, коли в ній більше не буде потреби.",
      title: "ОНОВЛЕННЯ ІНФОРМАЦІЇ (SI-21)",
      parameters: [
        {:si_21_01,
         "Інформація оновлюється частота або генерується на вимогу і видаляється, коли більше не потрібна. з якими потрібно оновлювати",
         [type: :string, default: "щорічно"]},
        {:si_21_odp_01,
         "Визначена інформація, яку потрібно оновити",
         [type: :string, default: nil]},
        {:si_21_odp_02,
         "Визначені частоти, інформацію",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-si-22") do
    %{
      id: :"id-spe-si-22",
      description: "a. Визначити наступні альтернативні джерела інформації для [Завдання: основні функції та послуги, визначені організацією]: [Завдання: альтернативні, визначені організацією джерела інформації]; b. Використовуйте альтернативне джерело інформації для виконання основних функцій або послуг на [Призначення: визначені організацією системи або системні компоненти], коли основне джерело інформації пошкоджено або недоступне.",
      title: "РІЗНОВИДИ ІНФОРМАЦІЇ (SI-22)",
      parameters: [
        {:si_22_odp_01,
         "Визначені альтернативні джерела інформації для основних функцій та послуг",
         [type: :string, default: nil]},
        {:si_22_odp_02,
         "Визначені основні функції та послуги, які потребують альтернативних джерел інформації",
         [type: :string, default: nil]},
        {:si_22_odp_03,
         "Визначені системи або компоненти системи, які потребують альтернативного джерела інформації для виконання основних функцій або послуг; SI-22a. визначені альтернативні джерела інформації для основних функцій та послуг; SI-22b. використовується альтернативне джерело інформації для виконання основних функцій або послуг у системах або компонентах системи, коли первинне джерело інформації пошкоджене або недоступне",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-si-23") do
    %{
      id: :"id-spe-si-23",
      description: "",
      title: "ФРАГМЕНТАЦІЯ ІНФОРМАЦІЇ (SI-23)",
      parameters: [
        {:si_23_odp_01,
         "Визначені обставини, інформації; які вимагають фрагментації",
         [type: :string, default: nil]},
        {:si_23_odp_02,
         "Визначена інформація, яка підлягає фрагментації",
         [type: :string, default: nil]},
        {:si_23_odp_03,
         "Визначені системи або компоненти системи, між якими має бути розподілена фрагментована інформація; SI-23a. за обставин, інформація є фрагментованою; SI-23b. за обставин фрагментована інформація розподіляється між системами або компонентами системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sr-1") do
    %{
      id: :"id-spe-sr-1",
      description: "a. Розробіть, задокументуйте та поширте [Призначення: персонал або ролі, визначені організацією]: 1. [Вибір (один або декілька): Рівень організації; Рівень місії/бізнес-процесу; рівень системи] політика управління ризиками ланцюга постачання, яка: a) Розглядає мету, сферу діяльності, ролі, відповідальність, зобов’язання керівництва, координацію між організаційними підрозділами та відповідність; b) Відповідає чинним законам, виконавчим наказам, директивам, положенням, політикам, стандартам і вказівкам; 2. Процедури для сприяння впровадженню політики управління ризиками ланцюга постачання та відповідних засобів контролю управління ризиками ланцюга постачання; b. Призначити [Призначення: посадова особа, визначена організацією] для управління розробкою, документуванням і розповсюдженням політики та процедур управління ризиками ланцюга постачання; c. Перегляньте та оновіть поточне управління ризиками ланцюга постачання: 1. Політика [Призначення: частота, визначена організацією] та наступне [Призначення: події, визначені організацією]; 2. Процедури [Призначення: частота, визначена організацією] та наступні [Призначення: події, визначені організацією].",
      title: "ПОЛІТИКА ТА ПРОЦЕДУРИ УПРАВЛІННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ (SR-1)",
      parameters: [
        {:sr_1_odp_01,
         "Визначено персонал або ролі, на які поширюється політика управління ризиками ланцюга постачання",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sr_1_odp_02,
         "Визначено персонал або ролі, на які поширюються процедури управління ризиками ланцюга постачання",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sr_1_odp_03,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {рівень організації; рівень завдань/бізнеспроцесу; рівень системи}",
         [type: :string, default: nil]},
        {:sr_1_odp_04,
         "Визначена посадова особа, відповідальна за розробку, документування та розповсюдження політики та процедур управління ризиками ланцюга постачання",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sr_1_odp_05,
         "Визначена періодичність перегляду та оновлення поточної політики управління ризиками ланцюга постачання",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sr_1_odp_06,
         "Є події, які вимагають перегляду та оновлення поточної політики управління ризиками ланцюга постачання",
         [type: :list, default: ["default_deny_rule", "abac_rule_1"]]},
        {:sr_1_odp_07,
         "Визначена періодичність перегляду та оновлення поточної процедури управління ризиками ланцюга постачання",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-sr-2") do
    %{
      id: :"id-spe-sr-2",
      description: "a. Розробіть план управління ризиками ланцюга постачання, пов’язаними з дослідженнями та розробкою, проектуванням, виробництвом, придбанням, доставкою, інтеграцією, експлуатацією та обслуговуванням, а також утилізацією таких систем, компонентів системи або послуг для системи: [Призначення: системи, визначені організацією, системні компоненти або системні служби]; b. Перегляньте та оновіть план управління ризиками ланцюга постачання [Призначення: частота, визначена організацією] або за потреби для усунення загроз; c. Захистіть план управління ризиками ланцюга постачання від несанкціонованого розголошення та модифікації.",
      title: "ПЛАН УПРАВЛІННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ (SR-2)",
      parameters: [
        {:sr_2_odp_01,
         "Визначені системи, компоненти системи або системні послуги, для яких розробляється план управління ризиками ланцюга постачання",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sr-2-1") do
    %{
      id: :"id-spe-sr-2-1",
      description: "",
      title: "СТВОРЕННЯ КОМАНДИ ПОСТАЧАННЯ (SR-2(1))",
      parameters: [
        {:sr_2_1_01,
         "Створена команда з управління ризиками ланцюга постачання, що складається з персонал, ролі та обов'язки для керівництва та підтримки діяльності з управління ризиками ланцюга постачання",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-sr-3") do
    %{
      id: :"id-spe-sr-3",
      description: "a. Встановлення процесу або процесів для виявлення та усунення слабких місць або недоліків в елементах і процесах ланцюга постачання [Призначення: визначена організацією система або компонент системи] у координації з [Завдання: персонал ланцюга постачання, визначений організацією]; b. Використовуйте такі заходи захисту, щоб захистити систему, компонент системи або системну службу від ризиків ланцюга постачання та обмежити шкоду чи наслідки від подій, пов’язаних із ланцюгом постачання: [Призначення: заходи захисту ланцюга постачання, визначені організацією]; c. Задокументуйте обрані та впроваджені процеси та заходи захисту ланцюгом постачання у [Вибір: плани безпеки та приватності; план управління ризиками ланцюга постачання; [Призначення: документ, визначений організацією]].",
      title: "КОНТРОЛЬ ЛАНЦЮГА ПОСТАЧАННЯ І ПРОЦЕСІВ (SR-3)",
      parameters: [
        {:sr_3_odp_01,
         "Визначено систему або компонент системи, який потребує процесу або процесів для виявлення та усунення слабких місць або недоліків",
         [type: :string, default: nil]},
        {:sr_3_odp_02,
         "Визначено персонал ланцюга поставок, з яким необхідно координувати процес або процеси виявлення та усунення слабких місць або недоліків в елементах і процесах ланцюга постачання",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sr_3_odp_03,
         "Визначені засоби контролю ланцюга постачання, що застосовуються для захисту від ризиків ланцюга постачання для системи, системного компонента або системної послуги, а також для обмеження шкоди або наслідків від подій, пов'язаних з ланцюгом постачання",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sr_3_odp_04,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {плани безпеки та конфіденційності; план управління ризиками ланцюга постачання; документ}; SR-03_ODP[05] визначено документ, що ідентифікує обрані та впроваджені процеси та засоби контролю ланцюга постачання (якщо обрано); SR-03a.[01] запроваджено процес або процеси для виявлення та усунення слабких місць або недоліків в елементах та процесах ланцюга постачання; SR-03a.[02] процес або процеси виявлення та усунення слабких місць або недоліків в елементах та процесах ланцюга постачання системи або компонента системи координується/координуються з персоналом ланцюга постачання; SR-03b. застосовуються засоби контролю ланцюга постачання для захисту від ризиків ланцюга постачання для системи, системного компонента або системної послуги, а також для обмеження шкоди або наслідків від подій, пов'язаних з ланцюгом постачання; SR-03c. задокументовані обрані та впроваджені процеси та засоби контролю ланцюга постачання в ЗНАЧЕННЯ ВИБІРКОВОГО ПАРАМЕТРА(ів)",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sr_3_odp_05,
         "Визначено документ, що ідентифікує обрані та впроваджені процеси та засоби контролю ланцюга постачання (якщо обрано); SR-03a.[01] запроваджено процес або процеси для виявлення та усунення слабких місць або недоліків в елементах та процесах ланцюга постачання; SR-03a.[02] процес або процеси виявлення та усунення слабких місць або недоліків в елементах та процесах ланцюга постачання системи або компонента системи координується/координуються з персоналом ланцюга постачання; SR-03b. застосовуються засоби контролю ланцюга постачання для захисту від ризиків ланцюга постачання для системи, системного компонента або системної послуги, а також для обмеження шкоди або наслідків від подій, пов'язаних з ланцюгом постачання; SR-03c. задокументовані обрані та впроваджені процеси та засоби контролю ланцюга постачання в ЗНАЧЕННЯ ВИБІРКОВОГО ПАРАМЕТРА(ів)",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-sr-3-1") do
    %{
      id: :"id-spe-sr-3-1",
      description: "",
      title: "КОНТРОЛЬ ЛАНЦЮГА ПОСТАЧАННЯ І ПРОЦЕСІВ - РІЗНІ БАЗИ ПОСТАЧАННЯ (SR-3(1))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sr-3-2") do
    %{
      id: :"id-spe-sr-3-2",
      description: "",
      title: "КОНТРОЛЬ ЛАНЦЮГА ПОСТАЧАННЯ І ПРОЦЕСІВ - ОБМЕЖЕННЯ ШКОДИ (SR-3(2))",
      parameters: [
        {:sr_3_2_odp,
         "Визначені засоби контролю для обмеження шкоди від потенційних супротивників ланцюга постачання; SR-03(02) застосовуються контроль для обмеження шкоди від потенційних супротивників, які ідентифікують та націлюються на ланцюг постачання організації",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sr-3-3") do
    %{
      id: :"id-spe-sr-3-3",
      description: "",
      title: "КОНТРОЛЬ ЛАНЦЮГА ПОСТАЧАННЯ І ПРОЦЕСІВ - ПЕРЕНЕСЕННЯ ЗАХОДІВ ЗАХИСТУ УПРАВЛІННЯ РИЗИКАМИ ЛАНЦЮГА ПОСТАЧАННЯ ДО СУБПІДРЯДНИКІВ (SR-3(3))",
      parameters: [
        {:sr_3_3_01,
         "Включені засоби контролю, передбачені в контрактах з основними підрядниками, також і в контрактах з субпідрядниками",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sr-4") do
    %{
      id: :"id-spe-sr-4",
      description: "Документуйте, відстежуйте та підтримуйте справжнє походження таких систем, компонентів системи і пов’язаних даних: [Призначення: системи, визначені організацією, системні компоненти та пов’язані дані].",
      title: "ПОХОДЖЕННЯ (SR-4)",
      parameters: [
        {:sr_4_01,
         "Задокументовано дійсне походження для систем, компонентів системи та пов'язаних з ними даних",
         [type: :string, default: nil]},
        {:sr_4_02,
         "Відстежується дійсне походження для систем, компонентів системи та пов'язаних з ними даних",
         [type: :string, default: nil]},
        {:sr_4_03,
         "Підтримується дійсне походження для систем, компонентів системи та пов'язаних з ними даних",
         [type: :string, default: nil]},
        {:sr_4_odp,
         "Визначені системи, компоненти системи та пов'язані з ними дані, які потребують достовірного походження",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sr-4-1") do
    %{
      id: :"id-spe-sr-4-1",
      description: "",
      title: "ПОХОДЖЕННЯ - ІДЕНТИЧНІСТЬ (SR-4(1))",
      parameters: [
        {:sr_4_1_01,
         "Встановлена унікальна ідентифікація елементів ланцюга постачання, процесів та персоналу; SR-04(01)[02] підтримується унікальна ідентифікація елементів ланцюга постачання, процесів та персоналу",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sr_4_1_02,
         "Зберігається унікальна ідентифікація систем та критично важливих системних компонентів для відстеження в ланцюгу постачання",
         [type: :string, default: nil]},
        {:sr_4_1_odp,
         "Визначені елементи ланцюга постачання, процеси та персонал, пов'язані з системами та критично важливими компонентами системи, які потребують унікальної ідентифікації",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-sr-4-2") do
    %{
      id: :"id-spe-sr-4-2",
      description: "",
      title: "ПОХОДЖЕННЯ - УНІКАЛЬНА ІДЕНТИФІКАЦІЯ (SR-4(2))",
      parameters: [
        {:sr_4_2_01,
         "Встановлена унікальна ідентифікація систем та критичних системних компонентів для відстеження в ланцюгу постачання",
         [type: :string, default: nil]},
        {:sr_4_2_odp,
         "Визначені системи та критичні компоненти системи, які потребують унікальної ідентифікації для відстеження в ланцюгу постачання",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sr-4-3") do
    %{
      id: :"id-spe-sr-4-3",
      description: "",
      title: "ПОХОДЖЕННЯ - ПЕРЕВІРКА НА СПРАВЖНІСТЬ І ВІДСУТНІСТЬ ВНЕСЕННЯ ЗМІН (SR-4(3))",
      parameters: [
        {:sr_4_3_01,
         "Застосовуються засоби контролю для перевірки того, що отримана система або компонент системи є справжніми",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sr_4_3_02,
         "Застосовуються засоби контролю для перевірки того, що отриману систему або компонент системи не було змінено",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sr-4-4") do
    %{
      id: :"id-spe-sr-4-4",
      description: "",
      title: "ПОХОДЖЕННЯ – ПЕРЕВІРКА ЛАНЦЮГА ЦІЛІСНОСТІ (SR-4(4))",
      parameters: [
        {:sr_4_4_01,
         "Застосовуються засоби контролю для забезпечення цілісності системи та її компонентів",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sr_4_4_02,
         "Проводиться метод аналізу для забезпечення цілісності системи та компонентів системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sr-5") do
    %{
      id: :"id-spe-sr-5",
      description: "Використовуйте наступні стратегії придбання, контрактні інструменти та методи закупівель, щоб захистити від ризиків ланцюга постачання, визначити та пом’якшити їх: [Призначення: визначені організацією стратегії придбання, контрактні інструменти та методи закупівель].",
      title: "СТРАТЕГІЇ ПРИДБАННЯ, ІНСТРУМЕНТИ І МЕТОДИ (SR-5)",
      parameters: [
        {:sr_5_01,
         "Застосовуються стратегії, інструменти та методи для захисту від ризиків ланцюга постачання",
         [type: :string, default: nil]},
        {:sr_5_02,
         "Застосовуються стратегії, інструменти та методи для виявлення ризиків ланцюга постачання",
         [type: :string, default: nil]},
        {:sr_5_03,
         "Застосовуються стратегії, інструменти та методи для зменшення ризиків ланцюга постачання",
         [type: :string, default: nil]},
        {:sr_5_odp,
         "Визначені стратегії закупівель, контрактні інструменти та методи закупівель для захисту, виявлення та пом'якшення ризиків ланцюга постачання",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sr-5-1") do
    %{
      id: :"id-spe-sr-5-1",
      description: "",
      title: "СТРАТЕГІЇ ПРИДБАННЯ, ІНСТРУМЕНТИ І МЕТОДИ - НАЛЕЖНЕ ПОСТАЧАННЯ (SR-5(1))",
      parameters: [
        {:sr_5_1_01,
         "Застосовуються засоби контролю для забезпечення адекватного постачання критично важливих компонентів системи",
         [type: :string, default: "автоматизований засіб моніторингу"]}
      ]
    }
  end

  def spec(:"id-spe-sr-5-2") do
    %{
      id: :"id-spe-sr-5-2",
      description: "",
      title: "СТРАТЕГІЇ ПРИДБАННЯ, ІНСТРУМЕНТИ І МЕТОДИ - ОЦІНКА ПЕРЕД ВІДБОРОМ, ПРИЙНЯТТЯ, МОДИФІКАЦІЯ ЧИ ОНОВЛЕННЯ (SR-5(2))",
      parameters: [
        {:sr_5_2_01,
         "Оцінюється система, компонент системи або послуги системи перед відбором",
         [type: :string, default: nil]},
        {:sr_5_2_02,
         "Оцінюється система, компонент системи або послуги системи перед прийняттям",
         [type: :string, default: nil]},
        {:sr_5_2_03,
         "Оцінюється система, компонент системи або послуги системи перед модифікацією",
         [type: :string, default: nil]},
        {:sr_5_2_04,
         "Оцінюється система, компонент системи або послуги системи перед оновленням",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sr-6") do
    %{
      id: :"id-spe-sr-6",
      description: "Оцініть і перегляньте ризики ланцюга постачання, пов’язані з постачальниками або підрядниками, системою, системним компонентом або системною послугою, яку вони надають [Призначення: частота, визначена організацією].",
      title: "ОЦІНКА ПОСТАЧАЛЬНИКІВ (SR-6)",
      parameters: [
        {:sr_6_01,
         "Оцінюються та аналізуються ризики, пов'язані з ланцюгом постачання, які стосуються постачальників або підрядників та систем, компонентів системи або системних послуг, які вони надають < SR-06_ODP частота >",
         [type: :string, default: "щорічно"]},
        {:sr_6_odp,
         "Визначена періодичність оцінки та аналізу ризиків, пов'язаних з ланцюгом постачання, що стосуються постачальників або підрядників, а також систем, компонентів системи або системних послуг, які вони надають",
         [type: :string, default: "щорічно"]}
      ]
    }
  end

  def spec(:"id-spe-sr-6-1") do
    %{
      id: :"id-spe-sr-6-1",
      description: "",
      title: "ОЦІНКА ПОСТАЧАЛЬНИКІВ - ТЕСТУВАННЯ ТА АНАЛІЗ (SR-6(1))",
      parameters: [

      ]
    }
  end

  def spec(:"id-spe-sr-7") do
    %{
      id: :"id-spe-sr-7",
      description: "Використовуйте такі заходи захисту операційної безпеки (OPSEC), щоб захистити інформацію, пов’язану з ланцюгом постачання для системи, системного компонента чи системної служби: [Призначення: визначені організацією заходи захисту операційної безпеки (OPSEC)].",
      title: "БЕЗПЕКА ОПЕРАЦІЙ ЛАНЦЮГА ПОСТАЧАННЯ (SR-7)",
      parameters: [
        {:sr_7_01,
         "Застосовуються засоби управління OPSEC для захисту інформації, пов'язаної з ланцюжком постачання для системи, системного компонента або системної служби",
         [type: :string, default: "автоматизований засіб моніторингу"]},
        {:sr_7_odp,
         "Визначені заходи захисту операційної безпеки (OPSEC) для захисту інформації, пов'язаної з ланцюжком поставок, для системи, системного компонента або системної служби",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sr-8") do
    %{
      id: :"id-spe-sr-8",
      description: "Затвердити угоди та процедури з суб’єктами, залученими до ланцюга постачання для системи, системного компонента або системної послуги для [Вибір (одного або кількох): повідомлення про порушення ланцюга постачання; результати оцінювання або аудитів; [Призначення: інформація, визначена організацією]].",
      title: "Повідомлення про порушення ланцюга постачання (SR-8)",
      parameters: [
        {:sr_8_01,
         "Аналізу/тестування елементів, ПОВІДОМЛЕННЯ ПРО ПОРУШЕННЯ ЛАНЦЮГА ПОСТАЧАННЯ",
         [type: :string, default: nil]},
        {:sr_8_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {повідомлення про порушення ланцюга постачання; результати оцінок або аудитів}",
         [type: :string, default: nil]},
        {:sr_8_odp_02,
         "Визначена інформація, для якої необхідно встановити угоди та процедури (якщо вибрано)",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sr-9") do
    %{
      id: :"id-spe-sr-9",
      description: "Впровадити програму захисту від несанкціонованого доступу для системи, системного компонента або системної служби.",
      title: "ЗАХИСТ ВІД ЗЛОМУ ТА ВИЯВЛЕННЯ (SR-9)",
      parameters: [
        {:sr_9_01,
         "Реалізована програма захисту від несанкціонованого доступу для системи, компонента системи або системної служби",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sr-9-1") do
    %{
      id: :"id-spe-sr-9-1",
      description: "",
      title: "ЗАХИСТ ВІД ЗЛОМУ ТА ВИЯВЛЕННЯ - ЕТАПИ ЧИ СИСТЕМИ РОЗВИТКУ ЖИТТЄВОГО ЦИКЛУ (SR-9(1))",
      parameters: [
        {:sr_9_1_01,
         "Застосовуються технології, інструменти та методи захисту від втручання протягом усього життєвого циклу розробки системи",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sr-10") do
    %{
      id: :"id-spe-sr-10",
      description: "Перевірте наступні системи або системні компоненти [Вибір (один або більше): випадковим чином обраних; на [Призначення: частота, визначена організацією], після [Призначення: визначені організацією ознаки необхідності перевірки]] для виявлення втручання: [Призначення: визначені організацією системи або компоненти системи].",
      title: "ПЕРЕВІРКА СИСТЕМИ І КОМПОНЕНТІВ СИСТЕМИ (SR-10)",
      parameters: [
        {:sr_10_odp_01,
         "Визначені системи або компоненти системи, які потребують перевірки",
         [type: :string, default: nil]},
        {:sr_10_odp_02,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРА: {випадково; з частотою <SR-10_ODP[03]; за наявності вказівок на необхідність перевірки}",
         [type: :integer, default: 30]},
        {:sr_10_odp_03,
         "Визначена періодичність проведення перевірок систем або компонентів системи (якщо вибрано)",
         [type: :string, default: "щорічно"]},
        {:sr_10_odp_04,
         "Визначені ознаки необхідності перевірки систем або компонентів системи (якщо вони були обрані)",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sr-11") do
    %{
      id: :"id-spe-sr-11",
      description: "a. Розробити та впровадити політику та процедури боротьби з підробками, які включають засоби для виявлення та запобігання потраплянню підроблених компонентів у систему; b. Повідомляти про підроблені системні компоненти [Вибір (один або кілька): джерело підробленого компонента; [Призначення: зовнішні звітні організації, визначені організацією]; [Призначення: персонал або ролі, визначені організацією]].",
      title: "АВТЕНТИЧНІСТЬ КОМПОНЕНТУ (SR-11)",
      parameters: [
        {:sr_11_odp_01,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРА: {джерело підробленого компонента; зовнішні підзвітні організації; персонал або ролі}",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sr_11_odp_02,
         "Визначені зовнішні підзвітні організації, яким слід повідомляти про підроблені компоненти системи (якщо вони були обрані)",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-sr-11-1") do
    %{
      id: :"id-spe-sr-11-1",
      description: "",
      title: "Додаток В ВІДОБРАЖЕННЯ МІЖНАРОДНИХ СТАНДАРТІВ ТА КАТАЛОГУ ЗАХОДІВ ЗАХИСТУ Таблиці відображень у цьому додатку надають організаціям загальну інформацію щодо відповідності заходів безпеки цього нормативного документа вимогам міжнародного стандарту ISO/IEC 27001 «Інформаційні технології — Технології безпеки — Системи управління інформаційною безпекою» та міжнародного стандарту ISO/IEC 15408 «Інформаційні технології — Техніка безпеки — Критерії оцінювання ІТ безпеки». Таблиці відповідності розроблені з метою зіставлення вимог стандартів з вимогами цього нормативного документа. Зіставлення здійснювалося на якісному рівні, тобто припускається, що реалізація (впровадження) заходів захисту, зіставлених у таблицях, приводять до досягнення еквівалентних результатів захисту. Але це не означає, що розробники профілів захисту повинні припускати повну еквівалентність заходів захисту, базуючись на цих таблицях. Організації можуть використовувати контрольні відображення, які наведено в Таблицях В.1 та В.2, при організації взаємодії із зовнішніми організаціями, включно з, наприклад, визначенням вимог безпеки та приватності в договорах і угодах. Організації відповідають за аналіз заходів захисту, що впроваджені відповідно до вимог ISO/IEC 27001; їх узгодженість з вимогами цього НД ТЗІ і усунення будь-яких прогалин у сфері застосування заходів захисту. Крім того, через процес вибору заходів захисту, захід захисту, який не застосовується в рамках стандартів ISO/IEC 27001 та ISO/IEC 15408, може бути вибраний, впроваджений і оцінений для забезпечення захисту інформації, відповідно до ризиків. Зрештою, рішення про використання вимог ISO/IEC 27001 та ISO/IEC 15408 залишається за уповноваженою посадовою особою організації. Примітка: зірочка (*) вказує на те, що захід захисту Каталогу заходів захисту не повню мірою відповідає вимогам ISO/IEC 27001. Таблиця В.1 — Відображення заходів захисту Каталогу, який наведений в цьому НД ТЗІ на вимоги ISO/IEC27001 Шифр (SR-11(1))",
      parameters: [
        {:sr_11_1_01,
         "Підготовлений персонал або ролі до виявлення підроблених компонентів системи, включаючи апаратне, програмне та мікропрограмне забезпечення",
         [type: :list, default: ["admin", "security_officer"]]},
        {:sr_11_1_odp,
         "Визначено персонал або ролі, які потребують підготовки для виявлення підроблених компонентів системи (включаючи апаратне, програмне та мікропрограмне забезпечення)",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-sr-12") do
    %{
      id: :"id-spe-sr-12",
      description: "Утилізуйте [Призначення: визначені організацією дані, документація, інструменти або системні компоненти] за допомогою таких прийомів і методів: [Призначення: визначені організацією прийоми та методи].",
      title: "УТИЛІЗАЦІЯ КОМПОНЕНТУ (SR-12)",
      parameters: [
        {:sr_12_01,
         "Утилізуються дані, документація, інструменти або компоненти системи з використанням прийомів і методів",
         [type: :string, default: nil]},
        {:sr_12_odp_01,
         "Визначені дані, документація, інструменти або компоненти системи, які підлягають утилізації",
         [type: :string, default: nil]},
        {:sr_12_odp_02,
         "Визначені методи та способи утилізації даних, документації, інструментів або компонентів системи",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-at-2-2") do
    %{
      id: :"id-spe-at-2-2",
      description: "Ввести до програми навчання вправи з розпізнавання та виявлення потенційних індикаторів внутрішніх загроз.",
      title: "НАВЧАННЯ З ПІДВИЩЕННЯ ОБІЗНАНОСТІ | НАВЧАННЯ ЩОДО РОЗПІЗНАВАННЯ ВНУТРІШНЬОЇ ЗАГРОЗИ",
      parameters: [
        {:at_2_2_01,
         "Введено до програми навчання вправи з розпізнавання потенційних індикаторів внутрішніх загроз",
         [type: :string, default: nil]},
        {:at_2_2_02,
         "Введено до програми навчання вправи з виявлення потенційних індикаторів внутрішніх загроз",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-at-2-3") do
    %{
      id: :"id-spe-at-2-3",
      description: "Ввести до програми навчання вправи з підвищення обізнаності щодо розпізнавання та повідомлення про потенційні та фактичні атаки, з використанням методів соціальної інженерії та інтелектуального аналізу соціальних даних.",
      title: "НАВЧАННЯ З ПІДВИЩЕННЯ ОБІЗНАНОСТІ | НАВЧАННЯ З ПИТАНЬ СОЦІАЛЬНОЇ ІНЖЕНЕРІЇ",
      parameters: [
        {:at_2_3_01,
         "До програми навчання введено вправи з розпізнавання потенційних та фактичних випадків соціального інжинірингу",
         [type: :string, default: nil]},
        {:at_2_3_02,
         "До програми навчання введено вправи з повідомлення про потенційні та фактичні випадки соціального інжинірингу",
         [type: :string, default: nil]},
        {:at_2_3_03,
         "До програми навчання введено вправи з розпізнавання потенційних та фактичних випадків інтелектуального аналізу соціальних даних",
         [type: :string, default: nil]},
        {:at_2_3_04,
         "До програми навчання введено вправи з повідомлення про потенційні та фактичні випадки інтелектуального аналізу соціальних даних",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-ia-5") do
    %{
      id: :"id-spe-ia-5",
      description: "",
      title: "АВТЕНТИФІКАТОР УПРАВЛІННЯ",
      parameters: [
        {:ia_5_a,
         "Управління системними автентифікаторами здійснюється шляхом перевірки, як частини початкового розподілу автентифікатора, особи, групи, ролі або пристрою, який отримує автентифікатор",
         [type: :list, default: ["admin", "security_officer"]]},
        {:ia_5_b,
         "Управління системними автентифікаторами здійснюється шляхом створення вихідного вмісту автентифікатора для будь-яких автентифікаторів, виданих організацією",
         [type: :string, default: nil]},
        {:ia_5_c,
         "Управління системними автентифікаторами здійснюється шляхом забезпечення того, щоб автентифікатори мали достатню стійкість механізму для їх використання за призначенням; IA-05(d) управління системними автентифікаторами здійснюється шляхом створення та реалізація адміністративних процедур для первинного розповсюдження автентифікаторів, для втрачених/скомпрометованих або пошкоджених автентифікаторів, а також для відкликання автентифікаторів",
         [type: :string, default: nil]},
        {:ia_5_e,
         "Управління системними автентифікаторами здійснюється шляхом зміни типових автентифікаторів перед першим використанням",
         [type: :string, default: nil]},
        {:ia_5_f,
         "Управління системними автентифікаторами здійснюється шляхом зміни/оновлення автентифікаторів у встановлений період часу або коли відбуваються події",
         [type: :list, default: ["login", "logout", "failed_attempt"]]},
        {:ia_5_g,
         "Управління системними автентифікаторами здійснюється шляхом захисту вмісту автентифікатора від несанкціонованого розкриття та модифікацій",
         [type: :string, default: nil]},
        {:ia_5_h,
         "Управління системними автентифікаторами здійснюється шляхом вимоги до осіб, які використовують пристрої, використовувати спеціальні заходи безпеки для захисту автентифікаторів",
         [type: :string, default: nil]},
        {:ia_5_i,
         "Управління системними автентифікаторами здійснюється шляхом вимоги змінювати автентифікатори для облікових записів груп/ролей при зміні членства в цих облікових записах",
         [type: :string, default: nil]},
        {:ia_5_odp_01,
         "Визначено період часу для зміни або оновлення автентифікаторів за типом автентифікатора",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-ia-6") do
    %{
      id: :"id-spe-ia-6",
      description: "",
      title: "ПРИХОВУВАННЯ ЗВОРОТНОГО ЗВ'ЯЗКУ АВТЕНТИФІКАТОРА",
      parameters: [
        {:ia_6_01,
         "Забезпечино приховану зворотну передачу інформації автентифікації в про- цесі автентифікації для забезпечення захисту інформації від можливої експлуатації та використання неавторизованими особами",
         [type: :list, default: ["admin", "security_officer"]]}
      ]
    }
  end

  def spec(:"id-spe-pe-3") do
    %{
      id: :"id-spe-pe-3",
      description: "",
      title: "ФІЗИЧНИЙ ДОСТУП ДО СИСТЕМИ",
      parameters: [
        {:pe_3_a_01,
         "Авторизація фізичного доступу забезпечується в пунктах входу і виходу шляхом перевірки індивідуальних дозволів доступу",
         [type: :string, default: nil]},
        {:pe_3_b,
         "Журнали контролю фізичного доступу ведуться для 03_ODP[04] точок входу або виходу>",
         [type: :string, default: nil]},
        {:pe_3_c,
         "Доступ в зони всередині об'єкту, визначені як загальнодоступні, підтримується шляхом впровадження заходів захисту",
         [type: :string, default: nil]},
        {:pe_3_d_01,
         "Відвідувачів супроводжують",
         [type: :string, default: nil]},
        {:pe_3_d_02,
         "Активність відвідувачів контролюється умови",
         [type: :list, default: []]},
        {:pe_3_e_01,
         "Ключі захищені",
         [type: :string, default: nil]},
        {:pe_3_e_02,
         "Коди доступу захищені",
         [type: :string, default: nil]},
        {:pe_3_e_03,
         "Інші пристрої фізичного доступу захищені",
         [type: :string, default: nil]},
        {:pe_3_f,
         "Пристрої фізичного доступу інвентаризуються частота",
         [type: :string, default: "щорічно"]},
        {:pe_3_g_01,
         "Коди доступу змінюється частота, коли код скомпрометовано, або коли особи, які володіють кодом, переводяться або звільняються; <PE- PE-03(g)[02] ключі змінюються частота, коли ключі втрачено, або коли особи, що володіють ключами, переводяться або звільняються",
         [type: :list, default: ["admin", "security_officer"]]},
        {:pe_3_odp_01,
         "Визначено точки входу та виходу в об'єкт, в якому знаходиться система",
         [type: :string, default: nil]},
        {:pe_3_odp_02,
         "Вибрано одне або декілька з наступних ЗНАЧЕНЬ ПАРАМЕТРІВ: {системи або пристрої; охоронці}",
         [type: :string, default: nil]},
        {:pe_3_odp_03,
         "Визначено фізичні системи або пристрої контролю доступу, що використовуються для контролю входу та виходу на об'єкт (якщо вибрано); PE-03_ODP[04] визначено точки входу або виходу, для яких ведуться журнали контролю фізичного доступу",
         [type: :string, default: nil]},
        {:pe_3_odp_05,
         "Визначено заходи захисту для контролю доступу в зони всередині об'єкту, позначені як загальнодоступні",
         [type: :string, default: nil]},
        {:pe_3_odp_06,
         "Визначено умови, що вимагають супроводу відвідувачів та моніторингу активності відвідувачів",
         [type: :list, default: []]},
        {:pe_3_odp_07,
         "Визначені пристрої фізичного доступу, що підлягають інвентаризації",
         [type: :string, default: nil]},
        {:pe_3_odp_08,
         "Визначено частоту проведення інвентаризації пристроїв фізичного доступу",
         [type: :integer, default: 30]},
        {:pe_3_odp_09,
         "Визначено частоту, з якою потрібно змінювати коди доступу",
         [type: :integer, default: 30]},
        {:pe_3_odp_10,
         "Визначено частоту, з якою потрібно змінювати ключі",
         [type: :integer, default: 30]}
      ]
    }
  end

  def spec(:"id-spe-pe-5") do
    %{
      id: :"id-spe-pe-5",
      description: "",
      title: "КОНТРОЛЬ ДОСТУПУ В ПРИМІЩЕННЯ ДЛЯ ВІДОБРАЖЕННЯ ІНФОРМАЦІЇ",
      parameters: [
        {:pe_5_odp,
         "Визначено пристрої для виведення інформації над якими необхідний контроль над фізичним доступом до вихідних даних",
         [type: :string, default: nil]}
      ]
    }
  end

  def spec(:"id-spe-pe-6") do
    %{
      id: :"id-spe-pe-6",
      description: "",
      title: "МОНІТОРИНГ ФІЗИЧНОГО ДОСТУПУ",
      parameters: [
        {:pe_6_a,
         "Фізичний доступ до об'єкту, де знаходиться система, моніториться з метою виявлення та реагування на інциденти фізичної безпеки",
         [type: :string, default: nil]},
        {:pe_6_b_01,
         "Переглядаються журнали фізичного доступу частота",
         [type: :string, default: "щорічно"]},
        {:pe_6_b_02,
         "Журнали фізичного доступу переглядаються при виникненні подій",
         [type: :string, default: nil]},
        {:pe_6_c_01,
         "Результати переглядів узгоджуються з можливостями організації щодо реагування на інциденти",
         [type: :string, default: nil]},
        {:pe_6_c_02,
         "Результати розслідувань узгоджуються з можливостями організації щодо реагування на інциденти",
         [type: :string, default: nil]},
        {:pe_6_odp_01,
         "Визначено частоту перегляду журналів фізичного доступу",
         [type: :integer, default: 30]},
        {:pe_6_odp_02,
         "Визначено події або потенційні ознаки подій, що вимагають перегляду журналів фізичного доступу",
         [type: :list, default: ["login", "logout", "failed_attempt"]]}
      ]
    }
  end

  def spec(:"id-spe-sc-28-1") do
    %{
      id: :"id-spe-sc-28-1",
      description: "",
      title: "ЗАХИСТ ІНФОРМАЦІЇ В СТАНІ СПОКОЮ | КРИПТОГРАФІЧНИЙ ЗАХИСТ",
      parameters: [
        {:sc_28_1_01,
         "Реалізовані криптографічні механізми для запобігання несанкціонованому розкриттю інформації, що знаходиться в стані спокою на системних компонентах або носіях",
         [type: :string, default: "AES-256-GCM"]},
        {:sc_28_1_02,
         "Реалізовані криптографічні механізми для запобігання несанкціонованій модифікації інформації, що знаходиться в стані спокою на системних компонентах або носіях",
         [type: :string, default: "AES-256-GCM"]}
      ]
    }
  end

  def spec(_), do: nil
end
